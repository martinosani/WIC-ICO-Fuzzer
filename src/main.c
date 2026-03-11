/*
 * main.c
 *
 * WIC ICO Fuzzing Harness -- Main Entry Point
 *
 * WinAFL persistent mode target: fuzz_target()
 * TinyInst coverage module: windowscodecs.dll
 *
 * Architecture:
 *   COM init + WIC factory: outside loop (once per process)
 *   fuzz_target(): inside loop (every iteration)
 *
 * COM interface chain exercised:
 *   IWICImagingFactory
 *   IWICImagingFactory2         (CreateColorContext)
 *   IWICBitmapDecoder
 *   IWICBitmapDecoderInfo
 *   IWICBitmapFrameDecode
 *   IWICBitmapSource            (via QueryInterface -- never raw cast)
 *   IWICFormatConverter
 *   IWICMetadataQueryReader     (recursive descent into nested readers)
 *   IWICEnumMetadataItem
 *   IWICPalette
 *   IWICColorContext
 *   IWICComponentInfo / IWICPixelFormatInfo
 *   IWICBitmapSourceTransform   (scaled decode path)
 *   IWICProgressiveLevelControl (progressive / interlaced PNG path)
 */

#define WIN32_LEAN_AND_MEAN
#define COBJMACROS   /* C-style COM macro calls: pObj->lpVtbl->Method() */

#include <windows.h>
#include <ole2.h>
#include <wincodec.h>
#include <wincodecsdk.h>
#include <shlobj.h>
#include <stdio.h>
#include <strsafe.h>

#include "config.h"
#include "policy.h"
#include "trace.h"
#include "ini.h"

/* =========================================================================
 * SAFE_RELEASE
 * Calls Release() only if the pointer is non-NULL, then NULLs it.
 * Safe to call on already-NULL pointers (no-op).
 * ========================================================================= */
#define SAFE_RELEASE(p) \
    do { if ((p)) { (p)->lpVtbl->Release((p)); (p) = NULL; } } while(0)

/* =========================================================================
 * CHECK_HR_GOTO
 * Log stage + HRESULT.  On failure: jump to label for cleanup.
 * ========================================================================= */
#define CHECK_HR_GOTO(hr, stage, label)            \
    do {                                           \
        trace_stage(&g_trace, (stage), (hr));      \
        if (FAILED(hr)) { goto label; }            \
    } while(0)

/* =========================================================================
 * Global state -- initialized once, outside the fuzz loop
 * ========================================================================= */
static IWICImagingFactory*  g_pFactory  = NULL;

/*
 * g_pFactory2 holds IWICImagingFactory2, obtained via QI from g_pFactory.
 * IWICImagingFactory does not expose CreateColorContext; that method exists
 * only on IWICImagingFactory2.  Both pointers refer to the same underlying
 * COM object.  Released in reverse-QI order during global cleanup.
 */
static IWICImagingFactory2* g_pFactory2 = NULL;

static HARNESS_CONFIG       g_cfg;
static HARNESS_TRACE_CTX    g_trace;
static BOOL                 g_initialized = FALSE;

#ifdef HARNESS_MODE_RESEARCH
/*
 * Thread-ID captured at harness_global_init() time.
 * Checked at the start of each fuzz_target() in RESEARCH mode to detect
 * COM apartment violations if WinAFL ever calls fuzz_target() from a
 * different thread than the one that called CoInitializeEx.
 */
static DWORD g_initTid = 0;
#endif

/* =========================================================================
 * Forward declarations
 * ========================================================================= */
static void harness_global_init(void);
static void harness_global_cleanup(void);

static void process_metadata_reader(
    IWICMetadataQueryReader*    pMQR,
    BOOL                        isFrame,
    UINT                        depth,
    UINT*                       pTotalItems);

static void process_palette(
    IWICPalette*    pPalette,
    BOOL            isFrame);

static void process_color_contexts(
    IWICBitmapDecoder*      pDecoder,
    IWICBitmapFrameDecode*  pFrame);

static void process_thumbnail(
    IWICBitmapSource*   pSource,
    BOOL                isContainer);

static void process_frame_copy_pixels(
    IWICBitmapFrameDecode*      pFrame,
    UINT                        frameIndex,
    UINT                        width,
    UINT                        height,
    const WICPixelFormatGUID*   pFmt);

static void process_frame_copy_pixels_partial(
    IWICBitmapFrameDecode*      pFrame,
    UINT                        width,
    UINT                        height,
    const WICPixelFormatGUID*   pFmt);

static void process_frame_transform(
    IWICBitmapFrameDecode*      pFrame,
    UINT                        width,
    UINT                        height,
    const WICPixelFormatGUID*   pFmt);

static void process_frame_progressive(
    IWICBitmapFrameDecode*      pFrame,
    UINT                        width,
    UINT                        height,
    const WICPixelFormatGUID*   pFmt);

static void process_wic_convert(
    IWICBitmapFrameDecode*  pFrame,
    UINT                    width,
    UINT                    height);

/* =========================================================================
 * fuzz_target
 *
 * WinAFL persistent mode target function.
 * Called repeatedly with mutated input files.
 *
 * Invariants:
 *   1. Accepts a file path (from argv[1] / WinAFL @@)
 *   2. Exercises all reachable WIC COM paths for ICO decoding
 *   3. Releases all per-iteration COM objects before returning
 *   4. Never crashes the harness process on malformed input
 *      (crashes inside windowscodecs.dll propagate naturally to WinAFL)
 * ========================================================================= */
__declspec(noinline)
void fuzz_target(const WCHAR* filePath)
{
    IWICBitmapDecoder*      pDecoder        = NULL;
    IWICBitmapDecoderInfo*  pDecoderInfo    = NULL;
    IWICBitmapFrameDecode*  pFrame          = NULL;
    IWICFormatConverter*    pConverter      = NULL;
    IWICMetadataQueryReader* pContainerMQR  = NULL;
    IWICPalette*            pPalette        = NULL;
    IWICBitmapSource*       pPreview        = NULL;
    IWICBitmapSource*       pThumb          = NULL;

    HRESULT     hr;
    UINT        uFrameCount     = 0;
    UINT        uCappedFrames   = 0;
    UINT        uFrameIdx;
    UINT        uProcessed      = 0;
    UINT        uSkipped        = 0;
    GUID        containerFmt;
    DWORD       dwCapabilities  = 0;

    /* Per-iteration metadata item counter shared across all recursive
     * process_metadata_reader calls.  Bounds the total enumeration work
     * regardless of nesting depth, preventing throughput collapse on
     * pathologically nested malformed ICO files. */
    UINT        uTotalMetaItems = 0;

    static UINT s_iteration = 0;
    s_iteration++;

    if (!g_initialized || !g_pFactory || !filePath) return;

#ifdef HARNESS_MODE_RESEARCH
    /* Apartment threading guard: all COM calls must occur on the thread
     * that called CoInitializeEx.  This fires if WinAFL ever dispatches
     * fuzz_target() from a helper thread. */
    if (GetCurrentThreadId() != g_initTid) {
        trace_write_direct(&g_trace,
            "[!TID]  fuzz_target called from wrong thread -- COM apartment violation\r\n");
        return;
    }
#endif

    trace_iteration_begin(&g_trace, s_iteration, filePath);

    /* ===============================================================
     * STAGE 1: Create decoder from filename
     * Forces all metadata parsing immediately (CacheOnLoad mode).
     * Exercises: file signature detection, ICONDIR initial read,
     *            codec selection, metadata cache population.
     *
     * Campaign 2: build with /D HARNESS_CACHE_ON_DEMAND to switch to
     * lazy metadata parsing -- a distinct internal code path used by
     * real Windows applications.
     * =============================================================== */

#ifdef HARNESS_MODE_RESEARCH
    __try {
#endif

        hr = g_pFactory->lpVtbl->CreateDecoderFromFilename(
            g_pFactory,
            filePath,
            NULL,
            GENERIC_READ,
            HARNESS_DECODE_OPTIONS,
            &pDecoder);

        CHECK_HR_GOTO(hr, STAGE_DECODER_CREATE, cleanup);

        /* ===============================================================
         * STAGE 2: QueryCapability
         * Forces a capability detection pass over the file via IStream.
         * This is a distinct internal code path from CreateDecoderFromFilename.
         * IStream is seeked to offset 0 before the call as required by
         * the QueryCapability contract (some codec implementations are
         * sensitive to non-zero initial stream positions).
         * =============================================================== */
        {
            IStream* pStream = NULL;
            hr = SHCreateStreamOnFileW(filePath,
                STGM_READ | STGM_SHARE_DENY_WRITE, &pStream);
            if (SUCCEEDED(hr) && pStream) {
                LARGE_INTEGER liZero;
                liZero.QuadPart = 0;
                pStream->lpVtbl->Seek(pStream, liZero, STREAM_SEEK_SET, NULL);

                {
                    HRESULT hrCap = pDecoder->lpVtbl->QueryCapability(
                        pDecoder, pStream, &dwCapabilities);
                    trace_decoder_capabilities(&g_trace, hrCap, dwCapabilities);
                }
                pStream->lpVtbl->Release(pStream);
            }
        }

        /* ===============================================================
         * STAGE 3: GetContainerFormat
         * =============================================================== */
        ZeroMemory(&containerFmt, sizeof(containerFmt));
        hr = pDecoder->lpVtbl->GetContainerFormat(pDecoder, &containerFmt);
        trace_stage(&g_trace, STAGE_CONTAINER_FORMAT, hr);
        trace_container_format(&g_trace, hr, &containerFmt);

        /* ===============================================================
         * STAGE 4: GetDecoderInfo
         * Exercises codec info strings (file extensions, MIME types) and
         * multi-frame / lossless / animation capability flags.
         * =============================================================== */
        if (g_cfg.decoderInfoPath) {
            hr = pDecoder->lpVtbl->GetDecoderInfo(pDecoder, &pDecoderInfo);
            trace_stage(&g_trace, STAGE_DECODER_INFO, hr);
            if (SUCCEEDED(hr) && pDecoderInfo) {
                BOOL  bMultiframe = FALSE;
                BOOL  bLossless   = FALSE;
                BOOL  bAnimation  = FALSE;
                WCHAR extBuf[256] = { 0 };
                WCHAR mimeBuf[256]= { 0 };
                UINT  extLen = 0, mimeLen = 0;

                pDecoderInfo->lpVtbl->DoesSupportMultiframe(pDecoderInfo, &bMultiframe);
                pDecoderInfo->lpVtbl->DoesSupportLossless(pDecoderInfo,   &bLossless);
                pDecoderInfo->lpVtbl->DoesSupportAnimation(pDecoderInfo,  &bAnimation);

                pDecoderInfo->lpVtbl->GetFileExtensions(pDecoderInfo, 0, NULL, &extLen);
                if (extLen > 0 && extLen < 256)
                    pDecoderInfo->lpVtbl->GetFileExtensions(
                        pDecoderInfo, extLen, extBuf, &extLen);

                pDecoderInfo->lpVtbl->GetMimeTypes(pDecoderInfo, 0, NULL, &mimeLen);
                if (mimeLen > 0 && mimeLen < 256)
                    pDecoderInfo->lpVtbl->GetMimeTypes(
                        pDecoderInfo, mimeLen, mimeBuf, &mimeLen);

                SAFE_RELEASE(pDecoderInfo);
            }
        }

        /* ===============================================================
         * STAGE 5: Container-level metadata
         * Recursive descent into nested VT_UNKNOWN readers (XMP/EXIF
         * blocks inside PNG-in-ICO tEXt/iTXt/eXIf chunks).
         * uTotalMetaItems caps total enumeration work across all recursive
         * calls for this iteration.
         * =============================================================== */
        if (g_cfg.metadataEnum) {
            hr = pDecoder->lpVtbl->GetMetadataQueryReader(
                pDecoder, &pContainerMQR);
            trace_stage(&g_trace, STAGE_CONTAINER_METADATA, hr);
            if (SUCCEEDED(hr) && pContainerMQR) {
                process_metadata_reader(pContainerMQR, FALSE, 0, &uTotalMetaItems);
                SAFE_RELEASE(pContainerMQR);
            }
        }

        /* ===============================================================
         * STAGE 6: Container-level palette
         * =============================================================== */
        if (g_cfg.palettePath) {
            hr = g_pFactory->lpVtbl->CreatePalette(g_pFactory, &pPalette);
            trace_stage(&g_trace, STAGE_CONTAINER_PALETTE, hr);
            if (SUCCEEDED(hr) && pPalette) {
                HRESULT hrCopy = pDecoder->lpVtbl->CopyPalette(pDecoder, pPalette);
                if (SUCCEEDED(hrCopy))
                    process_palette(pPalette, FALSE);
                SAFE_RELEASE(pPalette);
            }
        }

        /* ===============================================================
         * STAGE 7: Container-level color contexts (ICC profiles)
         * Routed through g_pFactory2 (IWICImagingFactory2) because
         * CreateColorContext does not exist on IWICImagingFactory.
         * =============================================================== */
        if (g_cfg.colorContextPath) {
            process_color_contexts(pDecoder, NULL);
        }

        /* ===============================================================
         * STAGE 8: GetPreview
         * Expected to return WINCODEC_ERR_UNSUPPORTEDOPERATION for most
         * ICO files; called anyway to exercise the check path.
         * =============================================================== */
        if (g_cfg.thumbnailPath) {
            hr = pDecoder->lpVtbl->GetPreview(pDecoder, &pPreview);
            trace_stage(&g_trace, STAGE_PREVIEW, hr);
            if (SUCCEEDED(hr) && pPreview) {
                process_thumbnail(pPreview, TRUE);
                SAFE_RELEASE(pPreview);
            }

            /* STAGE 9: Container-level thumbnail */
            hr = pDecoder->lpVtbl->GetThumbnail(pDecoder, &pThumb);
            trace_stage(&g_trace, STAGE_THUMBNAIL_CONTAINER, hr);
            if (SUCCEEDED(hr) && pThumb) {
                process_thumbnail(pThumb, TRUE);
                SAFE_RELEASE(pThumb);
            }
        }

        /* ===============================================================
         * STAGE 10: GetFrameCount
         * A malformed ICO may report 0, 1, or 65535 frames.
         * =============================================================== */
        hr = pDecoder->lpVtbl->GetFrameCount(pDecoder, &uFrameCount);
        trace_stage(&g_trace, STAGE_FRAME_COUNT, hr);
        if (FAILED(hr) || uFrameCount == 0) goto oob_probe;

        uCappedFrames = (uFrameCount <= g_cfg.policy.maxFrames)
            ? uFrameCount
            : g_cfg.policy.maxFrames;
        trace_frame_count(&g_trace, hr, uFrameCount, uCappedFrames);

        /* ===============================================================
         * STAGES 11-27: Per-frame processing loop
         * =============================================================== */
        for (uFrameIdx = 0; uFrameIdx < uCappedFrames; uFrameIdx++) {

            WICPixelFormatGUID  fmtGUID;
            UINT                width  = 0;
            UINT                height = 0;
            double              dpiX   = 0.0, dpiY = 0.0;
            BOOL                frameOk = FALSE;

            /* Sets ctx->currentFrame so every subsequent trace_stage()
             * for this frame includes the frame index automatically. */
            trace_frame_begin(&g_trace, uFrameIdx);
            ZeroMemory(&fmtGUID, sizeof(fmtGUID));

            /* STAGE 11: GetFrame(i)
             * Exercises ICONDIRENTRY[i] parsing and payload type detection
             * (BMP-style vs embedded PNG). */
            hr = pDecoder->lpVtbl->GetFrame(pDecoder, uFrameIdx, &pFrame);
            trace_stage(&g_trace, STAGE_FRAME_GET, hr);
            if (FAILED(hr) || !pFrame) { uSkipped++; continue; }

            /* STAGE 12: GetSize
             * Reads width/height.  Mismatches between the ICONDIRENTRY
             * declared size and the actual payload dimensions are a known
             * bug class.  Policy validation happens immediately after. */
            hr = pFrame->lpVtbl->GetSize(pFrame, &width, &height);
            trace_stage(&g_trace, STAGE_FRAME_SIZE, hr);
            trace_frame_size(&g_trace, hr, width, height);

            if (FAILED(hr)) { uSkipped++; SAFE_RELEASE(pFrame); continue; }

            {
                POLICY_RESULT pr = policy_validate_dimensions(
                    &g_cfg.policy, width, height);
                if (pr != POLICY_OK) {
                    trace_policy_violation(&g_trace, pr, width, height, 0, 0);
                    uSkipped++;
                    SAFE_RELEASE(pFrame);
                    continue;
                }
            }

            frameOk = TRUE;

            /* STAGE 13: GetPixelFormat */
            hr = pFrame->lpVtbl->GetPixelFormat(pFrame, &fmtGUID);
            trace_stage(&g_trace, STAGE_FRAME_PIXEL_FORMAT, hr);
            if (SUCCEEDED(hr)) {
                UINT bpp = policy_get_bpp_from_guid(g_pFactory, &fmtGUID);
                trace_frame_pixel_format(&g_trace, hr, &fmtGUID, bpp);
            }

            /* STAGE 14: GetResolution */
            hr = pFrame->lpVtbl->GetResolution(pFrame, &dpiX, &dpiY);
            trace_stage(&g_trace, STAGE_FRAME_RESOLUTION, hr);
            trace_frame_resolution(&g_trace, hr, dpiX, dpiY);

            /* STAGE 15: Frame palette
             * Critical for 1/4/8bpp ICO frames (palette-indexed).
             * Palette table overflow is a known vulnerability class. */
            if (g_cfg.palettePath) {
                hr = g_pFactory->lpVtbl->CreatePalette(g_pFactory, &pPalette);
                trace_stage(&g_trace, STAGE_FRAME_PALETTE, hr);
                if (SUCCEEDED(hr) && pPalette) {
                    HRESULT hrCopy = pFrame->lpVtbl->CopyPalette(pFrame, pPalette);
                    if (SUCCEEDED(hrCopy))
                        process_palette(pPalette, TRUE);
                    SAFE_RELEASE(pPalette);
                }
            }

            /* STAGE 16: Frame color contexts (ICC profiles)
             * For PNG-in-ICO: exercises iCCP chunk parsing. */
            if (g_cfg.colorContextPath) {
                process_color_contexts(NULL, pFrame);
            }

            /* STAGE 17: Frame metadata
             * For PNG-in-ICO: exercises tEXt/iTXt/zTXt chunk parsing.
             * Metadata size fields are a known integer overflow surface.
             * Recursive descent into nested VT_UNKNOWN readers. */
            if (g_cfg.metadataEnum) {
                IWICMetadataQueryReader* pFrameMQR = NULL;
                hr = pFrame->lpVtbl->GetMetadataQueryReader(pFrame, &pFrameMQR);
                trace_stage(&g_trace, STAGE_FRAME_METADATA, hr);
                if (SUCCEEDED(hr) && pFrameMQR) {
                    process_metadata_reader(
                        pFrameMQR, TRUE, 0, &uTotalMetaItems);
                    SAFE_RELEASE(pFrameMQR);
                }
            }

            /* STAGE 18: Frame thumbnail */
            if (g_cfg.thumbnailPath) {
                IWICBitmapSource* pFrameThumb = NULL;
                hr = pFrame->lpVtbl->GetThumbnail(pFrame, &pFrameThumb);
                trace_stage(&g_trace, STAGE_FRAME_THUMBNAIL, hr);
                if (SUCCEEDED(hr) && pFrameThumb) {
                    process_thumbnail(pFrameThumb, FALSE);
                    SAFE_RELEASE(pFrameThumb);
                }
            }

            /* STAGE 19: CopyPixels -- full rect (PRIMARY BUG TRIGGER)
             * Forces full pixel materialisation.
             *   BMP-payload: AND mask + XOR bitmap reconstruction
             *   PNG-payload: full PNG decode (libpng + zlib inflate)
             * PageHeap catches heap overflows here.
             *
             * CopyPixels is called via QI to IWICBitmapSource -- never
             * via a raw pointer cast, which is undefined behaviour in C
             * because vtable slot ordering for inherited interfaces is
             * implementation-defined. */
            process_frame_copy_pixels(
                pFrame, uFrameIdx, width, height, &fmtGUID);

            /* STAGE 19b: CopyPixels -- partial rect (top-left quadrant)
             * Exercises per-scanline offset arithmetic inside the decoder
             * for a sub-rectangle request -- a distinct code path from the
             * full-image copy with different stride/offset calculations. */
            if (frameOk && width > 1 && height > 1) {
                process_frame_copy_pixels_partial(
                    pFrame, width, height, &fmtGUID);
            }

            /* STAGE 25: IWICBitmapSourceTransform (scaled decode)
             * Exercises dimension scaling arithmetic inside the decoder --
             * a known integer overflow surface.  We request half-size output.
             * QI failure (not supported) is expected and silently skipped. */
            if (g_cfg.transformPath && frameOk) {
                process_frame_transform(pFrame, width, height, &fmtGUID);
            }

            /* STAGE 26: IWICProgressiveLevelControl
             * For PNG-in-ICO: exercises the Adam7 interlaced decode path
             * in the embedded libpng -- historically a vulnerability-rich
             * area (row-pointer reconstruction, per-pass dimension overflows).
             * QI failure (non-progressive frames) is expected. */
            if (g_cfg.progressivePath && frameOk) {
                process_frame_progressive(pFrame, width, height, &fmtGUID);
            }

            /* STAGE 20-21: Format conversion path
             * IWICFormatConverter -> BGRA32 -> CopyPixels.
             * Exercises the format conversion pipeline which has its own
             * internal buffer allocation and copy operations.
             *
             * The CanConvert check is intentional for this path.
             * process_wic_convert (below) exercises Initialize without
             * CanConvert via WICConvertBitmapSource. */
            if (g_cfg.conversionPath && frameOk) {
                hr = g_pFactory->lpVtbl->CreateFormatConverter(
                    g_pFactory, &pConverter);
                trace_stage(&g_trace, STAGE_CONVERTER_INIT, hr);

                if (SUCCEEDED(hr) && pConverter) {
                    BOOL bCanConvert = FALSE;
                    IWICBitmapSource* pFrameAsSource = NULL;

                    hr = pFrame->lpVtbl->QueryInterface(
                        pFrame,
                        &IID_IWICBitmapSource,
                        (void**)&pFrameAsSource);

                    if (SUCCEEDED(hr) && pFrameAsSource) {
                        pConverter->lpVtbl->CanConvert(
                            pConverter,
                            &fmtGUID,
                            &HARNESS_CONVERT_TARGET_FORMAT,
                            &bCanConvert);

                        if (bCanConvert) {
                            hr = pConverter->lpVtbl->Initialize(
                                pConverter,
                                pFrameAsSource,
                                &HARNESS_CONVERT_TARGET_FORMAT,
                                WICBitmapDitherTypeNone,
                                NULL,
                                0.0,
                                WICBitmapPaletteTypeCustom);

                            if (SUCCEEDED(hr)) {
                                UINT convWidth = 0, convHeight = 0;
                                UINT convStride = 0, convBufSize = 0;
                                BYTE* pConvPixels = NULL;
                                POLICY_RESULT pr;
                                WICPixelFormatGUID convFmt;
                                IWICBitmapSource* pConvAsSource = NULL;

                                pConverter->lpVtbl->GetSize(
                                    pConverter, &convWidth, &convHeight);
                                pConverter->lpVtbl->GetPixelFormat(
                                    pConverter, &convFmt);

                                pr = policy_compute_stride(
                                    &g_cfg.policy,
                                    convWidth,
                                    HARNESS_CONVERT_BPP * 8U,
                                    &convStride);

                                if (pr == POLICY_OK) {
                                    pr = policy_compute_buffer_size(
                                        &g_cfg.policy,
                                        convStride, convHeight,
                                        &convBufSize);
                                }

                                if (pr == POLICY_OK && convBufSize > 0) {
                                    pConvPixels = (BYTE*)HeapAlloc(
                                        GetProcessHeap(), 0, convBufSize);

                                    if (pConvPixels) {
                                        hr = pConverter->lpVtbl->QueryInterface(
                                            pConverter,
                                            &IID_IWICBitmapSource,
                                            (void**)&pConvAsSource);

                                        if (SUCCEEDED(hr) && pConvAsSource) {
                                            trace_stage(&g_trace,
                                                STAGE_CONVERTER_COPY, S_OK);
                                            hr = pConvAsSource->lpVtbl->CopyPixels(
                                                pConvAsSource,
                                                NULL,
                                                convStride,
                                                convBufSize,
                                                pConvPixels);
                                            trace_copy_pixels(&g_trace, hr,
                                                convStride, convBufSize,
                                                pr, TRUE);
                                            pConvAsSource->lpVtbl->Release(
                                                pConvAsSource);
                                        }
                                        HeapFree(GetProcessHeap(), 0, pConvPixels);
                                        pConvPixels = NULL;
                                    }
                                } else {
                                    trace_policy_violation(&g_trace, pr,
                                        convWidth, convHeight,
                                        convStride, convBufSize);
                                }
                            }
                        }

                        /*
                         * STAGE 20b: Force Initialize even when CanConvert=FALSE
                         * (RESEARCH mode only, wrapped in SEH).
                         *
                         * CanConvert returning FALSE may indicate the decoder
                         * returned an unexpected/malformed pixel format GUID.
                         * Calling Initialize directly on such a source exercises
                         * a code path that WICConvertBitmapSource also takes
                         * internally (it skips CanConvert), potentially reaching
                         * format validation bugs inside the converter.
                         */
#ifdef HARNESS_MODE_RESEARCH
                        if (!bCanConvert) {
                            __try {
                                HRESULT hrForce = pConverter->lpVtbl->Initialize(
                                    pConverter,
                                    pFrameAsSource,
                                    &HARNESS_CONVERT_TARGET_FORMAT,
                                    WICBitmapDitherTypeNone,
                                    NULL,
                                    0.0,
                                    WICBitmapPaletteTypeCustom);
                                /* Result is traced via STAGE_CONVERTER_INIT.
                                 * We do not call CopyPixels here -- the goal
                                 * is to reach the Initialize validation path,
                                 * not to produce pixel data. */
                                trace_stage(&g_trace, STAGE_CONVERTER_INIT, hrForce);
                            }
                            __except (EXCEPTION_EXECUTE_HANDLER) {
                                DWORD exCode = GetExceptionCode();
                                trace_seh_exception(&g_trace, exCode,
                                    g_trace.lastStage);
                            }
                        }
#endif
                        pFrameAsSource->lpVtbl->Release(pFrameAsSource);
                    }
                    SAFE_RELEASE(pConverter);
                }
            }

            /* STAGE 28: WICConvertBitmapSource
             * Alternative conversion API with a distinct internal code path:
             * skips CanConvert, uses different internal allocation strategy,
             * wraps decode and convert in a single lazy-evaluated object.
             * Identified from IDA string analysis at 0x18000A1940. */
            if (g_cfg.wicConvertPath && frameOk) {
                process_wic_convert(pFrame, width, height);
            }

            uProcessed++;
            SAFE_RELEASE(pFrame);

        } /* end per-frame loop */

    oob_probe:
        /*
         * Out-of-bounds frame index stress probes.
         * Tests boundary validation in the ICONDIR frame dispatcher.
         * Any S_OK response from a probe indicates an index validation
         * bug -- high exploitability signal.
         *
         * Probes:
         *   GetFrame(uFrameCount)   -- one past the last valid index
         *   GetFrame(0xFFFF)        -- ICO format max (65535 entries)
         *   GetFrame(0xFFFFFFFF)    -- full UINT32 range
         *   GetFrame(0x80000000)    -- sign-bit probe
         *
         * Also verifies that GetFrame(uFrameCount - 1) succeeds, which
         * it must: if the last valid frame is not accessible, the decoder
         * has an off-by-one in the opposite direction.
         */
        if (pDecoder && uFrameCount > 0) {
            IWICBitmapFrameDecode*  pOobFrame   = NULL;
            HRESULT hrAtCount   = S_OK;
            HRESULT hrAt0xFFFF  = S_OK;
            HRESULT hrAtUintMax = S_OK;
            HRESULT hrAtHigh    = S_OK;

            /* Marker stage -- not an error */
            trace_stage(&g_trace, STAGE_FRAME_OOB, S_OK);

            hrAtCount = pDecoder->lpVtbl->GetFrame(
                pDecoder, uFrameCount, &pOobFrame);
            if (SUCCEEDED(hrAtCount) && pOobFrame)
                SAFE_RELEASE(pOobFrame);

            hrAt0xFFFF = pDecoder->lpVtbl->GetFrame(
                pDecoder, 0xFFFFU, &pOobFrame);
            if (SUCCEEDED(hrAt0xFFFF) && pOobFrame)
                SAFE_RELEASE(pOobFrame);

            hrAtUintMax = pDecoder->lpVtbl->GetFrame(
                pDecoder, 0xFFFFFFFFU, &pOobFrame);
            if (SUCCEEDED(hrAtUintMax) && pOobFrame)
                SAFE_RELEASE(pOobFrame);

            hrAtHigh = pDecoder->lpVtbl->GetFrame(
                pDecoder, 0x80000000U, &pOobFrame);
            if (SUCCEEDED(hrAtHigh) && pOobFrame)
                SAFE_RELEASE(pOobFrame);

            trace_oob_frame(&g_trace, uFrameCount,
                hrAtCount, hrAt0xFFFF, hrAtUintMax, hrAtHigh);
        }

    cleanup:

#ifdef HARNESS_MODE_RESEARCH
    } /* end __try */
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DWORD exCode = GetExceptionCode();
        trace_seh_exception(&g_trace, exCode, g_trace.lastStage);
        SAFE_RELEASE(pConverter);
        SAFE_RELEASE(pFrame);
        SAFE_RELEASE(pContainerMQR);
        SAFE_RELEASE(pPalette);
        SAFE_RELEASE(pPreview);
        SAFE_RELEASE(pThumb);
        SAFE_RELEASE(pDecoderInfo);
        SAFE_RELEASE(pDecoder);
        RaiseException(exCode, EXCEPTION_NONCONTINUABLE, 0, NULL);
    }
#endif

    /* Mandatory per-iteration COM cleanup.
     * Release order: converter -> frame -> metadata -> palette
     *                -> thumbnails -> decoder info -> decoder */
    SAFE_RELEASE(pConverter);
    SAFE_RELEASE(pFrame);
    SAFE_RELEASE(pContainerMQR);
    SAFE_RELEASE(pPalette);
    SAFE_RELEASE(pPreview);
    SAFE_RELEASE(pThumb);
    SAFE_RELEASE(pDecoderInfo);
    SAFE_RELEASE(pDecoder);

    trace_iteration_end(&g_trace, uProcessed, uSkipped);
}

/* =========================================================================
 * process_metadata_reader
 *
 * Exercises IWICMetadataQueryReader:
 *   GetContainerFormat, GetLocation, GetEnumerator, IWICEnumMetadataItem
 *
 * Recursive descent into nested VT_UNKNOWN readers (XMP/EXIF blocks
 * embedded inside PNG-in-ICO tEXt/iTXt/eXIf chunks).
 *
 * depth:        current recursion depth (0 = direct child of frame/container)
 * pTotalItems:  shared counter across all recursive calls for this iteration;
 *               caps total enumeration work regardless of nesting depth.
 * ========================================================================= */
#define HARNESS_METADATA_MAX_DEPTH  4U

/* Known metadata key paths for PNG-in-ICO.
 * Queried via GetMetadataByName after enumeration to exercise the
 * name-lookup code path, which is separate from enumeration internally. */
static const WCHAR* s_knownMetaKeys[] = {
    L"/iCCP/ProfileName",
    L"/tEXt/Comment",
    L"/iTXt/TextEntry",
    L"/[0]ifd/{ushort=274}",   /* EXIF orientation */
    NULL
};

static void process_metadata_reader(
    IWICMetadataQueryReader*    pMQR,
    BOOL                        isFrame,
    UINT                        depth,
    UINT*                       pTotalItems)
{
    HRESULT               hr;
    GUID                  fmtGuid;
    WCHAR                 locationBuf[256] = { 0 };
    UINT                  locationLen  = 0;
    IWICEnumMetadataItem* pEnum        = NULL;
    UINT                  itemCount    = 0;
    UINT                  nestedCount  = 0;
    HRESULT               enumHr       = E_FAIL;

    if (!pMQR || depth > HARNESS_METADATA_MAX_DEPTH) return;

    /* Honour the per-iteration total cap before doing any work */
    if (pTotalItems &&
        *pTotalItems >= g_cfg.policy.maxTotalMetadataItems) return;

    ZeroMemory(&fmtGuid, sizeof(fmtGuid));
    hr = pMQR->lpVtbl->GetContainerFormat(pMQR, &fmtGuid);

    pMQR->lpVtbl->GetLocation(pMQR, 0, NULL, &locationLen);
    if (locationLen > 0 && locationLen < 256)
        pMQR->lpVtbl->GetLocation(pMQR, locationLen, locationBuf, &locationLen);

    enumHr = pMQR->lpVtbl->GetEnumerator(pMQR, &pEnum);
    if (SUCCEEDED(enumHr) && pEnum) {
        PROPVARIANT schema, id, value;
        UINT        fetched   = 0;
        UINT        safeLimit = 0;

        PropVariantInit(&schema);
        PropVariantInit(&id);
        PropVariantInit(&value);

        while (safeLimit < g_cfg.policy.maxMetadataItems) {

            /* Also respect the per-iteration global cap */
            if (pTotalItems &&
                *pTotalItems >= g_cfg.policy.maxTotalMetadataItems)
                break;

            fetched = 0;
            hr = pEnum->lpVtbl->Next(pEnum, 1, &schema, &id, &value, &fetched);
            if (hr != S_OK || fetched == 0) break;

            /* VT_UNKNOWN may wrap a nested IWICMetadataQueryReader.
             * This is how XMP/EXIF blocks are embedded inside PNG-in-ICO
             * metadata.  Recurse into the sub-reader. */
            if (value.vt == VT_UNKNOWN && value.punkVal != NULL
                && depth < HARNESS_METADATA_MAX_DEPTH)
            {
                IWICMetadataQueryReader* pSubMQR = NULL;
                HRESULT hrSub = value.punkVal->lpVtbl->QueryInterface(
                    value.punkVal,
                    &IID_IWICMetadataQueryReader,
                    (void**)&pSubMQR);
                if (SUCCEEDED(hrSub) && pSubMQR) {
                    nestedCount++;
                    process_metadata_reader(
                        pSubMQR, isFrame, depth + 1, pTotalItems);
                    pSubMQR->lpVtbl->Release(pSubMQR);
                }
            }

            PropVariantClear(&schema);
            PropVariantClear(&id);
            PropVariantClear(&value);
            itemCount++;
            safeLimit++;
            if (pTotalItems) (*pTotalItems)++;
        }

        pEnum->lpVtbl->Release(pEnum);
    }

    /*
     * Query known metadata keys via GetMetadataByName.
     * This exercises the name-lookup code path inside the metadata engine,
     * which is separate from the enumerator path above.  Only run at
     * depth 0 (direct frame/container reader) to avoid redundant queries
     * on nested sub-readers.
     */
    if (depth == 0) {
        const WCHAR** ppKey = s_knownMetaKeys;
        while (*ppKey) {
            PROPVARIANT val;
            PropVariantInit(&val);
            /* HRESULT is intentionally ignored: WINCODEC_ERR_PROPERTYNOTFOUND
             * is expected for most keys on most frames and is not an error. */
            pMQR->lpVtbl->GetMetadataByName(pMQR, *ppKey, &val);
            PropVariantClear(&val);
            ppKey++;
        }
    }

    trace_metadata(&g_trace, hr, enumHr, itemCount, nestedCount, &fmtGuid);
}

/* =========================================================================
 * process_palette
 *
 * Exercises IWICPalette: GetType, GetColorCount, GetColors, HasAlpha.
 * GetColors() on a palette-indexed frame is a primary overflow target for
 * 1/4/8bpp ICO frames.
 * ========================================================================= */
static void process_palette(
    IWICPalette*    pPalette,
    BOOL            isFrame)
{
    HRESULT              hr;
    WICBitmapPaletteType paletteType = WICBitmapPaletteTypeCustom;
    UINT                 colorCount  = 0;
    BOOL                 hasAlpha    = FALSE;
    WICColor*            pColors     = NULL;

    if (!pPalette) return;

    pPalette->lpVtbl->GetType(pPalette, &paletteType);

    hr = pPalette->lpVtbl->GetColorCount(pPalette, &colorCount);
    if (FAILED(hr)) goto done;

    if (colorCount > g_cfg.policy.maxPaletteColors)
        colorCount = g_cfg.policy.maxPaletteColors;

    if (colorCount > 0) {
        pColors = (WICColor*)HeapAlloc(
            GetProcessHeap(), 0, colorCount * sizeof(WICColor));
        if (pColors) {
            UINT actualColors = 0;
            pPalette->lpVtbl->GetColors(
                pPalette, colorCount, pColors, &actualColors);
            HeapFree(GetProcessHeap(), 0, pColors);
            pColors = NULL;
        }
    }

    pPalette->lpVtbl->HasAlpha(pPalette, &hasAlpha);

done:
    trace_palette(&g_trace, hr, colorCount, hasAlpha, paletteType);
}

/* =========================================================================
 * process_color_contexts
 *
 * Exercises GetColorContexts for ICC profile parsing (iCCP chunk in
 * PNG-in-ICO).  ICC profile data structures are variable-length binary --
 * a known overflow target.
 *
 * FIX: The allocated count is snapshotted into 'allocatedCount' before
 * the second GetColorContexts call.  The second call writes its returned
 * count to 'returnedCount' (a separate variable) so that the cleanup loop
 * always iterates over the allocated range, not the returned range.
 * A malformed ICO that causes the decoder to return a count larger than
 * was allocated would previously have driven the cleanup loop out of bounds.
 * ========================================================================= */
static void process_color_contexts(
    IWICBitmapDecoder*      pDecoder,
    IWICBitmapFrameDecode*  pFrame)
{
    HRESULT            hr;
    UINT               actualCount    = 0;
    UINT               allocatedCount = 0; /* snapshot before second call */
    UINT               returnedCount  = 0; /* result of second call (log only) */
    UINT               i;
    IWICColorContext** ppContexts     = NULL;

    if (!g_pFactory2) {
        /* IWICImagingFactory2 not available on this WIC runtime */
        trace_color_contexts(&g_trace, E_NOINTERFACE, 0);
        return;
    }

    /* First call: get the count only */
    if (pDecoder) {
        hr = pDecoder->lpVtbl->GetColorContexts(
            pDecoder, 0, NULL, &actualCount);
    } else if (pFrame) {
        hr = pFrame->lpVtbl->GetColorContexts(
            pFrame, 0, NULL, &actualCount);
    } else return;

    trace_stage(&g_trace,
        pDecoder ? STAGE_COLOR_CONTEXTS : STAGE_FRAME_COLOR_CONTEXTS, hr);

    if (FAILED(hr) || actualCount == 0) {
        trace_color_contexts(&g_trace, hr, 0);
        return;
    }

    if (actualCount > g_cfg.policy.maxColorContexts)
        actualCount = g_cfg.policy.maxColorContexts;

    /* Snapshot the capped count; the cleanup loop must use this value,
     * not whatever the second GetColorContexts call returns. */
    allocatedCount = actualCount;

    ppContexts = (IWICColorContext**)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY,
        allocatedCount * sizeof(IWICColorContext*));
    if (!ppContexts) goto done;

    for (i = 0; i < allocatedCount; i++) {
        g_pFactory2->lpVtbl->CreateColorContext(g_pFactory2, &ppContexts[i]);
    }

    /* Second call: retrieve contexts into the pre-allocated array.
     * Write the returned count to returnedCount, NOT to actualCount,
     * to preserve the allocatedCount invariant for the cleanup loop. */
    if (pDecoder) {
        hr = pDecoder->lpVtbl->GetColorContexts(
            pDecoder, allocatedCount, ppContexts, &returnedCount);
    } else {
        hr = pFrame->lpVtbl->GetColorContexts(
            pFrame, allocatedCount, ppContexts, &returnedCount);
    }

done:
    /* Log the count the decoder actually returned */
    trace_color_contexts(&g_trace, hr, returnedCount);

    if (ppContexts) {
        /* Cleanup bounds: allocatedCount -- safe regardless of returnedCount */
        for (i = 0; i < allocatedCount; i++) {
            if (ppContexts[i]) ppContexts[i]->lpVtbl->Release(ppContexts[i]);
        }
        HeapFree(GetProcessHeap(), 0, ppContexts);
    }
}

/* =========================================================================
 * process_thumbnail
 * ========================================================================= */
static void process_thumbnail(
    IWICBitmapSource*   pSource,
    BOOL                isContainer)
{
    HRESULT hr;
    UINT    w = 0, h = 0;

    if (!pSource) return;
    hr = pSource->lpVtbl->GetSize(pSource, &w, &h);
    trace_thumbnail(&g_trace, hr, w, h);
}

/* =========================================================================
 * process_frame_copy_pixels
 *
 * Primary bug trigger: CopyPixels on a raw decoded frame (full rect).
 *
 * For BMP-payload frames: triggers AND mask + XOR bitmap reconstruction.
 * For PNG-payload frames: triggers full libpng decode + zlib inflate.
 *
 * Buffer allocated on heap; PageHeap detects any overrun.
 *
 * CopyPixels is obtained via QI to IWICBitmapSource -- never via raw cast.
 * If bpp resolution returns 0 (factory unavailable), the frame is skipped
 * rather than allocating with a wrong bpp value.
 * ========================================================================= */
static void process_frame_copy_pixels(
    IWICBitmapFrameDecode*      pFrame,
    UINT                        frameIndex,
    UINT                        width,
    UINT                        height,
    const WICPixelFormatGUID*   pFmt)
{
    HRESULT           hr;
    UINT              bpp     = 0U;
    UINT              stride  = 0;
    UINT              bufSize = 0;
    BYTE*             pPixels = NULL;
    POLICY_RESULT     prStride, prBuf;
    IWICBitmapSource* pSource = NULL;

    if (!pFrame || width == 0 || height == 0) return;

    if (pFmt) bpp = policy_get_bpp_from_guid(g_pFactory, pFmt);
    if (bpp == 0) {
        trace_stage(&g_trace, STAGE_COPY_PIXELS, E_FAIL);
        return;
    }

    prStride = policy_compute_stride(&g_cfg.policy, width, bpp, &stride);
    if (prStride != POLICY_OK) {
        trace_policy_violation(&g_trace, prStride, width, height, 0, 0);
        return;
    }

    prBuf = policy_compute_buffer_size(&g_cfg.policy, stride, height, &bufSize);
    if (prBuf != POLICY_OK) {
        trace_policy_violation(&g_trace, prBuf, width, height, stride, 0);
        return;
    }

    pPixels = (BYTE*)HeapAlloc(GetProcessHeap(), 0, bufSize);
    if (!pPixels) {
        trace_stage(&g_trace, STAGE_COPY_PIXELS, E_OUTOFMEMORY);
        return;
    }

    hr = pFrame->lpVtbl->QueryInterface(
        pFrame, &IID_IWICBitmapSource, (void**)&pSource);

    if (SUCCEEDED(hr) && pSource) {
        hr = pSource->lpVtbl->CopyPixels(
            pSource,
            NULL,       /* entire image */
            stride,
            bufSize,
            pPixels);
        trace_stage(&g_trace, STAGE_COPY_PIXELS, hr);
        trace_copy_pixels(&g_trace, hr, stride, bufSize, POLICY_OK, FALSE);
        pSource->lpVtbl->Release(pSource);
    } else {
        trace_stage(&g_trace, STAGE_COPY_PIXELS, hr);
    }

    HeapFree(GetProcessHeap(), 0, pPixels);
    pPixels = NULL;
}

/* =========================================================================
 * process_frame_copy_pixels_partial
 *
 * Partial-rect CopyPixels (top-left quadrant).
 * Exercises per-scanline offset arithmetic inside the decoder for a
 * sub-rectangle -- a distinct code path from the full-image copy.
 * Off-by-one errors in this offset are a known bug class in codec
 * implementations.
 * ========================================================================= */
static void process_frame_copy_pixels_partial(
    IWICBitmapFrameDecode*      pFrame,
    UINT                        width,
    UINT                        height,
    const WICPixelFormatGUID*   pFmt)
{
    HRESULT           hr;
    UINT              bpp     = 0U;
    UINT              rw, rh;
    UINT              stride  = 0;
    UINT              bufSize = 0;
    BYTE*             pPixels = NULL;
    POLICY_RESULT     pr;
    IWICBitmapSource* pSource = NULL;
    WICRect           rect;

    if (!pFrame || width < 2 || height < 2) return;

    rw = width  / 2;
    rh = height / 2;
    if (rw == 0 || rh == 0) return;

    if (pFmt) bpp = policy_get_bpp_from_guid(g_pFactory, pFmt);
    if (bpp == 0) return;

    pr = policy_compute_stride(&g_cfg.policy, rw, bpp, &stride);
    if (pr != POLICY_OK) return;

    pr = policy_compute_buffer_size(&g_cfg.policy, stride, rh, &bufSize);
    if (pr != POLICY_OK) return;

    pPixels = (BYTE*)HeapAlloc(GetProcessHeap(), 0, bufSize);
    if (!pPixels) return;

    rect.X      = 0;
    rect.Y      = 0;
    rect.Width  = (INT)rw;
    rect.Height = (INT)rh;

    hr = pFrame->lpVtbl->QueryInterface(
        pFrame, &IID_IWICBitmapSource, (void**)&pSource);

    if (SUCCEEDED(hr) && pSource) {
        hr = pSource->lpVtbl->CopyPixels(
            pSource,
            &rect,
            stride,
            bufSize,
            pPixels);
        trace_stage(&g_trace, STAGE_COPY_PIXELS_PARTIAL, hr);
        trace_copy_pixels_partial(&g_trace, hr,
            rect.X, rect.Y, rw, rh, stride, bufSize);
        pSource->lpVtbl->Release(pSource);
    }

    HeapFree(GetProcessHeap(), 0, pPixels);
}

/* =========================================================================
 * process_frame_transform
 *
 * IWICBitmapSourceTransform: scaled / rotated / flipped decode.
 * Exercises dimension scaling arithmetic inside the decoder -- a known
 * integer overflow surface.  We request half-size output (WIDTHx2 x HEIGHTx2).
 * QI failure (not supported) is expected for most BMP-payload frames.
 * ========================================================================= */
static void process_frame_transform(
    IWICBitmapFrameDecode*      pFrame,
    UINT                        width,
    UINT                        height,
    const WICPixelFormatGUID*   pFmt)
{
    HRESULT                     hr;
    IWICBitmapSourceTransform*  pTransform = NULL;
    UINT                        scaledW    = width  / 2;
    UINT                        scaledH    = height / 2;
    UINT                        bpp        = 0U;
    UINT                        stride     = 0;
    UINT                        bufSize    = 0;
    BYTE*                       pPixels    = NULL;
    POLICY_RESULT               pr;
    BOOL                        bCanScale  = FALSE;

    if (!pFrame || scaledW == 0 || scaledH == 0) return;

    hr = pFrame->lpVtbl->QueryInterface(
        pFrame, &IID_IWICBitmapSourceTransform, (void**)&pTransform);
    trace_stage(&g_trace, STAGE_TRANSFORM, hr);
    if (FAILED(hr) || !pTransform) return;

    hr = pTransform->lpVtbl->DoesSupportTransform(
        pTransform, WICBitmapTransformRotate0, &bCanScale);
    if (FAILED(hr) || !bCanScale) goto transform_done;

    if (pFmt) bpp = policy_get_bpp_from_guid(g_pFactory, pFmt);
    if (bpp == 0) goto transform_done;

    pr = policy_compute_stride(&g_cfg.policy, scaledW, bpp, &stride);
    if (pr != POLICY_OK) goto transform_done;

    pr = policy_compute_buffer_size(&g_cfg.policy, stride, scaledH, &bufSize);
    if (pr != POLICY_OK) goto transform_done;

    pPixels = (BYTE*)HeapAlloc(GetProcessHeap(), 0, bufSize);
    if (!pPixels) goto transform_done;

    {
        /* CopyPixels on IWICBitmapSourceTransform takes a non-const
         * WICPixelFormatGUID* (in/out: decoder may adjust to nearest
         * supported format).  Copy pFmt to a local mutable variable. */
        WICPixelFormatGUID fmtMutable = pFmt
            ? *pFmt
            : GUID_WICPixelFormat32bppBGRA;

        hr = pTransform->lpVtbl->CopyPixels(
            pTransform,
            NULL,
            scaledW,
            scaledH,
            &fmtMutable,
            WICBitmapTransformRotate0,
            stride,
            bufSize,
            pPixels);
    }

    trace_transform(&g_trace, hr, scaledW, scaledH);
    HeapFree(GetProcessHeap(), 0, pPixels);

transform_done:
    pTransform->lpVtbl->Release(pTransform);
}

/* =========================================================================
 * process_frame_progressive
 *
 * IWICProgressiveLevelControl: progressive / interlaced PNG decode.
 * For PNG-in-ICO payloads, exercises the Adam7 interlaced decode path
 * in the embedded libpng (row-pointer reconstruction, per-pass dimension
 * overflows, iCCP chunk processing during progressive decode).
 *
 * The trace is emitted at every exit path so crash attribution is always
 * possible, regardless of which intermediate step failed.
 * ========================================================================= */
static void process_frame_progressive(
    IWICBitmapFrameDecode*      pFrame,
    UINT                        width,
    UINT                        height,
    const WICPixelFormatGUID*   pFmt)
{
    HRESULT                      hr;
    IWICProgressiveLevelControl* pProgressive = NULL;
    UINT                         levelCount   = 0;
    UINT                         i;
    IWICBitmapSource*            pSource      = NULL;
    UINT                         bpp          = 0U;
    UINT                         stride       = 0;
    UINT                         bufSize      = 0;
    BYTE*                        pPixels      = NULL;
    POLICY_RESULT                pr;
    BOOL                         traced       = FALSE; /* guards single trace call */

    if (!pFrame) return;

    hr = pFrame->lpVtbl->QueryInterface(
        pFrame, &IID_IWICProgressiveLevelControl, (void**)&pProgressive);
    trace_stage(&g_trace, STAGE_PROGRESSIVE, hr);

    if (FAILED(hr) || !pProgressive) {
        /* Interface not supported -- QI failure is expected for BMP frames */
        trace_progressive(&g_trace, hr, 0);
        return;
    }

    hr = pProgressive->lpVtbl->GetLevelCount(pProgressive, &levelCount);
    if (FAILED(hr) || levelCount == 0) {
        trace_progressive(&g_trace, hr, levelCount);
        traced = TRUE;
        goto progressive_done;
    }

    if (levelCount > 16U) levelCount = 16U;

    if (pFmt) bpp = policy_get_bpp_from_guid(g_pFactory, pFmt);
    if (bpp == 0) {
        trace_progressive(&g_trace, E_FAIL, levelCount);
        traced = TRUE;
        goto progressive_done;
    }

    pr = policy_compute_stride(&g_cfg.policy, width, bpp, &stride);
    if (pr != POLICY_OK) {
        trace_progressive(&g_trace, E_FAIL, levelCount);
        traced = TRUE;
        goto progressive_done;
    }

    pr = policy_compute_buffer_size(&g_cfg.policy, stride, height, &bufSize);
    if (pr != POLICY_OK) {
        trace_progressive(&g_trace, E_FAIL, levelCount);
        traced = TRUE;
        goto progressive_done;
    }

    pPixels = (BYTE*)HeapAlloc(GetProcessHeap(), 0, bufSize);
    if (!pPixels) {
        trace_progressive(&g_trace, E_OUTOFMEMORY, levelCount);
        traced = TRUE;
        goto progressive_done;
    }

    hr = pFrame->lpVtbl->QueryInterface(
        pFrame, &IID_IWICBitmapSource, (void**)&pSource);
    if (FAILED(hr) || !pSource) {
        trace_progressive(&g_trace, hr, levelCount);
        traced = TRUE;
        HeapFree(GetProcessHeap(), 0, pPixels);
        goto progressive_done;
    }

    /* Iterate through all progressive levels.
     * SetCurrentLevel() triggers internal libpng png_read_rows() per pass --
     * the level transitions are the primary exercise target. */
    for (i = 0; i < levelCount; i++) {
        hr = pProgressive->lpVtbl->SetCurrentLevel(pProgressive, i);
        if (FAILED(hr)) {
            trace_progressive(&g_trace, hr, levelCount);
            traced = TRUE;
            break;
        }
        hr = pSource->lpVtbl->CopyPixels(
            pSource, NULL, stride, bufSize, pPixels);
        /* Continue even on CopyPixels failure -- next level may succeed */
    }

    if (!traced) {
        trace_progressive(&g_trace, S_OK, levelCount);
    }

    pSource->lpVtbl->Release(pSource);
    HeapFree(GetProcessHeap(), 0, pPixels);

progressive_done:
    pProgressive->lpVtbl->Release(pProgressive);
}

/* =========================================================================
 * process_wic_convert
 *
 * WICConvertBitmapSource: single-call conversion API.
 * This function exercises a distinct internal code path from the manual
 * IWICFormatConverter sequence:
 *   - Does not perform a CanConvert check
 *   - Uses a different internal allocation strategy
 *   - Wraps decode and convert in a single lazy-evaluated object
 *
 * The STAGE_WIC_CONVERT stage is logged before the call so that if
 * WICConvertBitmapSource itself crashes, the trace identifies this path
 * as the crash location (not the previous frame's last stage).
 * ========================================================================= */
static void process_wic_convert(
    IWICBitmapFrameDecode*  pFrame,
    UINT                    width,
    UINT                    height)
{
    HRESULT           hr;
    IWICBitmapSource* pConverted = NULL;
    IWICBitmapSource* pFrameSrc  = NULL;
    UINT              stride     = 0;
    UINT              bufSize    = 0;
    BYTE*             pPixels    = NULL;
    POLICY_RESULT     pr;

    if (!pFrame || width == 0 || height == 0) return;

    hr = pFrame->lpVtbl->QueryInterface(
        pFrame, &IID_IWICBitmapSource, (void**)&pFrameSrc);
    if (FAILED(hr) || !pFrameSrc) return;

    /* Log the stage before the call so the trace identifies this path
     * even if the call itself causes a crash in the target DLL. */
    trace_stage(&g_trace, STAGE_WIC_CONVERT, S_OK);

    hr = WICConvertBitmapSource(
        &HARNESS_CONVERT_TARGET_FORMAT,
        pFrameSrc,
        &pConverted);

    pFrameSrc->lpVtbl->Release(pFrameSrc);

    if (FAILED(hr) || !pConverted) return;

    pr = policy_compute_stride(
        &g_cfg.policy, width, HARNESS_CONVERT_BPP * 8U, &stride);
    if (pr != POLICY_OK) goto wic_convert_done;

    pr = policy_compute_buffer_size(&g_cfg.policy, stride, height, &bufSize);
    if (pr != POLICY_OK) goto wic_convert_done;

    pPixels = (BYTE*)HeapAlloc(GetProcessHeap(), 0, bufSize);
    if (!pPixels) goto wic_convert_done;

    hr = pConverted->lpVtbl->CopyPixels(
        pConverted, NULL, stride, bufSize, pPixels);
    trace_copy_pixels(&g_trace, hr, stride, bufSize, pr, TRUE);

    HeapFree(GetProcessHeap(), 0, pPixels);

wic_convert_done:
    pConverted->lpVtbl->Release(pConverted);
}

/* =========================================================================
 * harness_global_init
 *
 * Called once before the fuzz loop.
 * Initialises COM, creates WIC factory, loads configuration.
 * ========================================================================= */
static void harness_global_init(void)
{
    HRESULT hr;

    config_init_defaults(&g_cfg);
    config_load_ini(&g_cfg);
    config_resolve_trace_path(&g_cfg);

    trace_init(&g_trace, g_cfg.tracePath, g_cfg.traceEnabled);
    config_print(&g_cfg, g_trace.hFile);

    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        OutputDebugStringA("[HARNESS] CoInitializeEx failed\n");
        ExitProcess(1);
    }

#ifdef HARNESS_MODE_RESEARCH
    /* Capture the apartment thread ID for later validation in fuzz_target */
    g_initTid = GetCurrentThreadId();
#endif

    hr = CoCreateInstance(
        &CLSID_WICImagingFactory,
        NULL,
        CLSCTX_INPROC_SERVER,
        &IID_IWICImagingFactory,
        (void**)&g_pFactory);

    if (FAILED(hr) || !g_pFactory) {
        OutputDebugStringA("[HARNESS] WIC factory creation failed\n");
        CoUninitialize();
        ExitProcess(1);
    }

    /* IWICImagingFactory2 is required for CreateColorContext.
     * If QI fails (older WIC runtime), the color context path is silently
     * disabled in process_color_contexts(). */
    hr = g_pFactory->lpVtbl->QueryInterface(
        g_pFactory,
        &IID_IWICImagingFactory2,
        (void**)&g_pFactory2);

    if (FAILED(hr) || !g_pFactory2) {
        g_pFactory2 = NULL;
        trace_write_direct(&g_trace,
            "[INIT]  IWICImagingFactory2 not available -- color context path disabled\r\n");
    }

    g_initialized = TRUE;
    trace_write_direct(&g_trace, "[INIT]  COM initialized, WIC factory ready\r\n");
}

/* =========================================================================
 * harness_global_cleanup
 *
 * Called once on process exit.
 * Release order: Factory2 before Factory1 (QI'd from it).
 * ========================================================================= */
static void harness_global_cleanup(void)
{
    g_initialized = FALSE;
    SAFE_RELEASE(g_pFactory2);
    SAFE_RELEASE(g_pFactory);
    CoUninitialize();
    trace_close(&g_trace);
}

/* =========================================================================
 * wmain
 *
 * Standalone mode:  harness.exe <input.ico>
 *   Runs fuzz_target() cfg.iterations times with the same file.
 *   Used for testing, debugging, and research runs with PageHeap.
 *
 * WinAFL mode:  harness.exe @@
 *   WinAFL replaces @@ with the mutated input file path.
 *   WinAFL calls fuzz_target() directly via -target_method after the
 *   process signals readiness on first call.  The wmain loop runs once.
 *
 * NOTE: The input path passed to CreateDecoderFromFilename must end in
 * .ico for the ICO decoder to be selected.  Configure WinAFL with
 * -file_extension ico or ensure input files are named *.ico.
 * ========================================================================= */
int wmain(int argc, WCHAR* argv[])
{
    UINT i;

    if (argc < 2) {
        wprintf(L"Usage: harness.exe <input.ico>\n");
        wprintf(L"       harness.exe @@    (WinAFL mode)\n");
        return 1;
    }

    harness_global_init();

    for (i = 0; i < g_cfg.iterations; i++) {
        fuzz_target(argv[1]);
    }

    harness_global_cleanup();
    return 0;
}
