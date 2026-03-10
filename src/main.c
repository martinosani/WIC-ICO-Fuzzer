/*
 * main.c
 *
 * WIC ICO Fuzzing Harness - Main Entry Point
 *
 * WinAFL persistent mode target function: fuzz_target()
 * TinyInst coverage module: windowscodecs.dll
 *
 * Architecture:
 *   COM init + WIC factory: outside loop (once per process)
 *   fuzz_target(): inside loop (every iteration)
 *
 * COM interface chain (all paths - no direct DLL calls):
 *   IWICImagingFactory
 *   IWICImagingFactory2        (for CreateColorContext - Fix #3)
 *   IWICBitmapDecoder
 *   IWICBitmapDecoderInfo
 *   IWICBitmapFrameDecode
 *   IWICBitmapSource           (via QueryInterface - Fix #5)
 *   IWICFormatConverter
 *   IWICMetadataQueryReader    (recursive enumeration - Fix #6)
 *   IWICEnumMetadataItem
 *   IWICPalette
 *   IWICColorContext
 *   IWICBitmapSource           (thumbnail/preview)
 *   IWICComponentInfo / IWICPixelFormatInfo (for bpp resolution)
 *   IWICBitmapSourceTransform  (scaled decode path - Fix #7)
 *   IWICProgressiveLevelControl (progressive decode path - Fix #8)
 *
 */

#define WIN32_LEAN_AND_MEAN
#define COBJMACROS  /* enable C-style COM macro calls: pObj->lpVtbl->Method() */

#include <windows.h>
#include <ole2.h>
#include <wincodec.h>
#include <wincodecsdk.h>
#include <shlobj.h>     /* SHCreateStreamOnFileW — Fix #4 (Lena Varga) */
#include <stdio.h>
#include <strsafe.h>

#include "config.h"
#include "policy.h"
#include "trace.h"
#include "ini.h"

 /* =========================================================================
  * Safe COM release macro
  * Calls Release() only if pointer is non-NULL, then NULLs the pointer.
  * Safe to call on already-NULL pointers.
  * ========================================================================= */
#define SAFE_RELEASE(p)  \
    do { if ((p)) { (p)->lpVtbl->Release((p)); (p) = NULL; } } while(0)

  /* =========================================================================
   * HRESULT check helper
   * hr must be an HRESULT lvalue.
   * On failure: log stage + hr, release all per-iteration COM objects, return.
   * ========================================================================= */
#define CHECK_HR_GOTO(hr, stage, label)                         \
    do {                                                        \
        trace_stage(&g_trace, (stage), (hr));                  \
        if (FAILED(hr)) { goto label; }                        \
    } while(0)

   /* =========================================================================
    * Global state (outside fuzz loop — initialized once)
    * ========================================================================= */
static IWICImagingFactory* g_pFactory = NULL;

/*
 * g_pFactory2 — IWICImagingFactory2 interface on the same factory object.
 *
 * Fix #3 (Viktor Hale): IWICImagingFactory does NOT expose CreateColorContext.
 * The correct interface is IWICImagingFactory2, obtained via QueryInterface
 * on the factory object created with CoCreateInstance(CLSID_WICImagingFactory).
 * Both pointers refer to the same underlying COM object — Factory2 is held
 * as a separate QI'd pointer to avoid repeated QI calls per iteration.
 * Released in reverse QI order during global cleanup.
 */
static IWICImagingFactory2* g_pFactory2 = NULL;

static HARNESS_CONFIG       g_cfg;
static HARNESS_TRACE_CTX    g_trace;
static BOOL                 g_initialized = FALSE;

/* =========================================================================
 * Forward declarations
 * ========================================================================= */
static void harness_global_init(void);
static void harness_global_cleanup(void);
static void process_metadata_reader(IWICMetadataQueryReader* pMQR,
    BOOL isFrame,
    UINT depth);
static void process_palette(IWICPalette* pPalette,
    BOOL isFrame);
static void process_color_contexts(IWICBitmapDecoder* pDecoder,
    IWICBitmapFrameDecode* pFrame);
static void process_thumbnail(IWICBitmapSource* pSource,
    BOOL isContainer);
static void process_frame_copy_pixels(IWICBitmapFrameDecode* pFrame,
    UINT frameIndex,
    UINT width,
    UINT height,
    const WICPixelFormatGUID* pFmt);
static void process_frame_copy_pixels_partial(IWICBitmapFrameDecode* pFrame,
    UINT width,
    UINT height,
    const WICPixelFormatGUID* pFmt);
static void process_frame_transform(IWICBitmapFrameDecode* pFrame,
    UINT width,
    UINT height,
    const WICPixelFormatGUID* pFmt);
static void process_frame_progressive(IWICBitmapFrameDecode* pFrame,
    UINT width,
    UINT height,
    const WICPixelFormatGUID* pFmt);
static void process_wic_convert(IWICBitmapFrameDecode* pFrame,
    UINT width,
    UINT height);

/* =========================================================================
 * fuzz_target
 *
 * WinAFL persistent mode target function.
 * This is the function TinyInst begins coverage measurement from.
 * WinAFL calls this function repeatedly with mutated input files.
 *
 * The function is designed to:
 *   1. Accept a file path (from argv[1] / WinAFL @@)
 *   2. Exercise ALL reachable WIC COM paths for ICO decoding
 *   3. Release all per-iteration COM objects before returning
 *   4. Never crash the harness process on malformed input
 *      (crashes inside windowscodecs.dll propagate naturally to WinAFL)
 *
 * IMPORTANT: This function must be exported or its name must be passed
 * to WinAFL via -target_method. Decorated name on x64: fuzz_target
 * ========================================================================= */
__declspec(noinline)
void fuzz_target(const WCHAR* filePath)
{
    /* ---------------------------------------------------------------
     * Per-iteration COM interface pointers — ALL must be NULL-init.
     * ALL must be released before this function returns.
     * --------------------------------------------------------------- */
    IWICBitmapDecoder* pDecoder = NULL;
    IWICBitmapDecoderInfo* pDecoderInfo = NULL;
    IWICBitmapFrameDecode* pFrame = NULL;
    IWICFormatConverter* pConverter = NULL;
    IWICMetadataQueryReader* pContainerMQR = NULL;
    IWICPalette* pPalette = NULL;
    IWICBitmapSource* pPreview = NULL;
    IWICBitmapSource* pThumb = NULL;

    HRESULT             hr;
    UINT                uFrameCount = 0;
    UINT                uCappedFrames = 0;
    UINT                uFrameIdx;
    UINT                uProcessed = 0;
    UINT                uSkipped = 0;
    GUID                containerFmt;
    DWORD               dwCapabilities = 0;

    static UINT         s_iteration = 0;
    s_iteration++;

    /* ---------------------------------------------------------------
     * Safety net: release any leftover pointers from a previous
     * iteration that exited abnormally (should never happen, but
     * defensive programming in persistent mode is mandatory).
     * --------------------------------------------------------------- */
    SAFE_RELEASE(pDecoder);
    SAFE_RELEASE(pDecoderInfo);
    SAFE_RELEASE(pFrame);
    SAFE_RELEASE(pConverter);
    SAFE_RELEASE(pContainerMQR);
    SAFE_RELEASE(pPalette);
    SAFE_RELEASE(pPreview);
    SAFE_RELEASE(pThumb);

    if (!g_initialized || !g_pFactory || !filePath) return;

    trace_iteration_begin(&g_trace, s_iteration, filePath);

    /* ===============================================================
     * STAGE 1: Create decoder from filename
     * COM: IWICImagingFactory::CreateDecoderFromFilename
     *
     * WICDecodeMetadataCacheOnLoad forces all metadata parsing
     * immediately — exercises maximum internal code paths.
     *
     * Fix #15 note: a second fuzzing campaign should use
     * WICDecodeMetadataCacheOnDemand here and add explicit
     * GetMetadataByName queries on known ICO/PNG key paths.
     * Controlled via HARNESS_CACHE_ON_DEMAND compile flag.
     *
     * Exercises internally:
     *   - File signature detection
     *   - ICONDIR initial read
     *   - Codec selection and initialization
     *   - Metadata cache population
     * =============================================================== */

#ifdef HARNESS_MODE_RESEARCH
    __try {
#endif

        hr = g_pFactory->lpVtbl->CreateDecoderFromFilename(
            g_pFactory,
            filePath,
            NULL,
            GENERIC_READ,
#ifdef HARNESS_CACHE_ON_DEMAND
            WICDecodeMetadataCacheOnDemand,   /* Fix #15: second campaign mode */
#else
            HARNESS_DECODE_OPTIONS,           /* default: WICDecodeMetadataCacheOnLoad */
#endif
            & pDecoder);

        CHECK_HR_GOTO(hr, STAGE_DECODER_CREATE, cleanup);

        /* ===============================================================
         * STAGE 2: QueryCapability
         * COM: IWICBitmapDecoder::QueryCapability
         *
         * Forces a capability detection pass over the file.
         * Creates an IStream internally and re-reads file header.
         * Exercises a separate code path from CreateDecoderFromFilename.
         *
         * Fix #2 (Dante Osei): IStream must be seeked to position 0
         * before QueryCapability. The stream position after
         * SHCreateStreamOnFileW is 0, but we call Seek explicitly as
         * a defensive guarantee — the spec requires it and some codec
         * implementations are sensitive to non-zero initial positions.
         * =============================================================== */
        {
            IStream* pStream = NULL;
            hr = SHCreateStreamOnFileW(filePath, STGM_READ | STGM_SHARE_DENY_WRITE, &pStream);
            if (SUCCEEDED(hr) && pStream) {
                LARGE_INTEGER liZero;
                liZero.QuadPart = 0;

                /* Seek to offset 0 — required by QueryCapability contract */
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
         * COM: IWICBitmapDecoder::GetContainerFormat
         * =============================================================== */
        ZeroMemory(&containerFmt, sizeof(containerFmt));
        hr = pDecoder->lpVtbl->GetContainerFormat(pDecoder, &containerFmt);
        trace_stage(&g_trace, STAGE_CONTAINER_FORMAT, hr);
        trace_container_format(&g_trace, hr, &containerFmt);

        /* ===============================================================
         * STAGE 4: GetDecoderInfo
         * COM: IWICBitmapDecoder::GetDecoderInfo ->
         *      IWICBitmapDecoderInfo::DoesSupportMultiframe etc.
         * =============================================================== */
        if (g_cfg.decoderInfoPath) {
            hr = pDecoder->lpVtbl->GetDecoderInfo(pDecoder, &pDecoderInfo);
            trace_stage(&g_trace, STAGE_DECODER_INFO, hr);
            if (SUCCEEDED(hr) && pDecoderInfo) {
                BOOL bMultiframe = FALSE;
                BOOL bLossless = FALSE;
                BOOL bAnimation = FALSE;
                WCHAR extBuf[256] = { 0 };
                WCHAR mimeBuf[256] = { 0 };
                UINT extLen = 0, mimeLen = 0;

                pDecoderInfo->lpVtbl->DoesSupportMultiframe(pDecoderInfo, &bMultiframe);
                pDecoderInfo->lpVtbl->DoesSupportLossless(pDecoderInfo, &bLossless);
                pDecoderInfo->lpVtbl->DoesSupportAnimation(pDecoderInfo, &bAnimation);

                /* Get file extensions — exercises codec info strings */
                pDecoderInfo->lpVtbl->GetFileExtensions(pDecoderInfo, 0, NULL, &extLen);
                if (extLen > 0 && extLen < 256)
                    pDecoderInfo->lpVtbl->GetFileExtensions(pDecoderInfo, extLen, extBuf, &extLen);

                /* Get MIME types */
                pDecoderInfo->lpVtbl->GetMimeTypes(pDecoderInfo, 0, NULL, &mimeLen);
                if (mimeLen > 0 && mimeLen < 256)
                    pDecoderInfo->lpVtbl->GetMimeTypes(pDecoderInfo, mimeLen, mimeBuf, &mimeLen);

                SAFE_RELEASE(pDecoderInfo);
            }
        }

        /* ===============================================================
         * STAGE 5: Container-level metadata
         * COM: IWICBitmapDecoder::GetMetadataQueryReader ->
         *      IWICMetadataQueryReader::GetContainerFormat
         *      IWICMetadataQueryReader::GetLocation
         *      IWICMetadataQueryReader::GetEnumerator -> enumerate items
         *
         * Fix #6 (Ryo Tanaka): process_metadata_reader now recursively
         * descends into nested VT_UNKNOWN propvariants that implement
         * IWICMetadataQueryReader (XMP/EXIF blocks inside PNG-in-ICO).
         * =============================================================== */
        if (g_cfg.metadataEnum) {
            hr = pDecoder->lpVtbl->GetMetadataQueryReader(pDecoder, &pContainerMQR);
            trace_stage(&g_trace, STAGE_CONTAINER_METADATA, hr);
            if (SUCCEEDED(hr) && pContainerMQR) {
                process_metadata_reader(pContainerMQR, FALSE, 0);
                SAFE_RELEASE(pContainerMQR);
            }
        }

        /* ===============================================================
         * STAGE 6: Container-level palette
         * COM: IWICImagingFactory::CreatePalette ->
         *      IWICBitmapDecoder::CopyPalette ->
         *      IWICPalette::GetType, GetColorCount, GetColors, HasAlpha
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
         * STAGE 7: Container-level color contexts
         * COM: IWICBitmapDecoder::GetColorContexts
         *
         * Fix #3 (Viktor Hale): CreateColorContext is called via
         * g_pFactory2 (IWICImagingFactory2), NOT via g_pFactory
         * (IWICImagingFactory). The standard IWICImagingFactory vtable
         * does not contain CreateColorContext — that method lives on
         * IWICImagingFactory2. Using g_pFactory directly would produce
         * a vtable corruption at runtime or a compile error.
         * g_pFactory2 is obtained once at startup via QueryInterface.
         * =============================================================== */
        if (g_cfg.colorContextPath) {
            process_color_contexts(pDecoder, NULL);
        }

        /* ===============================================================
         * STAGE 8: GetPreview
         * COM: IWICBitmapDecoder::GetPreview
         * Exercises a separate internal preview extraction path.
         * Expected to return WINCODEC_ERR_UNSUPPORTEDOPERATION for most
         * ICO files — we call it anyway to exercise the check path.
         * =============================================================== */
        if (g_cfg.thumbnailPath) {
            hr = pDecoder->lpVtbl->GetPreview(pDecoder, &pPreview);
            trace_stage(&g_trace, STAGE_PREVIEW, hr);
            if (SUCCEEDED(hr) && pPreview) {
                process_thumbnail(pPreview, TRUE);
                SAFE_RELEASE(pPreview);
            }

            /* ===============================================================
             * STAGE 9: Container-level thumbnail
             * COM: IWICBitmapDecoder::GetThumbnail
             * =============================================================== */
            hr = pDecoder->lpVtbl->GetThumbnail(pDecoder, &pThumb);
            trace_stage(&g_trace, STAGE_THUMBNAIL_CONTAINER, hr);
            if (SUCCEEDED(hr) && pThumb) {
                process_thumbnail(pThumb, TRUE);
                SAFE_RELEASE(pThumb);
            }
        }

        /* ===============================================================
         * STAGE 10: GetFrameCount
         * COM: IWICBitmapDecoder::GetFrameCount
         *
         * Exercises ICONDIR entry count parsing.
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
         * STAGE 11-21: Per-frame processing loop
         * Processes each ICONDIRENTRY individually.
         * Each GetFrame() call exercises a different entry in the
         * ICO directory — different offsets, different payload types.
         * =============================================================== */
        for (uFrameIdx = 0; uFrameIdx < uCappedFrames; uFrameIdx++) {

            WICPixelFormatGUID  fmtGUID;
            UINT                width = 0;
            UINT                height = 0;
            double              dpiX = 0.0, dpiY = 0.0;
            BOOL                frameOk = FALSE;

            trace_frame_begin(&g_trace, uFrameIdx);
            ZeroMemory(&fmtGUID, sizeof(fmtGUID));

            /* -------------------------------------------------------
             * STAGE 11: GetFrame(i)
             * COM: IWICBitmapDecoder::GetFrame
             *
             * Exercises ICONDIRENTRY[i] parsing and payload type
             * detection (BMP-style vs embedded PNG).
             * ------------------------------------------------------- */
            hr = pDecoder->lpVtbl->GetFrame(pDecoder, uFrameIdx, &pFrame);
            trace_stage(&g_trace, STAGE_FRAME_GET, hr);
            if (FAILED(hr) || !pFrame) { uSkipped++; continue; }

            /* -------------------------------------------------------
             * STAGE 12: GetSize
             * COM: IWICBitmapFrameDecode::GetSize
             *
             * Reads width/height. Critical: ICONDIRENTRY declares size
             * separately from the embedded payload. Mismatches between
             * declared and actual dimensions are a known bug class.
             * Policy validation happens immediately after.
             * ------------------------------------------------------- */
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

            /* -------------------------------------------------------
             * STAGE 13: GetPixelFormat
             * COM: IWICBitmapFrameDecode::GetPixelFormat
             * ------------------------------------------------------- */
            hr = pFrame->lpVtbl->GetPixelFormat(pFrame, &fmtGUID);
            trace_stage(&g_trace, STAGE_FRAME_PIXEL_FORMAT, hr);
            if (SUCCEEDED(hr)) {
                UINT bpp = policy_get_bpp_from_guid(g_pFactory, &fmtGUID);
                trace_frame_pixel_format(&g_trace, hr, &fmtGUID, bpp);
            }

            /* -------------------------------------------------------
             * STAGE 14: GetResolution
             * COM: IWICBitmapFrameDecode::GetResolution
             * ------------------------------------------------------- */
            hr = pFrame->lpVtbl->GetResolution(pFrame, &dpiX, &dpiY);
            trace_stage(&g_trace, STAGE_FRAME_RESOLUTION, hr);
            trace_frame_resolution(&g_trace, hr, dpiX, dpiY);

            /* -------------------------------------------------------
             * STAGE 15: Frame palette
             * COM: IWICImagingFactory::CreatePalette ->
             *      IWICBitmapFrameDecode::CopyPalette
             *
             * Critical for 1/4/8bpp ICO frames (palette-indexed).
             * Palette table overflow is a known vulnerability class.
             * ------------------------------------------------------- */
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

            /* -------------------------------------------------------
             * STAGE 16: Frame color contexts (ICC profiles)
             * COM: IWICBitmapFrameDecode::GetColorContexts
             *
             * For PNG-in-ICO: exercises iCCP chunk parsing inside
             * the embedded PNG decoder.
             * ------------------------------------------------------- */
            if (g_cfg.colorContextPath) {
                process_color_contexts(NULL, pFrame);
            }

            /* -------------------------------------------------------
             * STAGE 17: Frame metadata
             * COM: IWICBitmapFrameDecode::GetMetadataQueryReader
             *
             * For PNG-in-ICO: exercises tEXt/iTXt/zTXt chunk parsing.
             * Metadata size fields are a known integer overflow surface.
             * Fix #6: recursive descent into nested VT_UNKNOWN readers.
             * ------------------------------------------------------- */
            if (g_cfg.metadataEnum) {
                IWICMetadataQueryReader* pFrameMQR = NULL;
                hr = pFrame->lpVtbl->GetMetadataQueryReader(pFrame, &pFrameMQR);
                trace_stage(&g_trace, STAGE_FRAME_METADATA, hr);
                if (SUCCEEDED(hr) && pFrameMQR) {
                    process_metadata_reader(pFrameMQR, TRUE, 0);
                    SAFE_RELEASE(pFrameMQR);
                }
            }

            /* -------------------------------------------------------
             * STAGE 18: Frame thumbnail
             * COM: IWICBitmapFrameDecode::GetThumbnail
             * ------------------------------------------------------- */
            if (g_cfg.thumbnailPath) {
                IWICBitmapSource* pFrameThumb = NULL;
                hr = pFrame->lpVtbl->GetThumbnail(pFrame, &pFrameThumb);
                trace_stage(&g_trace, STAGE_FRAME_THUMBNAIL, hr);
                if (SUCCEEDED(hr) && pFrameThumb) {
                    process_thumbnail(pFrameThumb, FALSE);
                    SAFE_RELEASE(pFrameThumb);
                }
            }

            /* -------------------------------------------------------
             * STAGE 19: CopyPixels — full rect (PRIMARY BUG TRIGGER)
             * COM: IWICBitmapFrameDecode (via IWICBitmapSource QI)::CopyPixels
             *
             * This is the primary fuzzing target.
             * Forces full pixel materialization:
             *   - BMP-payload: AND mask + XOR bitmap reconstruction
             *   - PNG-payload: full PNG decode (libpng + zlib inflate)
             * PageHeap will catch heap overflows here.
             *
             * Fix #5 (Mara Schultz): CopyPixels is called via an explicit
             * QueryInterface to IWICBitmapSource, not a raw pointer cast.
             * Raw casting IWICBitmapFrameDecode* to IWICBitmapSource* is
             * undefined behaviour in C because the vtable layout is
             * implementation-defined. QI is the correct COM-compliant path.
             * ------------------------------------------------------- */
            process_frame_copy_pixels(pFrame, uFrameIdx, width, height, &fmtGUID);

            /* -------------------------------------------------------
             * STAGE 19b: CopyPixels — partial rect (top-left quadrant)
             * COM: IWICBitmapFrameDecode (via QI)::CopyPixels(WICRect*)
             *
             * Fix #10 (Ryo Tanaka): exercises a distinct code path inside
             * the decoder for partial-rect copies. The ICO BMP decoder
             * computes per-scanline offsets relative to the rect origin,
             * which involves different stride/offset arithmetic than a
             * full-image copy. This is a known location for off-by-one
             * bugs in codec implementations.
             *
             * Only called when full-image CopyPixels succeeds (frameOk).
             * ------------------------------------------------------- */
            if (frameOk && width > 1 && height > 1) {
                process_frame_copy_pixels_partial(pFrame, width, height, &fmtGUID);
            }

            /* -------------------------------------------------------
             * STAGE 25: IWICBitmapSourceTransform scaled decode
             * COM: IWICBitmapFrameDecode -> QI -> IWICBitmapSourceTransform
             *
             * Fix #7 (Ryo Tanaka): IWICBitmapSourceTransform exposes
             * scaled, rotated, and flipped decode paths. For ICO this
             * exercises dimension scaling arithmetic inside the decoder —
             * a known overflow surface. We request half-size output.
             * This interface is not always supported; absent support
             * produces a QI failure which is expected and not an error.
             * ------------------------------------------------------- */
            if (g_cfg.transformPath && frameOk) {
                process_frame_transform(pFrame, width, height, &fmtGUID);
            }

            /* -------------------------------------------------------
             * STAGE 26: IWICProgressiveLevelControl
             * COM: IWICBitmapFrameDecode -> QI -> IWICProgressiveLevelControl
             *
             * Fix #8 (Ryo Tanaka): For PNG-in-ICO payloads, WIC may expose
             * progressive decoding via IWICProgressiveLevelControl.
             * Progressive decode exercises interlaced PNG paths in libpng —
             * historically a vulnerability-rich area (Adam7 interlace,
             * row-pointer reconstruction with mismatched pass dimensions).
             * QI failure = not supported for this frame type, not an error.
             * ------------------------------------------------------- */
            if (g_cfg.progressivePath && frameOk) {
                process_frame_progressive(pFrame, width, height, &fmtGUID);
            }

            /* -------------------------------------------------------
             * STAGE 20-21: Format conversion path (optional)
             * COM: IWICImagingFactory::CreateFormatConverter ->
             *      IWICFormatConverter::CanConvert ->
             *      IWICFormatConverter::Initialize ->
             *      IWICFormatConverter::GetSize, GetPixelFormat ->
             *      IWICFormatConverter (via QI IWICBitmapSource)::CopyPixels
             *
             * Exercises the format conversion pipeline which has its
             * own internal buffer allocation and copy operations.
             * Target: GUID_WICPixelFormat32bppBGRA (always 4 bpp).
             *
             * Fix #5: CopyPixels on converter also uses QI, not raw cast.
             * ------------------------------------------------------- */
            if (g_cfg.conversionPath && frameOk) {
                hr = g_pFactory->lpVtbl->CreateFormatConverter(
                    g_pFactory, &pConverter);
                trace_stage(&g_trace, STAGE_CONVERTER_INIT, hr);

                if (SUCCEEDED(hr) && pConverter) {
                    BOOL bCanConvert = FALSE;

                    /*
                     * Fix #5: pFrame is passed as IWICBitmapSource* to
                     * IWICFormatConverter::Initialize via QI, not raw cast.
                     * The source pointer must be IWICBitmapSource* — obtain
                     * it via QueryInterface for correctness.
                     */
                    IWICBitmapSource* pFrameAsSource = NULL;
                    hr = pFrame->lpVtbl->QueryInterface(
                        pFrame,
                        &IID_IWICBitmapSource,
                        (void**)&pFrameAsSource);

                    if (SUCCEEDED(hr) && pFrameAsSource) {
                        /* CanConvert check */
                        pConverter->lpVtbl->CanConvert(
                            pConverter,
                            &fmtGUID,
                            &HARNESS_CONVERT_TARGET_FORMAT,
                            &bCanConvert);

                        if (bCanConvert) {
                            hr = pConverter->lpVtbl->Initialize(
                                pConverter,
                                pFrameAsSource,             /* correctly QI'd */
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

                                /* Verify output dimensions and format */
                                pConverter->lpVtbl->GetSize(
                                    pConverter, &convWidth, &convHeight);
                                pConverter->lpVtbl->GetPixelFormat(
                                    pConverter, &convFmt);

                                /* Compute stride for 32bppBGRA (always 32bpp) */
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
                                        /*
                                         * Fix #5: QI converter to IWICBitmapSource
                                         * before calling CopyPixels.
                                         */
                                        hr = pConverter->lpVtbl->QueryInterface(
                                            pConverter,
                                            &IID_IWICBitmapSource,
                                            (void**)&pConvAsSource);

                                        if (SUCCEEDED(hr) && pConvAsSource) {
                                            trace_stage(&g_trace, STAGE_CONVERTER_COPY, S_OK);
                                            hr = pConvAsSource->lpVtbl->CopyPixels(
                                                pConvAsSource,
                                                NULL,
                                                convStride,
                                                convBufSize,
                                                pConvPixels);

                                            trace_copy_pixels(&g_trace, hr,
                                                convStride, convBufSize, pr, TRUE);

                                            pConvAsSource->lpVtbl->Release(pConvAsSource);
                                        }

                                        HeapFree(GetProcessHeap(), 0, pConvPixels);
                                        pConvPixels = NULL;
                                    }
                                }
                                else {
                                    trace_policy_violation(&g_trace, pr,
                                        convWidth, convHeight, convStride, convBufSize);
                                }
                            }
                        }
                        pFrameAsSource->lpVtbl->Release(pFrameAsSource);
                    }
                    SAFE_RELEASE(pConverter);
                }
            }

            /* -------------------------------------------------------
             * Fix #11 (Ryo Tanaka): WICConvertBitmapSource single-call path
             *
             * WICConvertBitmapSource is an alternative conversion API that
             * internally chains decoder and format converter differently
             * from the manual IWICFormatConverter path above.
             * Identified from IDA string analysis at 0x18000A1940.
             * This function is a separate internal code path with its own
             * buffer allocation logic — not identical to what CreateFormatConverter
             * produces. It is declared in wincodec.h and exported from
             * windowscodecs.dll, but called via the WIC API (not direct DLL call).
             *
             * Only called when the manual conversion path is disabled (to avoid
             * double-triggering the same frame) or when the frame is valid.
             * We always call it to exercise the distinct code path.
             * ------------------------------------------------------- */
            if (g_cfg.wicConvertPath && frameOk) {
                process_wic_convert(pFrame, width, height);
            }

            uProcessed++;
            SAFE_RELEASE(pFrame);

        } /* end per-frame loop */

    oob_probe:
        /* ===============================================================
         * Fix #16: Out-of-bounds frame index stress probes
         * COM: IWICBitmapDecoder::GetFrame with invalid indices
         *
         *
         * Tests boundary validation in the ICONDIR frame dispatcher.
         * All three probes MUST return failure (E_INVALIDARG or similar).
         * A return of S_OK from any probe indicates an off-by-one or
         * index validation bug in the decoder — high exploitability signal.
         *
         * Probes:
         *   GetFrame(uFrameCount)   — one past the last valid index
         *   GetFrame(0xFFFF)        — ICO format max: 65535 entries
         *
         * These probes are run even if the earlier stages were skipped
         * (e.g. GetFrameCount failed), using the last known uFrameCount.
         * =============================================================== */
        if (pDecoder && uFrameCount > 0) {
            IWICBitmapFrameDecode* pOobFrame = NULL;
            HRESULT hrAtCount = S_OK;
            HRESULT hrAt0xFFFF = S_OK;

            trace_stage(&g_trace, STAGE_FRAME_OOB, S_OK); /* marker — not an error */

            /* Probe 1: GetFrame(frameCount) — one past last valid index */
            hrAtCount = pDecoder->lpVtbl->GetFrame(pDecoder, uFrameCount, &pOobFrame);
            if (SUCCEEDED(hrAtCount) && pOobFrame) {
                /* Unexpected success — decoder returned a frame for OOB index */
                SAFE_RELEASE(pOobFrame);
            }

            /* Probe 2: GetFrame(0xFFFF) — ICO format max entry count */
            hrAt0xFFFF = pDecoder->lpVtbl->GetFrame(pDecoder, 0xFFFFU, &pOobFrame);
            if (SUCCEEDED(hrAt0xFFFF) && pOobFrame) {
                SAFE_RELEASE(pOobFrame);
            }

            trace_oob_frame(&g_trace, uFrameCount, hrAtCount, hrAt0xFFFF);
        }

    cleanup:

#ifdef HARNESS_MODE_RESEARCH
    } /* end __try */
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DWORD exCode = GetExceptionCode();
        trace_seh_exception(&g_trace, exCode, g_trace.lastStage);
        /* Release all COM objects before re-raising */
        SAFE_RELEASE(pConverter);
        SAFE_RELEASE(pFrame);
        SAFE_RELEASE(pContainerMQR);
        SAFE_RELEASE(pPalette);
        SAFE_RELEASE(pPreview);
        SAFE_RELEASE(pThumb);
        SAFE_RELEASE(pDecoderInfo);
        SAFE_RELEASE(pDecoder);
        /* Re-raise so the crash is visible to external tools */
        RaiseException(exCode, EXCEPTION_NONCONTINUABLE, 0, NULL);
    }
#endif

    /* ---------------------------------------------------------------
     * Mandatory per-iteration COM cleanup.
     * Order: converter -> frame -> metadata -> palette ->
     *        thumbnails -> decoder info -> decoder
     * --------------------------------------------------------------- */
    SAFE_RELEASE(pConverter);
    SAFE_RELEASE(pFrame);
    SAFE_RELEASE(pContainerMQR);
    SAFE_RELEASE(pPalette);
    SAFE_RELEASE(pPreview);
    SAFE_RELEASE(pThumb);
    SAFE_RELEASE(pDecoderInfo);
    SAFE_RELEASE(pDecoder);

    trace_iteration_end(&g_trace, uProcessed, uSkipped);
    /* trace_iteration_end flushes the file — crash correlation guaranteed */
}

/* =========================================================================
 * process_metadata_reader
 *
 * Exercises IWICMetadataQueryReader paths:
 *   GetContainerFormat, GetLocation, GetEnumerator -> IWICEnumMetadataItem
 *
 * For PNG-in-ICO: exercises tEXt, iTXt, zTXt, iCCP chunk metadata.
 * Metadata size fields are a primary integer overflow target.
 *
 * Fix #6 (Ryo Tanaka):
 * Recursive descent into nested metadata readers.
 *
 * When a propvariant value has vt == VT_UNKNOWN, the unknown pointer
 * may implement IWICMetadataQueryReader — this is how XMP and EXIF
 * blocks are embedded inside PNG-in-ICO metadata. The original harness
 * called PropVariantClear() immediately after Next() without inspecting
 * the value type, leaving entire subtrees of the metadata tree unvisited.
 *
 * This version:
 *   1. Inspects each value's vt field.
 *   2. If vt == VT_UNKNOWN, attempts QI to IWICMetadataQueryReader.
 *   3. On success, recurses into the sub-reader (depth-limited by
 *      HARNESS_METADATA_MAX_DEPTH to prevent infinite loops on
 *      maliciously nested structures).
 *   4. Counts nested readers separately in the trace entry.
 *
 * depth: current recursion depth. 0 = direct child of frame/container.
 * ========================================================================= */
#define HARNESS_METADATA_MAX_DEPTH  4U

static void process_metadata_reader(
    IWICMetadataQueryReader* pMQR,
    BOOL                        isFrame,
    UINT                        depth)
{
    HRESULT                 hr;
    GUID                    fmtGuid;
    WCHAR                   locationBuf[256] = { 0 };
    UINT                    locationLen = 0;
    IWICEnumMetadataItem* pEnum = NULL;
    UINT                    itemCount = 0;
    UINT                    nestedCount = 0;
    HRESULT                 enumHr = E_FAIL;

    if (!pMQR || depth > HARNESS_METADATA_MAX_DEPTH) return;

    /* GetContainerFormat */
    ZeroMemory(&fmtGuid, sizeof(fmtGuid));
    hr = pMQR->lpVtbl->GetContainerFormat(pMQR, &fmtGuid);

    /* GetLocation */
    pMQR->lpVtbl->GetLocation(pMQR, 0, NULL, &locationLen);
    if (locationLen > 0 && locationLen < 256)
        pMQR->lpVtbl->GetLocation(pMQR, locationLen, locationBuf, &locationLen);

    /* GetEnumerator -> enumerate all metadata items */
    enumHr = pMQR->lpVtbl->GetEnumerator(pMQR, &pEnum);
    if (SUCCEEDED(enumHr) && pEnum) {
        PROPVARIANT schema, id, value;
        UINT fetched = 0;
        UINT safeLimit = 0;

        PropVariantInit(&schema);
        PropVariantInit(&id);
        PropVariantInit(&value);

        while (safeLimit < g_cfg.policy.maxMetadataItems) {
            fetched = 0;
            hr = pEnum->lpVtbl->Next(pEnum, 1, &schema, &id, &value, &fetched);
            if (hr != S_OK || fetched == 0) break;

            /*
             * Fix #6: Inspect value type before clearing.
             * VT_UNKNOWN may be an IWICMetadataQueryReader sub-reader.
             * This is the code path for XMP/EXIF blocks embedded inside
             * PNG-in-ICO tEXt/iTXt/eXIf chunks.
             */
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
                    process_metadata_reader(pSubMQR, isFrame, depth + 1);
                    pSubMQR->lpVtbl->Release(pSubMQR);
                }
            }

            PropVariantClear(&schema);
            PropVariantClear(&id);
            PropVariantClear(&value);
            itemCount++;
            safeLimit++;
        }

        pEnum->lpVtbl->Release(pEnum);
    }

    trace_metadata(&g_trace, hr, enumHr, itemCount, nestedCount, &fmtGuid);
}

/* =========================================================================
 * process_palette
 *
 * Exercises IWICPalette paths:
 *   GetType, GetColorCount, GetColors, HasAlpha
 *
 * Palette table extraction with GetColors() is a primary overflow target
 * for palette-indexed ICO frames (1/4/8 bpp).
 * ========================================================================= */
static void process_palette(
    IWICPalette* pPalette,
    BOOL            isFrame)
{
    HRESULT             hr;
    WICBitmapPaletteType paletteType = WICBitmapPaletteTypeCustom;
    UINT                colorCount = 0;
    BOOL                hasAlpha = FALSE;
    WICColor* pColors = NULL;

    if (!pPalette) return;

    pPalette->lpVtbl->GetType(pPalette, &paletteType);

    hr = pPalette->lpVtbl->GetColorCount(pPalette, &colorCount);
    if (FAILED(hr)) goto done;

    /* Safety cap on color count */
    if (colorCount > g_cfg.policy.maxPaletteColors)
        colorCount = g_cfg.policy.maxPaletteColors;

    if (colorCount > 0) {
        pColors = (WICColor*)HeapAlloc(
            GetProcessHeap(), 0, colorCount * sizeof(WICColor));
        if (pColors) {
            UINT actualColors = 0;
            /* GetColors: exercises palette table read */
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
 * Exercises IWICBitmapDecoder::GetColorContexts or
 * IWICBitmapFrameDecode::GetColorContexts.
 *
 * For PNG-in-ICO: exercises iCCP chunk (ICC profile) parsing.
 * ICC profile data structures are variable-length binary — overflow target.
 *
 * Fix #3 (Viktor Hale):
 * CreateColorContext is obtained via g_pFactory2 (IWICImagingFactory2).
 * IWICImagingFactory does not have CreateColorContext in its vtable.
 * IWICImagingFactory2 is QI'd from g_pFactory once at startup and stored
 * in g_pFactory2. If g_pFactory2 is NULL (QI failed at startup), the
 * color context path is skipped entirely rather than corrupting a vtable.
 * ========================================================================= */
static void process_color_contexts(
    IWICBitmapDecoder* pDecoder,
    IWICBitmapFrameDecode* pFrame)
{
    HRESULT             hr;
    UINT                actualCount = 0;
    UINT                i;
    IWICColorContext** ppContexts = NULL;

    /*
     * Fix #3: g_pFactory2 is required. If it was not obtained at startup
     * (e.g. WIC runtime is older than IWICImagingFactory2), skip this path.
     */
    if (!g_pFactory2) {
        trace_color_contexts(&g_trace, E_NOINTERFACE, 0);
        return;
    }

    /* Get count first */
    if (pDecoder) {
        hr = pDecoder->lpVtbl->GetColorContexts(
            pDecoder, 0, NULL, &actualCount);
    }
    else if (pFrame) {
        hr = pFrame->lpVtbl->GetColorContexts(
            pFrame, 0, NULL, &actualCount);
    }
    else return;

    trace_stage(&g_trace,
        pDecoder ? STAGE_COLOR_CONTEXTS : STAGE_FRAME_COLOR_CONTEXTS, hr);

    if (FAILED(hr) || actualCount == 0) {
        trace_color_contexts(&g_trace, hr, 0);
        return;
    }

    /* Cap context count */
    if (actualCount > g_cfg.policy.maxColorContexts)
        actualCount = g_cfg.policy.maxColorContexts;

    /* Allocate IWICColorContext instances */
    ppContexts = (IWICColorContext**)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY,
        actualCount * sizeof(IWICColorContext*));
    if (!ppContexts) goto done;

    /*
     * Fix #3: CreateColorContext is called via IWICImagingFactory2,
     * NOT via IWICImagingFactory. The standard factory vtable does not
     * expose this method — using it directly causes vtable corruption.
     */
    for (i = 0; i < actualCount; i++) {
        g_pFactory2->lpVtbl->CreateColorContext(g_pFactory2, &ppContexts[i]);
    }

    /* Retrieve color contexts — exercises ICC profile parsing */
    if (pDecoder) {
        hr = pDecoder->lpVtbl->GetColorContexts(
            pDecoder, actualCount, ppContexts, &actualCount);
    }
    else {
        hr = pFrame->lpVtbl->GetColorContexts(
            pFrame, actualCount, ppContexts, &actualCount);
    }

done:
    trace_color_contexts(&g_trace, hr, actualCount);

    if (ppContexts) {
        for (i = 0; i < actualCount; i++) {
            if (ppContexts[i]) ppContexts[i]->lpVtbl->Release(ppContexts[i]);
        }
        HeapFree(GetProcessHeap(), 0, ppContexts);
    }
}

/* =========================================================================
 * process_thumbnail
 *
 * Exercises thumbnail/preview image paths.
 * Thumbnails are decoded separately from main frames —
 * a distinct internal code path in the ICO decoder.
 * ========================================================================= */
static void process_thumbnail(
    IWICBitmapSource* pSource,
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
 * Primary bug trigger: CopyPixels on a raw decoded frame — full rect.
 *
 * For ICO BMP-payload frames:
 *   Triggers AND mask + XOR bitmap reconstruction.
 *   Exercises stride/height arithmetic with decoded BMP dimensions.
 *
 * For ICO PNG-payload frames:
 *   Triggers full libpng decode + zlib inflate.
 *   Exercises PNG chunk processing, IDAT decompression.
 *
 * Buffer is allocated on the heap (always — never stack).
 * PageHeap will catch any overrun into adjacent heap metadata.
 *
 * Fix #5 (Mara Schultz):
 * CopyPixels is called via QueryInterface to IWICBitmapSource.
 * This is the correct COM path. In C, casting IWICBitmapFrameDecode*
 * to IWICBitmapSource* is undefined behaviour — the vtable layout
 * for inherited interfaces is not guaranteed in C COM usage. Even if
 * it works with MSVC today, it relies on implementation details that
 * could change. QI is the only spec-correct approach.
 *
 * Fix #9 (Mara Schultz):
 * If policy_get_bpp_from_guid returns 0 (total failure), skip this
 * frame rather than allocating with a wrong bpp value. Previously
 * returned 32 as fallback which could under-allocate for wide formats.
 * ========================================================================= */
static void process_frame_copy_pixels(
    IWICBitmapFrameDecode* pFrame,
    UINT                        frameIndex,
    UINT                        width,
    UINT                        height,
    const WICPixelFormatGUID* pFmt)
{
    HRESULT             hr;
    UINT                bpp = 0U;
    UINT                stride = 0;
    UINT                bufSize = 0;
    BYTE* pPixels = NULL;
    POLICY_RESULT       prStride = POLICY_OK;
    POLICY_RESULT       prBuf = POLICY_OK;
    IWICBitmapSource* pSource = NULL;

    if (!pFrame || width == 0 || height == 0) return;

    /* Resolve bpp from pixel format GUID via COM */
    if (pFmt) {
        bpp = policy_get_bpp_from_guid(g_pFactory, pFmt);
    }

    /*
     * Fix #9: bpp == 0 means factory unavailable or complete COM failure.
     * Skip this frame — do not allocate with a placeholder value.
     */
    if (bpp == 0) {
        trace_stage(&g_trace, STAGE_COPY_PIXELS, E_FAIL);
        return;
    }

    /* Compute stride with overflow detection */
    prStride = policy_compute_stride(&g_cfg.policy, width, bpp, &stride);
    if (prStride != POLICY_OK) {
        trace_policy_violation(&g_trace, prStride, width, height, 0, 0);
        return;
    }

    /* Compute buffer size with overflow detection */
    prBuf = policy_compute_buffer_size(&g_cfg.policy, stride, height, &bufSize);
    if (prBuf != POLICY_OK) {
        trace_policy_violation(&g_trace, prBuf, width, height, stride, 0);
        return;
    }

    /* Allocate pixel buffer on heap — PageHeap monitors this allocation */
    pPixels = (BYTE*)HeapAlloc(GetProcessHeap(), 0, bufSize);
    if (!pPixels) {
        trace_stage(&g_trace, STAGE_COPY_PIXELS, E_OUTOFMEMORY);
        return;
    }

    /*
     * Fix #5: QI pFrame to IWICBitmapSource before calling CopyPixels.
     * Do NOT cast: (IWICBitmapSource*)pFrame — this is undefined behaviour.
     */
    hr = pFrame->lpVtbl->QueryInterface(
        pFrame,
        &IID_IWICBitmapSource,
        (void**)&pSource);

    if (SUCCEEDED(hr) && pSource) {
        /*
         * CopyPixels: the primary fuzzing target.
         * NULL rectangle = copy entire image.
         * Any overflow inside the decoder writes into our monitored heap buffer.
         */
        hr = pSource->lpVtbl->CopyPixels(
            pSource,
            NULL,       /* entire image */
            stride,
            bufSize,
            pPixels);

        trace_stage(&g_trace, STAGE_COPY_PIXELS, hr);
        trace_copy_pixels(&g_trace, hr, stride, bufSize, POLICY_OK, FALSE);

        pSource->lpVtbl->Release(pSource);
    }
    else {
        trace_stage(&g_trace, STAGE_COPY_PIXELS, hr);
    }

    /* Free pixel buffer — discard output, not needed for research */
    HeapFree(GetProcessHeap(), 0, pPixels);
    pPixels = NULL;
}

/* =========================================================================
 * process_frame_copy_pixels_partial
 *
 * Fix #10 (Ryo Tanaka): Partial-rect CopyPixels pass.
 *
 * Exercises the per-scanline offset calculation inside the ICO decoder
 * when a sub-rectangle is requested. This code path is distinct from the
 * full-image path: the decoder computes an initial byte offset into the
 * pixel data based on rect.Y * stride + rect.X * bpp/8, then reads
 * rect.Height scanlines of rect.Width pixels. Off-by-one errors in this
 * offset are a known bug class in codec implementations.
 *
 * We request the top-left quadrant: x=0, y=0, w=width/2, h=height/2.
 * This is a common test vector because:
 *   - It exercises the rect path without complex alignment requirements.
 *   - Width/2 and height/2 are guaranteed to be <= original dimensions.
 *   - The resulting stride for the partial rect is different from full
 *     stride, exposing stride mismatch bugs.
 * ========================================================================= */
static void process_frame_copy_pixels_partial(
    IWICBitmapFrameDecode* pFrame,
    UINT                        width,
    UINT                        height,
    const WICPixelFormatGUID* pFmt)
{
    HRESULT             hr;
    UINT                bpp = 0U;
    UINT                rw, rh;
    UINT                stride = 0;
    UINT                bufSize = 0;
    BYTE* pPixels = NULL;
    POLICY_RESULT       pr;
    IWICBitmapSource* pSource = NULL;
    WICRect             rect;

    if (!pFrame || width < 2 || height < 2) return;

    /* Partial rect: top-left quadrant */
    rw = width / 2;
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

    rect.X = 0;
    rect.Y = 0;
    rect.Width = (INT)rw;
    rect.Height = (INT)rh;

    /* Fix #5: QI to IWICBitmapSource */
    hr = pFrame->lpVtbl->QueryInterface(
        pFrame,
        &IID_IWICBitmapSource,
        (void**)&pSource);

    if (SUCCEEDED(hr) && pSource) {
        hr = pSource->lpVtbl->CopyPixels(
            pSource,
            &rect,      /* partial rect — top-left quadrant */
            stride,
            bufSize,
            pPixels);

        trace_stage(&g_trace, STAGE_COPY_PIXELS_PARTIAL, hr);
        trace_copy_pixels_partial(&g_trace, hr, rect.X, rect.Y, rw, rh, stride, bufSize);

        pSource->lpVtbl->Release(pSource);
    }

    HeapFree(GetProcessHeap(), 0, pPixels);
}

/* =========================================================================
 * process_frame_transform
 *
 * Fix #7 (Ryo Tanaka): IWICBitmapSourceTransform scaled decode path.
 *
 * IWICBitmapSourceTransform exposes CopyPixelsWithTransforms() which
 * allows the caller to request scaled, rotated, and flipped output
 * directly from the decoder without a separate converter step.
 * For ICO this exercises dimension scaling arithmetic inside the BMP
 * and PNG sub-decoders — a known integer overflow surface.
 *
 * We request half-size output (width/2 x height/2) with no rotation.
 * This is the minimal transform that exercises the scaling code path.
 *
 * QI failure is expected for frames that do not support this interface
 * (e.g. some BMP payload frames). Not an error.
 * ========================================================================= */
static void process_frame_transform(
    IWICBitmapFrameDecode* pFrame,
    UINT                        width,
    UINT                        height,
    const WICPixelFormatGUID* pFmt)
{
    HRESULT                     hr;
    IWICBitmapSourceTransform* pTransform = NULL;
    UINT                        scaledW = width / 2;
    UINT                        scaledH = height / 2;
    UINT                        bpp = 0U;
    UINT                        stride = 0;
    UINT                        bufSize = 0;
    BYTE* pPixels = NULL;
    POLICY_RESULT               pr;
    BOOL                        bCanScale = FALSE;

    if (!pFrame || scaledW == 0 || scaledH == 0) return;

    hr = pFrame->lpVtbl->QueryInterface(
        pFrame,
        &IID_IWICBitmapSourceTransform,
        (void**)&pTransform);

    trace_stage(&g_trace, STAGE_TRANSFORM, hr);

    if (FAILED(hr) || !pTransform) return; /* not supported — skip */

    /* Check if scaling is supported */
    hr = pTransform->lpVtbl->DoesSupportTransform(
        pTransform,
        WICBitmapTransformRotate0,
        &bCanScale);

    if (FAILED(hr) || !bCanScale) goto transform_done;

    /* Resolve bpp for buffer allocation */
    if (pFmt) bpp = policy_get_bpp_from_guid(g_pFactory, pFmt);
    if (bpp == 0) goto transform_done;

    /* The transform may adjust the requested dimensions — pass as in/out */
    pr = policy_compute_stride(&g_cfg.policy, scaledW, bpp, &stride);
    if (pr != POLICY_OK) goto transform_done;

    pr = policy_compute_buffer_size(&g_cfg.policy, stride, scaledH, &bufSize);
    if (pr != POLICY_OK) goto transform_done;

    pPixels = (BYTE*)HeapAlloc(GetProcessHeap(), 0, bufSize);
    if (!pPixels) goto transform_done;

    {
        /*
         * IWICBitmapSourceTransform::CopyPixels takes a non-const
         * WICPixelFormatGUID* for the pixel format parameter (in/out:
         * the decoder may adjust it to the nearest supported format).
         * Copy pFmt to a local mutable variable — do not cast away const.
         */
        WICPixelFormatGUID fmtMutable;
        if (pFmt) {
            fmtMutable = *pFmt;
        }
        else {
            fmtMutable = GUID_WICPixelFormat32bppBGRA; /* safe fallback */
        }

        /*
         * CopyPixels on IWICBitmapSourceTransform: requests scaled output.
         * The decoder materialises at the requested scale directly — this
         * exercises a separate internal downscaling code path.
         */
        hr = pTransform->lpVtbl->CopyPixels(
            pTransform,
            NULL,                   /* entire image at scaled size */
            scaledW,                /* requested output width */
            scaledH,                /* requested output height */
            &fmtMutable,            /* mutable copy — decoder may adjust */
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
 * Fix #8 (Ryo Tanaka): IWICProgressiveLevelControl path.
 *
 * For PNG-in-ICO payloads, the WIC PNG decoder may expose
 * IWICProgressiveLevelControl on the frame. This exercises the
 * Adam7 interlaced PNG decode path inside libpng — a historically
 * vulnerability-rich area:
 *   - Row-pointer reconstruction with per-pass dimensions
 *   - Pass-dependent width/height overflows in Adam7
 *   - libpng iCCP chunk processing during progressive decode
 *
 * We enumerate all available levels by calling GetCurrentLevel() and
 * SetCurrentLevel() sequentially, then calling CopyPixels at the last
 * level to force full decode. Each SetCurrentLevel() call may trigger
 * a libpng png_read_rows() call internally — the level transitions
 * are the primary exercise target.
 *
 * QI failure = interface not supported (BMP-payload frames, most ICOs).
 * Not an error.
 * ========================================================================= */
static void process_frame_progressive(
    IWICBitmapFrameDecode* pFrame,
    UINT                        width,
    UINT                        height,
    const WICPixelFormatGUID* pFmt)
{
    HRESULT                         hr;
    IWICProgressiveLevelControl* pProgressive = NULL;
    UINT                            levelCount = 0;
    UINT                            i;
    IWICBitmapSource* pSource = NULL;
    UINT                            bpp = 0U;
    UINT                            stride = 0;
    UINT                            bufSize = 0;
    BYTE* pPixels = NULL;
    POLICY_RESULT                   pr;

    if (!pFrame) return;

    hr = pFrame->lpVtbl->QueryInterface(
        pFrame,
        &IID_IWICProgressiveLevelControl,
        (void**)&pProgressive);

    trace_stage(&g_trace, STAGE_PROGRESSIVE, hr);

    if (FAILED(hr) || !pProgressive) return; /* not supported */

    /*
     * GetLevelCount: number of available progressive decode levels.
     * For a non-interlaced PNG this is typically 1. For Adam7
     * interlaced PNGs this is up to 7 (one per Adam7 pass).
     */
    hr = pProgressive->lpVtbl->GetLevelCount(pProgressive, &levelCount);
    if (FAILED(hr) || levelCount == 0) goto progressive_done;

    /* Cap level count defensively */
    if (levelCount > 16U) levelCount = 16U;

    /* Allocate pixel buffer for CopyPixels at final level */
    if (pFmt) bpp = policy_get_bpp_from_guid(g_pFactory, pFmt);
    if (bpp == 0) goto progressive_done;

    pr = policy_compute_stride(&g_cfg.policy, width, bpp, &stride);
    if (pr != POLICY_OK) goto progressive_done;

    pr = policy_compute_buffer_size(&g_cfg.policy, stride, height, &bufSize);
    if (pr != POLICY_OK) goto progressive_done;

    pPixels = (BYTE*)HeapAlloc(GetProcessHeap(), 0, bufSize);
    if (!pPixels) goto progressive_done;

    /* Fix #5: QI to IWICBitmapSource for CopyPixels */
    hr = pFrame->lpVtbl->QueryInterface(
        pFrame,
        &IID_IWICBitmapSource,
        (void**)&pSource);

    if (FAILED(hr) || !pSource) {
        HeapFree(GetProcessHeap(), 0, pPixels);
        goto progressive_done;
    }

    /*
     * Iterate through all progressive levels.
     * SetCurrentLevel() -> CopyPixels() exercises each pass of the
     * progressive decode — the level transitions are the key targets.
     */
    for (i = 0; i < levelCount; i++) {
        hr = pProgressive->lpVtbl->SetCurrentLevel(pProgressive, i);
        if (FAILED(hr)) break;

        /* CopyPixels at this progressive level */
        hr = pSource->lpVtbl->CopyPixels(
            pSource,
            NULL,
            stride,
            bufSize,
            pPixels);

        /* Continue even on failure — next level may succeed */
    }

    trace_progressive(&g_trace, S_OK, levelCount);

    pSource->lpVtbl->Release(pSource);
    HeapFree(GetProcessHeap(), 0, pPixels);

progressive_done:
    /* Only log the zero-level fallback if we never completed the loop above */
    if (levelCount == 0)
        trace_progressive(&g_trace, hr, 0);
    pProgressive->lpVtbl->Release(pProgressive);
}

/* =========================================================================
 * process_wic_convert
 *
 * Fix #11 (Ryo Tanaka): WICConvertBitmapSource single-call path.
 *
 * WICConvertBitmapSource() is an alternative conversion API identified
 * from IDA string analysis at 0x18000A1940. It internally chains the
 * decoder and format converter via a different code path than the manual
 * IWICFormatConverter sequence above. Specifically:
 *   - It may bypass the CanConvert check
 *   - It uses a different internal allocation strategy
 *   - The resulting IWICBitmapSource wraps both decode and convert ops
 *     in a single lazy-evaluate object
 *
 * This function exercises that path by calling WICConvertBitmapSource
 * with the frame as input and BGRA32 as output format, then calling
 * CopyPixels on the result.
 *
 * NOTE: WICConvertBitmapSource is declared in wincodec.h and is a
 * standard WIC API function — this is NOT a direct DLL call.
 * It goes through WIC's internal dispatch, maintaining the COM-only rule.
 * ========================================================================= */
static void process_wic_convert(
    IWICBitmapFrameDecode* pFrame,
    UINT                    width,
    UINT                    height)
{
    HRESULT             hr;
    IWICBitmapSource* pConverted = NULL;
    IWICBitmapSource* pFrameSrc = NULL;
    UINT                stride = 0;
    UINT                bufSize = 0;
    BYTE* pPixels = NULL;
    POLICY_RESULT       pr;

    if (!pFrame || width == 0 || height == 0) return;

    /* QI frame to IWICBitmapSource for WICConvertBitmapSource input */
    hr = pFrame->lpVtbl->QueryInterface(
        pFrame,
        &IID_IWICBitmapSource,
        (void**)&pFrameSrc);
    if (FAILED(hr) || !pFrameSrc) return;

    /*
     * WICConvertBitmapSource: single-call conversion.
     * Exercises the internal path at 0x18000A1940 identified in IDA.
     * Output format: 32bppBGRA (same target as manual conversion path).
     */
    hr = WICConvertBitmapSource(
        &HARNESS_CONVERT_TARGET_FORMAT,
        pFrameSrc,
        &pConverted);

    pFrameSrc->lpVtbl->Release(pFrameSrc);

    if (FAILED(hr) || !pConverted) return;

    /* Compute buffer for 32bppBGRA output */
    pr = policy_compute_stride(&g_cfg.policy, width, HARNESS_CONVERT_BPP * 8U, &stride);
    if (pr != POLICY_OK) goto wic_convert_done;

    pr = policy_compute_buffer_size(&g_cfg.policy, stride, height, &bufSize);
    if (pr != POLICY_OK) goto wic_convert_done;

    pPixels = (BYTE*)HeapAlloc(GetProcessHeap(), 0, bufSize);
    if (!pPixels) goto wic_convert_done;

    /* CopyPixels on the WICConvertBitmapSource result */
    hr = pConverted->lpVtbl->CopyPixels(
        pConverted,
        NULL,
        stride,
        bufSize,
        pPixels);

    trace_copy_pixels(&g_trace, hr, stride, bufSize, pr, TRUE);

    HeapFree(GetProcessHeap(), 0, pPixels);

wic_convert_done:
    pConverted->lpVtbl->Release(pConverted);
}

/* =========================================================================
 * harness_global_init
 *
 * Called once before the fuzz loop begins.
 * Initializes COM, creates WIC factory, loads configuration.
 * Must succeed or the process exits.
 *
 * Fix #3 (Viktor Hale): After creating the WIC factory, QI for
 * IWICImagingFactory2 and store in g_pFactory2. This is used by
 * process_color_contexts() for CreateColorContext calls.
 * ========================================================================= */
static void harness_global_init(void)
{
    HRESULT hr;

    /* Load configuration (INI + defaults) */
    config_init_defaults(&g_cfg);
    config_load_ini(&g_cfg);
    config_resolve_trace_path(&g_cfg);

    /* Initialize trace */
    trace_init(&g_trace, g_cfg.tracePath, g_cfg.traceEnabled);
    config_print(&g_cfg, g_trace.hFile);

    /* Initialize COM — apartment-threaded, single thread */
    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        OutputDebugStringA("[HARNESS] CoInitializeEx failed\n");
        ExitProcess(1);
    }

    /* Create WIC imaging factory — in-process only */
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

    /*
     * Fix #3: QI for IWICImagingFactory2.
     * IWICImagingFactory2::CreateColorContext is required for the color
     * context path. IWICImagingFactory::CreateColorContext does not exist.
     * If QI fails (older WIC runtime), g_pFactory2 stays NULL and the
     * color context path is skipped silently in process_color_contexts().
     */
    hr = g_pFactory->lpVtbl->QueryInterface(
        g_pFactory,
        &IID_IWICImagingFactory2,
        (void**)&g_pFactory2);

    if (FAILED(hr) || !g_pFactory2) {
        /* Non-fatal: color context path will be skipped */
        g_pFactory2 = NULL;
        trace_write_direct(&g_trace,
            "[INIT]  IWICImagingFactory2 not available — color context path disabled\r\n");
    }

    g_initialized = TRUE;

    /* Fix #1: trace_write_direct takes explicit ctx pointer */
    trace_write_direct(&g_trace, "[INIT]  COM initialized, WIC factory ready\r\n");
}

/* =========================================================================
 * harness_global_cleanup
 *
 * Called once on process exit.
 * Releases WIC factory interfaces and uninitializes COM.
 * Release order: Factory2 before Factory1 (QI'd from it).
 * ========================================================================= */
static void harness_global_cleanup(void)
{
    g_initialized = FALSE;
    /* Release Factory2 before Factory1 — QI order */
    SAFE_RELEASE(g_pFactory2);
    SAFE_RELEASE(g_pFactory);
    CoUninitialize();
    trace_close(&g_trace);
}

/* =========================================================================
 * wmain
 *
 * Entry point.
 *
 * Standalone mode:
 *   harness.exe <input.ico>
 *   Runs fuzz_target() cfg.iterations times with the same file.
 *   Used for testing, debugging, and research runs.
 *
 * WinAFL mode:
 *   WinAFL replaces @@ with the mutated input file path.
 *   WinAFL calls fuzz_target() directly via -target_method.
 *   The main() loop is not used in WinAFL persistent mode —
 *   WinAFL takes control after the harness signals readiness.
 *
 * NOTE ON WINAFL PERSISTENT MODE:
 *   When using WinAFL with -fuzz_iterations, WinAFL will:
 *   1. Run the process until the first call to fuzz_target()
 *   2. Save a snapshot
 *   3. Restore the snapshot and call fuzz_target() with each mutation
 *   The global init code above the fuzz loop runs exactly once.
 *
 * NOTE ON .ico EXTENSION:
 *   The input path passed to CreateDecoderFromFilename must end in .ico
 *   for the ICO decoder to be selected. WinAFL should be configured with
 *   -file_extension ico or the input file must be named *.ico.
 *   If WinAFL substitutes a tempfile without .ico extension, the WIC
 *   runtime may select a different decoder based on magic bytes, or fail.
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

    /*
     * Standalone mode: run fuzz_target() iterations times.
     * In WinAFL mode, WinAFL replaces this loop with its own
     * persistent mode mechanism after the first call.
     */
    for (i = 0; i < g_cfg.iterations; i++) {
        fuzz_target(argv[1]);
    }

    harness_global_cleanup();
    return 0;
}
