/*
 * trace.c
 *
 * Trace and instrumentation module implementation.
 * Security-relevant data logging for vulnerability research.
 */

#include <windows.h>
#include <wincodec.h>
#include <stdio.h>
#include <strsafe.h>
#include "trace.h"
#include "config.h"

/* =========================================================================
 * Internal helpers
 * ========================================================================= */
static void trace_reset_hr_summary(HARNESS_TRACE_CTX* ctx)
{
    if (!ctx)
        return;

    ZeroMemory(ctx->hrClassCounts, sizeof(ctx->hrClassCounts));
}

static const char* machine_to_string(WORD machine)
{
    switch (machine) {
    case IMAGE_FILE_MACHINE_I386:  return "x86";
    case IMAGE_FILE_MACHINE_AMD64: return "x64";
    case IMAGE_FILE_MACHINE_ARM64: return "arm64";
    case IMAGE_FILE_MACHINE_ARMNT: return "arm";
    case IMAGE_FILE_MACHINE_UNKNOWN:
    default:
        return "unknown";
    }
}

static void trace_write(HARNESS_TRACE_CTX* ctx, const char* fmt, ...)
{
    char    buf[1024];
    va_list args;
    DWORD   written;

    if (!ctx || !ctx->enabled || ctx->hFile == INVALID_HANDLE_VALUE)
        return;

    va_start(args, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, args);
    va_end(args);

    WriteFile(ctx->hFile, buf, (DWORD)strlen(buf), &written, NULL);
}

static void guid_to_string(const GUID* pGuid, char* buf, size_t bufLen)
{
    if (!pGuid || !buf) return;
    _snprintf_s(buf, bufLen, _TRUNCATE,
        "{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
        pGuid->Data1, pGuid->Data2, pGuid->Data3,
        pGuid->Data4[0], pGuid->Data4[1],
        pGuid->Data4[2], pGuid->Data4[3],
        pGuid->Data4[4], pGuid->Data4[5],
        pGuid->Data4[6], pGuid->Data4[7]);
}

static void trace_hr_summary(HARNESS_TRACE_CTX* ctx)
{
    if (!ctx || !ctx->enabled)
        return;

    trace_write(ctx,
        "[HRSUMMARY] success=%u unsupported=%u no_data=%u parser_reject=%u resource_limit=%u unexpected=%u\r\n",
        ctx->hrClassCounts[HRCLS_SUCCESS],
        ctx->hrClassCounts[HRCLS_UNSUPPORTED_EXPECTED],
        ctx->hrClassCounts[HRCLS_NO_DATA_EXPECTED],
        ctx->hrClassCounts[HRCLS_PARSER_REJECT],
        ctx->hrClassCounts[HRCLS_RESOURCE_LIMIT],
        ctx->hrClassCounts[HRCLS_UNEXPECTED_FAILURE]);
}


static const char* trace_hresult_class_to_string(HRESULT_CLASSIFICATION cls)
{
    switch (cls) {
    case HRCLS_SUCCESS:
        return "SUCCESS";
    case HRCLS_UNSUPPORTED_EXPECTED:
        return "UNSUPPORTED_EXPECTED";
    case HRCLS_NO_DATA_EXPECTED:
        return "NO_DATA_EXPECTED";
    case HRCLS_PARSER_REJECT:
        return "PARSER_REJECT";
    case HRCLS_RESOURCE_LIMIT:
        return "RESOURCE_LIMIT";
    case HRCLS_UNEXPECTED_FAILURE:
    default:
        return "UNEXPECTED_FAILURE";
    }
}


static HRESULT_CLASSIFICATION trace_classify_hresult(TRIAGE_STAGE stage, HRESULT hr)
{
    if (SUCCEEDED(hr))
        return HRCLS_SUCCESS;

    /*
     * Generic COM / Win32 resource failures.
     */
    if (hr == E_OUTOFMEMORY ||
        hr == HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_MEMORY) ||
        hr == HRESULT_FROM_WIN32(ERROR_OUTOFMEMORY))
    {
        return HRCLS_RESOURCE_LIMIT;
    }

    /*
     * Unsupported interface / unsupported operation.
     */
    if (hr == E_NOINTERFACE ||
        hr == WINCODEC_ERR_UNSUPPORTEDOPERATION)
    {
        return HRCLS_UNSUPPORTED_EXPECTED;
    }

    /*
     * Stage-specific expected "no data" cases.
     */
    switch (stage) {
    case STAGE_CONTAINER_METADATA:
    case STAGE_FRAME_METADATA:
    case STAGE_COLOR_CONTEXTS:
    case STAGE_PREVIEW:
    case STAGE_THUMBNAIL_CONTAINER:
    case STAGE_FRAME_COLOR_CONTEXTS:
    case STAGE_FRAME_THUMBNAIL:
        if (hr == WINCODEC_ERR_PROPERTYNOTFOUND ||
            hr == WINCODEC_ERR_CODECNOTHUMBNAIL ||
            hr == WINCODEC_ERR_PALETTEUNAVAILABLE ||
            hr == WINCODEC_ERR_UNSUPPORTEDOPERATION)
        {
            return HRCLS_NO_DATA_EXPECTED;
        }
        break;

    case STAGE_TRANSFORM:
        if (hr == E_NOINTERFACE ||
            hr == WINCODEC_ERR_UNSUPPORTEDOPERATION)
        {
            return HRCLS_UNSUPPORTED_EXPECTED;
        }
        break;

    default:
        break;
    }

    /*
     * Parser/content rejection cases.
     * These are interesting in malformed corpus analysis.
     */
    if (hr == WINCODEC_ERR_BADHEADER ||
        hr == WINCODEC_ERR_BADIMAGE ||
        hr == WINCODEC_ERR_BADSTREAMDATA ||
        hr == WINCODEC_ERR_STREAMREAD ||
        hr == WINCODEC_ERR_STREAMWRITE ||
        hr == WINCODEC_ERR_STREAMNOTAVAILABLE ||
        hr == WINCODEC_ERR_COMPONENTNOTFOUND ||
        hr == WINCODEC_ERR_IMAGESIZEOUTOFRANGE ||
        hr == WINCODEC_ERR_TOOMUCHMETADATA ||
        hr == WINCODEC_ERR_INVALIDQUERYREQUEST ||
        hr == WINCODEC_ERR_UNEXPECTEDSIZE ||
        hr == WINCODEC_ERR_INVALIDJPEGSCANINDEX)
    {
        return HRCLS_PARSER_REJECT;
    }

    /*
     * Invalid-parameter style failures: often useful as parser/control-flow signal.
     * Keep them as unexpected by default unless you later want a dedicated class.
     */
    if (hr == E_INVALIDARG ||
        hr == HRESULT_FROM_WIN32(ERROR_INVALID_DATA) ||
        hr == HRESULT_FROM_WIN32(ERROR_ARITHMETIC_OVERFLOW))
    {
        return HRCLS_UNEXPECTED_FAILURE;
    }

    return HRCLS_UNEXPECTED_FAILURE;
}

/* =========================================================================
 * trace_init
 * ========================================================================= */
BOOL trace_init(
    HARNESS_TRACE_CTX*  ctx,
    const WCHAR*        path,
    BOOL                enabled)
{
    if (!ctx) return FALSE;

    ZeroMemory(ctx, sizeof(*ctx));
    ctx->hFile          = INVALID_HANDLE_VALUE;
    ctx->lastStage      = STAGE_NONE;
    ctx->currentIteration = 0;
    ctx->currentFrame   = HARNESS_NO_FRAME;

#ifdef HARNESS_MODE_RESEARCH
    ctx->enabled = TRUE;    /* research mode: trace always active */
#else
    ctx->enabled = enabled;
#endif

    if (!ctx->enabled) return TRUE;

    StringCchCopyW(ctx->path, HARNESS_TRACE_PATH_MAX, path);

    ctx->hFile = CreateFileW(
        path,
        GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (ctx->hFile == INVALID_HANDLE_VALUE) {
        ctx->enabled = FALSE;
        return FALSE;
    }

    trace_write(ctx,
        "==========================================================\r\n"
        " WIC ICO Fuzzing Harness -- Trace File\r\n"
        " Target: windowscodecs.dll\r\n"
        " Build mode: %s\r\n"
        "==========================================================\r\n\r\n",
#ifdef HARNESS_MODE_RESEARCH
        "RESEARCH"
#else
        "FUZZ"
#endif
    );

    return TRUE;
}

/* =========================================================================
 * trace_close
 * ========================================================================= */
void trace_close(HARNESS_TRACE_CTX* ctx)
{
    if (!ctx) return;
    if (ctx->hFile != INVALID_HANDLE_VALUE) {
        trace_write(ctx, "\r\n[EOF]\r\n");
        FlushFileBuffers(ctx->hFile);
        CloseHandle(ctx->hFile);
        ctx->hFile = INVALID_HANDLE_VALUE;
    }
}

/* =========================================================================
 * trace_iteration_begin
 * ========================================================================= */
void trace_iteration_begin(
    HARNESS_TRACE_CTX*  ctx,
    UINT                iteration,
    const WCHAR*        filePath)
{
    if (!ctx || !ctx->enabled) return;
    ctx->currentIteration = iteration;
    ctx->lastStage        = STAGE_NONE;
    ctx->currentFrame     = HARNESS_NO_FRAME;

    trace_reset_hr_summary(ctx);

    trace_write(ctx,
        "----------------------------------------------------------\r\n"
        "[ITER] %u\r\n"
        "[FILE] %ws\r\n",
        iteration,
        filePath ? filePath : L"(null)");
}

/* =========================================================================
 * trace_iteration_end
 *
 * FlushFileBuffers guarantees the last complete [ITER]/[FILE] block is
 * on disk before a crash, enabling direct crash-input correlation.
 * ========================================================================= */
void trace_iteration_end(
    HARNESS_TRACE_CTX*  ctx,
    UINT                framesProcessed,
    UINT                framesSkipped)
{
    if (!ctx || !ctx->enabled) return;

   trace_hr_summary(ctx);

    trace_write(ctx,
        "[DONE] frames_processed=%u frames_skipped=%u\r\n",
        framesProcessed, framesSkipped);

    if (ctx->hFile != INVALID_HANDLE_VALUE)
        FlushFileBuffers(ctx->hFile);
}

/* =========================================================================
 * trace_stage
 *
 * Includes the current frame index in every [STAGE] line.
 * Container-level operations (currentFrame == HARNESS_NO_FRAME) printed
 * as frame=--.
 * ========================================================================= */
void trace_stage(
    HARNESS_TRACE_CTX* ctx,
    TRIAGE_STAGE        stage,
    HRESULT             hr)
{
    HRESULT_CLASSIFICATION cls;
    const char* classStr;

    if (!ctx || !ctx->enabled)
        return;

    ctx->lastStage = stage;

    cls = trace_classify_hresult(stage, hr);
    classStr = trace_hresult_class_to_string(cls);

    if ((unsigned)cls < HRCLS_COUNT) {
        ctx->hrClassCounts[cls]++;
    }

    if (ctx->currentFrame == HARNESS_NO_FRAME) {
        if (SUCCEEDED(hr)) {
            trace_write(ctx,
                "[STAGE] frame=-- %-28s hr=0x%08X OK\r\n",
                trace_stage_string(stage),
                (unsigned)hr);
        }
        else {
            trace_write(ctx,
                "[STAGE] frame=-- %-28s hr=0x%08X FAILED %s\r\n",
                trace_stage_string(stage),
                (unsigned)hr,
                classStr);
        }
    }
    else {
        if (SUCCEEDED(hr)) {
            trace_write(ctx,
                "[STAGE] frame=%-2u %-28s hr=0x%08X OK\r\n",
                ctx->currentFrame,
                trace_stage_string(stage),
                (unsigned)hr);
        }
        else {
            trace_write(ctx,
                "[STAGE] frame=%-2u %-28s hr=0x%08X FAILED %s\r\n",
                ctx->currentFrame,
                trace_stage_string(stage),
                (unsigned)hr,
                classStr);
        }
    }
}





/* =========================================================================
 * trace_decoder_capabilities
 * ========================================================================= */
void trace_decoder_capabilities(
    HARNESS_TRACE_CTX*  ctx,
    HRESULT             hr,
    DWORD               capabilities)
{
    trace_write(ctx,
        "[CAP]  hr=0x%08X capabilities=0x%08X"
        " [same_encoder=%d decode_all=%d decode_some=%d metadata=%d thumbnail=%d]\r\n",
        (unsigned)hr,
        (unsigned)capabilities,
        (capabilities & WICBitmapDecoderCapabilitySameEncoder)         ? 1 : 0,
        (capabilities & WICBitmapDecoderCapabilityCanDecodeAllImages)  ? 1 : 0,
        (capabilities & WICBitmapDecoderCapabilityCanDecodeSomeImages) ? 1 : 0,
        (capabilities & WICBitmapDecoderCapabilityCanEnumerateMetadata)? 1 : 0,
        (capabilities & WICBitmapDecoderCapabilityCanDecodeThumbnail)  ? 1 : 0);
}

/* =========================================================================
 * trace_container_format
 * ========================================================================= */
void trace_container_format(
    HARNESS_TRACE_CTX*  ctx,
    HRESULT             hr,
    const GUID*         pContainerFormat)
{
    char guidStr[64] = "(null)";
    if (pContainerFormat) guid_to_string(pContainerFormat, guidStr, sizeof(guidStr));
    trace_write(ctx,
        "[FMT]  hr=0x%08X container=%s\r\n",
        (unsigned)hr, guidStr);
}

/* =========================================================================
 * trace_frame_count
 * ========================================================================= */
void trace_frame_count(
    HARNESS_TRACE_CTX*  ctx,
    HRESULT             hr,
    UINT                frameCount,
    UINT                cappedCount)
{
    trace_write(ctx,
        "[FCNT] hr=0x%08X frame_count=%u capped=%u\r\n",
        (unsigned)hr, frameCount, cappedCount);
}

/* =========================================================================
 * trace_frame_begin
 * Sets ctx->currentFrame so subsequent trace_stage calls include the index.
 * ========================================================================= */
void trace_frame_begin(
    HARNESS_TRACE_CTX*  ctx,
    UINT                frameIndex)
{
    if (!ctx) return;
    ctx->currentFrame = frameIndex;
    trace_write(ctx, "  [FRAME] index=%u\r\n", frameIndex);
}

/* =========================================================================
 * trace_frame_budget
 *
 * Log the budget decision produced by policy_select_budget() for this frame.
 * This line appears immediately after [FRAME] index= so triage can
 * identify which decode paths were active for any given frame.
 *
 * BUDGET_METADATA_ONLY means CopyPixels was NOT called -- the crash happened
 * during a cheap path.  BUDGET_FULL means CopyPixels was active.
 * ========================================================================= */
void trace_frame_budget(
    HARNESS_TRACE_CTX*  ctx,
    FRAME_BUDGET        budget,
    UINT                width,
    UINT                height,
    UINT                estStride,
    UINT                estBuffer)
{
    if (!ctx || !ctx->enabled) return;
    trace_write(ctx,
        "  [BUDGET] %s width=%u height=%u est_stride=%u est_buf=%u\r\n",
        policy_budget_string(budget),
        width, height, estStride, estBuffer);
}

/* =========================================================================
 * trace_frame_size
 * ========================================================================= */
void trace_frame_size(
    HARNESS_TRACE_CTX*  ctx,
    HRESULT             hr,
    UINT                width,
    UINT                height)
{
    trace_write(ctx,
        "  [SIZE]  hr=0x%08X width=%u height=%u\r\n",
        (unsigned)hr, width, height);
}

/* =========================================================================
 * trace_frame_pixel_format
 * ========================================================================= */
void trace_frame_pixel_format(
    HARNESS_TRACE_CTX*  ctx,
    HRESULT             hr,
    const GUID*         pFmt,
    UINT                bpp)
{
    char guidStr[64] = "(null)";
    if (pFmt) guid_to_string(pFmt, guidStr, sizeof(guidStr));
    trace_write(ctx,
        "  [PFMT]  hr=0x%08X fmt=%s bpp=%u\r\n",
        (unsigned)hr, guidStr, bpp);
}

/* =========================================================================
 * trace_frame_resolution
 * ========================================================================= */
void trace_frame_resolution(
    HARNESS_TRACE_CTX*  ctx,
    HRESULT             hr,
    double              dpiX,
    double              dpiY)
{
    trace_write(ctx,
        "  [RES]   hr=0x%08X dpiX=%.2f dpiY=%.2f\r\n",
        (unsigned)hr, dpiX, dpiY);
}

/* =========================================================================
 * trace_palette
 * ========================================================================= */
void trace_palette(
    HARNESS_TRACE_CTX*  ctx,
    HRESULT             hr,
    UINT                colorCount,
    BOOL                hasAlpha,
    WICBitmapPaletteType paletteType)
{
    trace_write(ctx,
        "  [PAL]   hr=0x%08X color_count=%u has_alpha=%d palette_type=%d\r\n",
        (unsigned)hr, colorCount, hasAlpha, (int)paletteType);
}

/* =========================================================================
 * trace_color_contexts
 * ========================================================================= */
void trace_color_contexts(
    HARNESS_TRACE_CTX*  ctx,
    HRESULT             hr,
    UINT                contextCount)
{
    trace_write(ctx,
        "  [ICC]   hr=0x%08X color_context_count=%u\r\n",
        (unsigned)hr, contextCount);
}

/* =========================================================================
 * trace_metadata
 * nestedCount: VT_UNKNOWN items that were themselves IWICMetadataQueryReader
 * objects (XMP/EXIF nesting inside PNG-in-ICO chunks).
 * ========================================================================= */
void trace_metadata(
    HARNESS_TRACE_CTX*  ctx,
    HRESULT             hr,
    HRESULT             enumHr,
    UINT                itemCount,
    UINT                nestedCount,
    const GUID*         pContainerFmt)
{
    char guidStr[64] = "(null)";
    if (pContainerFmt) guid_to_string(pContainerFmt, guidStr, sizeof(guidStr));
    trace_write(ctx,
        "  [META]  hr=0x%08X enum_hr=0x%08X item_count=%u nested_readers=%u container_fmt=%s\r\n",
        (unsigned)hr, (unsigned)enumHr, itemCount, nestedCount, guidStr);
}

/* =========================================================================
 * trace_thumbnail
 * ========================================================================= */
void trace_thumbnail(
    HARNESS_TRACE_CTX*  ctx,
    HRESULT             hr,
    UINT                width,
    UINT                height)
{
    trace_write(ctx,
        "  [THUMB] hr=0x%08X width=%u height=%u\r\n",
        (unsigned)hr, width, height);
}

/* =========================================================================
 * trace_copy_pixels
 * ========================================================================= */
void trace_copy_pixels(
    HARNESS_TRACE_CTX*  ctx,
    HRESULT             hr,
    UINT                stride,
    UINT                bufferSize,
    POLICY_RESULT       policyResult,
    BOOL                isConverted)
{
    trace_write(ctx,
        "  [CPX]   hr=0x%08X stride=%u buf_size=%u policy=%s converted=%d\r\n",
        (unsigned)hr, stride, bufferSize,
        policy_result_string(policyResult),
        isConverted ? 1 : 0);
}

/* =========================================================================
 * trace_copy_pixels_partial
 * ========================================================================= */
void trace_copy_pixels_partial(
    HARNESS_TRACE_CTX*  ctx,
    HRESULT             hr,
    UINT                rectX,
    UINT                rectY,
    UINT                rectW,
    UINT                rectH,
    UINT                stride,
    UINT                bufferSize)
{
    trace_write(ctx,
        "  [CPXP]  hr=0x%08X rect=[%u,%u,%u,%u] stride=%u buf_size=%u\r\n",
        (unsigned)hr, rectX, rectY, rectW, rectH, stride, bufferSize);
}

/* =========================================================================
 * trace_transform
 * ========================================================================= */
void trace_transform(
    HARNESS_TRACE_CTX*  ctx,
    HRESULT             hr,
    UINT                scaledW,
    UINT                scaledH)
{
    trace_write(ctx,
        "  [XFRM]  hr=0x%08X scaled_w=%u scaled_h=%u\r\n",
        (unsigned)hr, scaledW, scaledH);
}

/* =========================================================================
 * trace_progressive
 * ========================================================================= */
void trace_progressive(
    HARNESS_TRACE_CTX*  ctx,
    HRESULT             hr,
    UINT                levelCount)
{
    trace_write(ctx,
        "  [PROG]  hr=0x%08X level_count=%u\r\n",
        (unsigned)hr, levelCount);
}

/* =========================================================================
 * trace_oob_frame
 * ========================================================================= */
void trace_oob_frame(
    HARNESS_TRACE_CTX*  ctx,
    UINT                frameCount,
    HRESULT             hrAtCount,
    HRESULT             hrAt0xFFFF,
    HRESULT             hrAtUintMax,
    HRESULT             hrAtHigh)
{
    trace_write(ctx,
        "[OOB]  frame_count=%u"
        " hr_at_count=0x%08X hr_at_0xFFFF=0x%08X"
        " hr_at_UINT_MAX=0x%08X hr_at_0x80000000=0x%08X"
        " [count_ok=%d ffff_ok=%d umax_ok=%d high_ok=%d]\r\n",
        frameCount,
        (unsigned)hrAtCount,
        (unsigned)hrAt0xFFFF,
        (unsigned)hrAtUintMax,
        (unsigned)hrAtHigh,
        FAILED(hrAtCount)   ? 1 : 0,
        FAILED(hrAt0xFFFF)  ? 1 : 0,
        FAILED(hrAtUintMax) ? 1 : 0,
        FAILED(hrAtHigh)    ? 1 : 0);
}

/* =========================================================================
 * trace_policy_violation
 *
 * Called when policy_select_budget returns BUDGET_METADATA_ONLY.
 * Logs the reason so triage knows which arithmetic check triggered.
 * ========================================================================= */
void trace_policy_violation(
    HARNESS_TRACE_CTX*  ctx,
    POLICY_RESULT       result,
    UINT                width,
    UINT                height,
    UINT                stride,
    UINT                bufferSize)
{
    trace_write(ctx,
        "  [!POLICY] result=%s width=%u height=%u stride=%u buf=%u\r\n",
        policy_result_string(result),
        width, height, stride, bufferSize);
}

/* =========================================================================
 * trace_seh_exception
 * ========================================================================= */
void trace_seh_exception(
    HARNESS_TRACE_CTX*  ctx,
    DWORD               exceptionCode,
    TRIAGE_STAGE        lastStage)
{
    trace_write(ctx,
        "[!SEH]  exception_code=0x%08X last_stage=%s\r\n",
        (unsigned)exceptionCode,
        trace_stage_string(lastStage));
    if (ctx && ctx->hFile != INVALID_HANDLE_VALUE)
        FlushFileBuffers(ctx->hFile);
}

/* =========================================================================
 * trace_write_direct
 * ========================================================================= */
void trace_write_direct(HARNESS_TRACE_CTX* ctx, const char* msg)
{
    DWORD written;
    if (!ctx || !msg) return;
    if (ctx->hFile != INVALID_HANDLE_VALUE)
        WriteFile(ctx->hFile, msg, (DWORD)strlen(msg), &written, NULL);
    OutputDebugStringA(msg);
}

/* =========================================================================
 * trace_stage_string
 * ========================================================================= */
const char* trace_stage_string(TRIAGE_STAGE stage)
{
    switch (stage) {
    case STAGE_NONE:                return "NONE";
    case STAGE_DECODER_CREATE:      return "DECODER_CREATE";
    case STAGE_QUERY_CAPABILITY:    return "QUERY_CAPABILITY";
    case STAGE_CONTAINER_FORMAT:    return "CONTAINER_FORMAT";
    case STAGE_DECODER_INFO:        return "DECODER_INFO";
    case STAGE_CONTAINER_METADATA:  return "CONTAINER_METADATA";
    case STAGE_CONTAINER_PALETTE:   return "CONTAINER_PALETTE";
    case STAGE_COLOR_CONTEXTS:      return "COLOR_CONTEXTS";
    case STAGE_PREVIEW:             return "PREVIEW";
    case STAGE_THUMBNAIL_CONTAINER: return "THUMBNAIL_CONTAINER";
    case STAGE_FRAME_COUNT:         return "FRAME_COUNT";
    case STAGE_FRAME_GET:           return "FRAME_GET";
    case STAGE_FRAME_SIZE:          return "FRAME_SIZE";
    case STAGE_FRAME_PIXEL_FORMAT:  return "FRAME_PIXEL_FORMAT";
    case STAGE_FRAME_RESOLUTION:    return "FRAME_RESOLUTION";
    case STAGE_FRAME_PALETTE:       return "FRAME_PALETTE";
    case STAGE_FRAME_COLOR_CONTEXTS:return "FRAME_COLOR_CONTEXTS";
    case STAGE_FRAME_METADATA:      return "FRAME_METADATA";
    case STAGE_FRAME_THUMBNAIL:     return "FRAME_THUMBNAIL";
    case STAGE_COPY_PIXELS:         return "COPY_PIXELS";
    case STAGE_CONVERTER_INIT:      return "CONVERTER_INIT";
    case STAGE_CONVERTER_COPY:      return "CONVERTER_COPY";
    case STAGE_CLEANUP:             return "CLEANUP";
    case STAGE_POLICY_VIOLATION:    return "POLICY_VIOLATION";
    case STAGE_COPY_PIXELS_PARTIAL: return "COPY_PIXELS_PARTIAL";
    case STAGE_TRANSFORM:           return "TRANSFORM";
    case STAGE_PROGRESSIVE:         return "PROGRESSIVE";
    case STAGE_FRAME_OOB:           return "FRAME_OOB";
    case STAGE_WIC_CONVERT:         return "WIC_CONVERT";
    default:                        return "UNKNOWN";
    }
}

/* =========================================================================
 * trace_runtime_info
 * ========================================================================= */
void trace_runtime_info(HARNESS_TRACE_CTX* ctx,
    const HARNESS_RUNTIME_INFO* info)
{
    if (!ctx || !ctx->enabled || !info)
        return;

    trace_write(ctx,
        "[ENV]  windows_version=%lu.%lu build=%lu\r\n",
        (unsigned long)info->windowsMajor,
        (unsigned long)info->windowsMinor,
        (unsigned long)info->windowsBuild);

    trace_write(ctx,
        "[ENV]  process_machine=%s native_machine=%s wow64=%d\r\n",
        machine_to_string(info->processMachine),
        machine_to_string(info->nativeMachine),
        info->isWow64 ? 1 : 0);

    trace_write(ctx,
        "[ENV]  IWICImagingFactory2=%s\r\n",
        info->hasFactory2 ? "available" : "not_available");

    if (info->hasWindowsCodecsVersion) {
        trace_write(ctx,
            "[ENV]  windowscodecs.dll version=%u.%u.%u.%u\r\n",
            HIWORD(info->wicVerMS),
            LOWORD(info->wicVerMS),
            HIWORD(info->wicVerLS),
            LOWORD(info->wicVerLS));
    }
    else {
        trace_write(ctx,
            "[ENV]  windowscodecs.dll version=(unavailable)\r\n");
    }
}

