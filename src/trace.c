/*
 * harness_trace.c
 *
 * Trace and instrumentation module implementation.
 * Security-relevant data logging for vulnerability research.
 *
 * Fix history:
 *   v2: trace_write_direct — removed hidden 'extern g_trace' dependency.
 *       Now takes explicit HARNESS_TRACE_CTX* parameter. (Fix #1)
 *   v2: trace_iteration_end — added FlushFileBuffers so the last complete
 *       iteration entry is always on disk before a crash kills the process.
 *       This enables direct crash-input / trace-entry correlation. (Fix #12)
 *   v2: trace_metadata — added nestedCount parameter for recursive metadata
 *       enumeration depth tracking. (Fix #6)
 *   v2: Added trace_copy_pixels_partial, trace_transform, trace_progressive,
 *       trace_oob_frame. (Fixes #7, #8, #10, #16)
 *
 * 
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

  /*
   * trace_write
   * Write a formatted string to the trace file.
   * Silently does nothing if trace is disabled or file is invalid.
   */
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

/*
 * guid_to_string
 * Format a GUID as {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
 */
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

/* =========================================================================
 * trace_init
 * ========================================================================= */
BOOL trace_init(
    HARNESS_TRACE_CTX* ctx,
    const WCHAR* path,
    BOOL                enabled)
{
    if (!ctx) return FALSE;

    ZeroMemory(ctx, sizeof(*ctx));
    ctx->hFile = INVALID_HANDLE_VALUE;
    ctx->lastStage = STAGE_NONE;
    ctx->currentIteration = 0;

#ifdef HARNESS_MODE_RESEARCH
    /* Research mode: trace always active */
    ctx->enabled = TRUE;
#else
    ctx->enabled = enabled;
#endif

    if (!ctx->enabled) return TRUE; /* disabled — not an error */

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
        " WIC ICO Fuzzing Harness — Trace File\r\n"
        " Target: windowscodecs.dll \r\n"
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
    HARNESS_TRACE_CTX* ctx,
    UINT                iteration,
    const WCHAR* filePath)
{
    if (!ctx || !ctx->enabled) return;
    ctx->currentIteration = iteration;
    ctx->lastStage = STAGE_NONE;

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
 * v2 change: FlushFileBuffers is called after writing the summary line.
 *
 * Crash-input correlation: WinAFL saves the crashing input file, but does
 * not record which harness iteration produced the crash. By flushing after
 * every iteration, the last complete [ITER]/[FILE] block in the trace file
 * corresponds exactly to the crashing input. The researcher can match:
 *   - Last [FILE] line in trace → crashing input path
 *   - Last [STAGE] line in trace → stage where crash occurred
 *   - Last [ITER] line → iteration number
 * This replaces manual iteration-number matching. (Fix #12 — Imogen Walsh)
 * ========================================================================= */
void trace_iteration_end(
    HARNESS_TRACE_CTX* ctx,
    UINT                framesProcessed,
    UINT                framesSkipped)
{
    if (!ctx || !ctx->enabled) return;

    trace_write(ctx,
        "[DONE] frames_processed=%u frames_skipped=%u\r\n",
        framesProcessed, framesSkipped);

    /*
     * Flush after every iteration.
     * Cost: ~1 syscall per iteration. Acceptable at typical fuzz speeds
     * (100-500 iter/sec). In high-throughput FUZZ_MODE without PageHeap,
     * disable trace entirely rather than removing this flush.
     */
    if (ctx->hFile != INVALID_HANDLE_VALUE)
        FlushFileBuffers(ctx->hFile);
}

/* =========================================================================
 * trace_stage
 * ========================================================================= */
void trace_stage(
    HARNESS_TRACE_CTX* ctx,
    TRIAGE_STAGE        stage,
    HRESULT             hr)
{
    if (!ctx || !ctx->enabled) return;
    ctx->lastStage = stage;
    trace_write(ctx,
        "[STAGE] %-30s hr=0x%08X %s\r\n",
        trace_stage_string(stage),
        (unsigned)hr,
        SUCCEEDED(hr) ? "OK" : "FAILED");
}

/* =========================================================================
 * trace_decoder_capabilities
 * ========================================================================= */
void trace_decoder_capabilities(
    HARNESS_TRACE_CTX* ctx,
    HRESULT             hr,
    DWORD               capabilities)
{
    trace_write(ctx,
        "[CAP]  hr=0x%08X capabilities=0x%08X"
        " [same_encoder=%d decode_all=%d decode_some=%d metadata=%d thumbnail=%d]\r\n",
        (unsigned)hr,
        (unsigned)capabilities,
        (capabilities & WICBitmapDecoderCapabilitySameEncoder) ? 1 : 0,
        (capabilities & WICBitmapDecoderCapabilityCanDecodeAllImages) ? 1 : 0,
        (capabilities & WICBitmapDecoderCapabilityCanDecodeSomeImages) ? 1 : 0,
        (capabilities & WICBitmapDecoderCapabilityCanEnumerateMetadata) ? 1 : 0,
        (capabilities & WICBitmapDecoderCapabilityCanDecodeThumbnail) ? 1 : 0);
}

/* =========================================================================
 * trace_container_format
 * ========================================================================= */
void trace_container_format(
    HARNESS_TRACE_CTX* ctx,
    HRESULT             hr,
    const GUID* pContainerFormat)
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
    HARNESS_TRACE_CTX* ctx,
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
 * ========================================================================= */
void trace_frame_begin(
    HARNESS_TRACE_CTX* ctx,
    UINT                frameIndex)
{
    trace_write(ctx,
        "  [FRAME] index=%u\r\n", frameIndex);
}

/* =========================================================================
 * trace_frame_size
 * ========================================================================= */
void trace_frame_size(
    HARNESS_TRACE_CTX* ctx,
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
    HARNESS_TRACE_CTX* ctx,
    HRESULT             hr,
    const GUID* pFmt,
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
    HARNESS_TRACE_CTX* ctx,
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
    HARNESS_TRACE_CTX* ctx,
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
    HARNESS_TRACE_CTX* ctx,
    HRESULT             hr,
    UINT                contextCount)
{
    trace_write(ctx,
        "  [ICC]   hr=0x%08X color_context_count=%u\r\n",
        (unsigned)hr, contextCount);
}

/* =========================================================================
 * trace_metadata
 *
 * v2: added nestedCount for recursive enumeration depth tracking.
 * nestedCount is the number of VT_UNKNOWN propvariants that were
 * themselves IWICMetadataQueryReader objects (nested sub-readers).
 * Non-zero values indicate XMP/EXIF nesting inside PNG-in-ICO. (Fix #6)
 * ========================================================================= */
void trace_metadata(
    HARNESS_TRACE_CTX* ctx,
    HRESULT             hr,
    HRESULT             enumHr,
    UINT                itemCount,
    UINT                nestedCount,
    const GUID* pContainerFmt)
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
    HARNESS_TRACE_CTX* ctx,
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
    HARNESS_TRACE_CTX* ctx,
    HRESULT             hr,
    UINT                stride,
    UINT                bufferSize,
    POLICY_RESULT       policyResult,
    BOOL                isConverted)
{
    trace_write(ctx,
        "  [CPX]   hr=0x%08X stride=%u buf_size=%u "
        "policy=%s converted=%d\r\n",
        (unsigned)hr, stride, bufferSize,
        policy_result_string(policyResult),
        isConverted ? 1 : 0);
}

/* =========================================================================
 * trace_copy_pixels_partial
 *
 * Partial-rect CopyPixels pass. The rect covers the top-left quadrant of
 * the frame. Documents stride/HRESULT for the partial decode path which
 * exercises different offset arithmetic inside the decoder. (Fix #10)
 * ========================================================================= */
void trace_copy_pixels_partial(
    HARNESS_TRACE_CTX* ctx,
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
 *
 * IWICBitmapSourceTransform path. scaledW/scaledH are the requested
 * output dimensions (half of original). (Fix #7)
 * ========================================================================= */
void trace_transform(
    HARNESS_TRACE_CTX* ctx,
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
 *
 * IWICProgressiveLevelControl path. levelCount is the number of
 * progressive levels available (0 if interface not supported). (Fix #8)
 * ========================================================================= */
void trace_progressive(
    HARNESS_TRACE_CTX* ctx,
    HRESULT             hr,
    UINT                levelCount)
{
    trace_write(ctx,
        "  [PROG]  hr=0x%08X level_count=%u\r\n",
        (unsigned)hr, levelCount);
}

/* =========================================================================
 * trace_oob_frame
 *
 * Out-of-bounds frame index probe results. (Fix #16 — Haruto Mori)
 * hrAtCount  = result of GetFrame(frameCount)    — should be E_INVALIDARG
 * hrAt0xFFFF = result of GetFrame(0xFFFF)        — should be E_INVALIDARG
 * Unexpected success (S_OK) or non-INVALIDARG errors indicate boundary bugs.
 * ========================================================================= */
void trace_oob_frame(
    HARNESS_TRACE_CTX* ctx,
    UINT                frameCount,
    HRESULT             hrAtCount,
    HRESULT             hrAt0xFFFF)
{
    trace_write(ctx,
        "[OOB]  frame_count=%u hr_at_count=0x%08X hr_at_0xFFFF=0x%08X"
        " [count_ok=%d ffff_ok=%d]\r\n",
        frameCount,
        (unsigned)hrAtCount,
        (unsigned)hrAt0xFFFF,
        FAILED(hrAtCount) ? 1 : 0,   /* 1 = correctly rejected */
        FAILED(hrAt0xFFFF) ? 1 : 0);
}

/* =========================================================================
 * trace_policy_violation
 * ========================================================================= */
void trace_policy_violation(
    HARNESS_TRACE_CTX* ctx,
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
    HARNESS_TRACE_CTX* ctx,
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
    default:                        return "UNKNOWN";
    }
}
