/*
 * harness_trace.h
 *
 * Trace and instrumentation module.
 * Logs security-relevant data to a .txt file for vulnerability research.
 *
 * Design principles:
 *   - Security-relevant fields only (dimensions, HRESULTs, pixel format,
 *     stride, buffer size, frame count, policy outcomes)
 *   - No file content logged (avoids trace file bloat, no value for RE)
 *   - Minimal overhead in FUZZ_MODE — trace can be disabled via INI
 *   - In RESEARCH_MODE trace is always active regardless of INI
 *   - Thread-safe within single-threaded persistent mode (no locking needed)
 *   - Trace is flushed after every iteration so the last complete entry
 *     before a crash is always present on disk (crash correlation fix)
 *
 * Fix history:
 *   v2: trace_write_direct now takes an explicit HARNESS_TRACE_CTX* parameter
 *       instead of using a hidden 'extern g_trace' dependency inside the TU.
 *       This makes the cross-module dependency explicit and safe across any
 *       linker ordering. (Fix #1 — Viktor Hale / Imogen Walsh)
 *   v2: trace_iteration_end flushes the file so the crash-correlated
 *       entry is always the last line before process termination. (Fix #12)
 *
 * 
 */

#ifndef HARNESS_TRACE_H
#define HARNESS_TRACE_H

#pragma once

#include <windows.h>
#include <wincodec.h>
#include "config.h"
#include "policy.h"

 /* =========================================================================
  * Triage stage identifiers
  * Maps directly to the COM call sequence defined by Sasha/Ryo.
  * Used in trace output and crash attribution.
  *
  * Extended in v2:
  *   STAGE_COPY_PIXELS_PARTIAL  — partial-rect CopyPixels pass (Fix #10)
  *   STAGE_TRANSFORM            — IWICBitmapSourceTransform path  (Fix #7)
  *   STAGE_PROGRESSIVE          — IWICProgressiveLevelControl path (Fix #8)
  *   STAGE_FRAME_OOB            — out-of-bounds frame index probe  (Fix #16)
  * ========================================================================= */
typedef enum _TRIAGE_STAGE {
    STAGE_NONE = 0,
    STAGE_DECODER_CREATE = 1,    /* CreateDecoderFromFilename */
    STAGE_QUERY_CAPABILITY = 2,    /* QueryCapability */
    STAGE_CONTAINER_FORMAT = 3,    /* GetContainerFormat */
    STAGE_DECODER_INFO = 4,    /* GetDecoderInfo */
    STAGE_CONTAINER_METADATA = 5,    /* container GetMetadataQueryReader */
    STAGE_CONTAINER_PALETTE = 6,    /* container CopyPalette */
    STAGE_COLOR_CONTEXTS = 7,    /* GetColorContexts */
    STAGE_PREVIEW = 8,    /* GetPreview */
    STAGE_THUMBNAIL_CONTAINER = 9,    /* container GetThumbnail */
    STAGE_FRAME_COUNT = 10,   /* GetFrameCount */
    STAGE_FRAME_GET = 11,   /* GetFrame(i) */
    STAGE_FRAME_SIZE = 12,   /* frame GetSize */
    STAGE_FRAME_PIXEL_FORMAT = 13,   /* frame GetPixelFormat */
    STAGE_FRAME_RESOLUTION = 14,   /* frame GetResolution */
    STAGE_FRAME_PALETTE = 15,   /* frame CopyPalette */
    STAGE_FRAME_COLOR_CONTEXTS = 16,   /* frame GetColorContexts */
    STAGE_FRAME_METADATA = 17,   /* frame GetMetadataQueryReader */
    STAGE_FRAME_THUMBNAIL = 18,   /* frame GetThumbnail */
    STAGE_COPY_PIXELS = 19,   /* CopyPixels full rect (PRIMARY) */
    STAGE_CONVERTER_INIT = 20,   /* IWICFormatConverter::Initialize */
    STAGE_CONVERTER_COPY = 21,   /* IWICFormatConverter::CopyPixels */
    STAGE_CLEANUP = 22,   /* cleanup / release */
    STAGE_POLICY_VIOLATION = 23,   /* policy enforcement triggered */
    STAGE_COPY_PIXELS_PARTIAL = 24,   /* CopyPixels partial rect pass */
    STAGE_TRANSFORM = 25,   /* IWICBitmapSourceTransform path */
    STAGE_PROGRESSIVE = 26,   /* IWICProgressiveLevelControl path */
    STAGE_FRAME_OOB = 27,   /* out-of-bounds frame index probe */
} TRIAGE_STAGE;

/* =========================================================================
 * Trace context — one per harness process lifetime
 * ========================================================================= */
typedef struct _HARNESS_TRACE_CTX {
    BOOL        enabled;
    HANDLE      hFile;
    WCHAR       path[HARNESS_TRACE_PATH_MAX];
    UINT        currentIteration;
    TRIAGE_STAGE lastStage;         /* last stage reached — crash attribution */
} HARNESS_TRACE_CTX;

/* =========================================================================
 * Function declarations
 * ========================================================================= */

 /*
  * trace_init
  * Open trace file and initialize context.
  * Must be called once before any trace_* functions.
  * Returns TRUE on success, FALSE if file cannot be opened
  * (harness continues without trace in FUZZ_MODE).
  */
BOOL trace_init(
    HARNESS_TRACE_CTX* ctx,
    const WCHAR* path,
    BOOL                enabled
);

/*
 * trace_close
 * Flush and close trace file.
 */
void trace_close(HARNESS_TRACE_CTX* ctx);

/*
 * trace_iteration_begin
 * Log iteration header with file path and iteration number.
 */
void trace_iteration_begin(
    HARNESS_TRACE_CTX* ctx,
    UINT                iteration,
    const WCHAR* filePath
);

/*
 * trace_iteration_end
 * Log iteration summary.
 * v2: also flushes the trace file so the last complete entry before a
 * crash is always committed to disk. Crash-input correlation: the last
 * [ITER]/[FILE] block before process termination corresponds to the
 * crashing input saved by WinAFL. (Fix #12 — Imogen Walsh)
 */
void trace_iteration_end(
    HARNESS_TRACE_CTX* ctx,
    UINT                framesProcessed,
    UINT                framesSkipped
);

/*
 * trace_stage
 * Log a stage transition with its HRESULT.
 * Updates lastStage for crash attribution.
 */
void trace_stage(
    HARNESS_TRACE_CTX* ctx,
    TRIAGE_STAGE        stage,
    HRESULT             hr
);

/*
 * trace_decoder_capabilities
 * Log QueryCapability result bitmask.
 */
void trace_decoder_capabilities(
    HARNESS_TRACE_CTX* ctx,
    HRESULT             hr,
    DWORD               capabilities
);

/*
 * trace_container_format
 * Log container format GUID.
 */
void trace_container_format(
    HARNESS_TRACE_CTX* ctx,
    HRESULT             hr,
    const GUID* pContainerFormat
);

/*
 * trace_frame_count
 * Log ICONDIR frame count and capped value.
 */
void trace_frame_count(
    HARNESS_TRACE_CTX* ctx,
    HRESULT             hr,
    UINT                frameCount,
    UINT                cappedCount
);

/*
 * trace_frame_begin
 * Log frame index header.
 */
void trace_frame_begin(
    HARNESS_TRACE_CTX* ctx,
    UINT                frameIndex
);

/*
 * trace_frame_size
 * Log decoded frame dimensions — critical for overflow triage.
 */
void trace_frame_size(
    HARNESS_TRACE_CTX* ctx,
    HRESULT             hr,
    UINT                width,
    UINT                height
);

/*
 * trace_frame_pixel_format
 * Log pixel format GUID and resolved bpp.
 */
void trace_frame_pixel_format(
    HARNESS_TRACE_CTX* ctx,
    HRESULT             hr,
    const GUID* pFmt,
    UINT                bpp
);

/*
 * trace_frame_resolution
 * Log DPI values.
 */
void trace_frame_resolution(
    HARNESS_TRACE_CTX* ctx,
    HRESULT             hr,
    double              dpiX,
    double              dpiY
);

/*
 * trace_palette
 * Log palette extraction result.
 */
void trace_palette(
    HARNESS_TRACE_CTX* ctx,
    HRESULT             hr,
    UINT                colorCount,
    BOOL                hasAlpha,
    WICBitmapPaletteType paletteType
);

/*
 * trace_color_contexts
 * Log color context count.
 */
void trace_color_contexts(
    HARNESS_TRACE_CTX* ctx,
    HRESULT             hr,
    UINT                contextCount
);

/*
 * trace_metadata
 * Log metadata reader result, container format, nesting depth.
 */
void trace_metadata(
    HARNESS_TRACE_CTX* ctx,
    HRESULT             hr,
    HRESULT             enumHr,
    UINT                itemCount,
    UINT                nestedCount,    /* v2: nested sub-reader count */
    const GUID* pContainerFmt
);

/*
 * trace_thumbnail
 * Log thumbnail extraction result.
 */
void trace_thumbnail(
    HARNESS_TRACE_CTX* ctx,
    HRESULT             hr,
    UINT                width,
    UINT                height
);

/*
 * trace_copy_pixels
 * Log CopyPixels operation — most critical trace entry.
 * Records stride, buffer size, policy outcome, HRESULT.
 */
void trace_copy_pixels(
    HARNESS_TRACE_CTX* ctx,
    HRESULT             hr,
    UINT                stride,
    UINT                bufferSize,
    POLICY_RESULT       policyResult,
    BOOL                isConverted
);

/*
 * trace_copy_pixels_partial
 * Log partial-rect CopyPixels pass. (Fix #10 — Ryo Tanaka)
 */
void trace_copy_pixels_partial(
    HARNESS_TRACE_CTX* ctx,
    HRESULT             hr,
    UINT                rectX,
    UINT                rectY,
    UINT                rectW,
    UINT                rectH,
    UINT                stride,
    UINT                bufferSize
);

/*
 * trace_transform
 * Log IWICBitmapSourceTransform result. (Fix #7 — Ryo Tanaka)
 */
void trace_transform(
    HARNESS_TRACE_CTX* ctx,
    HRESULT             hr,
    UINT                scaledW,
    UINT                scaledH
);

/*
 * trace_progressive
 * Log IWICProgressiveLevelControl result. (Fix #8 — Ryo Tanaka)
 */
void trace_progressive(
    HARNESS_TRACE_CTX* ctx,
    HRESULT             hr,
    UINT                levelCount
);

/*
 * trace_oob_frame
 * Log out-of-bounds frame index probe results. (Fix #16 — Haruto Mori)
 */
void trace_oob_frame(
    HARNESS_TRACE_CTX* ctx,
    UINT                frameCount,
    HRESULT             hrAtCount,
    HRESULT             hrAt0xFFFF
);

/*
 * trace_policy_violation
 * Log a policy enforcement event — dimension or buffer cap triggered.
 */
void trace_policy_violation(
    HARNESS_TRACE_CTX* ctx,
    POLICY_RESULT       result,
    UINT                width,
    UINT                height,
    UINT                stride,
    UINT                bufferSize
);

/*
 * trace_seh_exception
 * Log a caught SEH exception (RESEARCH_MODE only).
 * Records exception code, last stage, and re-raises.
 */
void trace_seh_exception(
    HARNESS_TRACE_CTX* ctx,
    DWORD               exceptionCode,
    TRIAGE_STAGE        lastStage
);

/*
 * trace_stage_string
 * Return human-readable string for a TRIAGE_STAGE value.
 */
const char* trace_stage_string(TRIAGE_STAGE stage);

/*
 * trace_write_direct
 * Write a literal string directly to a given trace context.
 *
 * v2 FIX: ctx is now passed explicitly instead of relying on a hidden
 * 'extern HARNESS_TRACE_CTX g_trace' declaration inside harness_trace.c.
 * This makes the cross-module dependency visible at all call sites and
 * eliminates fragile linker-order assumptions. (Fix #1 — Viktor Hale)
 *
 * Callers: pass &g_trace from harness_main.c.
 */
void trace_write_direct(HARNESS_TRACE_CTX* ctx, const char* msg);

#endif /* HARNESS_TRACE_H */
