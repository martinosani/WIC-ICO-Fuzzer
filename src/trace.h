/*
 * trace.h
 *
 * Trace and instrumentation module.
 * Logs security-relevant data to a text file for vulnerability research.
 *
 * Design principles:
 *   - Security-relevant fields only: dimensions, HRESULTs, pixel format,
 *     stride, buffer size, frame count, policy outcomes.
 *   - No file content logged (avoids bloat; raw bytes have no triage value).
 *   - Minimal overhead in FUZZ_MODE -- disable trace via INI for max speed.
 *   - In RESEARCH_MODE trace is always active regardless of INI.
 *   - Single-threaded persistent mode: no locking required.
 *   - Flushed after every iteration for crash-input correlation.
 *   - Every [STAGE] line includes the current frame index so crash
 *     attribution does not require manual line counting in the trace file.
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
 * Maps directly to the COM call sequence in fuzz_target().
 * Used in trace output and for crash attribution via lastStage.
 * ========================================================================= */
typedef enum _TRIAGE_STAGE {
    STAGE_NONE                  = 0,
    STAGE_DECODER_CREATE        = 1,    /* CreateDecoderFromFilename */
    STAGE_QUERY_CAPABILITY      = 2,    /* QueryCapability */
    STAGE_CONTAINER_FORMAT      = 3,    /* GetContainerFormat */
    STAGE_DECODER_INFO          = 4,    /* GetDecoderInfo */
    STAGE_CONTAINER_METADATA    = 5,    /* container GetMetadataQueryReader */
    STAGE_CONTAINER_PALETTE     = 6,    /* container CopyPalette */
    STAGE_COLOR_CONTEXTS        = 7,    /* GetColorContexts (container) */
    STAGE_PREVIEW               = 8,    /* GetPreview */
    STAGE_THUMBNAIL_CONTAINER   = 9,    /* container GetThumbnail */
    STAGE_FRAME_COUNT           = 10,   /* GetFrameCount */
    STAGE_FRAME_GET             = 11,   /* GetFrame(i) */
    STAGE_FRAME_SIZE            = 12,   /* frame GetSize */
    STAGE_FRAME_PIXEL_FORMAT    = 13,   /* frame GetPixelFormat */
    STAGE_FRAME_RESOLUTION      = 14,   /* frame GetResolution */
    STAGE_FRAME_PALETTE         = 15,   /* frame CopyPalette */
    STAGE_FRAME_COLOR_CONTEXTS  = 16,   /* frame GetColorContexts */
    STAGE_FRAME_METADATA        = 17,   /* frame GetMetadataQueryReader */
    STAGE_FRAME_THUMBNAIL       = 18,   /* frame GetThumbnail */
    STAGE_COPY_PIXELS           = 19,   /* CopyPixels full rect (primary) */
    STAGE_CONVERTER_INIT        = 20,   /* IWICFormatConverter::Initialize */
    STAGE_CONVERTER_COPY        = 21,   /* IWICFormatConverter CopyPixels */
    STAGE_CLEANUP               = 22,   /* cleanup / release */
    STAGE_POLICY_VIOLATION      = 23,   /* policy enforcement triggered */
    STAGE_COPY_PIXELS_PARTIAL   = 24,   /* CopyPixels partial rect pass */
    STAGE_TRANSFORM             = 25,   /* IWICBitmapSourceTransform path */
    STAGE_PROGRESSIVE           = 26,   /* IWICProgressiveLevelControl path */
    STAGE_FRAME_OOB             = 27,   /* out-of-bounds frame index probe */
    STAGE_WIC_CONVERT           = 28,   /* WICConvertBitmapSource path */
} TRIAGE_STAGE;

/* =========================================================================
 * Trace context -- one per harness process lifetime
 * ========================================================================= */
typedef struct _HARNESS_TRACE_CTX {
    BOOL         enabled;
    HANDLE       hFile;
    WCHAR        path[HARNESS_TRACE_PATH_MAX];
    UINT         currentIteration;
    UINT         currentFrame;      /* HARNESS_NO_FRAME at container level */
    TRIAGE_STAGE lastStage;         /* last stage reached -- crash attribution */
} HARNESS_TRACE_CTX;

/* =========================================================================
 * Function declarations
 * ========================================================================= */

BOOL trace_init(
    HARNESS_TRACE_CTX*  ctx,
    const WCHAR*        path,
    BOOL                enabled
);

void trace_close(HARNESS_TRACE_CTX* ctx);

void trace_iteration_begin(
    HARNESS_TRACE_CTX*  ctx,
    UINT                iteration,
    const WCHAR*        filePath
);

/*
 * trace_iteration_end
 * Logs iteration summary and flushes the trace file to disk.
 * The flush guarantees that the last complete [ITER]/[FILE] block before
 * a process crash is always committed, enabling direct crash-input
 * correlation: the last [FILE] line identifies the crashing input.
 */
void trace_iteration_end(
    HARNESS_TRACE_CTX*  ctx,
    UINT                framesProcessed,
    UINT                framesSkipped
);

/*
 * trace_stage
 * Log a stage transition with its HRESULT and the current frame index.
 * The frame index is taken from ctx->currentFrame; set it via
 * trace_frame_begin() or reset it to HARNESS_NO_FRAME for container-level
 * operations.  This embeds the frame context into every [STAGE] line,
 * eliminating the need for manual line counting during crash triage.
 */
void trace_stage(
    HARNESS_TRACE_CTX*  ctx,
    TRIAGE_STAGE        stage,
    HRESULT             hr
);

void trace_decoder_capabilities(
    HARNESS_TRACE_CTX*  ctx,
    HRESULT             hr,
    DWORD               capabilities
);

void trace_container_format(
    HARNESS_TRACE_CTX*  ctx,
    HRESULT             hr,
    const GUID*         pContainerFormat
);

void trace_frame_count(
    HARNESS_TRACE_CTX*  ctx,
    HRESULT             hr,
    UINT                frameCount,
    UINT                cappedCount
);

/* trace_frame_begin: sets ctx->currentFrame = frameIndex */
void trace_frame_begin(
    HARNESS_TRACE_CTX*  ctx,
    UINT                frameIndex
);

void trace_frame_size(
    HARNESS_TRACE_CTX*  ctx,
    HRESULT             hr,
    UINT                width,
    UINT                height
);

void trace_frame_pixel_format(
    HARNESS_TRACE_CTX*  ctx,
    HRESULT             hr,
    const GUID*         pFmt,
    UINT                bpp
);

void trace_frame_resolution(
    HARNESS_TRACE_CTX*  ctx,
    HRESULT             hr,
    double              dpiX,
    double              dpiY
);

void trace_palette(
    HARNESS_TRACE_CTX*  ctx,
    HRESULT             hr,
    UINT                colorCount,
    BOOL                hasAlpha,
    WICBitmapPaletteType paletteType
);

void trace_color_contexts(
    HARNESS_TRACE_CTX*  ctx,
    HRESULT             hr,
    UINT                contextCount
);

void trace_metadata(
    HARNESS_TRACE_CTX*  ctx,
    HRESULT             hr,
    HRESULT             enumHr,
    UINT                itemCount,
    UINT                nestedCount,
    const GUID*         pContainerFmt
);

void trace_thumbnail(
    HARNESS_TRACE_CTX*  ctx,
    HRESULT             hr,
    UINT                width,
    UINT                height
);

void trace_copy_pixels(
    HARNESS_TRACE_CTX*  ctx,
    HRESULT             hr,
    UINT                stride,
    UINT                bufferSize,
    POLICY_RESULT       policyResult,
    BOOL                isConverted
);

void trace_copy_pixels_partial(
    HARNESS_TRACE_CTX*  ctx,
    HRESULT             hr,
    UINT                rectX,
    UINT                rectY,
    UINT                rectW,
    UINT                rectH,
    UINT                stride,
    UINT                bufferSize
);

void trace_transform(
    HARNESS_TRACE_CTX*  ctx,
    HRESULT             hr,
    UINT                scaledW,
    UINT                scaledH
);

void trace_progressive(
    HARNESS_TRACE_CTX*  ctx,
    HRESULT             hr,
    UINT                levelCount
);

void trace_oob_frame(
    HARNESS_TRACE_CTX*  ctx,
    UINT                frameCount,
    HRESULT             hrAtCount,
    HRESULT             hrAt0xFFFF,
    HRESULT             hrAtUintMax,
    HRESULT             hrAtHigh
);

void trace_policy_violation(
    HARNESS_TRACE_CTX*  ctx,
    POLICY_RESULT       result,
    UINT                width,
    UINT                height,
    UINT                stride,
    UINT                bufferSize
);

void trace_seh_exception(
    HARNESS_TRACE_CTX*  ctx,
    DWORD               exceptionCode,
    TRIAGE_STAGE        lastStage
);

void trace_write_direct(HARNESS_TRACE_CTX* ctx, const char* msg);

const char* trace_stage_string(TRIAGE_STAGE stage);

#endif /* HARNESS_TRACE_H */
