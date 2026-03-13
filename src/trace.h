/*
 * trace.h
 *
 * Trace and instrumentation module.
 * Logs security-relevant data to a text file for vulnerability research.
 *
 * Design principles:
 *   - Security-relevant fields only: dimensions, HRESULTs, pixel format,
 *     stride, buffer size, frame count, policy outcomes, frame budget.
 *   - No file content logged (avoids bloat; raw bytes have no triage value).
 *   - Minimal overhead in FUZZ_MODE -- disable trace via INI for max speed.
 *   - In RESEARCH_MODE trace is always active regardless of INI.
 *   - Single-threaded persistent mode: no locking required.
 *   - Flushed after every iteration for crash-input correlation.
 *   - Every [STAGE] line includes the current frame index so crash
 *     attribution does not require manual line counting.
 *
 * Frame budget logging:
 *   trace_frame_budget() is called immediately after policy_select_budget()
 *   returns for each frame.  This allows post-crash trace analysis to
 *   identify which frames were processed at BUDGET_FULL vs
 *   BUDGET_METADATA_ONLY, and therefore which paths were active when the
 *   crash occurred.
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
 * ========================================================================= */
typedef enum _TRIAGE_STAGE {
    STAGE_NONE                  = 0,
    STAGE_DECODER_CREATE        = 1,
    STAGE_QUERY_CAPABILITY      = 2,
    STAGE_CONTAINER_FORMAT      = 3,
    STAGE_DECODER_INFO          = 4,
    STAGE_CONTAINER_METADATA    = 5,
    STAGE_CONTAINER_PALETTE     = 6,
    STAGE_COLOR_CONTEXTS        = 7,
    STAGE_PREVIEW               = 8,
    STAGE_THUMBNAIL_CONTAINER   = 9,
    STAGE_FRAME_COUNT           = 10,
    STAGE_FRAME_GET             = 11,
    STAGE_FRAME_SIZE            = 12,
    STAGE_FRAME_PIXEL_FORMAT    = 13,
    STAGE_FRAME_RESOLUTION      = 14,
    STAGE_FRAME_PALETTE         = 15,
    STAGE_FRAME_COLOR_CONTEXTS  = 16,
    STAGE_FRAME_METADATA        = 17,
    STAGE_FRAME_THUMBNAIL       = 18,
    STAGE_COPY_PIXELS           = 19,
    STAGE_CONVERTER_INIT        = 20,
    STAGE_CONVERTER_COPY        = 21,
    STAGE_CLEANUP               = 22,
    STAGE_POLICY_VIOLATION      = 23,   /* budget reduced to METADATA_ONLY */
    STAGE_COPY_PIXELS_PARTIAL   = 24,
    STAGE_TRANSFORM             = 25,
    STAGE_PROGRESSIVE           = 26,
    STAGE_FRAME_OOB             = 27,
    STAGE_WIC_CONVERT           = 28,
} TRIAGE_STAGE;

/* =========================================================================
 * Trace context
 * ========================================================================= */

typedef enum _HRESULT_CLASSIFICATION {
    HRCLS_SUCCESS = 0,
    HRCLS_UNSUPPORTED_EXPECTED,
    HRCLS_NO_DATA_EXPECTED,
    HRCLS_PARSER_REJECT,
    HRCLS_RESOURCE_LIMIT,
    HRCLS_UNEXPECTED_FAILURE,
    HRCLS_COUNT
} HRESULT_CLASSIFICATION;

typedef struct _HARNESS_TRACE_CTX {
    BOOL         enabled;
    HANDLE       hFile;
    WCHAR        path[MAX_PATH];
    unsigned int currentIteration;
    unsigned int currentFrame;
    TRIAGE_STAGE lastStage;
    unsigned int hrClassCounts[HRCLS_COUNT];
} HARNESS_TRACE_CTX;

typedef struct _HARNESS_RUNTIME_INFO {
    DWORD windowsMajor;
    DWORD windowsMinor;
    DWORD windowsBuild;

    WORD  processMachine;
    WORD  nativeMachine;

    BOOL  isWow64;
    BOOL  hasFactory2;

    DWORD wicVerMS;
    DWORD wicVerLS;
    BOOL  hasWindowsCodecsVersion;
} HARNESS_RUNTIME_INFO;

/* =========================================================================
 * Function declarations
 * ========================================================================= */

BOOL trace_init(HARNESS_TRACE_CTX* ctx, const WCHAR* path, BOOL enabled);
void trace_close(HARNESS_TRACE_CTX* ctx);

void trace_iteration_begin(HARNESS_TRACE_CTX* ctx, UINT iteration,
                           const WCHAR* filePath);
void trace_iteration_end(HARNESS_TRACE_CTX* ctx, UINT framesProcessed,
                         UINT framesSkipped);

void trace_stage(HARNESS_TRACE_CTX* ctx, TRIAGE_STAGE stage, HRESULT hr);

void trace_decoder_capabilities(HARNESS_TRACE_CTX* ctx, HRESULT hr,
                                DWORD capabilities);
void trace_container_format(HARNESS_TRACE_CTX* ctx, HRESULT hr,
                            const GUID* pContainerFormat);
void trace_frame_count(HARNESS_TRACE_CTX* ctx, HRESULT hr,
                       UINT frameCount, UINT cappedCount);
void trace_frame_begin(HARNESS_TRACE_CTX* ctx, UINT frameIndex);

void trace_runtime_info(HARNESS_TRACE_CTX* ctx,
    const HARNESS_RUNTIME_INFO* info);

/*
 * trace_frame_budget
 * Log the budget decision for the current frame immediately after
 * policy_select_budget() returns.  Includes estimated stride/buffer
 * so triage can reconstruct what allocation would have been attempted.
 */
void trace_frame_budget(HARNESS_TRACE_CTX* ctx, FRAME_BUDGET budget,
                        UINT width, UINT height,
                        UINT estStride, UINT estBuffer);

void trace_frame_size(HARNESS_TRACE_CTX* ctx, HRESULT hr, UINT width,
                      UINT height);
void trace_frame_pixel_format(HARNESS_TRACE_CTX* ctx, HRESULT hr,
                              const GUID* pFmt, UINT bpp);
void trace_frame_resolution(HARNESS_TRACE_CTX* ctx, HRESULT hr,
                            double dpiX, double dpiY);
void trace_palette(HARNESS_TRACE_CTX* ctx, HRESULT hr, UINT colorCount,
                   BOOL hasAlpha, WICBitmapPaletteType paletteType);
void trace_color_contexts(HARNESS_TRACE_CTX* ctx, HRESULT hr, UINT contextCount);
void trace_metadata(HARNESS_TRACE_CTX* ctx, HRESULT hr, HRESULT enumHr,
                    UINT itemCount, UINT nestedCount, const GUID* pContainerFmt);
void trace_thumbnail(HARNESS_TRACE_CTX* ctx, HRESULT hr, UINT width, UINT height);
void trace_copy_pixels(HARNESS_TRACE_CTX* ctx, HRESULT hr, UINT stride,
                       UINT bufferSize, POLICY_RESULT policyResult, BOOL isConverted);
void trace_copy_pixels_partial(HARNESS_TRACE_CTX* ctx, HRESULT hr,
                               UINT rectX, UINT rectY, UINT rectW, UINT rectH,
                               UINT stride, UINT bufferSize);
void trace_transform(HARNESS_TRACE_CTX* ctx, HRESULT hr, UINT scaledW, UINT scaledH);
void trace_progressive(HARNESS_TRACE_CTX* ctx, HRESULT hr, UINT levelCount);
void trace_oob_frame(HARNESS_TRACE_CTX* ctx, UINT frameCount,
                     HRESULT hrAtCount, HRESULT hrAt0xFFFF,
                     HRESULT hrAtUintMax, HRESULT hrAtHigh);
void trace_policy_violation(HARNESS_TRACE_CTX* ctx, POLICY_RESULT result,
                            UINT width, UINT height, UINT stride, UINT bufferSize);
void trace_seh_exception(HARNESS_TRACE_CTX* ctx, DWORD exceptionCode,
                         TRIAGE_STAGE lastStage);
void trace_write_direct(HARNESS_TRACE_CTX* ctx, const char* msg);

const char* trace_stage_string(TRIAGE_STAGE stage);




#endif /* HARNESS_TRACE_H */
