/*
 * policy.h
 *
 * Policy module -- frame budget selection, stride/buffer arithmetic,
 * integer overflow detection before memory allocation.
 *
 * -------------------------------------------------------------------------
 * DESIGN INTENT (bug-hunting oriented)
 * -------------------------------------------------------------------------
 *
 * The central concept is FRAME_BUDGET rather than binary allow/deny.
 * policy_select_budget() answers the question: "What decode work can the
 * harness safely perform for this frame?" -- not "Is this a valid frame?"
 *
 * Budget levels:
 *   BUDGET_FULL          All paths: CopyPixels (full + partial), format
 *                        converter, transform, progressive, wic_convert.
 *   BUDGET_LIGHT         Partial CopyPixels only (small ROI), converter
 *                        probe (Initialize only), transform probe.
 *   BUDGET_METADATA_ONLY No allocation-backed paths.  Exercises: pixel
 *                        format, resolution, palette, color contexts,
 *                        metadata, thumbnail, decoder info, OOB probes.
 *                        Used for frames whose estimated buffer exceeds the
 *                        harness cap -- these frames still exercise the
 *                        majority of windowscodecs.dll internal code paths.
 *   BUDGET_SKIP          Zero-dimension frames only.  The decoder cannot
 *                        even return a valid frame object; no COM paths are
 *                        meaningful.
 *
 * The key insight: cheap COM paths are ALWAYS safe regardless of dimensions.
 * GetPixelFormat, GetResolution, CopyPalette, GetColorContexts,
 * GetMetadataQueryReader, GetThumbnail do not allocate proportional-to-
 * dimension buffers.  A 200000x1 frame runs all these paths identically
 * to a 32x32 frame.  Only CopyPixels and its variants require a buffer
 * computed from width*height*bpp.
 *
 * Arithmetic:
 *   All stride and buffer computations use 64-bit intermediates.
 *   At UINT32_MAX x UINT32_MAX x 128bpp the buffer is ~2^71 bytes --
 *   far past any UINT64 reasonable cap.  The overflow is caught before
 *   any allocation attempt.
 *
 * Fallback bpp:
 *   When COM pixel format resolution fails, POLICY_BPP_FALLBACK_MAX (128)
 *   is used.  This over-allocates rather than under-allocates so PageHeap
 *   can catch real heap overflows.  Under-allocation would mask them.
 */

#ifndef HARNESS_POLICY_H
#define HARNESS_POLICY_H

#pragma once

#include <windows.h>
#include <wincodec.h>
#include "config.h"

/* Fallback bpp for unknown WIC pixel formats (128 = max WIC format depth) */
#define POLICY_BPP_FALLBACK_MAX  128U

/* =========================================================================
 * Runtime policy -- loaded from harness.ini, overrides compiled-in defaults
 * ========================================================================= */
typedef struct _HARNESS_POLICY {
    UINT    softMaxWidth;           /* soft hint: frames above → BUDGET_METADATA_ONLY */
    UINT    softMaxHeight;          /* soft hint: frames above → BUDGET_METADATA_ONLY */
    UINT    maxFrames;
    UINT    maxBufferBytes;         /* hard cap: CopyPixels allocation limit (bytes) */
    UINT    maxStride;              /* hard cap: computed row stride limit (bytes)    */
    UINT    maxColorContexts;
    UINT    maxPaletteColors;
    UINT    maxMetadataItems;       /* per-reader item cap */
    UINT    maxTotalMetadataItems;  /* per-iteration global cap across all readers */
} HARNESS_POLICY;

/* =========================================================================
 * Frame decode budget
 *
 * Returned by policy_select_budget().  The caller gates each code path
 * on the budget rather than on a dimension check.
 *
 * Ordering: BUDGET_FULL < BUDGET_LIGHT < BUDGET_METADATA_ONLY < BUDGET_SKIP
 * Callers can use (budget <= BUDGET_LIGHT) etc. for range checks.
 * ========================================================================= */
typedef enum _FRAME_BUDGET {
    BUDGET_FULL          = 0,   /* all paths: full CopyPixels, converter, transform, progressive */
    BUDGET_LIGHT         = 1,   /* partial CopyPixels (small ROI), converter probe only          */
    BUDGET_METADATA_ONLY = 2,   /* no allocation paths; cheap COM paths only                    */
    BUDGET_SKIP          = 3,   /* zero-dimension frame: nothing is safe to call                 */
} FRAME_BUDGET;

/* =========================================================================
 * Arithmetic result codes (used internally by policy_select_budget)
 * ========================================================================= */
typedef enum _POLICY_RESULT {
    POLICY_OK               = 0,
    POLICY_DIMENSION_EXCEED = 1,    /* above soft dimension hint */
    POLICY_STRIDE_OVERFLOW  = 2,
    POLICY_BUFFER_OVERFLOW  = 3,    /* stride * height overflowed 64-bit (theoretical) */
    POLICY_BUFFER_EXCEED    = 4,    /* buffer > maxBufferBytes */
    POLICY_STRIDE_EXCEED    = 5,    /* stride > maxStride */
    POLICY_ZERO_DIMENSION   = 6,
    POLICY_INVALID_ARG      = 7,
} POLICY_RESULT;

/* =========================================================================
 * Function declarations
 * ========================================================================= */

/*
 * policy_init
 * Populate *policy with compiled-in defaults.  Must be called before
 * ini_load_policy() / config_load_ini().
 */
void policy_init(HARNESS_POLICY* policy);

/*
 * policy_select_budget
 *
 * Core budget decision function.  Determines how much decode work the
 * harness can safely perform for a frame with the given dimensions.
 *
 * Decision logic:
 *   1. width == 0 || height == 0  → BUDGET_SKIP
 *   2. above soft dimension hints → BUDGET_METADATA_ONLY (fast path,
 *      avoids 64-bit multiply for obviously extreme dimensions)
 *   3. stride computation overflows or exceeds cap → BUDGET_METADATA_ONLY
 *   4. buffer computation overflows or exceeds cap → BUDGET_METADATA_ONLY
 *   5. otherwise → BUDGET_FULL
 *
 * bpp:
 *   Pass the frame's actual bpp when known.  Pass 0 to use
 *   POLICY_BPP_FALLBACK_MAX (128), which over-estimates and therefore
 *   selects a more conservative budget -- correct for pre-allocation checks.
 *
 * pEstStride / pEstBuffer:
 *   Optional output parameters.  Set to the computed values on BUDGET_FULL;
 *   set to 0 on any other budget (values are not safe for allocation use).
 *   May be NULL.
 */
FRAME_BUDGET policy_select_budget(
    const HARNESS_POLICY*   policy,
    UINT                    width,
    UINT                    height,
    UINT                    bpp,
    UINT*                   pEstStride,
    UINT*                   pEstBuffer
);

/*
 * policy_compute_stride
 *
 * Compute DWORD-aligned stride: ((width * bpp + 31) / 32) * 4.
 * All multiplications use 64-bit intermediates.
 *
 * Returns POLICY_OK and sets *pStride on success.
 * Returns POLICY_STRIDE_OVERFLOW if any intermediate exceeds UINT32_MAX.
 * Returns POLICY_STRIDE_EXCEED   if result > policy->maxStride.
 */
POLICY_RESULT policy_compute_stride(
    const HARNESS_POLICY*   policy,
    UINT                    width,
    UINT                    bpp,
    UINT*                   pStride
);

/*
 * policy_compute_buffer_size
 *
 * Compute pixel buffer: stride * height using 64-bit arithmetic.
 * Accepts only when result <= maxBufferBytes.
 */
POLICY_RESULT policy_compute_buffer_size(
    const HARNESS_POLICY*   policy,
    UINT                    stride,
    UINT                    height,
    UINT*                   pBufferSize
);

/*
 * policy_get_bpp_from_guid
 *
 * Resolve bits-per-pixel from WICPixelFormatGUID via COM.
 * Returns POLICY_BPP_FALLBACK_MAX on any COM query failure (over-allocates
 * rather than under-allocates; critical for PageHeap effectiveness).
 * Returns 0 only when pFactory is NULL (caller must skip CopyPixels).
 */
UINT policy_get_bpp_from_guid(
    IWICImagingFactory*         pFactory,
    const WICPixelFormatGUID*   pFmt
);

/* Human-readable strings for result codes and budget levels */
const char* policy_result_string(POLICY_RESULT result);
const char* policy_budget_string(FRAME_BUDGET budget);

#endif /* HARNESS_POLICY_H */
