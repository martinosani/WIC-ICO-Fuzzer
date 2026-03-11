/*
 * policy.h
 *
 * Policy module -- dimension validation, stride/buffer arithmetic,
 * integer overflow detection before memory allocation.
 *
 * Design intent:
 *   The policy is oriented towards bug hunting, not input sanitisation.
 *   It rejects only inputs that would cause the harness itself to misbehave
 *   (integer overflow in arithmetic, allocation exceeding the memory budget,
 *   zero dimensions).  Everything else is passed through to windowscodecs.dll
 *   so the fuzzer can exercise real decoder code paths.
 *
 * Arithmetic:
 *   All stride and buffer size calculations use 64-bit intermediates so that
 *   stride * height cannot silently overflow a 32-bit accumulator before
 *   being compared to the policy cap.  At max dimensions (65535 x 65535,
 *   128 bpp) the uncapped buffer would be ~68 GB -- well past UINT32_MAX.
 *
 * Fallback bpp:
 *   When COM pixel format resolution fails (factory present but a query
 *   step fails), POLICY_BPP_FALLBACK_MAX (128) is used.  This over-allocates
 *   rather than under-allocates, ensuring the pixel buffer is always large
 *   enough for any format the decoder could write.  Under-allocation would
 *   mask real heap overflows from PageHeap.
 */

#ifndef HARNESS_POLICY_H
#define HARNESS_POLICY_H

#pragma once

#include <windows.h>
#include <wincodec.h>
#include "config.h"

/*
 * Fallback bpp for unknown WIC pixel formats.
 * WIC formats top out at 128 bpp (GUID_WICPixelFormat128bppRGBAFloat).
 */
#define POLICY_BPP_FALLBACK_MAX  128U

/* =========================================================================
 * Runtime policy -- loaded from harness.ini, overrides compiled-in defaults
 * ========================================================================= */
typedef struct _HARNESS_POLICY {
    UINT    maxWidth;               /* max decoded frame width (pixels) */
    UINT    maxHeight;              /* max decoded frame height (pixels) */
    UINT    maxFrames;              /* max ICO frames processed per file */
    UINT    maxBufferBytes;         /* max CopyPixels buffer allocation (bytes) */
    UINT    maxStride;              /* max computed row stride (bytes) */
    UINT    maxColorContexts;       /* max IWICColorContext objects per call */
    UINT    maxPaletteColors;       /* max palette color entries */
    UINT    maxMetadataItems;       /* max items per single metadata reader */
    UINT    maxTotalMetadataItems;  /* max items across ALL readers per iteration */
} HARNESS_POLICY;

/* =========================================================================
 * Policy result codes
 * ========================================================================= */
typedef enum _POLICY_RESULT {
    POLICY_OK               = 0,
    POLICY_DIMENSION_EXCEED = 1,    /* width or height exceeds cap */
    POLICY_STRIDE_OVERFLOW  = 2,    /* stride calculation overflowed */
    POLICY_BUFFER_OVERFLOW  = 3,    /* stride * height overflowed 64-bit (impossible
                                     * with current limits, kept for future safety) */
    POLICY_BUFFER_EXCEED    = 4,    /* buffer size exceeds maxBufferBytes cap */
    POLICY_STRIDE_EXCEED    = 5,    /* stride exceeds maxStride cap */
    POLICY_ZERO_DIMENSION   = 6,    /* zero width or height */
    POLICY_INVALID_ARG      = 7,    /* NULL pointer argument */
} POLICY_RESULT;

/* =========================================================================
 * Function declarations
 * ========================================================================= */

/*
 * policy_init
 *
 * Populate *policy with compiled-in defaults from config.h.
 * Must be called before ini_load_policy() / config_load_ini() so that
 * INI values override a fully-initialised base.
 */
void policy_init(HARNESS_POLICY* policy);

/*
 * policy_validate_dimensions
 *
 * Validate decoded frame dimensions against policy caps.
 * Must be called immediately after GetSize() succeeds, before any
 * stride or buffer computation.
 *
 * Rejects: zero dimensions, dimensions exceeding maxWidth/maxHeight.
 * Does NOT reject large-but-valid dimensions -- those are interesting inputs.
 */
POLICY_RESULT policy_validate_dimensions(
    const HARNESS_POLICY*   policy,
    UINT                    width,
    UINT                    height
);

/*
 * policy_compute_stride
 *
 * Compute DWORD-aligned stride: ((width * bpp + 31) / 32) * 4.
 *
 * Uses 64-bit intermediates for all multiplications to guarantee correct
 * overflow detection regardless of width/bpp combination.
 *
 * Returns POLICY_OK and sets *pStride on success.
 * Returns POLICY_STRIDE_OVERFLOW if any intermediate exceeds UINT32_MAX.
 * Returns POLICY_STRIDE_EXCEED   if the result exceeds policy->maxStride.
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
 * Compute total pixel buffer size: stride * height.
 *
 * Uses 64-bit arithmetic for the multiplication because at max policy
 * dimensions the product can reach ~68 GB -- well past UINT32_MAX.
 * The result is accepted only when it fits within maxBufferBytes (256 MB).
 *
 * Returns POLICY_OK and sets *pBufferSize on success.
 * Returns POLICY_BUFFER_EXCEED if stride * height > maxBufferBytes.
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
 * Resolve bits-per-pixel from a WICPixelFormatGUID via COM:
 *   IWICImagingFactory -> CreateComponentInfo -> IWICPixelFormatInfo
 *   -> GetBitsPerPixel
 *
 * Return value:
 *   > 0  bpp resolved, or POLICY_BPP_FALLBACK_MAX if factory is present
 *        but a COM query step failed.  Fallback over-allocates rather than
 *        under-allocates, so PageHeap can catch real overflows.
 *   0    pFactory is NULL; caller must skip the frame.
 */
UINT policy_get_bpp_from_guid(
    IWICImagingFactory*         pFactory,
    const WICPixelFormatGUID*   pFmt
);

/*
 * policy_result_string
 *
 * Human-readable string for a POLICY_RESULT code (for trace output).
 */
const char* policy_result_string(POLICY_RESULT result);

#endif /* HARNESS_POLICY_H */
