/*
 * policy.h
 *
 * Policy module -- dimension validation, stride/buffer arithmetic,
 * integer overflow detection before memory allocation.
 *
 * All arithmetic is performed with explicit overflow checks at every
 * multiplication step.  These checks are security-critical: a bypass
 * here means a real overflow in the decoder is masked by an OOM crash
 * instead of triggering the PageHeap guard that we are targeting.
 */

#ifndef HARNESS_POLICY_H
#define HARNESS_POLICY_H

#pragma once

#include <windows.h>
#include <wincodec.h>
#include "config.h"

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
    POLICY_STRIDE_OVERFLOW  = 2,    /* stride calculation overflowed UINT32 */
    POLICY_BUFFER_OVERFLOW  = 3,    /* stride * height overflowed UINT32 */
    POLICY_BUFFER_EXCEED    = 4,    /* buffer size exceeds cap */
    POLICY_STRIDE_EXCEED    = 5,    /* stride exceeds cap */
    POLICY_ZERO_DIMENSION   = 6,    /* zero width or height */
} POLICY_RESULT;

/* =========================================================================
 * Function declarations
 * ========================================================================= */

/*
 * policy_init
 * Populate *policy with compiled-in defaults.
 * Must be called before config_load_ini so INI values can override defaults.
 */
void policy_init(HARNESS_POLICY* policy);

/*
 * policy_validate_dimensions
 * Validate decoded frame dimensions against policy caps.
 * Must be called immediately after GetSize() succeeds, before any
 * stride or buffer computation.
 */
POLICY_RESULT policy_validate_dimensions(
    const HARNESS_POLICY*   policy,
    UINT                    width,
    UINT                    height
);

/*
 * policy_compute_stride
 * Compute DWORD-aligned stride: ((width * bpp + 31) / 32) * 4.
 * Performs explicit UINT32 overflow check at every step.
 * Returns POLICY_OK and sets *pStride on success.
 *
 * NOTE: bpp is resolved from the WICPixelFormatGUID via
 *       IWICComponentInfo / IWICPixelFormatInfo (COM only -- no lookup table).
 */
POLICY_RESULT policy_compute_stride(
    const HARNESS_POLICY*   policy,
    UINT                    width,
    UINT                    bpp,
    UINT*                   pStride
);

/*
 * policy_compute_buffer_size
 * Compute total pixel buffer size: stride * height.
 * Performs explicit UINT32 overflow check.
 * Returns POLICY_OK and sets *pBufferSize on success.
 */
POLICY_RESULT policy_compute_buffer_size(
    const HARNESS_POLICY*   policy,
    UINT                    stride,
    UINT                    height,
    UINT*                   pBufferSize
);

/*
 * policy_get_bpp_from_guid
 * Resolve bits-per-pixel from a WICPixelFormatGUID via COM:
 *   IWICImagingFactory -> CreateComponentInfo -> IWICPixelFormatInfo
 *   -> GetBitsPerPixel
 *
 * Return value:
 *   > 0  bpp successfully resolved, or fallback applied (factory present
 *        but a COM query step failed).  Fallback is POLICY_BPP_FALLBACK_MAX
 *        (128 bpp) -- chosen to over-allocate rather than under-allocate,
 *        so the pixel buffer is always >= what any WIC decoder could write.
 *        Under-allocation would mask real heap overflows from PageHeap.
 *   0    pFactory is NULL; caller must skip the frame entirely.
 */
UINT policy_get_bpp_from_guid(
    IWICImagingFactory*         pFactory,
    const WICPixelFormatGUID*   pFmt
);

/*
 * policy_result_string
 * Human-readable string for a POLICY_RESULT code (trace output).
 */
const char* policy_result_string(POLICY_RESULT result);

#endif /* HARNESS_POLICY_H */
