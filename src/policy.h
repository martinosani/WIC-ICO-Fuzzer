/*
 * harness_policy.h
 *
 * Policy module — dimension validation, stride/buffer arithmetic,
 * integer overflow detection before memory allocation.
 *
 * All arithmetic is performed with explicit overflow checks.
 * These checks are security-critical: a bypass here means a real
 * overflow in the decoder is masked by an OOM crash instead of
 * triggering the bug we are looking for.
 *
 * Owner: Mara Schultz
 */

#ifndef HARNESS_POLICY_H
#define HARNESS_POLICY_H

#pragma once

#include <windows.h>
#include <wincodec.h>
#include "config.h"

 /* =========================================================================
  * Runtime policy — loaded from INI, overrides compiled-in defaults
  * ========================================================================= */
typedef struct _HARNESS_POLICY {
    UINT    maxWidth;           /* max decoded frame width */
    UINT    maxHeight;          /* max decoded frame height */
    UINT    maxFrames;          /* max ICO frames processed per file */
    UINT    maxBufferBytes;     /* max CopyPixels buffer allocation */
    UINT    maxStride;          /* max computed row stride */
    UINT    maxColorContexts;   /* max color context objects */
    UINT    maxPaletteColors;   /* max palette color entries */
    UINT    maxMetadataItems;   /* max metadata enumeration items */
} HARNESS_POLICY;

/* =========================================================================
 * Policy result codes
 * ========================================================================= */
typedef enum _POLICY_RESULT {
    POLICY_OK = 0,
    POLICY_DIMENSION_EXCEED = 1,    /* width or height exceeds cap */
    POLICY_STRIDE_OVERFLOW = 2,    /* stride calculation overflowed */
    POLICY_BUFFER_OVERFLOW = 3,    /* stride * height overflowed */
    POLICY_BUFFER_EXCEED = 4,    /* buffer size exceeds cap */
    POLICY_STRIDE_EXCEED = 5,    /* stride exceeds cap */
    POLICY_ZERO_DIMENSION = 6,    /* zero width or height */
} POLICY_RESULT;

/* =========================================================================
 * Function declarations
 * ========================================================================= */

 /*
  * policy_init
  * Initialize policy with compiled-in defaults.
  * Called once at startup before INI is loaded.
  */
void policy_init(HARNESS_POLICY* policy);

/*
 * policy_validate_dimensions
 * Validate decoded frame dimensions against policy caps.
 * Returns POLICY_OK if safe to proceed to buffer allocation.
 * Must be called immediately after GetSize() succeeds.
 */
POLICY_RESULT policy_validate_dimensions(
    const HARNESS_POLICY* policy,
    UINT                    width,
    UINT                    height
);

/*
 * policy_compute_stride
 * Compute DWORD-aligned stride for a given width and bits-per-pixel.
 * Performs explicit overflow check on (width * bpp + 31) / 32 * 4.
 * Returns POLICY_OK and sets *pStride on success.
 * Returns POLICY_STRIDE_OVERFLOW or POLICY_STRIDE_EXCEED on failure.
 *
 * NOTE: bpp is derived from the WICPixelFormatGUID via
 *       IWICComponentInfo / IWICPixelFormatInfo.
 *       For the conversion path (32bppBGRA), bpp = 32 always.
 */
POLICY_RESULT policy_compute_stride(
    const HARNESS_POLICY* policy,
    UINT                    width,
    UINT                    bpp,
    UINT* pStride
);

/*
 * policy_compute_buffer_size
 * Compute total pixel buffer size: stride * height.
 * Performs explicit overflow check.
 * Returns POLICY_OK and sets *pBufferSize on success.
 * Returns POLICY_BUFFER_OVERFLOW or POLICY_BUFFER_EXCEED on failure.
 */
POLICY_RESULT policy_compute_buffer_size(
    const HARNESS_POLICY* policy,
    UINT                    stride,
    UINT                    height,
    UINT* pBufferSize
);

/*
 * policy_get_bpp_from_guid
 * Resolve bits-per-pixel from a WICPixelFormatGUID using
 * IWICImagingFactory -> IWICComponentInfo -> IWICPixelFormatInfo.
 * Returns bpp on success, 0 on failure.
 * Falls back to 32 bpp if resolution fails (conservative).
 */
UINT policy_get_bpp_from_guid(
    IWICImagingFactory* pFactory,
    const WICPixelFormatGUID* pFmt
);

/*
 * policy_result_string
 * Return a human-readable string for a POLICY_RESULT code.
 * Used in trace output.
 */
const char* policy_result_string(POLICY_RESULT result);

#endif /* HARNESS_POLICY_H */
