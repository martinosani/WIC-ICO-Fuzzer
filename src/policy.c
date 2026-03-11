/*
 * policy.c
 *
 * Policy module implementation.
 * Dimension validation, stride/buffer arithmetic with 64-bit overflow
 * detection, COM-based pixel format resolution.
 */

#include <windows.h>
#include <wincodec.h>
#include <stdio.h>
#include "policy.h"
#include "config.h"

/* =========================================================================
 * policy_init
 * ========================================================================= */
void policy_init(HARNESS_POLICY* policy)
{
    if (!policy) return;

    policy->maxWidth              = POLICY_MAX_WIDTH;
    policy->maxHeight             = POLICY_MAX_HEIGHT;
    policy->maxBufferBytes        = POLICY_MAX_BUFFER_BYTES;
    policy->maxStride             = POLICY_MAX_STRIDE;
    policy->maxFrames             = POLICY_MAX_FRAMES;
    policy->maxColorContexts      = POLICY_MAX_COLOR_CONTEXTS;
    policy->maxPaletteColors      = POLICY_MAX_PALETTE_COLORS;
    policy->maxMetadataItems      = POLICY_MAX_METADATA_ITEMS;
    policy->maxTotalMetadataItems = POLICY_MAX_TOTAL_METADATA_ITEMS;
}

/* =========================================================================
 * policy_validate_dimensions
 * ========================================================================= */
POLICY_RESULT policy_validate_dimensions(
    const HARNESS_POLICY*   policy,
    UINT                    width,
    UINT                    height)
{
    if (!policy) return POLICY_INVALID_ARG;

    if (width == 0 || height == 0)
        return POLICY_ZERO_DIMENSION;

    if (width > policy->maxWidth || height > policy->maxHeight)
        return POLICY_DIMENSION_EXCEED;

    return POLICY_OK;
}

/* =========================================================================
 * policy_compute_stride
 *
 * Formula: stride = ((width * bpp + 31) / 32) * 4
 *
 * 64-bit intermediate analysis at maximum policy dimensions:
 *   width  = 65535, bpp = 128 (POLICY_BPP_FALLBACK_MAX)
 *   w64    = 65535 * 128    = 8,388,480      (fits in UINT64, < UINT32_MAX)
 *   w64+31 = 8,388,511                       (fits, < UINT32_MAX)
 *   /32    = 262,141                          (fits, < UINT32_MAX)
 *   *4     = 1,048,564 bytes (~1 MB stride)  (fits, < POLICY_MAX_STRIDE)
 *
 * Despite the safe current analysis, all multiplications use UINT64
 * intermediates so future policy increases cannot silently introduce bugs.
 * ========================================================================= */
POLICY_RESULT policy_compute_stride(
    const HARNESS_POLICY*   policy,
    UINT                    width,
    UINT                    bpp,
    UINT*                   pStride)
{
    UINT64 w64;
    UINT64 aligned64;
    UINT64 stride64;

    if (!policy || !pStride) return POLICY_INVALID_ARG;
    if (bpp == 0)             return POLICY_STRIDE_OVERFLOW;

    /* width * bpp -- both are UINT, product fits in UINT64 easily */
    w64 = (UINT64)width * (UINT64)bpp;

    /* Add 31 for alignment; no overflow possible (max w64 << UINT64_MAX) */
    w64 += 31ULL;

    /* Divide by 32 to get 32-pixel-aligned row width in pixels */
    aligned64 = w64 / 32ULL;

    /* Multiply by 4 to get byte stride */
    stride64 = aligned64 * 4ULL;

    /* Check that the result fits in UINT32 before the policy cap */
    if (stride64 > 0xFFFFFFFFULL)
        return POLICY_STRIDE_OVERFLOW;

    if ((UINT)stride64 > policy->maxStride)
        return POLICY_STRIDE_EXCEED;

    *pStride = (UINT)stride64;
    return POLICY_OK;
}

/* =========================================================================
 * policy_compute_buffer_size
 *
 * stride * height computed as UINT64 to prevent overflow before the
 * comparison to maxBufferBytes.
 *
 * At maximum policy dimensions (65535 x 65535, 128 bpp):
 *   stride = 1,048,564 bytes
 *   buffer = 1,048,564 * 65,535 = ~68.7 GB (> UINT32_MAX, > maxBufferBytes)
 *   -> POLICY_BUFFER_EXCEED
 *
 * For any input that the policy accepts (buffer <= maxBufferBytes = 256 MB),
 * the result always fits in UINT32, so *pBufferSize is safe to use as UINT.
 * ========================================================================= */
POLICY_RESULT policy_compute_buffer_size(
    const HARNESS_POLICY*   policy,
    UINT                    stride,
    UINT                    height,
    UINT*                   pBufferSize)
{
    UINT64 buf64;

    if (!policy || !pBufferSize) return POLICY_INVALID_ARG;

    /* 64-bit multiply: stride and height are both UINT32, product fits in UINT64 */
    buf64 = (UINT64)stride * (UINT64)height;

    /*
     * Compare against the 32-bit policy cap.  The cap itself (256 MB = 268435456)
     * is well within UINT64 range.  Any buffer that exceeds the cap is rejected;
     * any buffer within the cap fits in UINT32 by definition.
     */
    if (buf64 > (UINT64)policy->maxBufferBytes)
        return POLICY_BUFFER_EXCEED;

    *pBufferSize = (UINT)buf64;
    return POLICY_OK;
}

/* =========================================================================
 * policy_get_bpp_from_guid
 *
 * COM-only path:
 *   IWICImagingFactory -> CreateComponentInfo -> IWICPixelFormatInfo
 *   -> GetBitsPerPixel
 *
 * Returns 0 only when pFactory is NULL (caller must skip the frame entirely).
 * Any COM failure on an otherwise present factory applies
 * POLICY_BPP_FALLBACK_MAX (128) to ensure we over-allocate rather than
 * under-allocate -- under-allocation would mask real heap overflows from
 * PageHeap.
 * ========================================================================= */
UINT policy_get_bpp_from_guid(
    IWICImagingFactory*         pFactory,
    const WICPixelFormatGUID*   pFmt)
{
    HRESULT              hr;
    IWICComponentInfo*   pInfo    = NULL;
    IWICPixelFormatInfo* pFmtInfo = NULL;
    UINT                 bpp      = 0U;

    /* NULL factory: caller must skip -- no fallback is useful here */
    if (!pFactory || !pFmt) return 0U;

    hr = pFactory->lpVtbl->CreateComponentInfo(pFactory, pFmt, &pInfo);
    if (FAILED(hr) || !pInfo) {
        bpp = POLICY_BPP_FALLBACK_MAX;
        goto done;
    }

    hr = pInfo->lpVtbl->QueryInterface(
        pInfo,
        &IID_IWICPixelFormatInfo,
        (void**)&pFmtInfo);
    if (FAILED(hr) || !pFmtInfo) {
        bpp = POLICY_BPP_FALLBACK_MAX;
        goto done;
    }

    hr = pFmtInfo->lpVtbl->GetBitsPerPixel(pFmtInfo, &bpp);
    if (FAILED(hr) || bpp == 0U)
        bpp = POLICY_BPP_FALLBACK_MAX;

done:
    if (pFmtInfo) pFmtInfo->lpVtbl->Release(pFmtInfo);
    if (pInfo)    pInfo->lpVtbl->Release(pInfo);
    return bpp;
}

/* =========================================================================
 * policy_result_string
 * ========================================================================= */
const char* policy_result_string(POLICY_RESULT result)
{
    switch (result) {
    case POLICY_OK:               return "POLICY_OK";
    case POLICY_DIMENSION_EXCEED: return "POLICY_DIMENSION_EXCEED";
    case POLICY_STRIDE_OVERFLOW:  return "POLICY_STRIDE_OVERFLOW";
    case POLICY_BUFFER_OVERFLOW:  return "POLICY_BUFFER_OVERFLOW";
    case POLICY_BUFFER_EXCEED:    return "POLICY_BUFFER_EXCEED";
    case POLICY_STRIDE_EXCEED:    return "POLICY_STRIDE_EXCEED";
    case POLICY_ZERO_DIMENSION:   return "POLICY_ZERO_DIMENSION";
    case POLICY_INVALID_ARG:      return "POLICY_INVALID_ARG";
    default:                      return "POLICY_UNKNOWN";
    }
}
