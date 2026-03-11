/*
 * policy.c
 *
 * Policy module implementation.
 * Dimension validation, stride/buffer arithmetic with overflow detection.
 */

#include <windows.h>
#include <wincodec.h>
#include <stdio.h>
#include "policy.h"
#include "config.h"

/*
 * Maximum plausible bpp for an unknown WIC pixel format.
 * WIC formats top out at 128 bpp (GUID_WICPixelFormat128bppRGBAFloat).
 * Using this as fallback ensures the pixel buffer is always large enough
 * for any format the decoder might materialise -- we over-allocate rather
 * than risk masking a real overflow with an under-sized buffer.
 */
#define POLICY_BPP_FALLBACK_MAX  128U

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
    if (!policy) return POLICY_DIMENSION_EXCEED;

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
 * Overflow analysis (UINT32):
 *   width_max = 16384, bpp_max = 128
 *   16384 * 128 = 2,097,152  -- fits in UINT32
 *   + 31        = 2,097,183  -- fits in UINT32
 *   / 32        = 65,537     -- fits in UINT32
 *   * 4         = 262,148    -- fits in UINT32, < POLICY_MAX_STRIDE
 *
 * Despite the safe compile-time analysis, we check anyway: a malformed ICO
 * could supply a pixel format whose bpp exceeds 128, or future policy
 * constants might be raised.
 * ========================================================================= */
POLICY_RESULT policy_compute_stride(
    const HARNESS_POLICY*   policy,
    UINT                    width,
    UINT                    bpp,
    UINT*                   pStride)
{
    UINT widthBits;
    UINT aligned;
    UINT stride;

    if (!policy || !pStride) return POLICY_STRIDE_OVERFLOW;
    if (bpp == 0)            return POLICY_STRIDE_OVERFLOW;

    /* width * bpp overflow? */
    if (width > (0xFFFFFFFFU / bpp))
        return POLICY_STRIDE_OVERFLOW;
    widthBits = width * bpp;

    /* widthBits + 31 overflow? */
    if (widthBits > (0xFFFFFFFFU - 31U))
        return POLICY_STRIDE_OVERFLOW;
    aligned = (widthBits + 31U) / 32U;

    /* aligned * 4 overflow? */
    if (aligned > (0xFFFFFFFFU / 4U))
        return POLICY_STRIDE_OVERFLOW;
    stride = aligned * 4U;

    if (stride > policy->maxStride)
        return POLICY_STRIDE_EXCEED;

    *pStride = stride;
    return POLICY_OK;
}

/* =========================================================================
 * policy_compute_buffer_size
 * ========================================================================= */
POLICY_RESULT policy_compute_buffer_size(
    const HARNESS_POLICY*   policy,
    UINT                    stride,
    UINT                    height,
    UINT*                   pBufferSize)
{
    UINT bufferSize;

    if (!policy || !pBufferSize) return POLICY_BUFFER_OVERFLOW;

    /* stride * height overflow? */
    if (stride > 0U && height > (0xFFFFFFFFU / stride))
        return POLICY_BUFFER_OVERFLOW;
    bufferSize = stride * height;

    if (bufferSize > policy->maxBufferBytes)
        return POLICY_BUFFER_EXCEED;

    *pBufferSize = bufferSize;
    return POLICY_OK;
}

/* =========================================================================
 * policy_get_bpp_from_guid
 *
 * COM-only path: IWICImagingFactory -> IWICComponentInfo
 *             -> IWICPixelFormatInfo -> GetBitsPerPixel
 *
 * Returns 0 only when pFactory is NULL (caller must skip the frame).
 * Any other failure applies POLICY_BPP_FALLBACK_MAX (128) so we always
 * over-allocate -- never under-allocate -- on partial COM failure.
 * ========================================================================= */
UINT policy_get_bpp_from_guid(
    IWICImagingFactory*         pFactory,
    const WICPixelFormatGUID*   pFmt)
{
    HRESULT              hr;
    IWICComponentInfo*   pInfo    = NULL;
    IWICPixelFormatInfo* pFmtInfo = NULL;
    UINT                 bpp      = 0U;

    /* NULL factory: caller must skip -- no guessing allowed */
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
    default:                      return "POLICY_UNKNOWN";
    }
}
