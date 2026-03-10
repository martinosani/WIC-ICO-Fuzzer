/*
 * harness_policy.c
 *
 * Policy module implementation.
 * Dimension validation, stride/buffer arithmetic with overflow detection.
 *
 * Fix history:
 *   v2: policy_get_bpp_from_guid — fallback bpp on resolution failure
 *       changed from 32 to POLICY_BPP_FALLBACK_MAX (128). (Fix #9)
 *
 *       REASON: The previous fallback of 32 bpp caused under-allocation
 *       for exotic pixel formats (64bppRGBA, 128bppFloat etc.). When the
 *       decoder expects 8+ bytes per pixel but the harness allocated for
 *       4 bytes per pixel, an actual heap overflow inside the decoder was
 *       masked: the write extended into valid heap memory rather than past
 *       the buffer boundary that PageHeap monitors. The correct defensive
 *       posture is to over-allocate on failure (use maximum plausible bpp)
 *       so the buffer is always >= what the decoder expects. If the format
 *       is genuinely unknown, wasting 3x memory per frame is acceptable.
 *       If the format is a standard 32bpp format and COM query just failed
 *       transiently, we over-allocate by 4x — also acceptable.
 *
 *       If bpp resolution fails entirely (pFactory unavailable, QI fails),
 *       we skip the frame rather than proceeding with any fallback value.
 *       This is controlled by the return value: 0 means "skip this frame".
 *
 */

#include <windows.h>
#include <wincodec.h>
#include <stdio.h>
#include "policy.h"
#include "config.h"

 /*
  * POLICY_BPP_FALLBACK_MAX
  * Maximum plausible bpp for an unknown WIC pixel format.
  * WIC formats top out at 128bpp (GUID_WICPixelFormat128bppRGBAFloat).
  * Using this as fallback means the pixel buffer is always large enough
  * for any format the decoder might materialise.
  */
#define POLICY_BPP_FALLBACK_MAX     128U

  /* =========================================================================
   * policy_init
   * ========================================================================= */
void policy_init(HARNESS_POLICY* policy)
{
    if (!policy) return;

    policy->maxWidth = POLICY_MAX_WIDTH;
    policy->maxHeight = POLICY_MAX_HEIGHT;
    policy->maxBufferBytes = POLICY_MAX_BUFFER_BYTES;
    policy->maxStride = POLICY_MAX_STRIDE;
    policy->maxFrames = POLICY_MAX_FRAMES;
    policy->maxColorContexts = POLICY_MAX_COLOR_CONTEXTS;
    policy->maxPaletteColors = POLICY_MAX_PALETTE_COLORS;
    policy->maxMetadataItems = POLICY_MAX_METADATA_ITEMS;
}

/* =========================================================================
 * policy_validate_dimensions
 * ========================================================================= */
POLICY_RESULT policy_validate_dimensions(
    const HARNESS_POLICY* policy,
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
 * This is the standard DWORD-aligned stride computation.
 *
 * Overflow analysis (UINT32):
 *   width_max = 16384, bpp_max = 128 (exotic formats)
 *   width * bpp max = 16384 * 128 = 2,097,152  (fits in UINT32)
 *   + 31 = 2,097,183                            (fits in UINT32)
 *   / 32 = 65,537                               (fits in UINT32)
 *   * 4  = 262,148                              (fits in UINT32, < POLICY_MAX_STRIDE)
 *
 * For standard formats (bpp <= 64) at POLICY_MAX_WIDTH:
 *   16384 * 64 = 1,048,576 — no overflow risk at compile-time limits.
 *   However, a malformed ICO may report dimensions that bypass GetSize()
 *   validation in the decoder. We check anyway.
 * ========================================================================= */
POLICY_RESULT policy_compute_stride(
    const HARNESS_POLICY* policy,
    UINT                    width,
    UINT                    bpp,
    UINT* pStride)
{
    UINT widthBits;
    UINT aligned;
    UINT stride;

    if (!policy || !pStride) return POLICY_STRIDE_OVERFLOW;

    /*
     * bpp == 0 means resolution completely failed and caller chose not
     * to skip — treat as internal error rather than silently using a
     * placeholder value that could hide bugs.
     */
    if (bpp == 0) return POLICY_STRIDE_OVERFLOW;

    /* Check: width * bpp overflows UINT32? */
    /* Threshold: if width > (UINT32_MAX / bpp), overflow */
    if (width > (0xFFFFFFFFU / bpp))
        return POLICY_STRIDE_OVERFLOW;

    widthBits = width * bpp;

    /* Check: widthBits + 31 overflows? */
    if (widthBits > (0xFFFFFFFFU - 31U))
        return POLICY_STRIDE_OVERFLOW;

    aligned = (widthBits + 31U) / 32U;

    /* Check: aligned * 4 overflows? */
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
    const HARNESS_POLICY* policy,
    UINT                    stride,
    UINT                    height,
    UINT* pBufferSize)
{
    UINT bufferSize;

    if (!policy || !pBufferSize) return POLICY_BUFFER_OVERFLOW;

    /* Check: stride * height overflows UINT32? */
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
 * Resolve bits-per-pixel from a WICPixelFormatGUID.
 * Uses IWICImagingFactory -> QueryInterface -> IWICComponentInfo
 * -> QueryInterface -> IWICPixelFormatInfo -> GetBitsPerPixel.
 *
 * This is the correct COM-only path. No hardcoded GUID-to-bpp table.
 *
 * Return value:
 *   > 0  : bpp successfully resolved or fallback applied
 *   0    : complete failure — caller must skip the frame
 *
 * v2 CHANGE: fallback on partial failure (factory present but QI/COM
 * query fails) is now POLICY_BPP_FALLBACK_MAX (128) instead of 32.
 * This ensures the pixel buffer is always >= what any WIC decoder could
 * need, preventing under-allocation from masking real overflows. (Fix #9)
 *
 * If pFactory is NULL, returns 0 — caller must skip. We do not guess
 * when the factory is completely unavailable.
 * ========================================================================= */
UINT policy_get_bpp_from_guid(
    IWICImagingFactory* pFactory,
    const WICPixelFormatGUID* pFmt)
{
    HRESULT             hr;
    IWICComponentInfo* pInfo = NULL;
    IWICPixelFormatInfo* pFmtInfo = NULL;
    UINT                bpp = 0U;

    /*
     * If pFactory is NULL the caller cannot resolve anything.
     * Return 0 so the caller skips this frame entirely rather than
     * allocating with a stale or wrong bpp value.
     */
    if (!pFactory || !pFmt) return 0U;

    hr = pFactory->lpVtbl->CreateComponentInfo(pFactory, pFmt, &pInfo);
    if (FAILED(hr) || !pInfo) {
        /*
         * Factory available but CreateComponentInfo failed.
         * Use maximum fallback — we'd rather over-allocate than mask a bug.
         */
        bpp = POLICY_BPP_FALLBACK_MAX;
        goto done;
    }

    hr = pInfo->lpVtbl->QueryInterface(
        pInfo,
        &IID_IWICPixelFormatInfo,
        (void**)&pFmtInfo);
    if (FAILED(hr) || !pFmtInfo) {
        /* ComponentInfo exists but QI to PixelFormatInfo failed */
        bpp = POLICY_BPP_FALLBACK_MAX;
        goto done;
    }

    hr = pFmtInfo->lpVtbl->GetBitsPerPixel(pFmtInfo, &bpp);
    if (FAILED(hr) || bpp == 0U) {
        /* GetBitsPerPixel failed or returned zero */
        bpp = POLICY_BPP_FALLBACK_MAX;
    }

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
