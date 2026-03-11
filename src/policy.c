/*
 * policy.c
 *
 * Policy module implementation.
 *
 * Central function: policy_select_budget()
 *   Replaces the old binary dimension-check skip with a graduated budget
 *   decision.  The harness never discards a frame solely because its
 *   declared dimensions are large.  It only limits which COM paths it
 *   performs on that frame based on whether a safe harness-side allocation
 *   is arithmetically possible within the configured cap.
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

    policy->softMaxWidth          = POLICY_SOFT_MAX_WIDTH;
    policy->softMaxHeight         = POLICY_SOFT_MAX_HEIGHT;
    policy->maxBufferBytes        = POLICY_MAX_BUFFER_BYTES;
    policy->maxStride             = POLICY_MAX_STRIDE;
    policy->maxFrames             = POLICY_MAX_FRAMES;
    policy->maxColorContexts      = POLICY_MAX_COLOR_CONTEXTS;
    policy->maxPaletteColors      = POLICY_MAX_PALETTE_COLORS;
    policy->maxMetadataItems      = POLICY_MAX_METADATA_ITEMS;
    policy->maxTotalMetadataItems = POLICY_MAX_TOTAL_METADATA_ITEMS;
}

/* =========================================================================
 * policy_select_budget
 *
 * The core bug-hunting decision function.  Answers: "What work can the
 * harness safely do for this frame?"
 *
 * This function intentionally does NOT reject frames for being 'too large'.
 * Frames with extreme dimensions are the most interesting inputs the fuzzer
 * can produce -- they exercise overflow arithmetic inside windowscodecs.dll.
 * The harness can still exercise metadata, palette, color contexts, pixel
 * format resolution, and OOB probes on such frames; only the heap-
 * allocation-backed paths (CopyPixels, full converter, progressive) are
 * gated to avoid harness OOM.
 *
 * Budget selection order:
 *   1. Zero dimension  → BUDGET_SKIP  (decoder cannot produce a usable frame)
 *   2. Soft hint check → BUDGET_METADATA_ONLY  (fast path for obvious cases)
 *   3. Stride overflow/exceed → BUDGET_METADATA_ONLY
 *   4. Buffer overflow/exceed → BUDGET_METADATA_ONLY
 *   5. Otherwise       → BUDGET_FULL
 * ========================================================================= */
FRAME_BUDGET policy_select_budget(
    const HARNESS_POLICY*   policy,
    UINT                    width,
    UINT                    height,
    UINT                    bpp,
    UINT*                   pEstStride,
    UINT*                   pEstBuffer)
{
    UINT         useBpp;
    UINT         stride  = 0;
    UINT         buf     = 0;
    POLICY_RESULT prS, prB;

    /* Zero out optional output params */
    if (pEstStride) *pEstStride = 0;
    if (pEstBuffer) *pEstBuffer = 0;

    if (!policy) return BUDGET_SKIP;

    /* Zero dimensions -- the decoder cannot meaningfully materialise a frame */
    if (width == 0 || height == 0)
        return BUDGET_SKIP;

    /*
     * Soft hint fast path.
     * If either dimension exceeds the soft hint we skip the 64-bit arithmetic
     * entirely and go directly to BUDGET_METADATA_ONLY.  This is not a filter:
     * the frame is NOT skipped; all cheap COM paths still execute.
     *
     * The soft hint values (65535 x 65535) are chosen so that any frame
     * within them can be fully decoded within the default 128 MB buffer cap
     * at 32bppBGRA.  Frames above the hint may or may not fit -- we simply
     * choose not to attempt the full allocation, not to skip the frame.
     */
    if (width > policy->softMaxWidth || height > policy->softMaxHeight)
        return BUDGET_METADATA_ONLY;

    /* Use fallback bpp for conservative buffer estimation when bpp unknown */
    useBpp = (bpp > 0) ? bpp : POLICY_BPP_FALLBACK_MAX;

    /* Overflow-safe stride computation */
    prS = policy_compute_stride(policy, width, useBpp, &stride);
    if (prS != POLICY_OK)
        return BUDGET_METADATA_ONLY;

    /* Overflow-safe buffer computation */
    prB = policy_compute_buffer_size(policy, stride, height, &buf);
    if (prB != POLICY_OK)
        return BUDGET_METADATA_ONLY;

    /* Buffer and stride fit: full decode is safe */
    if (pEstStride) *pEstStride = stride;
    if (pEstBuffer) *pEstBuffer = buf;
    return BUDGET_FULL;
}

/* =========================================================================
 * policy_compute_stride
 *
 * Formula: stride = ((width * bpp + 31) / 32) * 4
 *
 * All intermediate values are computed in UINT64 to prevent silent overflow
 * before the cap comparison.  At max supported dimensions (65535 x 128 bpp):
 *   stride = 1,048,564 bytes (~1 MB) -- well within any reasonable cap.
 * At pathological dimensions (UINT32_MAX x 128 bpp):
 *   intermediate = ~549,755,813,760 -- correctly caught before cast to UINT32.
 * ========================================================================= */
POLICY_RESULT policy_compute_stride(
    const HARNESS_POLICY*   policy,
    UINT                    width,
    UINT                    bpp,
    UINT*                   pStride)
{
    UINT64 w64, aligned64, stride64;

    if (!policy || !pStride) return POLICY_INVALID_ARG;
    if (bpp == 0)             return POLICY_STRIDE_OVERFLOW;

    w64      = (UINT64)width * (UINT64)bpp;
    w64     += 31ULL;
    aligned64 = w64 / 32ULL;
    stride64  = aligned64 * 4ULL;

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
 * stride * height in 64-bit.  At 65535 x 65535 x 128bpp:
 *   stride = 1,048,564; buffer = 68.7 GB > UINT32_MAX > any sane cap.
 * The check catches this before any allocation attempt.
 * ========================================================================= */
POLICY_RESULT policy_compute_buffer_size(
    const HARNESS_POLICY*   policy,
    UINT                    stride,
    UINT                    height,
    UINT*                   pBufferSize)
{
    UINT64 buf64;

    if (!policy || !pBufferSize) return POLICY_INVALID_ARG;

    buf64 = (UINT64)stride * (UINT64)height;

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
 * On any COM query failure with a non-NULL factory: returns
 * POLICY_BPP_FALLBACK_MAX (128).  This over-allocates rather than
 * under-allocates -- critical so that PageHeap can detect real heap
 * overflows that would be masked by an under-sized buffer.
 *
 * Returns 0 only when pFactory is NULL; caller must skip allocation paths.
 * ========================================================================= */
UINT policy_get_bpp_from_guid(
    IWICImagingFactory*         pFactory,
    const WICPixelFormatGUID*   pFmt)
{
    HRESULT              hr;
    IWICComponentInfo*   pInfo    = NULL;
    IWICPixelFormatInfo* pFmtInfo = NULL;
    UINT                 bpp      = 0U;

    if (!pFactory || !pFmt) return 0U;

    hr = pFactory->lpVtbl->CreateComponentInfo(pFactory, pFmt, &pInfo);
    if (FAILED(hr) || !pInfo) { bpp = POLICY_BPP_FALLBACK_MAX; goto done; }

    hr = pInfo->lpVtbl->QueryInterface(
        pInfo, &IID_IWICPixelFormatInfo, (void**)&pFmtInfo);
    if (FAILED(hr) || !pFmtInfo) { bpp = POLICY_BPP_FALLBACK_MAX; goto done; }

    hr = pFmtInfo->lpVtbl->GetBitsPerPixel(pFmtInfo, &bpp);
    if (FAILED(hr) || bpp == 0U)
        bpp = POLICY_BPP_FALLBACK_MAX;

done:
    if (pFmtInfo) pFmtInfo->lpVtbl->Release(pFmtInfo);
    if (pInfo)    pInfo->lpVtbl->Release(pInfo);
    return bpp;
}

/* =========================================================================
 * Diagnostic string helpers
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

const char* policy_budget_string(FRAME_BUDGET budget)
{
    switch (budget) {
    case BUDGET_FULL:          return "BUDGET_FULL";
    case BUDGET_LIGHT:         return "BUDGET_LIGHT";
    case BUDGET_METADATA_ONLY: return "BUDGET_METADATA_ONLY";
    case BUDGET_SKIP:          return "BUDGET_SKIP";
    default:                   return "BUDGET_UNKNOWN";
    }
}
