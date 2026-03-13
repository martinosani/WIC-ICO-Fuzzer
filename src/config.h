/*
 * config.h
 *
 * WIC ICO Fuzzing Harness -- Compile-time Configuration
 * Target: windowscodecs.dll via WIC COM interfaces.
 *
 * Architecture:
 *   COM interfaces only -- no direct DLL imports.
 *   WinAFL persistent mode (Option B):
 *     - COM init + WIC factory: outside fuzz loop (once per process)
 *     - Decoder creation through CopyPixels: inside fuzz loop (every iteration)
 *   TinyInst coverage module: windowscodecs.dll
 *
 * Build variants:
 *   /D HARNESS_MODE_FUZZ      -- WinAFL production run (default)
 *   /D HARNESS_MODE_RESEARCH  -- standalone debugging, SEH logging
 *
 * Metadata cache campaigns:
 *   Default (no flag)         : WICDecodeMetadataCacheOnDemand  (Campaign 1, lazy metadata loading)
 *   /D HARNESS_CACHE_ON_LOAD  : WICDecodeMetadataCacheOnLoad    (Campaign 2, eager metadata loading)
 *
 * -------------------------------------------------------------------------
 * BUG-HUNTING POLICY PHILOSOPHY
 * -------------------------------------------------------------------------
 *
 * The harness protects itself at the point of cost (memory allocation),
 * NOT at input ingress.  Dimension checks are soft hints for budget
 * selection -- they are never binary skip conditions.
 *
 * A frame with an extreme declared size (e.g. width=200000, height=1) still
 * exercises every cheap COM path: GetPixelFormat, GetResolution, CopyPalette,
 * GetColorContexts, GetMetadataQueryReader, GetThumbnail, IWICFormatConverter
 * probe, WICConvertBitmapSource probe, IWICBitmapSourceTransform probe.
 * Only heap-allocation-backed paths (CopyPixels full, CopyPixels partial,
 * full transform/progressive decode) are gated on the FRAME_BUDGET.
 *
 * This design ensures windowscodecs.dll sees every input the fuzzer produces,
 * including the malformed large-dimension inputs that historically trigger
 * real heap overflows.  The harness never acts as a plausibility filter.
 *
 * The real arithmetic safety net: policy_select_budget() in policy.c uses
 * 64-bit overflow-safe arithmetic (policy_compute_stride /
 * policy_compute_buffer_size) to decide the budget.  At extreme dimensions
 * (UINT32_MAX x UINT32_MAX, 128 bpp) the computed buffer is ~2^71 bytes --
 * rejected immediately by the 64-bit buffer cap without any dimension check.
 *
 * -------------------------------------------------------------------------
 * EXECUTION PROFILES
 * -------------------------------------------------------------------------
 *
 * Three built-in profiles control the tradeoff between throughput and
 * coverage depth.  Select via harness.ini:
 *
 *   policy_profile = fast      (max throughput, allocation-free paths only)
 *   policy_profile = balanced  (all paths, budget-gated -- DEFAULT)
 *   policy_profile = deep      (all paths, max allocation budget, low iter)
 *
 * Individual INI keys override profile presets.
 */

#ifndef HARNESS_CONFIG_H
#define HARNESS_CONFIG_H

#pragma once

/* =========================================================================
 * Build mode selection
 * ========================================================================= */
#if !defined(HARNESS_MODE_FUZZ) && !defined(HARNESS_MODE_RESEARCH)
#define HARNESS_MODE_FUZZ
#endif

/* =========================================================================
 * Soft dimension hints (bug-hunting oriented)
 *
 * Used ONLY by policy_select_budget() to select BUDGET_FULL vs
 * BUDGET_METADATA_ONLY.  Never used as a hard skip condition.
 *
 * Frames above these values → BUDGET_METADATA_ONLY (cheap paths run, no
 * large CopyPixels allocation).
 * Frames at or below  → BUDGET_FULL (all paths including CopyPixels).
 *
 * These exist because at 65535x65535 with 32bppBGRA the buffer is ~16 GB,
 * which must be caught by the arithmetic cap anyway.  The soft hints allow
 * the budget selector to avoid even attempting the 64-bit multiply for
 * obviously extreme inputs, keeping the decision fast.
 * ========================================================================= */
#define POLICY_SOFT_MAX_WIDTH           65535U
#define POLICY_SOFT_MAX_HEIGHT          65535U

/* =========================================================================
 * Balanced-profile policy limits (compiled-in defaults)
 * ========================================================================= */

/* Hard allocation cap -- the true harness safety net (128 MB default) */
#define POLICY_MAX_BUFFER_BYTES         (128U * 1024U * 1024U)

/* Row stride cap -- equal to buffer cap for arithmetic consistency */
#define POLICY_MAX_STRIDE               (128U * 1024U * 1024U)

/* Maximum frames processed per ICO file */
#define POLICY_MAX_FRAMES               256U

/* Maximum IWICColorContext objects per GetColorContexts call */
#define POLICY_MAX_COLOR_CONTEXTS       64U

/* Maximum palette color entries */
#define POLICY_MAX_PALETTE_COLORS       4096U

/* Maximum metadata items per single IWICEnumMetadataItem reader */
#define POLICY_MAX_METADATA_ITEMS       4096U

/* Maximum total metadata items across ALL readers per fuzz_target() call */
#define POLICY_MAX_TOTAL_METADATA_ITEMS 8192U

/* =========================================================================
 * Profile presets
 *
 * fast:     High throughput.  No allocation-heavy paths.  No metadata,
 *           transform, progressive, thumbnail.  Suitable for large corpora
 *           and initial corpus coverage phases.
 *
 * balanced: All paths enabled, budget-gated allocation.  Optimal for
 *           sustained WinAFL+TinyInst campaigns.  DEFAULT.
 *
 * deep:     Maximum coverage depth.  Large allocation budget, rich metadata
 *           enumeration, all paths.  Pair with frequent process restart
 *           (iterations=200) and PageHeap enabled on windowscodecs.dll.
 * ========================================================================= */

/* ---- fast ---- */
#define PROFILE_FAST_MAX_BUFFER_BYTES         (32U  * 1024U * 1024U)
#define PROFILE_FAST_MAX_STRIDE               (32U  * 1024U * 1024U)
#define PROFILE_FAST_MAX_TOTAL_METADATA       2048U
#define PROFILE_FAST_MAX_METADATA_ITEMS       512U
#define PROFILE_FAST_ITERATIONS               10000U
#define PROFILE_FAST_CONVERSION_PATH          0
#define PROFILE_FAST_METADATA_ENUM            0
#define PROFILE_FAST_PALETTE_PATH             1
#define PROFILE_FAST_COLOR_CONTEXT_PATH       0
#define PROFILE_FAST_THUMBNAIL_PATH           0
#define PROFILE_FAST_DECODER_INFO_PATH        0
#define PROFILE_FAST_TRANSFORM_PATH           0
#define PROFILE_FAST_PROGRESSIVE_PATH         0
#define PROFILE_FAST_WIC_CONVERT_PATH         0

/* ---- balanced ---- */
#define PROFILE_BALANCED_MAX_BUFFER_BYTES     (128U * 1024U * 1024U)
#define PROFILE_BALANCED_MAX_STRIDE           (128U * 1024U * 1024U)
#define PROFILE_BALANCED_MAX_TOTAL_METADATA   8192U
#define PROFILE_BALANCED_MAX_METADATA_ITEMS   4096U
#define PROFILE_BALANCED_ITERATIONS           5000U
#define PROFILE_BALANCED_CONVERSION_PATH      1
#define PROFILE_BALANCED_METADATA_ENUM        1
#define PROFILE_BALANCED_PALETTE_PATH         1
#define PROFILE_BALANCED_COLOR_CONTEXT_PATH   1
#define PROFILE_BALANCED_THUMBNAIL_PATH       1
#define PROFILE_BALANCED_DECODER_INFO_PATH    1
#define PROFILE_BALANCED_TRANSFORM_PATH       1
#define PROFILE_BALANCED_PROGRESSIVE_PATH     1
#define PROFILE_BALANCED_WIC_CONVERT_PATH     1

/* ---- deep ---- */
#define PROFILE_DEEP_MAX_BUFFER_BYTES         (256U * 1024U * 1024U)
#define PROFILE_DEEP_MAX_STRIDE               (256U * 1024U * 1024U)
#define PROFILE_DEEP_MAX_TOTAL_METADATA       65536U
#define PROFILE_DEEP_MAX_METADATA_ITEMS       16384U
#define PROFILE_DEEP_ITERATIONS               200U
#define PROFILE_DEEP_CONVERSION_PATH          1
#define PROFILE_DEEP_METADATA_ENUM            1
#define PROFILE_DEEP_PALETTE_PATH             1
#define PROFILE_DEEP_COLOR_CONTEXT_PATH       1
#define PROFILE_DEEP_THUMBNAIL_PATH           1
#define PROFILE_DEEP_DECODER_INFO_PATH        1
#define PROFILE_DEEP_TRANSFORM_PATH           1
#define PROFILE_DEEP_PROGRESSIVE_PATH         1
#define PROFILE_DEEP_WIC_CONVERT_PATH         1

/* =========================================================================
 * Compiled-in defaults (balanced profile)
 * ========================================================================= */
#define HARNESS_ITERATIONS_DEFAULT          PROFILE_BALANCED_ITERATIONS
#define HARNESS_CONVERSION_PATH_DEFAULT     PROFILE_BALANCED_CONVERSION_PATH
#define HARNESS_TRACE_ENABLED_DEFAULT       1
#define HARNESS_METADATA_ENUM_DEFAULT       PROFILE_BALANCED_METADATA_ENUM
#define HARNESS_PALETTE_PATH_DEFAULT        PROFILE_BALANCED_PALETTE_PATH
#define HARNESS_COLOR_CONTEXT_PATH_DEFAULT  PROFILE_BALANCED_COLOR_CONTEXT_PATH
#define HARNESS_THUMBNAIL_PATH_DEFAULT      PROFILE_BALANCED_THUMBNAIL_PATH
#define HARNESS_DECODER_INFO_PATH_DEFAULT   PROFILE_BALANCED_DECODER_INFO_PATH
#define HARNESS_TRANSFORM_PATH_DEFAULT      PROFILE_BALANCED_TRANSFORM_PATH
#define HARNESS_PROGRESSIVE_PATH_DEFAULT    PROFILE_BALANCED_PROGRESSIVE_PATH
#define HARNESS_WIC_CONVERT_PATH_DEFAULT    PROFILE_BALANCED_WIC_CONVERT_PATH

/* =========================================================================
 * Trace configuration
 * ========================================================================= */
#define HARNESS_TRACE_PATH_MAX      512U
#define HARNESS_TRACE_FILE_DEFAULT  L"harness_trace.txt"
#define HARNESS_NO_FRAME            0xFFFFFFFFU

/* =========================================================================
 * INI configuration
 * ========================================================================= */
#define HARNESS_INI_FILE_DEFAULT            L"harness.ini"
#define INI_VALUE_MAX_LEN                   64U
#define INI_SECTION_HARNESS                 L"harness"

/* Profile key */
#define INI_KEY_POLICY_PROFILE              L"policy_profile"

/* Policy keys */
#define INI_KEY_MAX_WIDTH                   L"max_width"
#define INI_KEY_MAX_HEIGHT                  L"max_height"
#define INI_KEY_MAX_FRAMES                  L"max_frames"
#define INI_KEY_MAX_BUFFER_MB               L"max_buffer_mb"
#define INI_KEY_MAX_STRIDE_MB               L"max_stride_mb"
#define INI_KEY_MAX_COLOR_CONTEXTS          L"max_color_contexts"
#define INI_KEY_MAX_PALETTE_COLORS          L"max_palette_colors"
#define INI_KEY_MAX_METADATA_ITEMS          L"max_metadata_items"
#define INI_KEY_MAX_TOTAL_METADATA_ITEMS    L"max_total_metadata_items"

/* Behaviour keys */
#define INI_KEY_ITERATIONS                  L"iterations"
#define INI_KEY_CONVERSION_PATH             L"conversion_path"
#define INI_KEY_TRACE_ENABLED               L"trace_enabled"
#define INI_KEY_METADATA_ENUM               L"metadata_enum"
#define INI_KEY_PALETTE_PATH                L"palette_path"
#define INI_KEY_COLOR_CONTEXT_PATH          L"color_context_path"
#define INI_KEY_THUMBNAIL_PATH              L"thumbnail_path"
#define INI_KEY_DECODER_INFO_PATH           L"decoder_info_path"
#define INI_KEY_TRANSFORM_PATH              L"transform_path"
#define INI_KEY_PROGRESSIVE_PATH            L"progressive_path"
#define INI_KEY_WIC_CONVERT_PATH            L"wic_convert_path"
#define INI_KEY_MODE                        L"mode"

/* =========================================================================
 * COM / WIC
 * ========================================================================= */
#define HARNESS_CONVERT_TARGET_FORMAT   GUID_WICPixelFormat32bppBGRA
#define HARNESS_CONVERT_BPP             4U

#ifdef HARNESS_CACHE_ON_LOAD
#define HARNESS_DECODE_OPTIONS  WICDecodeMetadataCacheOnLoad
#else
#define HARNESS_DECODE_OPTIONS  WICDecodeMetadataCacheOnDemand
#endif

#define WINAFL_TARGET_FUNCTION  fuzz_target

/* =========================================================================
 * Platform requirements
 * ========================================================================= */
#ifndef _WIN64
#error "This harness targets x64 only. Build with the x64 configuration."
#endif

#ifndef _MSC_VER
#error "This harness requires MSVC. Use the Visual Studio x64 toolchain."
#endif

#pragma warning(disable: 4995)
#pragma warning(disable: 4996)

#endif /* HARNESS_CONFIG_H */
