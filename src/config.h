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
 *   FUZZ_MODE    : /D HARNESS_MODE_FUZZ     -- WinAFL production run
 *   RESEARCH_MODE: /D HARNESS_MODE_RESEARCH  -- standalone debugging, SEH logging
 *
 * Metadata cache mode:
 *   Default (no flag) : WICDecodeMetadataCacheOnDemand  -- Campaign 1
 *   /D HARNESS_CACHE_ON_LOAD : WICDecodeMetadataCacheOnLoad -- Campaign 2
 *
 *   CacheOnDemand is the default because it matches how real Windows
 *   applications (Explorer, preview handlers, thumbnail generators) open
 *   ICO files.  Bugs found in this mode are directly exploitable in
 *   real-world attack scenarios.  See README.md for the two-campaign strategy.
 */

#ifndef HARNESS_CONFIG_H
#define HARNESS_CONFIG_H

#pragma once

/* =========================================================================
 * Build mode selection
 * Define exactly one via compiler flag.  Default: FUZZ.
 * ========================================================================= */
#if !defined(HARNESS_MODE_FUZZ) && !defined(HARNESS_MODE_RESEARCH)
#define HARNESS_MODE_FUZZ
#endif

/* =========================================================================
 * Policy limits -- compiled-in defaults.
 *
 * These caps prevent resource-exhaustion OOM/timeout crashes in the harness
 * while allowing real heap overflows to reach the allocator and trigger.
 *
 * Do NOT lower them aggressively.  Tight caps cause the harness to skip
 * inputs that are exactly the interesting mutated cases the fuzzer should
 * be reaching.  The policy rejects only inputs that are genuinely dangerous
 * for the harness itself (integer overflow, uncontrolled allocation) and
 * nothing else.
 *
 * Width/height cap set to 65535: ICO ICONDIRENTRY.bWidth/bHeight are BYTE
 * fields, but the embedded PNG/BMP payload can declare any dimension.
 * Covering up to 65535 ensures we reach all dimensions a real or malformed
 * encoder could emit.
 *
 * Buffer cap (256 MB): at max dimensions (65535 x 65535) and 128 bpp the
 * theoretical buffer is ~68 GB.  The policy rejects those after overflow-safe
 * 64-bit arithmetic; 256 MB is generous enough to pass nearly all real and
 * interesting mutated inputs.
 *
 * maxStride is set equal to maxBufferBytes so the two limits are never
 * contradictory: a stride that individually passes cannot be rejected as
 * inconsistent by the buffer check.
 * ========================================================================= */

/* Maximum decoded frame dimensions (pixels) */
#define POLICY_MAX_WIDTH                65535U
#define POLICY_MAX_HEIGHT               65535U

/* Maximum per-frame pixel buffer (bytes) -- 256 MB */
#define POLICY_MAX_BUFFER_BYTES         (256U * 1024U * 1024U)

/*
 * Maximum row stride (bytes).
 *
 * Set equal to POLICY_MAX_BUFFER_BYTES so the two limits are consistent.
 * At max practical dimensions (65535 px wide, 128 bpp):
 *   stride = ((65535 * 128 + 31) / 32) * 4 = 1,048,564 bytes (~1 MB)
 * which is well within this cap.
 */
#define POLICY_MAX_STRIDE               (256U * 1024U * 1024U)

/* Maximum frames processed per ICO file */
#define POLICY_MAX_FRAMES               256U

/* Maximum IWICColorContext objects per GetColorContexts call */
#define POLICY_MAX_COLOR_CONTEXTS       64U

/* Maximum palette color entries */
#define POLICY_MAX_PALETTE_COLORS       4096U

/* Maximum metadata items per single IWICEnumMetadataItem reader */
#define POLICY_MAX_METADATA_ITEMS       4096U

/*
 * Maximum total metadata items across ALL readers (including recursive
 * sub-readers) per single fuzz_target() invocation.
 *
 * Guards against throughput collapse on pathologically nested malformed
 * metadata.  16384 is large enough to enumerate real-world metadata without
 * cutting off interesting inputs prematurely.
 */
#define POLICY_MAX_TOTAL_METADATA_ITEMS 16384U

/* =========================================================================
 * Persistent mode iteration count
 * Overridden by WinAFL -fuzz_iterations at runtime.
 * ========================================================================= */
#define HARNESS_ITERATIONS_DEFAULT      5000U

/* =========================================================================
 * Coverage path feature flags -- compiled-in defaults.
 * All can be overridden at runtime via harness.ini.
 * ========================================================================= */
#define HARNESS_CONVERSION_PATH_DEFAULT     1
#define HARNESS_TRACE_ENABLED_DEFAULT       1
#define HARNESS_METADATA_ENUM_DEFAULT       1
#define HARNESS_PALETTE_PATH_DEFAULT        1
#define HARNESS_COLOR_CONTEXT_PATH_DEFAULT  1
#define HARNESS_THUMBNAIL_PATH_DEFAULT      1
#define HARNESS_DECODER_INFO_PATH_DEFAULT   1
#define HARNESS_TRANSFORM_PATH_DEFAULT      1
#define HARNESS_PROGRESSIVE_PATH_DEFAULT    1
#define HARNESS_WIC_CONVERT_PATH_DEFAULT    1

/* =========================================================================
 * Trace configuration
 * ========================================================================= */
#define HARNESS_TRACE_PATH_MAX      512U
#define HARNESS_TRACE_FILE_DEFAULT  L"harness_trace.txt"

/* Sentinel value stored in HARNESS_TRACE_CTX.currentFrame when the
 * current operation is at container level (not inside a frame loop). */
#define HARNESS_NO_FRAME            0xFFFFFFFFU

/* =========================================================================
 * INI configuration file
 * ========================================================================= */
#define HARNESS_INI_FILE_DEFAULT            L"harness.ini"

/* Maximum length of a raw INI value string (characters, excluding NUL) */
#define INI_VALUE_MAX_LEN                   64U

/* Section name */
#define INI_SECTION_HARNESS                 L"harness"

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

/* Harness behaviour keys */
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
 * COM / WIC target format
 * ========================================================================= */

/* Output pixel format for IWICFormatConverter and WICConvertBitmapSource.
 * 32bppBGRA is universally supported by all built-in WIC codecs. */
#define HARNESS_CONVERT_TARGET_FORMAT   GUID_WICPixelFormat32bppBGRA

/* Bytes per pixel for BGRA32 -- used in stride computation */
#define HARNESS_CONVERT_BPP             4U

/*
 * Metadata cache mode for CreateDecoderFromFilename.
 *
 * Campaign 1 (default): WICDecodeMetadataCacheOnDemand
 *   Metadata is parsed lazily on first access via GetMetadataQueryReader.
 *   Matches how real Windows applications open ICO files.  Bugs found here
 *   are directly exploitable in real-world scenarios.
 *
 * Campaign 2: build with /D HARNESS_CACHE_ON_LOAD
 *   All metadata is parsed immediately on decoder creation, exercising the
 *   eager metadata path -- a distinct internal implementation.
 *   Keep the output directory separate; coverage bitmaps are not comparable.
 */
#ifdef HARNESS_CACHE_ON_LOAD
#define HARNESS_DECODE_OPTIONS  WICDecodeMetadataCacheOnLoad
#else
#define HARNESS_DECODE_OPTIONS  WICDecodeMetadataCacheOnDemand
#endif

/* WinAFL persistent mode target function name */
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
