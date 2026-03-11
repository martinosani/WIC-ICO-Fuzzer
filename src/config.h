/*
 * config.h
 *
 * WIC ICO Fuzzing Harness -- Compile-time Configuration  [v4]
 * Target: windowscodecs.dll
 *
 * Architecture:
 *   COM interfaces only -- no direct DLL calls.
 *   WinAFL persistent mode (Option B):
 *     - COM init + WIC factory: outside fuzz loop (once per process)
 *     - Decoder creation through CopyPixels: inside fuzz loop
 *   TinyInst coverage module: windowscodecs.dll (full module)
 *
 * Build variants:
 *   FUZZ_MODE    : /D HARNESS_MODE_FUZZ    -- WinAFL production run
 *   RESEARCH_MODE: /D HARNESS_MODE_RESEARCH -- standalone debugging, SEH logging
 *
 * Metadata cache mode:
 *   Default (no flag) : WICDecodeMetadataCacheOnDemand  -- Campaign 1
 *   /D HARNESS_CACHE_ON_LOAD : WICDecodeMetadataCacheOnLoad -- Campaign 2
 *
 *   CacheOnDemand is the default because it matches how real Windows
 *   applications (Explorer, preview handlers, thumbnail generators) open
 *   ICO files.  Bugs found in this mode are directly exploitable in
 *   real-world attack scenarios without additional preconditions.
 *   See README.md for a full explanation of the two-campaign strategy.
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
   * Policy limits
   * These caps prevent resource-exhaustion crashes (OOM, timeout) while
   * allowing real heap overflows to reach the allocator and trigger.
   * Do NOT lower them aggressively -- overly tight caps hide real bugs.
   * ========================================================================= */

   /* Maximum decoded frame dimensions (pixels) */
#define POLICY_MAX_WIDTH            16384U
#define POLICY_MAX_HEIGHT           16384U

/* Maximum per-frame pixel buffer (bytes) -- 256 MB */
#define POLICY_MAX_BUFFER_BYTES     (256U * 1024U * 1024U)

/* Maximum stride (bytes per row) */
#define POLICY_MAX_STRIDE           65536U

/* Maximum frames processed per ICO file */
#define POLICY_MAX_FRAMES           256U

/* Maximum IWICColorContext objects per GetColorContexts call */
#define POLICY_MAX_COLOR_CONTEXTS   8U

/* Maximum palette color entries */
#define POLICY_MAX_PALETTE_COLORS   256U

/* Maximum metadata items per single IWICEnumMetadataItem reader */
#define POLICY_MAX_METADATA_ITEMS   512U

/*
 * Maximum total metadata items across all readers (including recursive
 * sub-readers) per single fuzz_target() invocation.  This prevents a
 * deeply nested malformed ICO from consuming unbounded CPU time in the
 * metadata enumeration path, which would collapse fuzzing throughput.
 * Value: MAX_DEPTH(4) * MAX_ITEMS(512) = 2048.
 */
#define POLICY_MAX_TOTAL_METADATA_ITEMS  2048U

 /* =========================================================================
  * Persistent mode iteration count
  * Overridden by WinAFL -fuzz_iterations at runtime.
  * ========================================================================= */
#define HARNESS_ITERATIONS_DEFAULT  5000U

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
#define HARNESS_INI_FILE_DEFAULT    L"harness.ini"

#define INI_SECTION_HARNESS             L"harness"
#define INI_KEY_MAX_WIDTH               L"max_width"
#define INI_KEY_MAX_HEIGHT              L"max_height"
#define INI_KEY_MAX_FRAMES              L"max_frames"
#define INI_KEY_MAX_BUFFER_MB           L"max_buffer_mb"
#define INI_KEY_ITERATIONS              L"iterations"
#define INI_KEY_CONVERSION_PATH         L"conversion_path"
#define INI_KEY_TRACE_ENABLED           L"trace_enabled"
#define INI_KEY_METADATA_ENUM           L"metadata_enum"
#define INI_KEY_PALETTE_PATH            L"palette_path"
#define INI_KEY_COLOR_CONTEXT_PATH      L"color_context_path"
#define INI_KEY_THUMBNAIL_PATH          L"thumbnail_path"
#define INI_KEY_DECODER_INFO_PATH       L"decoder_info_path"
#define INI_KEY_TRANSFORM_PATH          L"transform_path"
#define INI_KEY_PROGRESSIVE_PATH        L"progressive_path"
#define INI_KEY_WIC_CONVERT_PATH        L"wic_convert_path"
#define INI_KEY_MODE                    L"mode"

	  /* =========================================================================
	   * COM / WIC target format
	   * ========================================================================= */

	   /* Output pixel format for the IWICFormatConverter and WICConvertBitmapSource
		* conversion paths.  32bppBGRA is universally supported by all WIC codecs. */
#define HARNESS_CONVERT_TARGET_FORMAT   GUID_WICPixelFormat32bppBGRA

		/* Bytes per pixel for BGRA32 -- used in stride computation */
#define HARNESS_CONVERT_BPP             4U

/*
 * Metadata cache mode for CreateDecoderFromFilename.
 *
 * Campaign 1 (default): WICDecodeMetadataCacheOnDemand
 *   Metadata is parsed lazily on first access via GetMetadataQueryReader.
 *   This is the default mode used by real Windows applications (Explorer,
 *   preview handlers, thumbnail generators).  Bugs found in this path are
 *   directly exploitable in real-world scenarios without additional
 *   preconditions.  The lazy deserialisation code path inside
 *   windowscodecs.dll is distinct from the eager path and has historically
 *   been the location of exploitable vulnerabilities (e.g. CVE-2021-43893).
 *
 * Campaign 2: build with /D HARNESS_CACHE_ON_LOAD
 *   All metadata is parsed immediately on decoder creation.  This exercises
 *   the eager metadata parsing path and maximises internal code coverage on
 *   first contact with the file.  Run with a separate -o output directory
 *   so WinAFL coverage deltas are comparable across campaigns.
 */
#ifdef HARNESS_CACHE_ON_LOAD
#define HARNESS_DECODE_OPTIONS  WICDecodeMetadataCacheOnLoad
#else
#define HARNESS_DECODE_OPTIONS  WICDecodeMetadataCacheOnDemand
#endif

 /* WinAFL persistent mode target function */
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