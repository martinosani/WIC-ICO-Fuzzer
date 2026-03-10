/*
 * harness_config.h
 *
 * WIC ICO Fuzzing Harness — Configuration Header  [v2]
 * Target: windowscodecs.dll
 *
 * v2 changes:
 *   - Added HARNESS_CACHE_ON_DEMAND flag for second campaign mode (Fix #15)
 *   - Added HARNESS_TRANSFORM_PATH_DEFAULT, HARNESS_PROGRESSIVE_PATH_DEFAULT,
 *     HARNESS_WIC_CONVERT_PATH_DEFAULT for new coverage paths (Fixes #7,#8,#11)
 *   - IWICImagingFactory2 note added (Fix #3)
 *
 *
 * Architecture:
 *   COM interfaces only — no direct DLL calls
 *   WinAFL persistent mode (Option B):
 *     - COM init + WIC factory: outside fuzz loop (once)
 *     - Decoder creation through CopyPixels: inside fuzz loop
 *   TinyInst coverage module: windowscodecs.dll (full module)
 *
 * Build:
 *   MSVC, static CRT (/MT), x64
 *   FUZZ_MODE   : /D HARNESS_MODE_FUZZ   (default, WinAFL production)
 *   RESEARCH_MODE: /D HARNESS_MODE_RESEARCH (standalone debugging)
 */

#ifndef HARNESS_CONFIG_H
#define HARNESS_CONFIG_H

#pragma once

 /* =========================================================================
  * Build mode selection
  * Define exactly one of these via compiler flag or edit here.
  * HARNESS_MODE_FUZZ     : WinAFL production run, exceptions propagate
  * HARNESS_MODE_RESEARCH : Standalone research run, SEH logging + re-raise
  * ========================================================================= */
#if !defined(HARNESS_MODE_FUZZ) && !defined(HARNESS_MODE_RESEARCH)
#define HARNESS_MODE_FUZZ
#endif

  /* =========================================================================
   * Policy limits — security research tuned
   * These caps prevent resource exhaustion crashes (OOM, timeout) while
   * allowing real heap/stack overflows to reach the allocator and trigger.
   * Do NOT lower these aggressively — overly tight caps hide real bugs.
   * ========================================================================= */

   /* Maximum image dimensions (pixels) */
#define POLICY_MAX_WIDTH            16384U
#define POLICY_MAX_HEIGHT           16384U

/* Maximum per-frame pixel buffer (bytes) — 256 MB */
#define POLICY_MAX_BUFFER_BYTES     (256U * 1024U * 1024U)

/* Maximum stride (bytes per row) */
#define POLICY_MAX_STRIDE           65536U

/* Maximum frames processed per ICO file */
#define POLICY_MAX_FRAMES           256U

/* Maximum color context objects per frame */
#define POLICY_MAX_COLOR_CONTEXTS   8U

/* Maximum palette colors */
#define POLICY_MAX_PALETTE_COLORS   256U

/* Maximum metadata enumeration items per reader */
#define POLICY_MAX_METADATA_ITEMS   512U

/* =========================================================================
 * Persistent mode configuration
 * HARNESS_ITERATIONS : standalone loop count (overridden by WinAFL
 *                      -fuzz_iterations at runtime)
 * ========================================================================= */
#define HARNESS_ITERATIONS_DEFAULT  5000U

 /* =========================================================================
  * Coverage path feature flags
  * Controlled at runtime via .ini — these are compiled-in defaults.
  * ========================================================================= */

  /* Enable optional IWICFormatConverter path (BGRA32 conversion) */
#define HARNESS_CONVERSION_PATH_DEFAULT     1

/* Enable trace file output */
#define HARNESS_TRACE_ENABLED_DEFAULT       1

/* Enable container-level metadata enumeration */
#define HARNESS_METADATA_ENUM_DEFAULT       1

/* Enable palette extraction path */
#define HARNESS_PALETTE_PATH_DEFAULT        1

/* Enable color context extraction path */
#define HARNESS_COLOR_CONTEXT_PATH_DEFAULT  1

/* Enable thumbnail/preview extraction path */
#define HARNESS_THUMBNAIL_PATH_DEFAULT      1

/* Enable decoder info path */
#define HARNESS_DECODER_INFO_PATH_DEFAULT   1

/* Enable IWICBitmapSourceTransform scaled decode path (Fix #7) */
#define HARNESS_TRANSFORM_PATH_DEFAULT      1

/* Enable IWICProgressiveLevelControl path for interlaced PNG-in-ICO (Fix #8) */
#define HARNESS_PROGRESSIVE_PATH_DEFAULT    1

/* Enable WICConvertBitmapSource single-call conversion path (Fix #11) */
#define HARNESS_WIC_CONVERT_PATH_DEFAULT    1

/* =========================================================================
 * Trace configuration
 * ========================================================================= */

 /* Maximum trace file path length */
#define HARNESS_TRACE_PATH_MAX      512U

/* Default trace file name (relative to harness .exe directory) */
#define HARNESS_TRACE_FILE_DEFAULT  L"harness_trace.txt"

/* =========================================================================
 * INI configuration file
 * ========================================================================= */
#define HARNESS_INI_FILE_DEFAULT    L"harness.ini"

 /* INI section and key names */
#define INI_SECTION_HARNESS         L"harness"
#define INI_KEY_MAX_WIDTH           L"max_width"
#define INI_KEY_MAX_HEIGHT          L"max_height"
#define INI_KEY_MAX_FRAMES          L"max_frames"
#define INI_KEY_MAX_BUFFER_MB       L"max_buffer_mb"
#define INI_KEY_ITERATIONS          L"iterations"
#define INI_KEY_CONVERSION_PATH     L"conversion_path"
#define INI_KEY_TRACE_ENABLED       L"trace_enabled"
#define INI_KEY_METADATA_ENUM       L"metadata_enum"
#define INI_KEY_PALETTE_PATH        L"palette_path"
#define INI_KEY_COLOR_CONTEXT_PATH  L"color_context_path"
#define INI_KEY_THUMBNAIL_PATH      L"thumbnail_path"
#define INI_KEY_DECODER_INFO_PATH   L"decoder_info_path"
#define INI_KEY_TRANSFORM_PATH      L"transform_path"
#define INI_KEY_PROGRESSIVE_PATH    L"progressive_path"
#define INI_KEY_WIC_CONVERT_PATH    L"wic_convert_path"
#define INI_KEY_MODE                L"mode"

/* =========================================================================
 * COM / WIC target format
 * ========================================================================= */

 /* Output pixel format for IWICFormatConverter conversion path */
 /* GUID_WICPixelFormat32bppBGRA — defined in wincodec.h */
#define HARNESS_CONVERT_TARGET_FORMAT   GUID_WICPixelFormat32bppBGRA

/* Bytes per pixel for 32bppBGRA output */
#define HARNESS_CONVERT_BPP             4U

/* WICDecodeOptions for CreateDecoderFromFilename */
/* WICDecodeMetadataCacheOnLoad: forces all metadata parsing immediately */
#define HARNESS_DECODE_OPTIONS          WICDecodeMetadataCacheOnLoad

/* =========================================================================
 * WinAFL persistent mode target function marker
 * The fuzz_target() function is the persistent loop entry point.
 * TinyInst instruments windowscodecs.dll as the coverage module.
 * WinAFL target: harness.exe!fuzz_target
 * ========================================================================= */
#define WINAFL_TARGET_FUNCTION          fuzz_target

 /* =========================================================================
  * TODO: FORMAT-AWARE MUTATION HOOK
  * Phase 2 insertion point for structure-aware ICO mutation feedback.
  * When Cyrus completes ICO decoder RE, insert format-aware pre-parse
  * validation here to guide mutation toward interesting code paths.
  * Hook signature: void mutation_hook_pre_parse(const WCHAR* path);
  * ========================================================================= */

  /* =========================================================================
   * Future: IStream input path stub
   * #define HARNESS_INPUT_STREAM  (not active — file-based only for now)
   * When enabled, replaces CreateDecoderFromFilename with
   * CreateDecoderFromStream using IWICStream initialized from file.
   * ========================================================================= */
   /* #define HARNESS_INPUT_STREAM */

   /* =========================================================================
	* Fix #15: Second fuzzing campaign — WICDecodeMetadataCacheOnDemand
	*
	* Define HARNESS_CACHE_ON_DEMAND to switch from CacheOnLoad to
	* CacheOnDemand mode. This exercises the lazy metadata parsing paths
	* that Windows applications use by default. Real-world apps that use
	* CacheOnDemand may trigger bugs that CacheOnLoad hides.
	*
	* Usage: rebuild with /D HARNESS_CACHE_ON_DEMAND and run separately.
	* Do NOT combine both campaigns in a single binary — the mode should
	* be fixed per campaign so WinAFL coverage deltas are comparable.
	* ========================================================================= */
	/* #define HARNESS_CACHE_ON_DEMAND */

	/* =========================================================================
	 * Fix #3: IWICImagingFactory2 requirement for CreateColorContext
	 *
	 * IWICImagingFactory does NOT expose CreateColorContext.
	 * The correct interface is IWICImagingFactory2, available via QI from
	 * the factory object. harness_main.c stores g_pFactory2 for this purpose.
	 * ========================================================================= */

	 /* =========================================================================
	  * Compiler / platform
	  * ========================================================================= */
#ifndef _WIN64
#error "This harness targets x64 only. Build with x64 configuration."
#endif

#ifndef _MSC_VER
#error "This harness requires MSVC. Use Visual Studio x64 toolchain."
#endif

	  /* Suppress MSVC warnings for WIC COM interface usage */
#pragma warning(disable: 4995)  /* deprecated function */
#pragma warning(disable: 4996)  /* unsafe function */

#endif /* HARNESS_CONFIG_H */
