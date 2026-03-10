/*
 * harness_ini.h
 *
 * INI configuration loader.
 * Reads harness.ini from the same directory as the harness executable.
 * All values have compiled-in defaults (harness_config.h) so the INI
 * file is fully optional — harness runs correctly without it.
 *
 * INI format (Windows GetPrivateProfileInt/String):
 *
 *   [harness]
 *   max_width         = 16384
 *   max_height        = 16384
 *   max_frames        = 256
 *   max_buffer_mb     = 256
 *   iterations        = 5000
 *   conversion_path   = 1
 *   trace_enabled     = 1
 *   metadata_enum     = 1
 *   palette_path      = 1
 *   color_context_path= 1
 *   thumbnail_path    = 1
 *   decoder_info_path = 1
 *   mode              = FUZZ
 *
 */

#ifndef HARNESS_INI_H
#define HARNESS_INI_H

#pragma once

#include <windows.h>
#include "config.h"
#include "policy.h"

 /* =========================================================================
  * Runtime configuration — populated from INI + defaults
  * ========================================================================= */
typedef struct _HARNESS_CONFIG {
    /* Policy */
    HARNESS_POLICY  policy;

    /* Iteration count for standalone mode */
    UINT            iterations;

    /* Coverage path feature flags */
    BOOL            conversionPath;
    BOOL            traceEnabled;
    BOOL            metadataEnum;
    BOOL            palettePath;
    BOOL            colorContextPath;
    BOOL            thumbnailPath;
    BOOL            decoderInfoPath;
    BOOL            transformPath;      /* IWICBitmapSourceTransform (Fix #7) */
    BOOL            progressivePath;   /* IWICProgressiveLevelControl (Fix #8) */
    BOOL            wicConvertPath;    /* WICConvertBitmapSource (Fix #11) */

    /* Build mode override from INI (FUZZ / RESEARCH) */
    BOOL            researchMode;

    /* Trace file path */
    WCHAR           tracePath[HARNESS_TRACE_PATH_MAX];

    /* INI file path (resolved at startup) */
    WCHAR           iniPath[MAX_PATH];

} HARNESS_CONFIG;

/* =========================================================================
 * Function declarations
 * ========================================================================= */

 /*
  * config_init_defaults
  * Populate config with compiled-in defaults.
  * Must be called before config_load_ini.
  */
void config_init_defaults(HARNESS_CONFIG* cfg);

/*
 * config_load_ini
 * Load configuration from INI file.
 * Resolves INI path relative to the harness executable directory.
 * Values missing from INI retain their compiled-in defaults.
 * Returns TRUE if INI was found and parsed, FALSE if not found
 * (defaults are still valid — this is not an error).
 */
BOOL config_load_ini(HARNESS_CONFIG* cfg);

/*
 * config_resolve_trace_path
 * Resolve trace file path relative to executable directory.
 * Called after config_load_ini.
 */
void config_resolve_trace_path(HARNESS_CONFIG* cfg);

/*
 * config_print
 * Print active configuration to trace file and debug output.
 * Called once at startup for research documentation.
 */
void config_print(const HARNESS_CONFIG* cfg, HANDLE hTraceFile);

#endif /* HARNESS_INI_H */
