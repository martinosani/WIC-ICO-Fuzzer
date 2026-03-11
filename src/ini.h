/*
 * ini.h
 *
 * INI configuration loader.
 *
 * Reads harness.ini from the same directory as the harness executable.
 * All values have compiled-in defaults from config.h so the INI file is
 * fully optional -- the harness runs correctly without it.
 *
 * Two entry points:
 *   ini_load_policy()   -- load only policy limits into a HARNESS_POLICY
 *   config_load_ini()   -- load full harness config into a HARNESS_CONFIG
 *
 * Integer parsing:
 *   All integer fields are parsed as signed INT via GetPrivateProfileIntW,
 *   then validated against explicit [min, max] ranges before assignment.
 *   Out-of-range or negative values are silently ignored; the compiled-in
 *   default (already set by policy_init / config_init_defaults) is kept.
 */

#ifndef HARNESS_INI_H
#define HARNESS_INI_H

#pragma once

#include <windows.h>
#include "config.h"
#include "policy.h"

/* =========================================================================
 * Runtime configuration -- populated from INI + compiled-in defaults
 * ========================================================================= */
typedef struct _HARNESS_CONFIG {
    /* Policy limits (dimensions, buffer caps, metadata caps) */
    HARNESS_POLICY  policy;

    /* Iteration count for standalone mode (overridden by WinAFL) */
    UINT            iterations;

    /* Coverage path feature flags */
    BOOL            conversionPath;
    BOOL            traceEnabled;
    BOOL            metadataEnum;
    BOOL            palettePath;
    BOOL            colorContextPath;
    BOOL            thumbnailPath;
    BOOL            decoderInfoPath;
    BOOL            transformPath;      /* IWICBitmapSourceTransform */
    BOOL            progressivePath;    /* IWICProgressiveLevelControl */
    BOOL            wicConvertPath;     /* WICConvertBitmapSource */

    /* Build mode (RESEARCH = TRUE enables SEH logging) */
    BOOL            researchMode;

    /* Resolved file paths */
    WCHAR           tracePath[HARNESS_TRACE_PATH_MAX];
    WCHAR           iniPath[MAX_PATH];

} HARNESS_CONFIG;

/* =========================================================================
 * Function declarations
 * ========================================================================= */

/*
 * ini_load_policy
 *
 * Load only the policy-limit keys from iniPath into *policy.
 * *policy must already be initialised (e.g. via policy_init()) before
 * calling this function; keys missing from the INI file keep their
 * existing value.
 *
 * Returns TRUE if the INI file was found and at least opened.
 * Returns FALSE if the file does not exist or iniPath is NULL.
 */
BOOL ini_load_policy(const WCHAR* iniPath, HARNESS_POLICY* policy);

/*
 * config_init_defaults
 *
 * Populate *cfg with compiled-in defaults.  Must be called before
 * config_load_ini() so INI values can override a fully-initialised base.
 */
void config_init_defaults(HARNESS_CONFIG* cfg);

/*
 * config_load_ini
 *
 * Locate harness.ini next to the running executable, parse all keys, and
 * update *cfg in-place.  Keys missing from the INI keep their default.
 *
 * Internally calls ini_load_policy() for the policy sub-set so that the
 * policy parsing logic is not duplicated.
 *
 * Returns TRUE if the INI file was found and processed.
 * Returns FALSE if the file does not exist (defaults remain active).
 */
BOOL config_load_ini(HARNESS_CONFIG* cfg);

/*
 * config_resolve_trace_path
 *
 * Build the trace file path as <exedir>\harness_trace.txt and store it
 * in cfg->tracePath.  Falls back to a relative path if the executable
 * directory cannot be determined.
 */
void config_resolve_trace_path(HARNESS_CONFIG* cfg);

/*
 * config_print
 *
 * Write a human-readable summary of *cfg to hTraceFile and to the
 * debugger via OutputDebugStringA.  Used at harness startup.
 */
void config_print(const HARNESS_CONFIG* cfg, HANDLE hTraceFile);

#endif /* HARNESS_INI_H */
