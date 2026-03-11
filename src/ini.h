/*
 * ini.h
 *
 * INI configuration loader.
 *
 * Reads harness.ini from the same directory as the harness executable.
 * All values have compiled-in defaults so the INI file is fully optional.
 *
 * Profile system:
 *   Setting policy_profile = fast|balanced|deep in harness.ini pre-populates
 *   all feature flags and resource limits as a bundle.  Individual keys
 *   appearing after the profile line override the profile preset.
 *   This enables purpose-built execution profiles for different campaign
 *   phases without manual per-key tuning.
 *
 * Profile definitions (compiled into config.h):
 *   fast     -- max throughput, minimal paths, no allocation-heavy ops
 *   balanced -- all paths, budget-gated allocation (DEFAULT)
 *   deep     -- all paths, max budget, low iterations, frequent restart
 *
 * Integer parsing:
 *   All integer fields parsed as signed INT via GetPrivateProfileIntW,
 *   validated against [min, max] before assignment.  Out-of-range or
 *   negative values are silently ignored; defaults remain active.
 */

#ifndef HARNESS_INI_H
#define HARNESS_INI_H

#pragma once

#include <windows.h>
#include "config.h"
#include "policy.h"

/* =========================================================================
 * Execution profile enum
 * ========================================================================= */
typedef enum _HARNESS_PROFILE {
    PROFILE_BALANCED = 0,   /* default */
    PROFILE_FAST     = 1,
    PROFILE_DEEP     = 2,
} HARNESS_PROFILE;

/* =========================================================================
 * Runtime configuration -- populated from INI + compiled-in defaults
 * ========================================================================= */
typedef struct _HARNESS_CONFIG {
    /* Active execution profile (set from policy_profile= key) */
    HARNESS_PROFILE profile;

    /* Policy limits */
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
    BOOL            transformPath;
    BOOL            progressivePath;
    BOOL            wicConvertPath;

    /* Build mode */
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
 * Load only policy-limit keys from iniPath into *policy.
 * *policy must be initialised before calling.
 */
BOOL ini_load_policy(const WCHAR* iniPath, HARNESS_POLICY* policy);

/*
 * config_init_defaults
 * Populate *cfg with compiled-in defaults (balanced profile).
 * Must be called before config_load_ini().
 */
void config_init_defaults(HARNESS_CONFIG* cfg);

/*
 * config_apply_profile
 * Apply a named profile preset to *cfg.
 * Called internally by config_load_ini() when policy_profile= is found.
 * Can also be called directly before config_load_ini() to set a base profile.
 */
void config_apply_profile(HARNESS_CONFIG* cfg, HARNESS_PROFILE profile);

/*
 * config_load_ini
 * Locate harness.ini next to the running executable, parse all keys,
 * update *cfg in-place.  Profile key is applied first; individual keys
 * override.  Keys missing from INI keep their current value.
 *
 * Returns TRUE if the INI file was found and processed.
 */
BOOL config_load_ini(HARNESS_CONFIG* cfg);

/*
 * config_resolve_trace_path
 * Build the trace file path as <exedir>\harness_trace.txt.
 */
void config_resolve_trace_path(HARNESS_CONFIG* cfg);

/*
 * config_print
 * Write a human-readable config summary to hTraceFile and OutputDebugString.
 */
void config_print(const HARNESS_CONFIG* cfg, HANDLE hTraceFile);

#endif /* HARNESS_INI_H */
