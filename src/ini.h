/*
 * ini.h
 *
 * INI configuration loader.
 * Reads harness.ini from the same directory as the harness executable.
 * All values have compiled-in defaults so the INI file is fully optional.
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

void config_init_defaults(HARNESS_CONFIG* cfg);
BOOL config_load_ini(HARNESS_CONFIG* cfg);
void config_resolve_trace_path(HARNESS_CONFIG* cfg);
void config_print(const HARNESS_CONFIG* cfg, HANDLE hTraceFile);

#endif /* HARNESS_INI_H */
