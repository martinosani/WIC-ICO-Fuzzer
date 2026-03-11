/*
 * ini.c
 *
 * INI configuration loader implementation.
 *
 * Parsing rules:
 *   - All integer keys are read via GetPrivateProfileIntW (returns signed INT).
 *   - Each value is validated against an explicit [min, max] range derived
 *     from the policy semantics before assignment.  A value of 0 or negative,
 *     or a value above the parser-level ceiling, is silently ignored and the
 *     compiled-in default (already set by policy_init) is kept.
 *   - MB-unit keys (max_buffer_mb, max_stride_mb) are clamped to [1, 512] MB
 *     at the parser level; the resulting byte value is then stored.
 *   - The parser-level ceilings are intentionally generous: they exist to
 *     catch genuinely bogus values (e.g. max_width = 2000000000) without
 *     reintroducing the tight policy caps that this harness is designed to
 *     avoid.
 *   - Policy arithmetic logic is NOT duplicated here; ini.c only reads raw
 *     values and normalises them into the HARNESS_POLICY struct.  All
 *     overflow detection happens in policy.c at call time.
 */

#include <windows.h>
#include <strsafe.h>
#include <stdio.h>
#include "ini.h"
#include "config.h"
#include "policy.h"

/* =========================================================================
 * Internal helper: read a UINT from the INI file.
 *
 * Returns the INI value as UINT if it is in [minVal, maxVal].
 * Returns defaultVal otherwise (key absent, negative, or out of range).
 * ========================================================================= */
static UINT ini_read_uint(
    const WCHAR* iniPath,
    const WCHAR* section,
    const WCHAR* key,
    UINT         defaultVal,
    UINT         minVal,
    UINT         maxVal)
{
    INT raw = GetPrivateProfileIntW(section, key, (INT)defaultVal, iniPath);
    if (raw < (INT)minVal) return defaultVal;
    if ((UINT)raw > maxVal) return defaultVal;
    return (UINT)raw;
}

/* =========================================================================
 * ini_load_policy
 *
 * Standalone policy-only loader.  Reads the nine policy limit keys from
 * iniPath and updates the matching fields in *policy.
 *
 * *policy must be fully initialised (via policy_init()) before calling;
 * any key absent from the file keeps its existing value.
 * ========================================================================= */
BOOL ini_load_policy(const WCHAR* iniPath, HARNESS_POLICY* policy)
{
    DWORD attr;
    UINT  uval;

    if (!iniPath || !policy) return FALSE;

    attr = GetFileAttributesW(iniPath);
    if (attr == INVALID_FILE_ATTRIBUTES) return FALSE;

    /* max_width: [1, 65535] */
    uval = ini_read_uint(iniPath, INI_SECTION_HARNESS, INI_KEY_MAX_WIDTH,
                         policy->maxWidth, 1U, 65535U);
    policy->maxWidth = uval;

    /* max_height: [1, 65535] */
    uval = ini_read_uint(iniPath, INI_SECTION_HARNESS, INI_KEY_MAX_HEIGHT,
                         policy->maxHeight, 1U, 65535U);
    policy->maxHeight = uval;

    /* max_frames: [1, 65535] */
    uval = ini_read_uint(iniPath, INI_SECTION_HARNESS, INI_KEY_MAX_FRAMES,
                         policy->maxFrames, 1U, 65535U);
    policy->maxFrames = uval;

    /*
     * max_buffer_mb: [1, 512] MB.
     * Parser ceiling of 512 MB is a generous harness-safety cap.
     * Values are converted to bytes for storage.
     */
    uval = ini_read_uint(iniPath, INI_SECTION_HARNESS, INI_KEY_MAX_BUFFER_MB,
                         policy->maxBufferBytes / (1024U * 1024U),
                         1U, 512U);
    policy->maxBufferBytes = uval * 1024U * 1024U;

    /*
     * max_stride_mb: [1, 512] MB.
     * Stored as bytes.  Keeping stride and buffer caps consistent is the
     * caller's responsibility; the INI simply allows independent tuning.
     */
    uval = ini_read_uint(iniPath, INI_SECTION_HARNESS, INI_KEY_MAX_STRIDE_MB,
                         policy->maxStride / (1024U * 1024U),
                         1U, 512U);
    policy->maxStride = uval * 1024U * 1024U;

    /* max_color_contexts: [1, 256] */
    uval = ini_read_uint(iniPath, INI_SECTION_HARNESS, INI_KEY_MAX_COLOR_CONTEXTS,
                         policy->maxColorContexts, 1U, 256U);
    policy->maxColorContexts = uval;

    /* max_palette_colors: [1, 65536] */
    uval = ini_read_uint(iniPath, INI_SECTION_HARNESS, INI_KEY_MAX_PALETTE_COLORS,
                         policy->maxPaletteColors, 1U, 65536U);
    policy->maxPaletteColors = uval;

    /* max_metadata_items: [1, 65536] -- per-reader limit */
    uval = ini_read_uint(iniPath, INI_SECTION_HARNESS, INI_KEY_MAX_METADATA_ITEMS,
                         policy->maxMetadataItems, 1U, 65536U);
    policy->maxMetadataItems = uval;

    /* max_total_metadata_items: [1, 1048576] -- per-iteration global limit */
    uval = ini_read_uint(iniPath, INI_SECTION_HARNESS, INI_KEY_MAX_TOTAL_METADATA_ITEMS,
                         policy->maxTotalMetadataItems, 1U, 1048576U);
    policy->maxTotalMetadataItems = uval;

    return TRUE;
}

/* =========================================================================
 * config_init_defaults
 * ========================================================================= */
void config_init_defaults(HARNESS_CONFIG* cfg)
{
    if (!cfg) return;
    ZeroMemory(cfg, sizeof(*cfg));

    policy_init(&cfg->policy);

    cfg->iterations       = HARNESS_ITERATIONS_DEFAULT;
    cfg->conversionPath   = HARNESS_CONVERSION_PATH_DEFAULT;
    cfg->traceEnabled     = HARNESS_TRACE_ENABLED_DEFAULT;
    cfg->metadataEnum     = HARNESS_METADATA_ENUM_DEFAULT;
    cfg->palettePath      = HARNESS_PALETTE_PATH_DEFAULT;
    cfg->colorContextPath = HARNESS_COLOR_CONTEXT_PATH_DEFAULT;
    cfg->thumbnailPath    = HARNESS_THUMBNAIL_PATH_DEFAULT;
    cfg->decoderInfoPath  = HARNESS_DECODER_INFO_PATH_DEFAULT;
    cfg->transformPath    = HARNESS_TRANSFORM_PATH_DEFAULT;
    cfg->progressivePath  = HARNESS_PROGRESSIVE_PATH_DEFAULT;
    cfg->wicConvertPath   = HARNESS_WIC_CONVERT_PATH_DEFAULT;

#ifdef HARNESS_MODE_RESEARCH
    cfg->researchMode = TRUE;
#else
    cfg->researchMode = FALSE;
#endif
}

/* =========================================================================
 * config_load_ini
 * ========================================================================= */
BOOL config_load_ini(HARNESS_CONFIG* cfg)
{
    WCHAR iniPath[MAX_PATH] = { 0 };
    WCHAR exeDir[MAX_PATH]  = { 0 };
    DWORD attr;

    if (!cfg) return FALSE;

    /* Locate harness.ini next to the running executable */
    if (!GetModuleFileNameW(NULL, exeDir, MAX_PATH)) return FALSE;

    {
        WCHAR* lastSlash = wcsrchr(exeDir, L'\\');
        if (lastSlash) *(lastSlash + 1) = L'\0';
    }

    StringCchPrintfW(iniPath, MAX_PATH, L"%s%s", exeDir, HARNESS_INI_FILE_DEFAULT);
    StringCchCopyW(cfg->iniPath, MAX_PATH, iniPath);

    attr = GetFileAttributesW(iniPath);
    if (attr == INVALID_FILE_ATTRIBUTES) return FALSE;

    /* Load policy-limit keys via the standalone function */
    ini_load_policy(iniPath, &cfg->policy);

    /* ---- iterations: [1, 1000000] ---- */
    {
        INT rawIter = GetPrivateProfileIntW(
            INI_SECTION_HARNESS, INI_KEY_ITERATIONS,
            (INT)cfg->iterations, iniPath);
        if (rawIter >= 1 && (UINT)rawIter <= 1000000U)
            cfg->iterations = (UINT)rawIter;
    }

    /* ---- Feature flags (0 = disabled, anything else = enabled) ---- */
    cfg->conversionPath = GetPrivateProfileIntW(INI_SECTION_HARNESS,
        INI_KEY_CONVERSION_PATH, cfg->conversionPath, iniPath) ? TRUE : FALSE;

    cfg->traceEnabled = GetPrivateProfileIntW(INI_SECTION_HARNESS,
        INI_KEY_TRACE_ENABLED, cfg->traceEnabled, iniPath) ? TRUE : FALSE;

    cfg->metadataEnum = GetPrivateProfileIntW(INI_SECTION_HARNESS,
        INI_KEY_METADATA_ENUM, cfg->metadataEnum, iniPath) ? TRUE : FALSE;

    cfg->palettePath = GetPrivateProfileIntW(INI_SECTION_HARNESS,
        INI_KEY_PALETTE_PATH, cfg->palettePath, iniPath) ? TRUE : FALSE;

    cfg->colorContextPath = GetPrivateProfileIntW(INI_SECTION_HARNESS,
        INI_KEY_COLOR_CONTEXT_PATH, cfg->colorContextPath, iniPath) ? TRUE : FALSE;

    cfg->thumbnailPath = GetPrivateProfileIntW(INI_SECTION_HARNESS,
        INI_KEY_THUMBNAIL_PATH, cfg->thumbnailPath, iniPath) ? TRUE : FALSE;

    cfg->decoderInfoPath = GetPrivateProfileIntW(INI_SECTION_HARNESS,
        INI_KEY_DECODER_INFO_PATH, cfg->decoderInfoPath, iniPath) ? TRUE : FALSE;

    cfg->transformPath = GetPrivateProfileIntW(INI_SECTION_HARNESS,
        INI_KEY_TRANSFORM_PATH, cfg->transformPath, iniPath) ? TRUE : FALSE;

    cfg->progressivePath = GetPrivateProfileIntW(INI_SECTION_HARNESS,
        INI_KEY_PROGRESSIVE_PATH, cfg->progressivePath, iniPath) ? TRUE : FALSE;

    cfg->wicConvertPath = GetPrivateProfileIntW(INI_SECTION_HARNESS,
        INI_KEY_WIC_CONVERT_PATH, cfg->wicConvertPath, iniPath) ? TRUE : FALSE;

    /* ---- Mode override ---- */
    {
        WCHAR modeBuf[32] = { 0 };
        GetPrivateProfileStringW(INI_SECTION_HARNESS, INI_KEY_MODE,
            L"FUZZ", modeBuf, 32, iniPath);
        if (_wcsicmp(modeBuf, L"RESEARCH") == 0)
            cfg->researchMode = TRUE;
    }

    return TRUE;
}

/* =========================================================================
 * config_resolve_trace_path
 * ========================================================================= */
void config_resolve_trace_path(HARNESS_CONFIG* cfg)
{
    WCHAR exeDir[MAX_PATH] = { 0 };

    if (!cfg) return;

    if (!GetModuleFileNameW(NULL, exeDir, MAX_PATH)) {
        StringCchCopyW(cfg->tracePath, HARNESS_TRACE_PATH_MAX,
            HARNESS_TRACE_FILE_DEFAULT);
        return;
    }

    {
        WCHAR* lastSlash = wcsrchr(exeDir, L'\\');
        if (lastSlash) *(lastSlash + 1) = L'\0';
    }

    StringCchPrintfW(cfg->tracePath, HARNESS_TRACE_PATH_MAX,
        L"%s%s", exeDir, HARNESS_TRACE_FILE_DEFAULT);
}

/* =========================================================================
 * config_print
 * ========================================================================= */
void config_print(const HARNESS_CONFIG* cfg, HANDLE hTraceFile)
{
    char  buf[2048];
    DWORD written;

    if (!cfg) return;

    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "[CONFIG]\r\n"
        "  mode                      = %s\r\n"
        "  max_width                 = %u\r\n"
        "  max_height                = %u\r\n"
        "  max_frames                = %u\r\n"
        "  max_buffer_mb             = %u\r\n"
        "  max_stride_mb             = %u\r\n"
        "  max_color_contexts        = %u\r\n"
        "  max_palette_colors        = %u\r\n"
        "  max_metadata_items        = %u\r\n"
        "  max_total_metadata_items  = %u\r\n"
        "  iterations                = %u\r\n"
        "  conversion_path           = %d\r\n"
        "  trace_enabled             = %d\r\n"
        "  metadata_enum             = %d\r\n"
        "  palette_path              = %d\r\n"
        "  color_context_path        = %d\r\n"
        "  thumbnail_path            = %d\r\n"
        "  decoder_info_path         = %d\r\n"
        "  transform_path            = %d\r\n"
        "  progressive_path          = %d\r\n"
        "  wic_convert_path          = %d\r\n"
        "  ini_path                  = %ws\r\n"
        "\r\n",
        cfg->researchMode ? "RESEARCH" : "FUZZ",
        cfg->policy.maxWidth,
        cfg->policy.maxHeight,
        cfg->policy.maxFrames,
        cfg->policy.maxBufferBytes / (1024U * 1024U),
        cfg->policy.maxStride      / (1024U * 1024U),
        cfg->policy.maxColorContexts,
        cfg->policy.maxPaletteColors,
        cfg->policy.maxMetadataItems,
        cfg->policy.maxTotalMetadataItems,
        cfg->iterations,
        cfg->conversionPath,
        cfg->traceEnabled,
        cfg->metadataEnum,
        cfg->palettePath,
        cfg->colorContextPath,
        cfg->thumbnailPath,
        cfg->decoderInfoPath,
        cfg->transformPath,
        cfg->progressivePath,
        cfg->wicConvertPath,
        cfg->iniPath[0] ? cfg->iniPath : L"(not found -- defaults active)"
    );

    if (hTraceFile != INVALID_HANDLE_VALUE)
        WriteFile(hTraceFile, buf, (DWORD)strlen(buf), &written, NULL);

    OutputDebugStringA(buf);
}
