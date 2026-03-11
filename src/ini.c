/*
 * ini.c
 *
 * INI configuration loader implementation.
 *
 * Loading order (later overrides earlier):
 *   1. config_init_defaults()   -- compiled-in balanced profile
 *   2. policy_profile=          -- apply named profile preset
 *   3. individual keys          -- override individual fields
 *
 * This means a user can write:
 *   policy_profile = fast
 *   metadata_enum  = 1
 * to start from the fast profile but re-enable metadata enumeration.
 *
 * Integer parsing:
 *   GetPrivateProfileIntW returns signed INT.  All values are validated
 *   against an explicit [min, max] range before assignment.  Invalid values
 *   are silently ignored; the current value (from default or profile) is kept.
 *
 *   MB-unit keys are clamped to [1, 512] MB at the parser level; the
 *   resulting byte value is then stored.
 */

#include <windows.h>
#include <strsafe.h>
#include <stdio.h>
#include "ini.h"
#include "config.h"
#include "policy.h"

/* =========================================================================
 * Internal: read a UINT from the INI file.
 * Returns INI value if in [minVal, maxVal]; returns defaultVal otherwise.
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
 * ========================================================================= */
BOOL ini_load_policy(const WCHAR* iniPath, HARNESS_POLICY* policy)
{
    DWORD attr;
    UINT  uval;

    if (!iniPath || !policy) return FALSE;
    attr = GetFileAttributesW(iniPath);
    if (attr == INVALID_FILE_ATTRIBUTES) return FALSE;

    /* max_width / max_height: soft hints only [1, 65535] */
    uval = ini_read_uint(iniPath, INI_SECTION_HARNESS, INI_KEY_MAX_WIDTH,
                         policy->softMaxWidth, 1U, 65535U);
    policy->softMaxWidth = uval;

    uval = ini_read_uint(iniPath, INI_SECTION_HARNESS, INI_KEY_MAX_HEIGHT,
                         policy->softMaxHeight, 1U, 65535U);
    policy->softMaxHeight = uval;

    /* max_frames [1, 65535] */
    uval = ini_read_uint(iniPath, INI_SECTION_HARNESS, INI_KEY_MAX_FRAMES,
                         policy->maxFrames, 1U, 65535U);
    policy->maxFrames = uval;

    /* max_buffer_mb [1, 512] */
    uval = ini_read_uint(iniPath, INI_SECTION_HARNESS, INI_KEY_MAX_BUFFER_MB,
                         policy->maxBufferBytes / (1024U * 1024U), 1U, 512U);
    policy->maxBufferBytes = uval * 1024U * 1024U;

    /* max_stride_mb [1, 512] */
    uval = ini_read_uint(iniPath, INI_SECTION_HARNESS, INI_KEY_MAX_STRIDE_MB,
                         policy->maxStride / (1024U * 1024U), 1U, 512U);
    policy->maxStride = uval * 1024U * 1024U;

    /* max_color_contexts [1, 256] */
    uval = ini_read_uint(iniPath, INI_SECTION_HARNESS, INI_KEY_MAX_COLOR_CONTEXTS,
                         policy->maxColorContexts, 1U, 256U);
    policy->maxColorContexts = uval;

    /* max_palette_colors [1, 65536] */
    uval = ini_read_uint(iniPath, INI_SECTION_HARNESS, INI_KEY_MAX_PALETTE_COLORS,
                         policy->maxPaletteColors, 1U, 65536U);
    policy->maxPaletteColors = uval;

    /* max_metadata_items [1, 65536] */
    uval = ini_read_uint(iniPath, INI_SECTION_HARNESS, INI_KEY_MAX_METADATA_ITEMS,
                         policy->maxMetadataItems, 1U, 65536U);
    policy->maxMetadataItems = uval;

    /* max_total_metadata_items [1, 1048576] */
    uval = ini_read_uint(iniPath, INI_SECTION_HARNESS, INI_KEY_MAX_TOTAL_METADATA_ITEMS,
                         policy->maxTotalMetadataItems, 1U, 1048576U);
    policy->maxTotalMetadataItems = uval;

    return TRUE;
}

/* =========================================================================
 * config_apply_profile
 *
 * Apply a named profile preset to *cfg.  Sets all resource limits and
 * feature flags as a bundle.  Individual INI keys parsed after this call
 * override the profile values.
 * ========================================================================= */
void config_apply_profile(HARNESS_CONFIG* cfg, HARNESS_PROFILE profile)
{
    if (!cfg) return;
    cfg->profile = profile;

    switch (profile) {

    case PROFILE_FAST:
        cfg->policy.maxBufferBytes        = PROFILE_FAST_MAX_BUFFER_BYTES;
        cfg->policy.maxStride             = PROFILE_FAST_MAX_STRIDE;
        cfg->policy.maxTotalMetadataItems = PROFILE_FAST_MAX_TOTAL_METADATA;
        cfg->policy.maxMetadataItems      = PROFILE_FAST_MAX_METADATA_ITEMS;
        cfg->iterations                   = PROFILE_FAST_ITERATIONS;
        cfg->conversionPath               = PROFILE_FAST_CONVERSION_PATH;
        cfg->metadataEnum                 = PROFILE_FAST_METADATA_ENUM;
        cfg->palettePath                  = PROFILE_FAST_PALETTE_PATH;
        cfg->colorContextPath             = PROFILE_FAST_COLOR_CONTEXT_PATH;
        cfg->thumbnailPath                = PROFILE_FAST_THUMBNAIL_PATH;
        cfg->decoderInfoPath              = PROFILE_FAST_DECODER_INFO_PATH;
        cfg->transformPath                = PROFILE_FAST_TRANSFORM_PATH;
        cfg->progressivePath              = PROFILE_FAST_PROGRESSIVE_PATH;
        cfg->wicConvertPath               = PROFILE_FAST_WIC_CONVERT_PATH;
        break;

    case PROFILE_DEEP:
        cfg->policy.maxBufferBytes        = PROFILE_DEEP_MAX_BUFFER_BYTES;
        cfg->policy.maxStride             = PROFILE_DEEP_MAX_STRIDE;
        cfg->policy.maxTotalMetadataItems = PROFILE_DEEP_MAX_TOTAL_METADATA;
        cfg->policy.maxMetadataItems      = PROFILE_DEEP_MAX_METADATA_ITEMS;
        cfg->iterations                   = PROFILE_DEEP_ITERATIONS;
        cfg->conversionPath               = PROFILE_DEEP_CONVERSION_PATH;
        cfg->metadataEnum                 = PROFILE_DEEP_METADATA_ENUM;
        cfg->palettePath                  = PROFILE_DEEP_PALETTE_PATH;
        cfg->colorContextPath             = PROFILE_DEEP_COLOR_CONTEXT_PATH;
        cfg->thumbnailPath                = PROFILE_DEEP_THUMBNAIL_PATH;
        cfg->decoderInfoPath              = PROFILE_DEEP_DECODER_INFO_PATH;
        cfg->transformPath                = PROFILE_DEEP_TRANSFORM_PATH;
        cfg->progressivePath              = PROFILE_DEEP_PROGRESSIVE_PATH;
        cfg->wicConvertPath               = PROFILE_DEEP_WIC_CONVERT_PATH;
        break;

    case PROFILE_BALANCED:
    default:
        cfg->policy.maxBufferBytes        = PROFILE_BALANCED_MAX_BUFFER_BYTES;
        cfg->policy.maxStride             = PROFILE_BALANCED_MAX_STRIDE;
        cfg->policy.maxTotalMetadataItems = PROFILE_BALANCED_MAX_TOTAL_METADATA;
        cfg->policy.maxMetadataItems      = PROFILE_BALANCED_MAX_METADATA_ITEMS;
        cfg->iterations                   = PROFILE_BALANCED_ITERATIONS;
        cfg->conversionPath               = PROFILE_BALANCED_CONVERSION_PATH;
        cfg->metadataEnum                 = PROFILE_BALANCED_METADATA_ENUM;
        cfg->palettePath                  = PROFILE_BALANCED_PALETTE_PATH;
        cfg->colorContextPath             = PROFILE_BALANCED_COLOR_CONTEXT_PATH;
        cfg->thumbnailPath                = PROFILE_BALANCED_THUMBNAIL_PATH;
        cfg->decoderInfoPath              = PROFILE_BALANCED_DECODER_INFO_PATH;
        cfg->transformPath                = PROFILE_BALANCED_TRANSFORM_PATH;
        cfg->progressivePath              = PROFILE_BALANCED_PROGRESSIVE_PATH;
        cfg->wicConvertPath               = PROFILE_BALANCED_WIC_CONVERT_PATH;
        break;
    }
}

/* =========================================================================
 * config_init_defaults
 * ========================================================================= */
void config_init_defaults(HARNESS_CONFIG* cfg)
{
    if (!cfg) return;
    ZeroMemory(cfg, sizeof(*cfg));

    policy_init(&cfg->policy);
    config_apply_profile(cfg, PROFILE_BALANCED);

    cfg->traceEnabled = HARNESS_TRACE_ENABLED_DEFAULT;

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

    if (!GetModuleFileNameW(NULL, exeDir, MAX_PATH)) return FALSE;
    {
        WCHAR* lastSlash = wcsrchr(exeDir, L'\\');
        if (lastSlash) *(lastSlash + 1) = L'\0';
    }

    StringCchPrintfW(iniPath, MAX_PATH, L"%s%s", exeDir, HARNESS_INI_FILE_DEFAULT);
    StringCchCopyW(cfg->iniPath, MAX_PATH, iniPath);

    attr = GetFileAttributesW(iniPath);
    if (attr == INVALID_FILE_ATTRIBUTES) return FALSE;

    /* ---- Profile key: read first so individual keys can override ---- */
    {
        WCHAR profBuf[32] = { 0 };
        GetPrivateProfileStringW(INI_SECTION_HARNESS, INI_KEY_POLICY_PROFILE,
            L"balanced", profBuf, 32, iniPath);

        if (_wcsicmp(profBuf, L"fast") == 0)
            config_apply_profile(cfg, PROFILE_FAST);
        else if (_wcsicmp(profBuf, L"deep") == 0)
            config_apply_profile(cfg, PROFILE_DEEP);
        else
            config_apply_profile(cfg, PROFILE_BALANCED);
    }

    /* ---- Policy limits (individual overrides) ---- */
    ini_load_policy(iniPath, &cfg->policy);

    /* ---- iterations [1, 1000000] ---- */
    {
        INT rawIter = GetPrivateProfileIntW(
            INI_SECTION_HARNESS, INI_KEY_ITERATIONS,
            (INT)cfg->iterations, iniPath);
        if (rawIter >= 1 && (UINT)rawIter <= 1000000U)
            cfg->iterations = (UINT)rawIter;
    }

    /* ---- Feature flags ---- */
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
static const char* profile_name_str(HARNESS_PROFILE p)
{
    switch (p) {
    case PROFILE_FAST:     return "fast";
    case PROFILE_DEEP:     return "deep";
    case PROFILE_BALANCED: return "balanced";
    default:               return "unknown";
    }
}

void config_print(const HARNESS_CONFIG* cfg, HANDLE hTraceFile)
{
    char  buf[2048];
    DWORD written;

    if (!cfg) return;

    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "[CONFIG]\r\n"
        "  mode                      = %s\r\n"
        "  policy_profile            = %s\r\n"
        "  soft_max_width            = %u\r\n"
        "  soft_max_height           = %u\r\n"
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
        profile_name_str(cfg->profile),
        cfg->policy.softMaxWidth,
        cfg->policy.softMaxHeight,
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
