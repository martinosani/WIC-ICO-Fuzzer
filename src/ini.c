/*
 * harness_ini.c
 *
 * INI configuration loader implementation.
 *
 */

#include <windows.h>
#include <strsafe.h>
#include <stdio.h>
#include "ini.h"
#include "config.h"
#include "policy.h"

 /* =========================================================================
  * config_init_defaults
  * ========================================================================= */
void config_init_defaults(HARNESS_CONFIG* cfg)
{
    if (!cfg) return;
    ZeroMemory(cfg, sizeof(*cfg));

    policy_init(&cfg->policy);

    cfg->iterations = HARNESS_ITERATIONS_DEFAULT;
    cfg->conversionPath = HARNESS_CONVERSION_PATH_DEFAULT;
    cfg->traceEnabled = HARNESS_TRACE_ENABLED_DEFAULT;
    cfg->metadataEnum = HARNESS_METADATA_ENUM_DEFAULT;
    cfg->palettePath = HARNESS_PALETTE_PATH_DEFAULT;
    cfg->colorContextPath = HARNESS_COLOR_CONTEXT_PATH_DEFAULT;
    cfg->thumbnailPath = HARNESS_THUMBNAIL_PATH_DEFAULT;
    cfg->decoderInfoPath = HARNESS_DECODER_INFO_PATH_DEFAULT;
    cfg->transformPath = HARNESS_TRANSFORM_PATH_DEFAULT;
    cfg->progressivePath = HARNESS_PROGRESSIVE_PATH_DEFAULT;
    cfg->wicConvertPath = HARNESS_WIC_CONVERT_PATH_DEFAULT;

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
    WCHAR   exeDir[MAX_PATH] = { 0 };
    WCHAR   iniPath[MAX_PATH] = { 0 };
    DWORD   attr;
    UINT    uval;

    if (!cfg) return FALSE;

    /* Resolve INI path relative to executable */
    if (!GetModuleFileNameW(NULL, exeDir, MAX_PATH)) return FALSE;

    {
        /* Strip filename to get directory */
        WCHAR* lastSlash = wcsrchr(exeDir, L'\\');
        if (lastSlash) *(lastSlash + 1) = L'\0';
    }

    StringCchPrintfW(iniPath, MAX_PATH, L"%s%s", exeDir, HARNESS_INI_FILE_DEFAULT);
    StringCchCopyW(cfg->iniPath, MAX_PATH, iniPath);

    /* Check if INI exists */
    attr = GetFileAttributesW(iniPath);
    if (attr == INVALID_FILE_ATTRIBUTES) return FALSE;

    /* Load policy values */
    uval = GetPrivateProfileIntW(INI_SECTION_HARNESS, INI_KEY_MAX_WIDTH,
        (INT)cfg->policy.maxWidth, iniPath);
    cfg->policy.maxWidth = (uval > 0 && uval <= 65536U) ? uval : cfg->policy.maxWidth;

    uval = GetPrivateProfileIntW(INI_SECTION_HARNESS, INI_KEY_MAX_HEIGHT,
        (INT)cfg->policy.maxHeight, iniPath);
    cfg->policy.maxHeight = (uval > 0 && uval <= 65536U) ? uval : cfg->policy.maxHeight;

    uval = GetPrivateProfileIntW(INI_SECTION_HARNESS, INI_KEY_MAX_FRAMES,
        (INT)cfg->policy.maxFrames, iniPath);
    cfg->policy.maxFrames = (uval > 0 && uval <= 65535U) ? uval : cfg->policy.maxFrames;

    uval = GetPrivateProfileIntW(INI_SECTION_HARNESS, INI_KEY_MAX_BUFFER_MB,
        (INT)(cfg->policy.maxBufferBytes / (1024 * 1024)), iniPath);
    if (uval > 0 && uval <= 1024U)
        cfg->policy.maxBufferBytes = uval * 1024U * 1024U;

    /* Load feature flags */
    cfg->iterations = GetPrivateProfileIntW(INI_SECTION_HARNESS, INI_KEY_ITERATIONS,
        (INT)cfg->iterations, iniPath);

    cfg->conversionPath = GetPrivateProfileIntW(INI_SECTION_HARNESS, INI_KEY_CONVERSION_PATH,
        cfg->conversionPath, iniPath) ? TRUE : FALSE;

    cfg->traceEnabled = GetPrivateProfileIntW(INI_SECTION_HARNESS, INI_KEY_TRACE_ENABLED,
        cfg->traceEnabled, iniPath) ? TRUE : FALSE;

    cfg->metadataEnum = GetPrivateProfileIntW(INI_SECTION_HARNESS, INI_KEY_METADATA_ENUM,
        cfg->metadataEnum, iniPath) ? TRUE : FALSE;

    cfg->palettePath = GetPrivateProfileIntW(INI_SECTION_HARNESS, INI_KEY_PALETTE_PATH,
        cfg->palettePath, iniPath) ? TRUE : FALSE;

    cfg->colorContextPath = GetPrivateProfileIntW(INI_SECTION_HARNESS, INI_KEY_COLOR_CONTEXT_PATH,
        cfg->colorContextPath, iniPath) ? TRUE : FALSE;

    cfg->thumbnailPath = GetPrivateProfileIntW(INI_SECTION_HARNESS, INI_KEY_THUMBNAIL_PATH,
        cfg->thumbnailPath, iniPath) ? TRUE : FALSE;

    cfg->decoderInfoPath = GetPrivateProfileIntW(INI_SECTION_HARNESS, INI_KEY_DECODER_INFO_PATH,
        cfg->decoderInfoPath, iniPath) ? TRUE : FALSE;

    cfg->transformPath = GetPrivateProfileIntW(INI_SECTION_HARNESS, INI_KEY_TRANSFORM_PATH,
        cfg->transformPath, iniPath) ? TRUE : FALSE;

    cfg->progressivePath = GetPrivateProfileIntW(INI_SECTION_HARNESS, INI_KEY_PROGRESSIVE_PATH,
        cfg->progressivePath, iniPath) ? TRUE : FALSE;

    cfg->wicConvertPath = GetPrivateProfileIntW(INI_SECTION_HARNESS, INI_KEY_WIC_CONVERT_PATH,
        cfg->wicConvertPath, iniPath) ? TRUE : FALSE;

    /* Load mode override */
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
        StringCchCopyW(cfg->tracePath, HARNESS_TRACE_PATH_MAX, HARNESS_TRACE_FILE_DEFAULT);
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
    char    buf[2048];
    DWORD   written;

    if (!cfg) return;

    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "[CONFIG]\r\n"
        "  mode              = %s\r\n"
        "  max_width         = %u\r\n"
        "  max_height        = %u\r\n"
        "  max_frames        = %u\r\n"
        "  max_buffer_mb     = %u\r\n"
        "  max_stride        = %u\r\n"
        "  iterations        = %u\r\n"
        "  conversion_path   = %d\r\n"
        "  trace_enabled     = %d\r\n"
        "  metadata_enum     = %d\r\n"
        "  palette_path      = %d\r\n"
        "  color_context_path= %d\r\n"
        "  thumbnail_path    = %d\r\n"
        "  decoder_info_path = %d\r\n"
        "  transform_path    = %d\r\n"
        "  progressive_path  = %d\r\n"
        "  wic_convert_path  = %d\r\n"
        "  ini_path          = %ws\r\n"
        "\r\n",
        cfg->researchMode ? "RESEARCH" : "FUZZ",
        cfg->policy.maxWidth,
        cfg->policy.maxHeight,
        cfg->policy.maxFrames,
        cfg->policy.maxBufferBytes / (1024 * 1024),
        cfg->policy.maxStride,
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
        cfg->iniPath[0] ? cfg->iniPath : L"(not found — defaults active)"
    );

    if (hTraceFile != INVALID_HANDLE_VALUE)
        WriteFile(hTraceFile, buf, (DWORD)strlen(buf), &written, NULL);

    OutputDebugStringA(buf);
}
