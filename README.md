# WIC ICO Fuzzing Harness

A WinAFL persistent-mode fuzzing harness targeting `windowscodecs.dll` through the Windows Imaging Component (WIC) COM interface, with a specific focus on the ICO container format and its embedded PNG and BMP payloads. The objective is to discover memory corruption vulnerabilities, integer overflows, and parsing logic bugs in the ICO decoder — bugs that are directly reachable from real Windows applications without any privilege escalation precondition.

---

## Table of Contents

1. [Background and Motivation](#1-background-and-motivation)
2. [Attack Surface Overview](#2-attack-surface-overview)
3. [Harness Architecture](#3-harness-architecture)
4. [Coverage Paths](#4-coverage-paths)
5. [Policy System](#5-policy-system)
6. [Build System Requirements](#6-build-system-requirements)
7. [Building the Harness](#7-building-the-harness)
8. [Environment Setup](#8-environment-setup)
9. [Seed Corpus Preparation](#9-seed-corpus-preparation)
10. [WinAFL and TinyInst Setup](#10-winafl-and-tinyinst-setup)
11. [Launching Fuzzing Campaigns](#11-launching-fuzzing-campaigns)
12. [Monitoring and Triage](#12-monitoring-and-triage)
13. [Reproducing and Debugging Crashes](#13-reproducing-and-debugging-crashes)
14. [Configuration Reference](#14-configuration-reference)
15. [Source File Map](#15-source-file-map)
16. [Known Vulnerability Classes](#16-known-vulnerability-classes)

---

## 1. Background and Motivation

`windowscodecs.dll` is a kernel-adjacent user-mode DLL loaded into virtually every Windows process that renders images. Shell extensions, preview handlers, thumbnail generators, the Windows Photo app, Office, browsers via DirectX surface composition, and countless third-party applications all funnel image parsing through WIC. An attacker who controls a malformed ICO file placed in a network share, sent as an email attachment, or embedded in a document can trigger parsing in `windowscodecs.dll` without any explicit user action beyond navigating to a folder.

ICO is a container format that packs multiple image frames at different sizes and bit depths into a single file. Each frame can be either a legacy BMP-style payload (BITMAPINFOHEADER + XOR/AND mask bitmaps) or, since Windows Vista, a full embedded PNG stream. This dual-format nature creates a large heterogeneous parsing surface: the ICO container parser, the BMP raster decoder, the PNG decoder (with its own zlib decompressor and progressive/interlaced paths), palette reconstruction logic, ICC profile parsing, and the metadata engine are all reachable from a single ICO file.

Historical CVEs in `windowscodecs.dll` demonstrate that this surface produces high-severity exploitable bugs: heap overflows in the BMP height calculation (negative height values in BITMAPINFOHEADER), integer overflows in palette size fields, out-of-bounds reads during metadata enumeration, and use-after-free conditions during format converter initialization. This harness is designed to maximize coverage of all those paths simultaneously in a single fuzzing campaign.

---

## 2. Attack Surface Overview

### ICO container parser

The ICO file begins with an `ICONDIR` header followed by an array of `ICONDIRENTRY` structures. Each entry declares a frame size (`bWidth`, `bHeight` as BYTE fields — capped at 255 in the spec, but the actual PNG/BMP payload inside can declare any dimension), a bit depth, a palette color count, and an offset/size pair pointing to the payload data. Discrepancies between the ICONDIRENTRY-declared dimensions and the actual payload dimensions are a known bug class: the decoder may use one value for allocation and the other for the copy, producing a classic under-allocation followed by a heap write overrun.

### BMP payload path

BMP-payload frames are decoded via a BITMAPINFOHEADER read. Negative height values are meaningful in BMP (top-down vs bottom-up orientation) but create sign-extension hazards in size calculations. The AND mask appended after the XOR bitmap in ICO-style BMP frames is an additional source of off-by-one bugs that differ from standard BMP decoding.

### PNG payload path

PNG-payload frames (indicated by the `\x89PNG` magic at the frame payload offset) are decoded by an internal libpng instance inside `windowscodecs.dll`. This path includes:

- `IHDR` chunk parsing (width, height, bit depth, color type, interlace method)
- `PLTE` palette chunk parsing
- `tEXt`, `iTXt`, `zTXt` metadata chunks (text with optional zlib compression)
- `iCCP` ICC color profile chunk (variable-length binary, historically a good overflow target)
- `eXIf` EXIF data chunk
- `IDAT` chunk streaming and zlib decompression
- Adam7 interlaced decode (7-pass, each pass with different per-row dimensions)

### Metadata engine

WIC exposes a generic metadata query engine (`IWICMetadataQueryReader`) that is separate from and layered on top of the format-specific parsers. Metadata items can be nested: a PNG `iTXt` chunk can contain an XMP block, which the metadata engine exposes as a `VT_UNKNOWN` containing a nested `IWICMetadataQueryReader`. The harness performs recursive descent into all nested readers, exercising the allocation and lifetime management of the metadata engine alongside the underlying chunk parsers.

### Format converter path

`IWICFormatConverter` converts between pixel formats (e.g. 8bpp palette-indexed to 32bppBGRA). The converter has its own internal buffer allocation and per-pixel conversion loop. `WICConvertBitmapSource` is a distinct API that exercises a different internal code path — it does not call `CanConvert` and uses a different allocation strategy.

---

## 3. Harness Architecture

### Persistent mode design

The harness uses WinAFL Option B (persistent mode). COM initialization and WIC factory creation happen once at process startup in `harness_global_init()` and remain alive for the entire process lifetime. `fuzz_target()` is the hot loop: it creates a decoder, exercises every COM path, releases all per-iteration COM objects, and returns. WinAFL calls `fuzz_target()` directly in a tight loop without process restart, giving throughput of thousands of iterations per second rather than tens.

```
Process startup
  └── harness_global_init()
        ├── config_init_defaults() + config_load_ini()
        ├── CoInitializeEx(COINIT_APARTMENTTHREADED)
        ├── CoCreateInstance(CLSID_WICImagingFactory)
        └── QI -> IWICImagingFactory2
 
  [WinAFL loop]
  └── fuzz_target(filePath)  ← called N times per process lifetime
        ├── CreateDecoderFromFilename
        ├── [container-level paths]
        ├── GetFrameCount
        ├── for each frame:
        │     ├── GetFrame / GetSize / GetPixelFormat / GetResolution
        │     ├── policy_validate_dimensions
        │     ├── CopyPixels (full rect)
        │     ├── CopyPixels (partial rect)
        │     ├── IWICFormatConverter path
        │     ├── WICConvertBitmapSource path
        │     ├── IWICBitmapSourceTransform path
        │     ├── IWICProgressiveLevelControl path
        │     ├── palette, color contexts, metadata, thumbnail
        │     └── SAFE_RELEASE all frame COM objects
        ├── out-of-bounds frame index probes
        └── SAFE_RELEASE decoder

Process exit
  └── harness_global_cleanup()
        ├── SAFE_RELEASE factory objects
        └── CoUninitialize()
```

### COM interface chain

The harness uses exclusively C-style COM (`COBJMACROS`, `pObj->lpVtbl->Method()`). All interface pointers are obtained via `QueryInterface` — never via raw pointer casts — because vtable slot ordering for inherited interfaces is implementation-defined in C and a raw cast is undefined behaviour.

Interfaces exercised per iteration:

| Interface | Source |
|---|---|
| `IWICImagingFactory` | `CoCreateInstance(CLSID_WICImagingFactory)` |
| `IWICImagingFactory2` | `QI` from factory (for `CreateColorContext`) |
| `IWICBitmapDecoder` | `CreateDecoderFromFilename` |
| `IWICBitmapDecoderInfo` | `GetDecoderInfo` |
| `IWICBitmapFrameDecode` | `GetFrame(i)` |
| `IWICBitmapSource` | `QI` from frame / converter |
| `IWICFormatConverter` | `CreateFormatConverter` |
| `IWICMetadataQueryReader` | `GetMetadataQueryReader` (container + frame) |
| `IWICEnumMetadataItem` | `GetEnumerator` |
| `IWICPalette` | `CreatePalette` + `CopyPalette` |
| `IWICColorContext` | `CreateColorContext` + `GetColorContexts` |
| `IWICComponentInfo` / `IWICPixelFormatInfo` | `CreateComponentInfo` (bpp resolution) |
| `IWICBitmapSourceTransform` | `QI` from frame |
| `IWICProgressiveLevelControl` | `QI` from frame |

### Metadata cache campaigns

Two mutually exclusive compile-time modes exercise distinct internal code paths:

**Campaign 1 — `WICDecodeMetadataCacheOnDemand` (default)**  
The decoder is created without parsing any metadata. Metadata is parsed lazily the first time `GetMetadataQueryReader` is called. This is how Explorer, thumbnail generators, and preview handlers open ICO files. Bugs in this path are reachable from a remote file share with no user action beyond folder navigation. The lazy deserialisation code within `windowscodecs.dll` is a historically vulnerability-rich area.

**Campaign 2 — `WICDecodeMetadataCacheOnLoad`**  
All metadata is parsed immediately inside `CreateDecoderFromFilename`. This exercises the eager path — a distinct internal implementation. Running both campaigns maximizes total coverage.

---

## 4. Coverage Paths

Every path is independently togglable via `harness.ini`. All are enabled by default.

### Stage sequence within fuzz_target()

| Stage | ID | What it exercises |
|---|---|---|
| `STAGE_DECODER_CREATE` | 1 | File signature detection, ICONDIR initial read, codec selection |
| `STAGE_QUERY_CAPABILITY` | 2 | `QueryCapability` via `IStream` — distinct from decoder creation path |
| `STAGE_CONTAINER_FORMAT` | 3 | `GetContainerFormat` GUID verification |
| `STAGE_DECODER_INFO` | 4 | `GetDecoderInfo`: MIME types, extensions, multi-frame/lossless/animation flags |
| `STAGE_CONTAINER_METADATA` | 5 | Container-level `IWICMetadataQueryReader` + recursive enumeration |
| `STAGE_CONTAINER_PALETTE` | 6 | Container-level `CopyPalette` |
| `STAGE_COLOR_CONTEXTS` | 7 | Container-level `GetColorContexts` (ICC profile parsing) |
| `STAGE_PREVIEW` | 8 | `GetPreview` |
| `STAGE_THUMBNAIL_CONTAINER` | 9 | Container-level `GetThumbnail` |
| `STAGE_FRAME_COUNT` | 10 | `GetFrameCount` |
| `STAGE_FRAME_GET` | 11 | `GetFrame(i)` — ICONDIRENTRY[i] parsing, payload type detection |
| `STAGE_FRAME_SIZE` | 12 | `GetSize` + policy dimension validation |
| `STAGE_FRAME_PIXEL_FORMAT` | 13 | `GetPixelFormat` + bpp resolution via `IWICPixelFormatInfo` |
| `STAGE_FRAME_RESOLUTION` | 14 | `GetResolution` (DPI fields — overflow surface in some codecs) |
| `STAGE_FRAME_PALETTE` | 15 | Frame `CopyPalette` + `GetColors` — primary target for 1/4/8bpp |
| `STAGE_FRAME_COLOR_CONTEXTS` | 16 | Frame `GetColorContexts` — `iCCP` chunk in PNG-in-ICO |
| `STAGE_FRAME_METADATA` | 17 | Frame metadata recursive descent |
| `STAGE_FRAME_THUMBNAIL` | 18 | Frame `GetThumbnail` |
| `STAGE_COPY_PIXELS` | 19 | **Primary bug trigger**: full-rect `CopyPixels`, heap-allocated buffer |
| `STAGE_COPY_PIXELS_PARTIAL` | 24 | Partial-rect `CopyPixels` (top-left quadrant) — exercises sub-rect offset arithmetic |
| `STAGE_CONVERTER_INIT` | 20 | `IWICFormatConverter::Initialize` (with and without `CanConvert` in RESEARCH mode) |
| `STAGE_CONVERTER_COPY` | 21 | Converter `CopyPixels` to BGRA32 |
| `STAGE_TRANSFORM` | 25 | `IWICBitmapSourceTransform::CopyPixels` at half scale |
| `STAGE_PROGRESSIVE` | 26 | `IWICProgressiveLevelControl`: `SetCurrentLevel` + `CopyPixels` per level |
| `STAGE_WIC_CONVERT` | 28 | `WICConvertBitmapSource` — distinct internal conversion path |
| `STAGE_FRAME_OOB` | 27 | Out-of-bounds `GetFrame` probes: `count`, `0xFFFF`, `0xFFFFFFFF`, `0x80000000` |

### Out-of-bounds frame index probes

After the frame loop, the harness probes four boundary conditions on `GetFrame`:

- `GetFrame(uFrameCount)` — one past the last valid index
- `GetFrame(0xFFFF)` — ICO format maximum (ICONDIR can declare up to 65535 entries)
- `GetFrame(0xFFFFFFFF)` — full UINT32 range
- `GetFrame(0x80000000)` — sign-bit probe (detects signed/unsigned confusion in index validation)

Any `S_OK` return from a probe is a high-confidence indicator of an index validation bug.

### Metadata recursive descent

`process_metadata_reader()` recursively follows `VT_UNKNOWN` values in `IWICEnumMetadataItem` results: a `VT_UNKNOWN` may expose `IWICMetadataQueryReader` via `QueryInterface`, indicating an embedded sub-reader (e.g. an EXIF block inside a PNG iTXt chunk). The harness descends up to `HARNESS_METADATA_MAX_DEPTH` (4) levels. After enumeration, it also queries four known key paths via `GetMetadataByName`:

```
/iCCP/ProfileName
/tEXt/Comment
/iTXt/TextEntry
/[0]ifd/{ushort=274}   (EXIF orientation tag)
```

These named-lookup calls exercise a separate code path from the enumerator inside the metadata engine.

---

## 5. Policy System

The policy module (`policy.c` / `policy.h`) performs all arithmetic needed before a heap allocation. Its design goal is to reject only inputs that would harm the harness itself — integer overflow in size calculations, or an allocation that would exhaust available memory — and nothing else. All other inputs, including large, unusual, or malformed ones, are passed through to `windowscodecs.dll`.

### 64-bit arithmetic for stride and buffer

Both `policy_compute_stride` and `policy_compute_buffer_size` use `UINT64` intermediates.

Stride computation:

```c
UINT64 w64     = (UINT64)width * (UINT64)bpp;
w64           += 31ULL;
UINT64 aligned = w64 / 32ULL;
UINT64 stride  = aligned * 4ULL;
```

At maximum policy dimensions (65535 × 65535, 128 bpp), the uncapped buffer would be approximately 68 GB — far past `UINT32_MAX`. A 32-bit multiply silently wraps to a small positive value, which the old harness would have passed to `HeapAlloc`, producing a dangerously undersized buffer that masks real overflows from PageHeap. The 64-bit path computes the true value and rejects it via the 256 MB cap.

### Fallback bpp

When COM pixel format resolution fails — factory present but a query step fails (e.g. an unknown or malformed format GUID returned by the decoder) — the harness uses `POLICY_BPP_FALLBACK_MAX = 128`. This over-allocates rather than under-allocates. Under-allocation would silently prevent `CopyPixels` from triggering the heap overflow that PageHeap is there to catch.

### Policy result codes

| Code | Meaning |
|---|---|
| `POLICY_OK` | Accepted — proceed |
| `POLICY_ZERO_DIMENSION` | Width or height is zero |
| `POLICY_DIMENSION_EXCEED` | Dimension exceeds `maxWidth` / `maxHeight` |
| `POLICY_STRIDE_OVERFLOW` | Stride calculation overflowed UINT64 (impossible with current limits; future-proof) |
| `POLICY_STRIDE_EXCEED` | Stride exceeds `maxStride` cap |
| `POLICY_BUFFER_EXCEED` | `stride × height` exceeds `maxBufferBytes` cap |
| `POLICY_BUFFER_OVERFLOW` | Buffer arithmetic overflowed (same as above — reserved) |
| `POLICY_INVALID_ARG` | NULL pointer argument |

---

## 6. Build System Requirements

- Windows 10 21H2 or later, x64 (Windows 11 preferred)
- Visual Studio 2019 (v16.x) or 2022 (v17.x) with the **Desktop development with C++** workload
- Windows SDK 10.0.19041.0 or later (installed via Visual Studio installer)
- No additional third-party libraries required; `windowscodecs.lib` and `ole32.lib` are part of the SDK

All source files are C (not C++). The harness requires the MSVC x64 toolchain specifically — `_WIN64` and `_MSC_VER` are enforced at compile time. MinGW and Clang-cl are not tested.

---

## 7. Building the Harness

Open an **x64 Native Tools Command Prompt** (from the Visual Studio start menu entry, or via `vcvars64.bat`). All commands below are run from the project root directory.

### Campaign 1 — lazy metadata (default, production fuzzing)

```cmd
cl /nologo /W3 /O2 /D HARNESS_MODE_FUZZ ^
   main.c policy.c ini.c trace.c ^
   /link ole32.lib oleaut32.lib windowscodecs.lib shlwapi.lib ^
   /Fe:harness_c1.exe
```

### Campaign 2 — eager metadata

```cmd
cl /nologo /W3 /O2 /D HARNESS_MODE_FUZZ /D HARNESS_CACHE_ON_LOAD ^
   main.c policy.c ini.c trace.c ^
   /link ole32.lib oleaut32.lib windowscodecs.lib shlwapi.lib ^
   /Fe:harness_c2.exe
```

### Research / debug build (SEH logging, no optimisation)

```cmd
cl /nologo /W4 /Zi /Od /RTC1 /D HARNESS_MODE_RESEARCH ^
   main.c policy.c ini.c trace.c ^
   /link ole32.lib oleaut32.lib windowscodecs.lib shlwapi.lib ^
   /Fe:harness_research.exe
```

The research build wraps `fuzz_target()` in a structured exception handler that logs the exception code and last executed stage to `harness_trace.txt` before re-raising. It also forces `IWICFormatConverter::Initialize` even when `CanConvert` returns FALSE, exercising the format validation path with sources the converter was not designed for.

### Verify the build

```cmd
harness_research.exe path\to\any_valid.ico
```

Expected: the harness runs one iteration (or more, depending on `harness.ini`), writes `harness_trace.txt` next to the binary, and exits cleanly. Check the trace file to confirm all major stages executed.

---

## 8. Environment Setup

### Page Heap — mandatory

Page Heap places a guard page immediately after every heap allocation. A heap overflow that writes even one byte past the end of the buffer triggers an access violation immediately, at the point of the write, rather than corrupting metadata silently and crashing later at an unrelated site. Without Page Heap, many real heap overflows in `windowscodecs.dll` will not produce a crash at all during a fuzzing campaign.

Enable Page Heap for each harness binary you build:

```cmd
gflags.exe /p /enable harness_c1.exe /full
gflags.exe /p /enable harness_c2.exe /full
gflags.exe /p /enable harness_research.exe /full
```

`gflags.exe` ships with Debugging Tools for Windows (part of the Windows SDK). To confirm Page Heap is active:

```cmd
gflags.exe /p /query harness_c1.exe
```

To disable after a campaign:

```cmd
gflags.exe /p /disable harness_c1.exe
```

**Important**: Page Heap increases memory usage per allocation significantly. A harness that allocates a 256 MB pixel buffer under Page Heap will consume 256 MB + one 4 KB guard page, plus the heap metadata overhead. This is expected. If the machine runs out of virtual address space due to Page Heap overhead during deep campaigns, reduce `max_buffer_mb` in `harness.ini` — but do not go below 64 MB without a specific reason.

### Crash dumps

Configure Windows Error Reporting to write full crash dumps to a known directory, or use WinDbg's `adplus` in crash mode. Alternatively, set the global registry key:

```cmd
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" ^
    /v DumpType /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" ^
    /v DumpFolder /t REG_EXPAND_SZ /d "C:\dumps" /f
```

This produces full crash dumps in `C:\dumps\` whenever any process crashes, including the harness under WinAFL.

### Antivirus exclusions

Add the harness working directory, the WinAFL output directory, and the `windowscodecs.dll` instrumented process to AV exclusions. Behavioural AV engines frequently intercept the high-frequency file open/close pattern of fuzzing, collapsing throughput by 80-95% and producing false timeout crashes.

### Windows Defender exclusions (PowerShell, run as administrator)

```powershell
Add-MpPreference -ExclusionPath "C:\fuzz"
Add-MpPreference -ExclusionProcess "harness_c1.exe"
Add-MpPreference -ExclusionProcess "harness_c2.exe"
Add-MpPreference -ExclusionProcess "afl-fuzz.exe"
```

### Disable automatic crash reporting dialogs

```cmd
reg add "HKCU\SOFTWARE\Microsoft\Windows\Windows Error Reporting" ^
    /v DontShowUI /t REG_DWORD /d 1 /f
```

This prevents WER from popping an interactive dialog that would block the crashed process and halt the fuzzing campaign.

---

## 9. Seed Corpus Preparation

### Sources

The seed corpus quality directly determines how quickly the fuzzer reaches interesting internal states. Good seeds for ICO fuzzing:

**System ICO files** — Windows ships thousands of ICO files embedded in system DLLs. Extract them with any resource extraction tool:

```cmd
:: Using 7-Zip to extract resources from shell32.dll
7z e C:\Windows\System32\shell32.dll -o seeds_raw\
```

Tools like **Resource Hacker**, **BinFly**, or **pe-bear** can extract icons more cleanly. Targets worth extracting: `shell32.dll`, `imageres.dll`, `wmploc.dll`, `ieframe.dll`, `explorer.exe`.

**PNG-embedded ICO files** — These are particularly valuable because they exercise the PNG-in-ICO code path. Look for ICO files where individual frames exceed 48×48 pixels; by convention those are PNG-encoded. You can verify with a hex editor: frame payload starting with `\x89PNG\r\n\x1a\n` is PNG.

**Multi-depth ICO files** — ICO files containing both 1bpp and 32bpp frames in the same container exercise the most code paths per file. Prefer seeds with 4-8 frames at different dimensions.

### Corpus minimisation

Before launching the main campaign, minimise the seed set with WinAFL's corpus minimisation mode. This identifies the subset of seeds that together cover the most coverage edges in `windowscodecs.dll` and discards redundant files:

```cmd
afl-fuzz.exe ^
    -i seeds_raw ^
    -o seeds_min ^
    -coverage_module windowscodecs.dll ^
    -target_module harness_c1.exe ^
    -target_method fuzz_target ^
    -nargs 1 ^
    -minimize_corpus ^
    -- harness_c1.exe @@
```

The minimised corpus in `seeds_min\queue\` replaces `seeds_raw` as the input for the fuzzing campaign. Aim for 50–200 minimised seeds. Fewer seeds means WinAFL's mutation engine spends more mutations per seed; too many seeds increases scheduling overhead.

### Corpus structuring tip

Group seeds by payload type into subdirectories before minimisation to help WinAFL discover distinct mutation starting points:

```
seeds_raw\
  bmp_payload\     -- ICO files with BMP-style frames only
  png_payload\     -- ICO files with PNG-embedded frames
  mixed\           -- ICO files with both payload types
  palette\         -- ICO files with 1bpp / 4bpp / 8bpp palette frames
```

---

## 10. WinAFL and TinyInst Setup

### Obtaining WinAFL with TinyInst support

Clone the official WinAFL repository and build with TinyInst as the coverage backend:

```cmd
git clone https://github.com/googleprojectzero/winafl.git
cd winafl
git submodule update --init --recursive
```

Build instructions for the TinyInst backend are in `winafl\README.md` and `winafl\readme_winafl.md`. Follow the official documentation for your specific version — TinyInst's API has changed across releases and the build flags in this document may not match your checkout. The official documentation is the authoritative source.

### Key WinAFL/TinyInst parameters explained

The parameters below are specifically relevant to this harness. Consult the WinAFL README for the complete option reference.

**Coverage and targeting:**

| Parameter | Value for this harness | Why |
|---|---|---|
| `-coverage_module` | `windowscodecs.dll` | This is the real target. TinyInst instruments this DLL's basic blocks for coverage feedback. The harness binary itself contains almost no interesting code. |
| `-target_module` | `harness_c1.exe` | Module containing the persistent-mode target function. |
| `-target_method` | `fuzz_target` | Exported function WinAFL calls in a loop. Must match `WINAFL_TARGET_FUNCTION` in `config.h`. The function is declared `__declspec(noinline)` to prevent the compiler from inlining it. |
| `-nargs` | `1` | `fuzz_target` takes one argument: a `WCHAR*` file path. WinAFL passes the mutated file path as the first argument. |

**Input delivery:**

| Parameter | Value | Why |
|---|---|---|
| `@@` | (token in target argv) | WinAFL replaces `@@` with the path to the current mutated input file before each `fuzz_target` call. The harness reads the file via `CreateDecoderFromFilename`; WinAFL writes the mutated bytes to a temp file and passes its path. |

**Iteration control:**

| Parameter | Suggested value | Notes |
|---|---|---|
| `-fuzz_iterations` | `5000` | Number of `fuzz_target()` calls before WinAFL restarts the process. Higher values = more throughput; lower values = more frequent process resets (better isolation if a COM object becomes corrupted). Start with 5000 and tune based on observed stability. |

**Timeout:**

Check the WinAFL documentation for the correct flag name in your build (`-timeout`, `-t`, or similar). A reasonable starting value is 5000 ms per iteration. Reduce if throughput is low; raise if complex ICO files with many metadata-heavy frames are timing out legitimately (check `harness_trace.txt` to distinguish a real hang from a slow-but-correct run).

### TinyInst-specific notes

TinyInst operates by rewriting the target module's code at the basic block level in a child process. Some practical implications:

- TinyInst needs write access to the process memory space of the instrumented binary. Run WinAFL as administrator, or ensure the harness binary and `windowscodecs.dll` are not in a protected directory.
- TinyInst instruments `windowscodecs.dll` as loaded in the harness process. The `windowscodecs.dll` that TinyInst sees is the one from `C:\Windows\System32\`. On a stock Windows installation this is the version you want. If you are testing a patched or modified version of the DLL, place it next to the harness binary and set the DLL search order accordingly.
- Coverage maps from two different `windowscodecs.dll` versions (e.g. pre-patch and post-patch) are not comparable. Keep separate output directories if you test across different OS versions.

---

## 11. Launching Fuzzing Campaigns

Set up the directory structure first:

```
C:\fuzz\
  harness_c1.exe
  harness_c2.exe
  harness_research.exe
  harness.ini
  in\              -- minimised seed corpus (copy seeds_min\queue\ here)
  findings_c1\     -- Campaign 1 output
  findings_c2\     -- Campaign 2 output
```

### Campaign 1 — lazy metadata parsing

```cmd
cd C:\fuzz

afl-fuzz.exe ^
    -i in ^
    -o findings_c1 ^
    -fuzz_iterations 5000 ^
    -coverage_module windowscodecs.dll ^
    -target_module harness_c1.exe ^
    -target_method fuzz_target ^
    -nargs 1 ^
    -- harness_c1.exe @@
```

### Campaign 2 — eager metadata parsing

```cmd
cd C:\fuzz

afl-fuzz.exe ^
    -i in ^
    -o findings_c2 ^
    -fuzz_iterations 5000 ^
    -coverage_module windowscodecs.dll ^
    -target_module harness_c2.exe ^
    -target_method fuzz_target ^
    -nargs 1 ^
    -- harness_c2.exe @@
```

**The two `-o` directories must be kept separate.** Coverage bitmaps for Campaign 1 and Campaign 2 are generated by two different DLL code paths and are not comparable. Mixing them will corrupt WinAFL's coverage accounting and produce false positives or missed paths.

### Parallel instances

WinAFL supports multiple parallel fuzzer instances sharing the same output directory via `-M` (master) and `-S` (secondary) flags:

```cmd
:: Instance 1 (master)
afl-fuzz.exe -M fuzzer1 -i in -o findings_c1 [... rest of flags ...] -- harness_c1.exe @@

:: Instance 2 (secondary, separate window)
afl-fuzz.exe -S fuzzer2 -i in -o findings_c1 [... rest of flags ...] -- harness_c1.exe @@
```

Each secondary instance reads from the master's queue and adds its own findings. The coverage module and target method flags must be identical across all instances. Consult the WinAFL README for parallel mode details and synchronisation behaviour.

### Trace file in FUZZ mode

By default `trace_enabled = 1` in `harness.ini`, which writes `harness_trace.txt` next to the binary. During a production FUZZ campaign, set `trace_enabled = 0` in `harness.ini` to eliminate the file I/O overhead. Re-enable it for research and crash reproduction runs.

---

## 12. Monitoring and Triage

### WinAFL status screen

WinAFL displays a real-time status screen in the console window. Key metrics to watch:

- **exec/sec**: iterations per second. For this harness with all paths enabled, expect 200–1000 exec/sec depending on machine speed and ICO complexity. Below 100 suggests a performance problem (AV interference, trace file I/O, excessive timeout triggers).
- **stability**: percentage of iterations that produce the same coverage bitmap for the same input. Below 85% indicates non-determinism — COM object state leaking between iterations, a timing issue, or a coverage counter race. Investigate before declaring crashes valid.
- **crashes**: count of inputs that caused the process to exit abnormally. Any non-zero value here is the primary output of the campaign.
- **hangs**: count of inputs that exceeded the iteration timeout. A few hangs are normal (complex nested metadata); sustained high hang rates suggest a throughput problem or a genuine infinite loop path in the decoder.

### Output directory layout

```
findings_c1\
  crashes\
    id:000000,sig:11,...    -- each file is a minimised input that crashed
  hangs\
    id:000000,...           -- each file is a minimised input that timed out
  queue\
    id:000000,...           -- current working corpus (seeds + generated inputs)
  fuzzer_stats              -- machine-readable campaign statistics
  plot_data                 -- coverage over time (parseable by afl-plot)
```

### Triage priority

Not all crashes are equal. Triage in this order:

1. **Access violation during `STAGE_COPY_PIXELS`** — heap overflow in the pixel buffer. Highest priority. If Page Heap is active, the crash address will be in the guard page immediately after the allocated buffer. The allocation size in the crash dump (from `!heap -x <addr>` in WinDbg) relative to the computed `stride × height` tells you the overflow magnitude.

2. **Access violation during `STAGE_FRAME_PALETTE`** — `IWICPalette::GetColors` overflow. A malformed ICO declares more palette entries than allocated. Check whether the ICO `ICONDIRENTRY` bit-depth field disagrees with the actual BMP/PNG palette declaration.

3. **Access violation during `STAGE_FRAME_METADATA` or `STAGE_CONTAINER_METADATA`** — metadata engine bug. Often an out-of-bounds read on a malformed chunk size field.

4. **`S_OK` from an OOB frame index probe** — index validation bypass. Trace stage `STAGE_FRAME_OOB` with `S_OK` on any of `GetFrame(0xFFFF)`, `GetFrame(0xFFFFFFFF)`, or `GetFrame(0x80000000)` is a high-confidence indicator of exploitable index confusion.

5. **Access violation during `STAGE_DECODER_CREATE`** — crash during initial file parsing, before any frame enumeration. This is the most likely location for a remote-without-user-action exploit primitive.

---

## 13. Reproducing and Debugging Crashes

### Step 1 — Confirm reproduction with the research build

```cmd
gflags.exe /p /enable harness_research.exe /full

harness_research.exe C:\fuzz\findings_c1\crashes\id:000000,...
```

If the crash reproduces, `harness_trace.txt` will contain the last stage reached before the exception, the exception code, and the frame index (if the crash is per-frame). If it does not reproduce on the first attempt, try 3-5 iterations: some crashes require a specific internal WIC state that builds up over multiple iterations in a live process but is not reproducible on the very first call in a fresh process.

### Step 2 — Reproduce under WinDbg with Page Heap

```cmd
windbg -g -o harness_research.exe C:\fuzz\findings_c1\crashes\id:000000,...
```

Useful WinDbg commands for first-pass crash analysis:

```
!analyze -v                  -- automatic crash analysis
!heap -x <crash_address>     -- heap block containing the faulting address
!heap -p -a <crash_address>  -- Page Heap allocation record with full stack trace
kb                           -- call stack at crash
lm m windowscodecs           -- module base and version of windowscodecs.dll
```

The Page Heap allocation record (`!heap -p -a`) is the most useful output: it shows the allocation call stack, the size of the buffer, and exactly how far past the end of the buffer the write landed.

### Step 3 — Identify the internal function

With the crash address and the `windowscodecs.dll` base from `lm m windowscodecs`, compute the RVA:

```
crash_rva = crash_address - windowscodecs_base
```

Load `windowscodecs.dll` in IDA Pro, Binary Ninja, or Ghidra and navigate to that RVA. The surrounding function name, the input fields it reads, and the allocation call higher in the call stack identify the bug class.

### Step 4 — Minimise the crashing input

WinAFL includes a test case minimisation mode. Use it to reduce the crash input to the smallest file that still triggers the same crash signature:

```cmd
afl-tmin.exe ^
    -i C:\fuzz\findings_c1\crashes\id:000000,... ^
    -o crash_minimised.ico ^
    -coverage_module windowscodecs.dll ^
    -target_module harness_c1.exe ^
    -target_method fuzz_target ^
    -nargs 1 ^
    -- harness_c1.exe @@
```

A minimised crash input is easier to analyse and is required for a quality vulnerability report.

---

## 14. Configuration Reference

`harness.ini` is placed next to the harness binary. All keys are optional; compiled-in defaults are used when the file is absent.

### Policy limits

| Key | Default | Range | Description |
|---|---|---|---|
| `max_width` | 65535 | 1–65535 | Maximum decoded frame width in pixels. Frames wider than this are skipped before `CopyPixels`. |
| `max_height` | 65535 | 1–65535 | Maximum decoded frame height in pixels. |
| `max_frames` | 256 | 1–65535 | Maximum ICO frames processed per file. ICONDIR can declare up to 65535. |
| `max_buffer_mb` | 256 | 1–512 | Maximum pixel buffer per frame, megabytes. |
| `max_stride_mb` | 256 | 1–512 | Maximum row stride per frame, megabytes. Must be ≤ `max_buffer_mb` for consistency. |
| `max_color_contexts` | 64 | 1–256 | Maximum `IWICColorContext` objects per `GetColorContexts` call. |
| `max_palette_colors` | 4096 | 1–65536 | Maximum palette entries passed to `IWICPalette::GetColors`. |
| `max_metadata_items` | 4096 | 1–65536 | Maximum items enumerated per single `IWICEnumMetadataItem` reader. |
| `max_total_metadata_items` | 16384 | 1–1048576 | Maximum total metadata items across all readers per `fuzz_target()` call. |

**Do not lower `max_width`, `max_height`, `max_buffer_mb`, or `max_metadata_items` aggressively during a fuzzing campaign.** Tight caps cause the harness to skip exactly the malformed large-dimension inputs that are most likely to trigger real bugs. The defaults were chosen to be generous enough to pass all interesting inputs while preventing genuine harness OOM.

### Iteration and mode

| Key | Default | Range | Description |
|---|---|---|---|
| `iterations` | 5000 | 1–1000000 | `fuzz_target()` calls in standalone mode. Overridden by WinAFL `-fuzz_iterations`. |
| `mode` | `FUZZ` | `FUZZ` / `RESEARCH` | Activates SEH logging in RESEARCH builds. Does not override the compile-time `/D HARNESS_MODE_RESEARCH` flag. |

### Feature flags

| Key | Default | Description |
|---|---|---|
| `trace_enabled` | 1 | Write iteration trace to `harness_trace.txt`. Set to 0 for production fuzzing. |
| `conversion_path` | 1 | `IWICFormatConverter` path. |
| `metadata_enum` | 1 | Metadata recursive enumeration. |
| `palette_path` | 1 | `IWICPalette::GetColors`. |
| `color_context_path` | 1 | ICC profile extraction. |
| `thumbnail_path` | 1 | `GetPreview` and `GetThumbnail`. |
| `decoder_info_path` | 1 | `IWICBitmapDecoderInfo` capability flags. |
| `transform_path` | 1 | `IWICBitmapSourceTransform` scaled decode. |
| `progressive_path` | 1 | `IWICProgressiveLevelControl` per-level decode. |
| `wic_convert_path` | 1 | `WICConvertBitmapSource` alternative conversion API. |

---

## 15. Source File Map

| File | Purpose |
|---|---|
| `main.c` | Harness entry point (`wmain`), global init/cleanup, `fuzz_target()`, all WIC exercise path functions |
| `policy.c` | Dimension validation, 64-bit stride/buffer arithmetic, COM-based bpp resolution |
| `policy.h` | `HARNESS_POLICY` struct, `POLICY_RESULT` enum, all policy function declarations |
| `ini.c` | INI loader: `ini_load_policy()`, `config_init_defaults()`, `config_load_ini()`, `config_print()` |
| `ini.h` | `HARNESS_CONFIG` struct, loader function declarations |
| `config.h` | All compile-time defaults: policy limits, feature flags, INI key names, COM format constants |
| `trace.c` | Structured trace log: per-stage, per-frame, crash attribution |
| `trace.h` | `HARNESS_TRACE_CTX`, stage enum (`HARNESS_STAGE`), trace function declarations |
| `harness.ini` | Runtime configuration (optional) |

---

## 16. Known Vulnerability Classes

The following bug classes have been observed historically in `windowscodecs.dll` and closely related WIC-stack DLLs. This harness covers all of them.

### Heap overflow via dimension mismatch (BMP payload)

The ICO `ICONDIRENTRY` declares a frame size. The embedded `BITMAPINFOHEADER` inside the frame payload declares a potentially different size. A decoder that allocates based on one value and copies based on the other produces a classic linear heap overflow. The `STAGE_COPY_PIXELS` full-rect call is the trigger; Page Heap catches it at the exact write instruction.

Variants to watch for in the crash dump: allocation size derived from `ICONDIRENTRY.bWidth × bHeight × (bBitCount / 8)`, actual copy size derived from `BITMAPINFOHEADER.biWidth × abs(biHeight)`. Any discrepancy where the copy is larger than the allocation is exploitable.

### Integer overflow in palette size calculation

`ICONDIRENTRY.bColorCount` is a BYTE field specifying the palette size. The corresponding `BITMAPINFOHEADER.biClrUsed` is a DWORD. A decoder that converts between the two without explicit range checking can produce a palette allocation that is smaller than the number of entries the BMP header claims. `GetColors` then writes past the end of the palette buffer.

### Negative biHeight / sign extension

`BITMAPINFOHEADER.biHeight` is a signed 32-bit integer. Negative values indicate a top-down bitmap. A codec that passes this value to a UINT multiplication without a sign check produces a very large positive stride via two's-complement wrap. With 64-bit arithmetic in the harness, this is detectable before allocation; the crash in the decoder occurs inside `CopyPixels`.

### PNG `IHDR` dimension overflow

The PNG `IHDR` chunk contains a 32-bit width and a 32-bit height. A malformed PNG-in-ICO can embed a PNG whose `IHDR` declares a much larger dimension than the ICO `ICONDIRENTRY` suggests. Depending on which value the ICO decoder uses for allocation vs. the PNG decoder for row stride, this produces an overflow. Adam7 interlaced PNG frames are additionally vulnerable because each of the 7 passes has a different effective row width; the pass-dimension calculation is a secondary overflow surface.

### Metadata chunk length integer overflow

PNG `iTXt`, `tEXt`, `zTXt`, and `eXIf` chunks carry a 32-bit length field in the chunk header. A corrupt length value can cause the metadata engine to read past the end of the chunk data buffer. This typically manifests as a read access violation (information disclosure) rather than a write overflow, but can also corrupt metadata engine internal structures if the read wraps into adjacent allocations.

### ICC profile (iCCP) overflow

The `iCCP` chunk contains a compressed ICC profile. The profile length is computed from the chunk length minus the null-terminated profile name length. A malformed chunk with an overlong name, a truncated profile, or a mismatch between compressed and declared decompressed size can produce an overflow in the ICC profile parsing code.

### IWICFormatConverter::Initialize with malformed source

`IWICFormatConverter::Initialize` validates the source format before accepting the conversion request. A decoder that returns an unrecognised or internally inconsistent pixel format GUID from `GetPixelFormat` can trigger unvalidated code paths inside the converter. The RESEARCH build forces `Initialize` even when `CanConvert` returns FALSE, exercising the format validation logic directly.
