# WIC ICO Fuzzing Harness

A WinAFL persistent-mode fuzzing harness targeting `windowscodecs.dll` through the Windows Imaging Component (WIC) COM interface, specifically focused on the ICO container format and its embedded PNG and BMP payloads. The objective is to discover memory corruption vulnerabilities, integer overflows, and parsing logic bugs in the ICO decoder — bugs that are directly reachable from real Windows applications without any privilege escalation precondition.

---

## Table of Contents

1. [Background and Motivation](#1-background-and-motivation)
2. [Attack Surface Overview](#2-attack-surface-overview)
3. [Harness Architecture](#3-harness-architecture)
4. [Bug-Hunting Policy System](#4-bug-hunting-policy-system)
5. [Execution Profiles](#5-execution-profiles)
6. [Coverage Paths](#6-coverage-paths)
7. [Build System Requirements](#7-build-system-requirements)
8. [Building the Harness](#8-building-the-harness)
9. [Environment Setup](#9-environment-setup)
10. [Seed Corpus Preparation](#10-seed-corpus-preparation)
11. [WinAFL and TinyInst Setup](#11-winafl-and-tinyinst-setup)
12. [Launching Fuzzing Campaigns](#12-launching-fuzzing-campaigns)
13. [Monitoring and Triage](#13-monitoring-and-triage)
14. [Reproducing and Debugging Crashes](#14-reproducing-and-debugging-crashes)
15. [Configuration Reference](#15-configuration-reference)
16. [Source File Map](#16-source-file-map)
17. [Known Vulnerability Classes](#17-known-vulnerability-classes)

---

## 1. Background and Motivation

`windowscodecs.dll` is loaded into virtually every Windows process that renders images. Shell extensions, preview handlers, thumbnail generators, the Windows Photo app, Office, browsers via DirectX surface composition, and countless third-party applications all funnel image parsing through WIC. An attacker who controls a malformed ICO file placed on a network share, sent as an email attachment, or embedded in a document can trigger parsing in `windowscodecs.dll` without any explicit user action beyond navigating to a folder.

ICO is a container format that packs multiple image frames at different sizes and bit depths. Each frame can be either a legacy BMP-style payload (BITMAPINFOHEADER + XOR/AND mask bitmaps) or, since Windows Vista, a full embedded PNG stream. This dual-format nature creates a large heterogeneous parsing surface: the ICO container parser, the BMP raster decoder, the PNG decoder (with its own zlib decompressor and progressive/interlaced paths), palette reconstruction logic, ICC profile parsing, and the metadata engine are all reachable from a single ICO file.

Historical CVEs in `windowscodecs.dll` demonstrate that this surface produces high-severity exploitable bugs: heap overflows in the BMP height calculation (negative height values in BITMAPINFOHEADER), integer overflows in palette size fields, out-of-bounds reads during metadata enumeration, and use-after-free conditions during format converter initialization. This harness is designed to maximize coverage of all those paths simultaneously.

---

## 2. Attack Surface Overview

### ICO container parser

The ICO file begins with an `ICONDIR` header followed by an array of `ICONDIRENTRY` structures. Each entry declares a frame size (`bWidth`, `bHeight` as BYTE fields — capped at 255 in the spec, but the actual PNG/BMP payload inside can declare any 32-bit dimension), a bit depth, a palette color count, and an offset/size pair pointing to the payload data. Discrepancies between the ICONDIRENTRY-declared dimensions and the actual payload dimensions are a known bug class: the decoder may use one value for allocation and the other for the copy, producing a classic under-allocation followed by a heap write overrun.

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

WIC exposes a generic metadata query engine (`IWICMetadataQueryReader`) that is separate from and layered on top of the format-specific parsers. Metadata items can be nested: a PNG `iTXt` chunk can contain an XMP block, which the metadata engine exposes as a `VT_UNKNOWN` containing a nested `IWICMetadataQueryReader`. The harness performs recursive descent into all nested readers (up to depth 4), exercising the allocation and lifetime management of the metadata engine alongside the underlying chunk parsers.

### Format converter path

`IWICFormatConverter` converts between pixel formats (e.g. 8bpp palette-indexed to 32bppBGRA). The converter has its own internal buffer allocation and per-pixel conversion loop. `WICConvertBitmapSource` is a distinct API that exercises a different internal code path — it does not call `CanConvert` and uses a different allocation strategy, making it useful for exercising format validation logic with unexpected pixel format GUIDs.

---

## 3. Harness Architecture

### Persistent mode design

The harness uses WinAFL Option B (persistent mode). COM initialization and WIC factory creation happen once at process startup in `harness_global_init()` and remain alive for the entire process lifetime. `fuzz_target()` is the hot loop: it creates a decoder, exercises every COM path, releases all per-iteration COM objects, and returns.

```
Process startup
  └── harness_global_init()
        ├── config_init_defaults() + config_load_ini()  ← profile applied here
        ├── CoInitializeEx(COINIT_APARTMENTTHREADED)
        ├── CoCreateInstance(CLSID_WICImagingFactory)
        └── QI -> IWICImagingFactory2

  [WinAFL loop]
  └── fuzz_target(filePath)
        ├── CreateDecoderFromFilename
        ├── [container-level paths: QueryCapability, GetContainerFormat,
        │    GetDecoderInfo, metadata, palette, color contexts,
        │    GetPreview, GetThumbnail]
        ├── GetFrameCount
        ├── for each frame:
        │     ├── GetFrame / GetSize
        │     ├── policy_select_budget()          ← budget decision
        │     ├── [ALL frames, any budget]:
        │     │     GetPixelFormat, GetResolution, CopyPalette,
        │     │     GetColorContexts, GetMetadataQueryReader (recursive),
        │     │     GetThumbnail, IWICFormatConverter probe,
        │     │     WICConvertBitmapSource, IWICBitmapSourceTransform probe
        │     └── [BUDGET_FULL only]:
        │           CopyPixels (full), CopyPixels (partial),
        │           full transform decode, full progressive decode
        ├── out-of-bounds frame index probes
        └── SAFE_RELEASE decoder

Process exit
  └── harness_global_cleanup()
```

### COM interface chain

The harness uses exclusively C-style COM (`COBJMACROS`). All interface pointers are obtained via `QueryInterface` — never via raw pointer casts (undefined behaviour in C). Interfaces exercised per iteration:

| Interface | Source |
|---|---|
| `IWICImagingFactory` | `CoCreateInstance(CLSID_WICImagingFactory)` |
| `IWICImagingFactory2` | QI from factory (for `CreateColorContext`) |
| `IWICBitmapDecoder` | `CreateDecoderFromFilename` |
| `IWICBitmapDecoderInfo` | `GetDecoderInfo` |
| `IWICBitmapFrameDecode` | `GetFrame(i)` |
| `IWICBitmapSource` | QI from frame/converter |
| `IWICFormatConverter` | `CreateFormatConverter` |
| `IWICMetadataQueryReader` | `GetMetadataQueryReader` (recursive) |
| `IWICEnumMetadataItem` | `GetEnumerator` |
| `IWICPalette` | `CreatePalette` |
| `IWICColorContext` | `CreateColorContext` |
| `IWICComponentInfo` / `IWICPixelFormatInfo` | `CreateComponentInfo` (bpp resolution) |
| `IWICBitmapSourceTransform` | QI from frame |
| `IWICProgressiveLevelControl` | QI from frame |

---

## 4. Bug-Hunting Policy System

### Core principle

The policy protects the harness process at the **point of cost** (memory allocation), not at the input ingress. Dimension checks are **soft hints** for budget selection — never binary skip conditions. The decoder always sees every frame the fuzzer produces, including malformed large-dimension inputs that historically trigger real heap overflows.

### Why this matters

A mutated ICO file can have `ICONDIRENTRY.bWidth = 32` while the embedded PNG `IHDR` declares `width = 200000`. `IWICBitmapFrameDecode::GetSize()` returns the value from the IHDR — the value controlled by the attacker. This exact mismatch is the root cause of "PNG IHDR dimension overflow" bugs. Under the old policy, this frame would be silently discarded after `GetSize()`. Under the new policy, the frame exercises all twelve cheap COM paths before the allocation decision is made.

### FRAME_BUDGET

`policy_select_budget()` in `policy.c` replaces the old `policy_validate_dimensions()` binary check. It returns one of four values:

| Budget | Meaning | When selected |
|---|---|---|
| `BUDGET_FULL` | All paths including `CopyPixels` | Stride and buffer fit within configured cap |
| `BUDGET_LIGHT` | Reserved for future partial-decode mode | (not yet activated) |
| `BUDGET_METADATA_ONLY` | Cheap COM paths only; no allocation | Stride or buffer exceeds cap or soft hints |
| `BUDGET_SKIP` | Nothing; release frame immediately | `width == 0` or `height == 0` |

### Budget selection logic

```
policy_select_budget(policy, width, height, bpp, &estStride, &estBuffer):

1. width == 0 || height == 0              → BUDGET_SKIP
2. width > softMaxWidth || height > softMaxHeight
                                          → BUDGET_METADATA_ONLY  (fast path)
3. policy_compute_stride overflows/exceeds → BUDGET_METADATA_ONLY
4. policy_compute_buffer_size exceeds cap  → BUDGET_METADATA_ONLY
5. otherwise                               → BUDGET_FULL
```

Step 2 is a fast path: if either dimension exceeds the soft hint (default 65535), we skip the 64-bit arithmetic entirely and select `BUDGET_METADATA_ONLY`. The frame is not discarded — all cheap paths still run.

Step 3 and 4 use the existing overflow-safe 64-bit arithmetic in `policy_compute_stride()` and `policy_compute_buffer_size()`. These are the real harness safety net.

### What runs at each budget level

| COM path | BUDGET_FULL | BUDGET_METADATA_ONLY |
|---|---|---|
| `GetPixelFormat` | ✓ | ✓ |
| `GetResolution` | ✓ | ✓ |
| `CopyPalette` + `GetColors` | ✓ | ✓ |
| `GetColorContexts` (ICC) | ✓ | ✓ |
| `GetMetadataQueryReader` (recursive) | ✓ | ✓ |
| `GetThumbnail` | ✓ | ✓ |
| `IWICFormatConverter` `CanConvert` + `Initialize` probe | ✓ | ✓ |
| `WICConvertBitmapSource` (lazy object creation) | ✓ | ✓ |
| `IWICBitmapSourceTransform` `DoesSupportTransform` probe | ✓ | ✓ |
| `CopyPixels` (full rect) | ✓ | — |
| `CopyPixels` (partial rect) | ✓ | — |
| `IWICBitmapSourceTransform::CopyPixels` (scaled) | ✓ | — |
| `IWICProgressiveLevelControl` per-level decode | ✓ | — |
| `WICConvertBitmapSource` result `CopyPixels` | ✓ | — |

---

## 5. Execution Profiles

Three built-in profiles allow purpose-built campaign configurations. Select via `harness.ini`:

```ini
policy_profile = balanced   ; fast | balanced | deep
```

Individual keys override the profile preset.

### fast

Maximum throughput. No metadata, transform, progressive, thumbnail, or ICC paths. No allocation-heavy operations.

| Parameter | Value |
|---|---|
| `max_buffer_mb` | 32 |
| `max_total_metadata_items` | 2048 |
| `iterations` | 10000 |
| Enabled paths | `decoder_create`, `frame_loop`, `copy_pixels`, `palette` |
| Disabled paths | `metadata_enum`, `conversion_path`, `color_context_path`, `thumbnail_path`, `decoder_info_path`, `transform_path`, `progressive_path`, `wic_convert_path` |

Use for: initial corpus triage, large seed exploration, exec/sec benchmarking.

### balanced (DEFAULT)

All paths enabled, budget-gated allocation. Optimal for sustained WinAFL+TinyInst campaigns.

| Parameter | Value |
|---|---|
| `max_buffer_mb` | 128 |
| `max_total_metadata_items` | 8192 |
| `iterations` | 5000 |
| All paths | enabled |

Use for: production fuzzing campaigns, general vulnerability hunting.

### deep

All paths, maximum metadata depth, large allocation budget. Pair with frequent process restart and PageHeap enabled on `windowscodecs.dll`.

| Parameter | Value |
|---|---|
| `max_buffer_mb` | 256 |
| `max_total_metadata_items` | 65536 |
| `iterations` | 200 |
| All paths | enabled |

Use for: targeted hunting on interesting seed subsets, crash reproduction with maximum coverage, research mode with PageHeap + ASAN-style allocators.

### Profile override example

Start from `fast` but re-enable metadata:

```ini
[harness]
policy_profile = fast
metadata_enum  = 1
max_total_metadata_items = 4096
```

---

## 6. Coverage Paths

### Container-level paths

| Stage | Interface | What it exercises |
|---|---|---|
| `STAGE_DECODER_CREATE` | `CreateDecoderFromFilename` | File signature detection, ICONDIR initial read, codec selection, metadata cache population |
| `STAGE_QUERY_CAPABILITY` | `QueryCapability` | Distinct capability detection pass via `IStream` |
| `STAGE_CONTAINER_FORMAT` | `GetContainerFormat` | GUID identification |
| `STAGE_DECODER_INFO` | `GetDecoderInfo` | File extensions, MIME types, multiframe/lossless/animation flags |
| `STAGE_CONTAINER_METADATA` | `GetMetadataQueryReader` | Container-level XMP/EXIF metadata, recursive VT_UNKNOWN descent |
| `STAGE_CONTAINER_PALETTE` | `CopyPalette` | Container palette |
| `STAGE_COLOR_CONTEXTS` | `GetColorContexts` | ICC profile structures |
| `STAGE_PREVIEW` | `GetPreview` | Preview bitmap |
| `STAGE_THUMBNAIL_CONTAINER` | `GetThumbnail` | Container thumbnail |

### Per-frame paths

| Stage | Interface | What it exercises |
|---|---|---|
| `STAGE_FRAME_GET` | `GetFrame(i)` | ICONDIRENTRY parsing, payload type detection |
| `STAGE_FRAME_SIZE` | `GetSize` | IHDR parsing for PNG payloads; ICO vs payload mismatch |
| `STAGE_FRAME_PIXEL_FORMAT` | `GetPixelFormat` | Format GUID resolution |
| `STAGE_FRAME_RESOLUTION` | `GetResolution` | DPI metadata |
| `STAGE_FRAME_PALETTE` | `CopyPalette` + `GetColors` | Palette table construction, overflow surface for 1/4/8bpp |
| `STAGE_FRAME_COLOR_CONTEXTS` | `GetColorContexts` | ICC profile chunk parsing |
| `STAGE_FRAME_METADATA` | `GetMetadataQueryReader` | `tEXt`/`iTXt`/`zTXt`/`eXIf` chunk parsing, nested XMP/EXIF |
| `STAGE_FRAME_THUMBNAIL` | `GetThumbnail` | Frame thumbnail |
| `STAGE_COPY_PIXELS` | `CopyPixels(NULL)` | Full pixel materialisation — primary PageHeap trigger |
| `STAGE_COPY_PIXELS_PARTIAL` | `CopyPixels(&rect)` | Per-scanline offset arithmetic for sub-rectangle |
| `STAGE_CONVERTER_INIT` | `IWICFormatConverter::Initialize` | Format conversion pipeline |
| `STAGE_CONVERTER_COPY` | Converter `CopyPixels` | Conversion with internal allocation |
| `STAGE_TRANSFORM` | `IWICBitmapSourceTransform::CopyPixels` | Dimension scaling arithmetic (overflow surface) |
| `STAGE_PROGRESSIVE` | `IWICProgressiveLevelControl` | Adam7 pass-dimension arithmetic, libpng row pointers |
| `STAGE_WIC_CONVERT` | `WICConvertBitmapSource` | Alternative conversion path; skips `CanConvert` |
| `STAGE_FRAME_OOB` | `GetFrame(N)`, `GetFrame(0xFFFF)`, `GetFrame(UINT_MAX)`, `GetFrame(0x80000000)` | Boundary validation in ICONDIR frame dispatcher |

### Metadata recursive descent

`process_metadata_reader()` performs recursive descent into nested `VT_UNKNOWN` `IWICMetadataQueryReader` objects (up to depth 4), exercising XMP and EXIF blocks embedded inside PNG-in-ICO `iTXt`/`eXIf` chunks. After enumeration, known key paths are queried via `GetMetadataByName` to exercise the name-lookup code path separately from the enumerator path.

---

## 7. Build System Requirements

- Visual Studio 2019 or 2022 (MSVC x64 toolchain)
- Windows SDK 10.0.19041 or later (`wincodec.h`, `wincodecsdk.h`)
- Target platform: Windows 10 x64 or later
- WinAFL + TinyInst (for fuzzing campaigns)

---

## 8. Building the Harness

All commands run in a Visual Studio x64 Developer Command Prompt.

### Campaign 1 — CacheOnDemand (default)

```cmd
cl /nologo /W3 /O2 /D HARNESS_MODE_FUZZ ^
   main.c policy.c ini.c trace.c ^
   /link ole32.lib oleaut32.lib windowscodecs.lib shlwapi.lib ^
   /Fe:harness_c1.exe
```

### Campaign 2 — CacheOnLoad

```cmd
cl /nologo /W3 /O2 /D HARNESS_MODE_FUZZ /D HARNESS_CACHE_ON_LOAD ^
   main.c policy.c ini.c trace.c ^
   /link ole32.lib oleaut32.lib windowscodecs.lib shlwapi.lib ^
   /Fe:harness_c2.exe
```

### Research build (SEH logging)

```cmd
cl /nologo /W3 /Od /Zi /D HARNESS_MODE_RESEARCH ^
   main.c policy.c ini.c trace.c ^
   /link ole32.lib oleaut32.lib windowscodecs.lib shlwapi.lib ^
   /Fe:harness_research.exe /Fd:harness_research.pdb
```

### Deep profile build

```cmd
cl /nologo /W3 /O2 /D HARNESS_MODE_FUZZ ^
   main.c policy.c ini.c trace.c ^
   /link ole32.lib oleaut32.lib windowscodecs.lib shlwapi.lib ^
   /Fe:harness_deep.exe
```

Then set `policy_profile = deep` in `harness.ini` next to the binary.

---

## 9. Environment Setup

### PageHeap

Enable full PageHeap on `windowscodecs.dll` for all campaign machines:

```cmd
gflags.exe /i harness_c1.exe +hpa
```

Or target the DLL directly when reproducing crashes:

```cmd
gflags.exe /p /enable harness_c1.exe /full
```

PageHeap converts heap overflows into access violations at the exact write instruction rather than at the next `HeapFree`. Without PageHeap, many heap overflows appear as corruptions deep in later allocations and are impossible to triage directly.

### ASLR and mitigations

Disable ASLR on `harness_c1.exe` for stable coverage bitmaps:

```cmd
EDITBIN /DYNAMICBASE:NO harness_c1.exe
```

### Output directories

Keep Campaign 1 and Campaign 2 output directories completely separate. Coverage bitmaps from `CacheOnDemand` and `CacheOnLoad` modes are not comparable and must never be mixed.

```
C:\fuzz\campaign1\
  corpus\      ← seed inputs
  findings\    ← WinAFL output

C:\fuzz\campaign2\
  corpus\
  findings\
```

---

## 10. Seed Corpus Preparation

### Recommended seed types

1. **Minimal valid ICO** — 1x1, 16-colour BMP payload. Triggers ICONDIR parsing, palette path.
2. **Multi-frame ICO** — Several frames at different sizes and bit depths (1bpp, 4bpp, 8bpp, 24bpp, 32bpp). Triggers the frame loop.
3. **PNG-payload ICO** — Frame with embedded PNG stream. Triggers the libpng path, iCCP, iTXt, Adam7.
4. **Progressive PNG ICO** — Embedded interlaced PNG. Triggers `IWICProgressiveLevelControl`.
5. **ICO with EXIF/XMP** — Embedded metadata in iTXt/eXIf chunks. Triggers nested metadata descent.
6. **Maximum-frame ICO** — ICONDIR with 256 entries (max_frames cap). Stress-tests frame enumeration.
7. **Palette-only ICO** — 256-colour 8bpp frame with full palette. Triggers `GetColors` overflow surface.
8. **ICC profile ICO** — PNG frame with iCCP chunk. Triggers `GetColorContexts` ICC parsing.

### Dimension diversity

Include seeds with unusual aspect ratios:
- `1 x 256`, `256 x 1` — extreme aspect ratios for stride arithmetic
- `255 x 255` — near-byte boundary
- `256 x 256` — byte boundary
- `65535 x 1` — maximum practical width at 1 pixel height

These seeds bootstrap the fuzzer's ability to explore the dimension overflow space.

---

## 11. WinAFL and TinyInst Setup

### TinyInst instrumentation

```cmd
liteCoverage.exe ^
    -coverage_module windowscodecs.dll ^
    -target_module harness_c1.exe ^
    -target_method fuzz_target ^
    -nargs 1 ^
    -instrument_module_name windowscodecs.dll ^
    -- harness_c1.exe @@
```

### WinAFL command line (balanced profile)

```cmd
afl-fuzz.exe ^
    -i C:\fuzz\campaign1\corpus ^
    -o C:\fuzz\campaign1\findings ^
    -coverage_module windowscodecs.dll ^
    -target_module harness_c1.exe ^
    -target_method fuzz_target ^
    -fuzz_iterations 5000 ^
    -nargs 1 ^
    -- harness_c1.exe @@
```

### WinAFL command line (deep profile)

```cmd
afl-fuzz.exe ^
    -i C:\fuzz\campaign1\corpus ^
    -o C:\fuzz\campaign1\findings_deep ^
    -coverage_module windowscodecs.dll ^
    -target_module harness_deep.exe ^
    -target_method fuzz_target ^
    -fuzz_iterations 200 ^
    -nargs 1 ^
    -- harness_deep.exe @@
```

### File extension requirement

The input path must end in `.ico` for the ICO decoder to be selected by WIC. Configure WinAFL with `-file_extension ico` or ensure seed files are named `*.ico`.

---

## 12. Launching Fuzzing Campaigns

### Recommended campaign strategy

**Phase 1 — fast profile corpus exploration**

Start with the `fast` profile and a broad seed corpus. This maximises exec/sec for initial coverage expansion.

```ini
policy_profile = fast
trace_enabled  = 0
```

Run until the exec/sec plateau (typically 24-48 hours).

**Phase 2 — balanced profile sustained fuzzing**

Switch to `balanced` with the corpus from Phase 1. All paths enabled; budget-gated allocation allows oversized frames to exercise cheap paths.

```ini
policy_profile = balanced
trace_enabled  = 0
```

Run for the main campaign duration. Monitor for crashes daily.

**Phase 3 — deep profile targeted hunting**

For any seed clusters that produce interesting coverage but no crashes, run a targeted `deep` campaign with PageHeap.

```ini
policy_profile = deep
trace_enabled  = 1
```

Pair with `gflags.exe /i harness_deep.exe +hpa` and frequent process restart (`-fuzz_iterations 200`).

**Campaign 2 — CacheOnLoad** runs in parallel or sequentially against Campaign 1. It exercises a completely different internal code path and must use a separate output directory.

---

## 13. Monitoring and Triage

### Key WinAFL statistics

- **exec/sec**: baseline 2000-5000 for `balanced`, 5000-10000 for `fast`.
- **unique_crashes**: primary indicator. Any non-zero value warrants investigation.
- **unique_hangs**: investigate if above baseline; may indicate infinite loop in metadata engine.
- **paths_total**: monitor for saturation.

### Trace-based crash attribution

The trace file `harness_trace.txt` logs every stage transition with its HRESULT and the current frame index. When WinAFL captures a crash:

1. Find the last `[FILE]` line — this is the crashing input.
2. Find the last `[STAGE]` line — this is the COM call where the crash occurred.
3. Find the `[BUDGET]` line for the crashing frame — this tells you whether the crash was in a cheap path (metadata/palette/ICC) or an allocation path (CopyPixels).
4. The `[OOB]` line shows whether any out-of-bounds frame index probe returned `S_OK` — a high-exploitability signal.

### STAGE_POLICY_VIOLATION in trace

A `[!POLICY]` line does NOT mean a frame was skipped. It indicates that `policy_select_budget()` selected `BUDGET_METADATA_ONLY` for a frame due to overflow-safe arithmetic. The frame was still processed via all cheap COM paths. This line is informational for post-crash analysis.

---

## 14. Reproducing and Debugging Crashes

### Step 1 — Reproduce with research build

```cmd
harness_research.exe crash_input.ico
```

The RESEARCH build wraps `fuzz_target()` in an SEH handler that logs the exception code and last trace stage before re-raising. The debugger catches the re-raise with full context.

### Step 2 — Enable PageHeap

```cmd
gflags.exe /p /enable harness_research.exe /full
```

Run the research build under WinDbg or CDB:

```cmd
windbg -g harness_research.exe crash_input.ico
```

### Step 3 — Compute RVA for IDA/Ghidra

```
crash_rva = crash_address - windowscodecs_base
```

Navigate to the RVA in IDA Pro. The surrounding function and the allocation call higher in the call stack identify the bug class.

### Step 4 — Minimise input

```cmd
afl-tmin.exe ^
    -i crash_input.ico ^
    -o crash_minimised.ico ^
    -coverage_module windowscodecs.dll ^
    -target_module harness_c1.exe ^
    -target_method fuzz_target ^
    -nargs 1 ^
    -- harness_c1.exe @@
```

---

## 15. Configuration Reference

`harness.ini` is placed next to the harness binary. All keys are optional; compiled-in defaults (balanced profile) are active when the file is absent.

### Profile key

| Key | Values | Description |
|---|---|---|
| `policy_profile` | `fast`, `balanced`, `deep` | Pre-set bundle of all limits and feature flags. Individual keys override. |

### Policy limits

| Key | Default | Range | Description |
|---|---|---|---|
| `max_width` | 65535 | 1–65535 | **Soft hint only.** Budget selection for `BUDGET_FULL` vs `BUDGET_METADATA_ONLY`. Never causes a frame skip. |
| `max_height` | 65535 | 1–65535 | **Soft hint only.** Same as above. |
| `max_frames` | 256 | 1–65535 | Maximum ICO frames processed per file. |
| `max_buffer_mb` | 128 | 1–512 | **Hard cap.** CopyPixels allocation limit. The real harness safety net. |
| `max_stride_mb` | 128 | 1–512 | Hard cap on computed row stride. Set equal to `max_buffer_mb`. |
| `max_color_contexts` | 64 | 1–256 | Maximum `IWICColorContext` objects per `GetColorContexts`. |
| `max_palette_colors` | 4096 | 1–65536 | Maximum palette entries for `IWICPalette::GetColors`. |
| `max_metadata_items` | 4096 | 1–65536 | Maximum items per single `IWICEnumMetadataItem` reader. |
| `max_total_metadata_items` | 8192 | 1–1048576 | Maximum total metadata items across all readers per `fuzz_target()`. |

**Important:** `max_width` and `max_height` are **soft hints**, not hard limits. Do not lower them expecting to "clean up" the run. Reducing them shrinks the budget-eligible window and causes more frames to receive `BUDGET_METADATA_ONLY`, reducing CopyPixels coverage.

### Iteration and mode

| Key | Default | Range | Description |
|---|---|---|---|
| `iterations` | 5000 | 1–1000000 | `fuzz_target()` calls in standalone mode. Overridden by WinAFL. |
| `mode` | `FUZZ` | `FUZZ`/`RESEARCH` | Does not override compile-time `/D HARNESS_MODE_RESEARCH`. |

### Feature flags

| Key | Default | Description |
|---|---|---|
| `trace_enabled` | 1 | Write iteration trace to `harness_trace.txt`. Disable for production fuzzing. |
| `conversion_path` | 1 | `IWICFormatConverter` path. Runs for all budgets; allocation gated internally. |
| `metadata_enum` | 1 | Recursive metadata enumeration. Disabled in `fast` profile. |
| `palette_path` | 1 | `IWICPalette::GetColors`. |
| `color_context_path` | 1 | ICC profile extraction. |
| `thumbnail_path` | 1 | `GetPreview` and `GetThumbnail`. |
| `decoder_info_path` | 1 | `IWICBitmapDecoderInfo` capability flags. |
| `transform_path` | 1 | `IWICBitmapSourceTransform` probe + scaled CopyPixels (BUDGET_FULL only). |
| `progressive_path` | 1 | `IWICProgressiveLevelControl` Adam7 per-level decode. |
| `wic_convert_path` | 1 | `WICConvertBitmapSource`. Runs for all budgets; CopyPixels gated on BUDGET_FULL. |

---

## 16. Source File Map

| File | Purpose |
|---|---|
| `main.c` | Harness entry point, global init/cleanup, `fuzz_target()`, all WIC exercise path functions |
| `policy.c` | `policy_select_budget()`, 64-bit stride/buffer arithmetic, bpp resolution via COM |
| `policy.h` | `HARNESS_POLICY`, `FRAME_BUDGET` enum, `POLICY_RESULT` enum, function declarations |
| `ini.c` | Profile loading, INI parsing, `config_apply_profile()`, `config_load_ini()`, `config_print()` |
| `ini.h` | `HARNESS_CONFIG` struct, `HARNESS_PROFILE` enum, loader function declarations |
| `config.h` | Compile-time defaults, profile presets, INI key names, COM format constants |
| `trace.c` | Structured trace log: per-stage, per-frame, budget logging, crash attribution |
| `trace.h` | `HARNESS_TRACE_CTX`, `TRIAGE_STAGE` enum, `trace_frame_budget()`, all declarations |
| `harness.ini` | Runtime configuration (optional) |

---

## 17. Known Vulnerability Classes

### Heap overflow via dimension mismatch (BMP payload)

The ICO `ICONDIRENTRY` declares a frame size. The embedded `BITMAPINFOHEADER` declares a potentially different size. A decoder that allocates based on one value and copies based on the other produces a linear heap overflow. `STAGE_COPY_PIXELS` is the trigger; PageHeap catches it at the exact write instruction.

### Integer overflow in palette size calculation

`ICONDIRENTRY.bColorCount` is a BYTE field; `BITMAPINFOHEADER.biClrUsed` is a DWORD. A decoder that converts between the two without range checking produces a palette allocation smaller than the copy count. `GetColors` then writes past the end of the palette buffer.

### Negative biHeight / sign extension

`BITMAPINFOHEADER.biHeight` is signed. Negative values indicate top-down bitmap. A codec that passes this to a UINT multiplication without a sign check produces a very large positive stride via two's-complement wrap. With 64-bit arithmetic in the harness this is detectable before allocation; the crash in the decoder occurs inside `CopyPixels`.

### PNG IHDR dimension overflow

The PNG `IHDR` contains 32-bit width and height. A malformed PNG-in-ICO can embed a PNG whose IHDR declares a much larger dimension than the ICO ICONDIRENTRY suggests. With the budget system, the harness exercises GetMetadataQueryReader, CopyPalette, GetColorContexts, and IWICFormatConverter probes on such a frame before the CopyPixels budget gate. The GetSize → IHDR dimension transition is the primary trigger surface.

### Adam7 pass-dimension overflow

PNG Adam7 interlaced frames have 7 passes, each with a different effective row width. The pass-dimension calculation is a secondary overflow surface: pass 1 operates on ceil(width/8) columns, pass 7 on all columns. Per-row pointer reconstruction across pass boundaries is historically vulnerable.

### Metadata chunk length integer overflow

PNG `iTXt`, `tEXt`, `zTXt`, `eXIf` carry a 32-bit length field. A corrupt length causes the metadata engine to read past the end of the chunk data buffer. Manifests as a read access violation or adjacent allocation corruption.

### ICC profile (iCCP) overflow

The `iCCP` chunk contains a compressed ICC profile. The profile length is computed from chunk length minus null-terminated profile name length. An overlong name, truncated profile, or decompressed-vs-declared size mismatch can produce an overflow in ICC profile parsing.

### IWICFormatConverter::Initialize with malformed source

`IWICFormatConverter::Initialize` validates the source format before accepting the conversion request. A decoder returning an unrecognised pixel format GUID triggers unvalidated code paths inside the converter. The RESEARCH build forces `Initialize` even when `CanConvert` returns FALSE, exercising format validation directly. With the budget system, this probe now runs on all frames including oversized ones.

### IWICBitmapSourceTransform dimension scaling overflow

`IWICBitmapSourceTransform::CopyPixels` accepts explicit output dimensions. The scaling arithmetic (requested dimensions vs actual frame dimensions) is an overflow surface. With the budget system, `DoesSupportTransform` now runs on frames with extreme dimensions (e.g. `width=200000`), exercising the capability introspection code path for off-nominal values.

### Out-of-bounds frame index validation

The OOB probe section tests `GetFrame(frameCount)`, `GetFrame(0xFFFF)`, `GetFrame(0xFFFFFFFF)`, and `GetFrame(0x80000000)`. Any `S_OK` return indicates an index validation bug with direct exploit potential: an attacker controlling the ICONDIR frame count can trigger access to unallocated or arbitrary frame structures.
