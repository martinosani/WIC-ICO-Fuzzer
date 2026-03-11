# WIC ICO Fuzzing Harness

A WinAFL persistent-mode fuzzing harness targeting `windowscodecs.dll` via the Windows Imaging Component (WIC) COM API. The target attack surface is the ICO file decoder, including both BMP-payload and PNG-in-ICO frames.

---

## Architecture

### Design Principles

- **COM-only interface chain** — no direct DLL calls. Every decoder interaction goes through the WIC COM vtable, matching the code paths exercised by real Windows applications (Explorer, preview handlers, shell thumbnail generators).
- **Persistent mode (WinAFL Option B)** — the WIC imaging factory and COM apartment are initialised once outside the fuzz loop. WinAFL snapshots the process state after global init and restores it between iterations, achieving high throughput without re-initialising COM per file.
- **Strict integer arithmetic** — all stride and buffer size computations use explicit UINT32 overflow checks before every multiplication. Under-allocation would mask real decoder overflows from PageHeap.
- **Modular coverage paths** — each COM interface sub-path is independently switchable via `harness.ini` for throughput/coverage trade-off tuning.

### Module Layout

```
main.c       fuzz_target() entry point, global COM lifecycle,
             all per-frame COM sub-paths
policy.c/h   Dimension validation, stride/buffer arithmetic,
             bpp resolution via IWICPixelFormatInfo
trace.c/h    Structured trace file: every stage, HRESULT,
             frame index, policy outcomes
ini.c/h      harness.ini loader; typed defaults for all keys
config.h     Compile-time constants, policy limits, INI key names
harness.ini  Runtime configuration (optional; defaults always valid)
```

### COM Interface Chain

```
IWICImagingFactory           (singleton, created once)
IWICImagingFactory2          (QI from factory; for CreateColorContext)
  └─ IWICBitmapDecoder       (per-iteration; one per input file)
       ├─ IWICBitmapDecoderInfo
       ├─ IWICMetadataQueryReader  (container level; recursive)
       │    └─ IWICEnumMetadataItem
       ├─ IWICPalette
       ├─ IWICColorContext[]
       ├─ IWICBitmapSource   (preview / thumbnail)
       └─ IWICBitmapFrameDecode  (per frame, up to max_frames)
            ├─ IWICBitmapSource       (via QI — never raw cast)
            ├─ IWICMetadataQueryReader (per-frame; recursive)
            ├─ IWICPalette
            ├─ IWICColorContext[]
            ├─ IWICFormatConverter    (-> BGRA32 -> CopyPixels)
            ├─ IWICBitmapSourceTransform  (scaled decode path)
            └─ IWICProgressiveLevelControl (Adam7 PNG-in-ICO)
```

### Coverage Paths per Iteration

| Stage | Interface | Description |
|---|---|---|
| 1 | `CreateDecoderFromFilename` | ICO signature detection, ICONDIR parse, codec select |
| 2 | `QueryCapability` | Capability detection via IStream (separate internal path) |
| 3 | `GetContainerFormat` | Container GUID |
| 4 | `GetDecoderInfo` | Codec info strings, multi-frame/lossless/animation flags |
| 5 | `GetMetadataQueryReader` | Container metadata, recursive XMP/EXIF descent, `GetMetadataByName` on known PNG-in-ICO keys |
| 6 | `CopyPalette` (container) | Container-level palette |
| 7 | `GetColorContexts` (container) | ICC profile parsing (iCCP chunk) |
| 8 | `GetPreview` | Preview bitmap extraction |
| 9 | `GetThumbnail` (container) | Container thumbnail |
| 10 | `GetFrameCount` | ICONDIR entry count |
| 11 | `GetFrame(i)` | Per-entry parsing, BMP vs PNG payload detection |
| 12 | `GetSize` | Declared dimensions vs payload dimensions |
| 13 | `GetPixelFormat` | Pixel format GUID |
| 14 | `GetResolution` | DPI values |
| 15 | `CopyPalette` (frame) | Frame palette for 1/4/8bpp |
| 16 | `GetColorContexts` (frame) | Per-frame ICC profile |
| 17 | `GetMetadataQueryReader` (frame) | Frame metadata, tEXt/iTXt/zTXt, recursive, `GetMetadataByName` |
| 18 | `GetThumbnail` (frame) | Frame thumbnail |
| 19 | `CopyPixels` (full rect) | **Primary bug trigger** — full pixel materialisation |
| 19b | `CopyPixels` (partial rect) | Top-left quadrant; exercises per-scanline offset arithmetic |
| 20–21 | `IWICFormatConverter` | BGRA32 conversion pipeline, CopyPixels on converter |
| 25 | `IWICBitmapSourceTransform` | Half-size scaled decode; dimension overflow surface |
| 26 | `IWICProgressiveLevelControl` | Adam7 interlaced PNG; level transition bug surface |
| 27 | OOB frame probes | `GetFrame` at count, 0xFFFF, 0xFFFFFFFF, 0x80000000 |
| 28 | `WICConvertBitmapSource` | Distinct internal conversion path; bypasses CanConvert |

---

## Two-Campaign Strategy

### What a Campaign Is

A campaign is a complete WinAFL fuzzing run: a corpus of ICO files mutated over time, with coverage feedback driving mutation priority. Each campaign runs as a separate `afl-fuzz.exe` process with its own corpus, output directory, and compiled harness binary.

This harness is designed to be run as **two complementary campaigns**. The two campaigns are not redundant — they exercise **different internal code paths** inside `windowscodecs.dll` that are mutually exclusive: a bug reachable in one campaign is structurally unreachable from the other. Running both is necessary to maximise total coverage of the decoder.

The entire difference between the two campaigns is a single parameter passed to `CreateDecoderFromFilename`: the **metadata cache mode**. This single flag determines how and when `windowscodecs.dll` deserialises the metadata chunks embedded in the ICO payload, and in doing so selects which internal implementation is exercised.

---

### Campaign 1 — `WICDecodeMetadataCacheOnDemand` (Default, Primary)

#### What it does

When `CreateDecoderFromFilename` is called with `WICDecodeMetadataCacheOnDemand`, WIC opens the file, reads the ICONDIR header, and identifies the frame list. It does **not** parse metadata at this point. The raw bytes of `tEXt`, `iTXt`, `iCCP`, EXIF, and XMP chunks remain unread in the file.

Metadata parsing is deferred and happens the first time the harness calls `GetMetadataQueryReader` on the decoder or on a frame. At that point, WIC reads and deserialises the relevant chunks on demand using a distinct lazy-loading internal implementation.

#### Why this is the primary campaign

This is how **every real Windows application** opens ICO files. Windows Explorer, the shell thumbnail handler, the File Explorer preview handler, and any application using WIC without an explicit override all use `CacheOnDemand`. Bugs found through this path are:

- Directly reachable from a user opening a malicious ICO file in Windows Explorer with no additional interaction
- Exploitable without relying on application-specific behaviour or configuration
- Higher real-world severity and higher priority for patching

Historically, several `windowscodecs.dll` vulnerabilities were only reachable through the lazy deserialisation path because the bug lived in the on-access state machine, not in the initial file open. An eager-parsing harness would miss these entirely.

#### Build

```bat
cl /nologo /W4 /O2 /MT /D HARNESS_MODE_FUZZ ^
   /D UNICODE /D _UNICODE ^
   main.c policy.c trace.c ini.c ^
   /Fe:harness.exe ^
   /link ole32.lib oleaut32.lib windowscodecs.lib shell32.lib shlwapi.lib
```

No additional flag is needed. `CacheOnDemand` is the compiled-in default.

#### Run — TinyInst (recommended)

```bat
afl-fuzz.exe ^
    -i corpus ^
    -o findings_c1 ^
    -t 5000 ^
    -fuzz_iterations 5000 ^
    -target_module harness.exe ^
    -target_method fuzz_target ^
    -nargs 1 ^
    -instrument_module windowscodecs.dll ^
    -- harness.exe @@
```

#### Run — DynamoRIO (alternative)

```bat
afl-fuzz.exe ^
    -i corpus ^
    -o findings_c1 ^
    -t 5000 ^
    -fuzz_iterations 5000 ^
    -D C:\DynamoRIO\bin64 ^
    -target_module harness.exe ^
    -target_method fuzz_target ^
    -nargs 1 ^
    -coverage_module windowscodecs.dll ^
    -- harness.exe @@
```

---

### Campaign 2 — `WICDecodeMetadataCacheOnLoad` (Complementary)

#### What it does

When `CreateDecoderFromFilename` is called with `WICDecodeMetadataCacheOnLoad`, WIC reads and fully deserialises **all** metadata in the file immediately, inside the `CreateDecoderFromFilename` call itself. By the time the harness receives the decoder object, every `tEXt`, `iTXt`, `iCCP`, EXIF, and XMP chunk has already been parsed into an in-memory cache. When the harness later calls `GetMetadataQueryReader`, it receives data from that cache rather than triggering any further parsing.

#### Why this is the complementary campaign

The eager and lazy metadata parsing implementations inside `windowscodecs.dll` share some code but follow different execution paths, maintain different internal state, and perform allocations in a different order. A malformed ICO chunk that triggers a bug in the eager path may not trigger the same bug in the lazy path, and vice versa, because:

- The call stack at the time of parsing is different, which affects heap layout and the order in which allocations occur
- Error handling branches differ between the eager and lazy implementations
- The eager path is invoked from a different COM method, meaning the decoder object is in a different state at parse time

Campaign 2 ensures the eager deserialisation code receives the same mutation pressure as the lazy code, filling coverage gaps that Campaign 1 cannot reach.

#### Build (requires `/D HARNESS_CACHE_ON_LOAD`)

```bat
cl /nologo /W4 /O2 /MT /D HARNESS_MODE_FUZZ /D HARNESS_CACHE_ON_LOAD ^
   /D UNICODE /D _UNICODE ^
   main.c policy.c trace.c ini.c ^
   /Fe:harness_c2.exe ^
   /link ole32.lib oleaut32.lib windowscodecs.lib shell32.lib shlwapi.lib
```

#### Run — TinyInst (recommended)

```bat
afl-fuzz.exe ^
    -i corpus ^
    -o findings_c2 ^
    -t 5000 ^
    -fuzz_iterations 5000 ^
    -target_module harness_c2.exe ^
    -target_method fuzz_target ^
    -nargs 1 ^
    -instrument_module windowscodecs.dll ^
    -- harness_c2.exe @@
```

#### Run — DynamoRIO (alternative)

```bat
afl-fuzz.exe ^
    -i corpus ^
    -o findings_c2 ^
    -t 5000 ^
    -fuzz_iterations 5000 ^
    -D C:\DynamoRIO\bin64 ^
    -target_module harness_c2.exe ^
    -target_method fuzz_target ^
    -nargs 1 ^
    -coverage_module windowscodecs.dll ^
    -- harness_c2.exe @@
```

---

### Campaign Comparison

| | Campaign 1 | Campaign 2 |
|---|---|---|
| **Metadata cache mode** | `WICDecodeMetadataCacheOnDemand` | `WICDecodeMetadataCacheOnLoad` |
| **Build flag** | *(none — default)* | `/D HARNESS_CACHE_ON_LOAD` |
| **Binary** | `harness.exe` | `harness_c2.exe` |
| **Output directory** | `findings_c1` | `findings_c2` |
| **When metadata is parsed** | On first `GetMetadataQueryReader` call | Inside `CreateDecoderFromFilename` |
| **Matches real-world app behaviour** | ✅ Yes — Explorer, preview handlers, thumbnail generators | ❌ No — requires explicit opt-in by the calling application |
| **Priority** | Primary | Complementary |
| **Unique internal paths exercised** | Lazy deserialisation state machine | Eager deserialisation at decoder creation |

> **Critical:** never mix output directories between campaigns. Coverage bitmaps are not comparable between runs. A finding in `findings_c1` must be reproduced with `harness.exe`; a finding in `findings_c2` must be reproduced with `harness_c2.exe`.

---

## Preparing WinAFL

### How Backend Selection Works

WinAFL supports two coverage backends: **TinyInst** and **DynamoRIO**. This is the single most important setup decision because **the backend is compiled into `afl-fuzz.exe` at build time — it is not a runtime flag**.

Building WinAFL with TinyInst and building it with DynamoRIO produce two different `afl-fuzz.exe` binaries. They are not interchangeable:

```
WinAFL built with -DUSE_TINYINST=1
    → afl-fuzz.exe understands:   -instrument_module <dll>
    → afl-fuzz.exe does NOT know: -D <path>  or  -coverage_module <dll>

WinAFL built with -DDynamoRIO_DIR=...
    → afl-fuzz.exe understands:   -D <path>  and  -coverage_module <dll>
    → afl-fuzz.exe does NOT know: -instrument_module <dll>
```

If you pass `-instrument_module` to a DynamoRIO build of `afl-fuzz.exe`, the flag is silently ignored and you get no coverage. If you pass `-coverage_module` to a TinyInst build, the same happens. There is no error message — the fuzzer simply runs with zero coverage feedback, producing no useful findings.

**Choose your backend once, build WinAFL once, use that binary for all campaigns.**

---

### Option A — TinyInst (Recommended)

#### What TinyInst is

TinyInst is a lightweight instrumentation library developed by Google Project Zero. It instruments `windowscodecs.dll` by rewriting its executable sections in memory at runtime, inserting coverage callbacks at every basic block boundary. It does not require a full Dynamic Binary Instrumentation framework.

TinyInst is the recommended backend for this harness for two reasons:

- `windowscodecs.dll` uses `CoInitializeEx` COM apartment threading internally. DynamoRIO's instrumentation layer has documented conflicts with COM STA persistence in some Windows 10/11 builds that manifest as spurious access violations inside the DBI framework rather than inside the target DLL, producing false-positive crashes that complicate triage. TinyInst does not have this conflict.
- TinyInst produces approximately 20–35% higher exec/s on this target due to lower instrumentation overhead.

#### Prerequisites

- Git
- Visual Studio 2019 or later (C++ workload)
- CMake 3.14 or later
- No additional download needed — TinyInst is bundled as a WinAFL git submodule

#### Step 1 — Clone WinAFL and pull TinyInst

```bat
git clone https://github.com/googleprojectzero/winafl.git
cd winafl
git submodule update --init --recursive
```

The `git submodule` command fetches TinyInst into `winafl\TinyInst\`. Without this step the build will fail with a missing dependency error.

#### Step 2 — Build WinAFL with TinyInst

Open an **x64 Native Tools Command Prompt for VS**, then:

```bat
cd winafl
mkdir build64
cd build64

cmake -G "Visual Studio 17 2022" -A x64 ^
    -DUSE_TINYINST=1 ^
    ..

cmake --build . --config Release
```

The output binary is `build64\Release\afl-fuzz.exe`. This binary has TinyInst compiled in.

#### Step 3 — Verify

```bat
build64\Release\afl-fuzz.exe --help 2>&1 | findstr instrument
```

You should see `-instrument_module` listed in the output. If you do not, the build did not pick up TinyInst correctly — re-check that `git submodule update` completed without errors.

#### How to specify the coverage module in the run command

When launching `afl-fuzz.exe` (TinyInst build), use `-instrument_module` to tell TinyInst which DLL to instrument:

```bat
-instrument_module windowscodecs.dll
```

There is no separate backend flag. The TinyInst runtime is already embedded in `afl-fuzz.exe`.

---

### Option B — DynamoRIO

#### What DynamoRIO is

DynamoRIO is a full Dynamic Binary Instrumentation framework. WinAFL uses it to insert coverage callbacks via the `drcov` client. It requires a separate installation and its path must be provided both at WinAFL build time and at runtime.

#### Prerequisites

- Git
- Visual Studio 2019 or later (C++ workload)
- CMake 3.14 or later
- DynamoRIO pre-built package — download from [https://dynamorio.org](https://dynamorio.org) and extract to a known path, e.g. `C:\DynamoRIO`

#### Step 1 — Clone WinAFL

```bat
git clone https://github.com/googleprojectzero/winafl.git
cd winafl
```

No submodule step needed for the DynamoRIO backend.

#### Step 2 — Build WinAFL with DynamoRIO

Open an **x64 Native Tools Command Prompt for VS**, then:

```bat
cd winafl
mkdir build64
cd build64

cmake -G "Visual Studio 17 2022" -A x64 ^
    -DDynamoRIO_DIR=C:\DynamoRIO\cmake ^
    ..

cmake --build . --config Release
```

Replace `C:\DynamoRIO\cmake` with the actual path to the `cmake` subdirectory inside your DynamoRIO installation.

The output binary is `build64\Release\afl-fuzz.exe`. This binary has DynamoRIO support compiled in.

#### Step 3 — Verify

```bat
build64\Release\afl-fuzz.exe --help 2>&1 | findstr coverage_module
```

You should see `-coverage_module` listed. If not, cmake did not find DynamoRIO — check that `-DDynamoRIO_DIR` points to the correct path.

#### How to specify the coverage module in the run command

When launching `afl-fuzz.exe` (DynamoRIO build), you need two flags: one to point to the DynamoRIO runtime, and one to specify the module:

```bat
-D C:\DynamoRIO\bin64 ^
-coverage_module windowscodecs.dll
```

The `-D` flag tells WinAFL where to find `drrun.exe` at runtime. Without it, WinAFL cannot launch the DynamoRIO instrumentation layer.

---

### Backend Comparison

| | TinyInst | DynamoRIO |
|---|---|---|
| **Backend compiled into afl-fuzz.exe** | `-DUSE_TINYINST=1` at cmake time | `-DDynamoRIO_DIR=...` at cmake time |
| **Runtime flag to select module** | `-instrument_module <dll>` | `-coverage_module <dll>` |
| **Additional runtime flag** | *(none)* | `-D C:\DynamoRIO\bin64` |
| **External dependency** | None — TinyInst is a submodule | DynamoRIO pre-built package required |
| **Throughput on this target** | ~20–35% higher | Baseline |
| **Stability with COM targets** | ✅ No known issues | ⚠️ Documented conflicts with `CoInitializeEx` + persistent mode |
| **Windows 11 22H2+ support** | ✅ Fully supported | ⚠️ Some compatibility issues |
| **Coverage granularity** | Basic-block edge | Basic-block edge |
| **Crash debugging** | Standard debugger | Richer: custom DynamoRIO clients |

> **Never mix output directories between backends.** Coverage bitmaps produced by TinyInst and DynamoRIO are incompatible. If you switch backends mid-campaign, create a new `-o` output directory from scratch — do not reuse an existing one.

---

## Environment Setup

### Requirements

| Component | Notes |
|---|---|
| Windows 10/11 x64 | Production `windowscodecs.dll` required |
| Visual Studio 2019+ | MSVC x64 toolchain, x64 Native Tools Command Prompt |
| WinAFL | Built with TinyInst or DynamoRIO (see above) |

### PageHeap (Required)

Without PageHeap, heap overflows in `windowscodecs.dll` may write into adjacent allocations silently and never crash the process.

```bat
:: Enable (run as Administrator)
gflags.exe /p /enable harness.exe /full
gflags.exe /p /enable harness_c2.exe /full

:: Verify
gflags.exe /p

:: Disable after campaign
gflags.exe /p /disable harness.exe
gflags.exe /p /disable harness_c2.exe
```

### Application Verifier (Optional, Research Mode)

```bat
appverif.exe -enable Heaps -for harness.exe
```

---

## Building the Harness

Open an **x64 Native Tools Command Prompt for VS**.

### Campaign 1 — FUZZ build (CacheOnDemand, default)

```bat
cl /nologo /W4 /O2 /MT /D HARNESS_MODE_FUZZ ^
   /D UNICODE /D _UNICODE ^
   main.c policy.c trace.c ini.c ^
   /Fe:harness.exe ^
   /link ole32.lib oleaut32.lib windowscodecs.lib shell32.lib shlwapi.lib
```

### Campaign 2 — FUZZ build (CacheOnLoad)

```bat
cl /nologo /W4 /O2 /MT /D HARNESS_MODE_FUZZ /D HARNESS_CACHE_ON_LOAD ^
   /D UNICODE /D _UNICODE ^
   main.c policy.c trace.c ini.c ^
   /Fe:harness_c2.exe ^
   /link ole32.lib oleaut32.lib windowscodecs.lib shell32.lib shlwapi.lib
```

### RESEARCH build (standalone debugging, SEH logging)

```bat
cl /nologo /W4 /Od /MTd /Zi /D HARNESS_MODE_RESEARCH ^
   /D UNICODE /D _UNICODE ^
   main.c policy.c trace.c ini.c ^
   /Fe:harness_research.exe ^
   /link ole32.lib oleaut32.lib windowscodecs.lib shell32.lib shlwapi.lib
```

Place `harness.ini` in the same directory as each built `.exe`.

---

## Running the Harness

### Standalone Mode (Testing / Research)

```bat
harness_research.exe sample.ico
type harness_trace.txt
```

Verify in `harness_trace.txt`:
- `[INIT]` lines confirm COM and WIC factory initialisation
- `[CONFIG]` block shows active settings
- `[ITER]` / `[FILE]` / `[DONE]` blocks confirm per-iteration flow
- `[STAGE] frame=N` for per-frame operations, `frame=--` for container-level

### Input File Extension

Input files **must** have the `.ico` extension. `CreateDecoderFromFilename` uses the extension to select the ICO codec. Configure WinAFL:

```bat
-file_extension ico
```

---

## Configuration (harness.ini)

`harness.ini` is optional. Resolved relative to the harness executable directory.

```ini
[harness]

max_width         = 16384
max_height        = 16384
max_frames        = 256
max_buffer_mb     = 256
iterations        = 5000   ; valid range: 1 to 1000000

conversion_path   = 1
trace_enabled     = 1      ; disable in FUZZ builds for max throughput
metadata_enum     = 1
palette_path      = 1
color_context_path= 1
thumbnail_path    = 1
decoder_info_path = 1
transform_path    = 1
progressive_path  = 1
wic_convert_path  = 1

mode              = FUZZ
```

---

## Trace File Format

`harness_trace.txt` is flushed to disk after every completed iteration. If the process crashes mid-iteration, the last complete `[ITER]`/`[FILE]` block identifies the crashing input exactly.

### Key Fields for Crash Triage

| Field | Meaning |
|---|---|
| `[FILE]` | Input file that produced the crash |
| `[STAGE] frame=N` | Last stage before crash; N is the exact frame index |
| `[STAGE] frame=--` | Container-level operation (outside per-frame loop) |
| `[SIZE]` | Decoded dimensions — mismatch with ICONDIRENTRY = decoder bug |
| `[CPX]` | Stride and buffer at CopyPixels; `policy=POLICY_OK` means harness allocation was correct |
| `[OOB]` | Out-of-bounds probe results; unexpected S_OK = index validation bug |
| `[!SEH]` | SEH exception (RESEARCH mode only); exception code + last stage |
| `[!POLICY]` | Policy cap triggered; frame was skipped, not a crash |

---

## Corpus Recommendations

| File type | Coverage target |
|---|---|
| ICO with 0 frames (`idCount = 0`) | ICONDIR zero-entry handling |
| ICO where `idCount` exceeds actual entry count | Declared vs actual mismatch |
| ICO with embedded PNG payload | libpng / zlib inflate paths |
| ICO with interlaced PNG payload | Adam7 progressive path |
| ICO with malformed iCCP chunk | ICC profile parsing surface |
| ICO with 1×1 frames | Minimum-dimension guard conditions |
| ICO with 1/4/8bpp BMP frames | Palette table extraction; GetColors overflow surface |
| ICO where `biSizeImage` is 0 and non-zero | Decoder size hint paths |
| ICO with 256 frames | Frame cap and per-frame loop at maximum depth |

---

## Policy Limits Reference

| Constant | Default | Purpose |
|---|---|---|
| `POLICY_MAX_WIDTH` | 16384 | Skip frames wider than this |
| `POLICY_MAX_HEIGHT` | 16384 | Skip frames taller than this |
| `POLICY_MAX_BUFFER_BYTES` | 256 MB | Skip frames requiring larger allocation |
| `POLICY_MAX_STRIDE` | 65536 | Skip frames with wider computed stride |
| `POLICY_MAX_FRAMES` | 256 | Process at most this many frames per file |
| `POLICY_MAX_COLOR_CONTEXTS` | 8 | Cap on IWICColorContext objects per call |
| `POLICY_MAX_PALETTE_COLORS` | 256 | Cap on GetColors allocation |
| `POLICY_MAX_METADATA_ITEMS` | 512 | Max items per single metadata reader |
| `POLICY_MAX_TOTAL_METADATA_ITEMS` | 2048 | Max total items per iteration across all readers |
| `POLICY_BPP_FALLBACK_MAX` | 128 | Fallback bpp on format resolution failure (over-allocates) |

---

## Security Notes

- **bpp fallback is 128, not 32** — on partial COM query failure the harness allocates for 128 bpp. Under-allocating for a higher-bpp format would place a real decoder overflow inside valid heap memory beyond the buffer, masking it from PageHeap.
- **`IWICBitmapSource` QI before CopyPixels** — casting `IWICBitmapFrameDecode*` to `IWICBitmapSource*` directly is undefined behaviour in C. All CopyPixels calls in this harness use QueryInterface.
- **`IWICImagingFactory2` for CreateColorContext** — `IWICImagingFactory` does not expose `CreateColorContext`. Using the wrong factory pointer would produce vtable corruption.
- **`actualCount` snapshot in `process_color_contexts`** — the allocated count is snapshotted before the second `GetColorContexts` call. A malformed ICO that causes the decoder to return a larger count cannot drive the cleanup loop out of bounds.
