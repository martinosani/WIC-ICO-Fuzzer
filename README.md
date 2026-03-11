# WIC ICO Fuzzing Harness

A WinAFL persistent-mode fuzzing harness targeting `windowscodecs.dll` through the Windows Imaging Component (WIC) COM interface. The goal is to find memory corruption bugs, integer overflows, and parsing vulnerabilities in the ICO decoder and related paths inside `windowscodecs.dll`.

---

## Overview

The harness exercises `windowscodecs.dll` exclusively through the documented WIC COM interface chain. There are no direct imports or calls to `windowscodecs.dll` functions; everything goes through COM. This mirrors how real Windows applications (Explorer, preview handlers, thumbnail generators) consume ICO files, making bugs found here directly relevant to real-world exploitation scenarios.

### What gets exercised

Each `fuzz_target()` call exercises, for every frame in the ICO file:

- `IWICBitmapDecoder`: decoder creation, `QueryCapability`, container format, frame count, out-of-bounds frame index probes
- `IWICBitmapFrameDecode`: `GetSize`, `GetPixelFormat`, `GetResolution`, `CopyPixels` (full rect and partial rect)
- `IWICFormatConverter`: `CanConvert`, `Initialize`, `CopyPixels` to BGRA32
- `WICConvertBitmapSource`: a distinct internal conversion path
- `IWICMetadataQueryReader` + `IWICEnumMetadataItem`: recursive metadata enumeration including nested VT_UNKNOWN sub-readers (XMP/EXIF blocks inside PNG-in-ICO)
- `IWICPalette`: `GetColors` for palette-indexed frames (1/4/8bpp)
- `IWICColorContext` / `IWICImagingFactory2`: ICC profile extraction
- `IWICBitmapSourceTransform`: scaled `CopyPixels` at half dimensions
- `IWICProgressiveLevelControl`: per-level `CopyPixels` for Adam7 interlaced PNG
- `IWICBitmapDecoderInfo`: capability flags, MIME types, file extensions
- Container and frame-level `GetPreview` and `GetThumbnail`

### Real coverage target

The real coverage module is `windowscodecs.dll`. The harness binary is a thin driver; all interesting code is inside the system DLL. TinyInst instruments `windowscodecs.dll` directly.

---

## Building

### Requirements

- Windows 10 or 11, x64
- Visual Studio 2019 or later with the MSVC x64 toolchain
- Windows SDK (included with Visual Studio)
- Administrator rights are not required for building

### Build steps

Open a **x64 Native Tools Command Prompt** and run from the project directory:

**Campaign 1 — lazy metadata parsing (default):**

```cmd
cl /nologo /W3 /O2 /D HARNESS_MODE_FUZZ ^
   main.c policy.c ini.c trace.c ^
   /link ole32.lib oleaut32.lib windowscodecs.lib shlwapi.lib ^
   /Fe:harness_c1.exe
```

**Campaign 2 — eager metadata parsing:**

```cmd
cl /nologo /W3 /O2 /D HARNESS_MODE_FUZZ /D HARNESS_CACHE_ON_LOAD ^
   main.c policy.c ini.c trace.c ^
   /link ole32.lib oleaut32.lib windowscodecs.lib shlwapi.lib ^
   /Fe:harness_c2.exe
```

**Research / debug build (SEH logging enabled):**

```cmd
cl /nologo /W3 /Zi /Od /D HARNESS_MODE_RESEARCH ^
   main.c policy.c ini.c trace.c ^
   /link ole32.lib oleaut32.lib windowscodecs.lib shlwapi.lib ^
   /Fe:harness_research.exe
```

Place `harness.ini` in the same directory as the compiled binary.

---

## Seed corpus

Create an `in\` directory and populate it with valid ICO files as seed inputs.

Good seed sources:
- ICO files extracted from Windows system directories (`shell32.dll`, `imageres.dll`, `wmploc.dll` via resource extraction tools such as `7-Zip`, `Resource Hacker`, or `BinFly`)
- ICO files with embedded PNG frames (these exercise the PNG-in-ICO path, which has historically been more vulnerability-rich than the BMP path)
- ICO files with multiple frames of varying dimensions and bit depths

Aim for 50–200 seeds with good format diversity. Minimise the corpus with WinAFL's `minset` mode before the main campaign:

```cmd
afl-fuzz.exe -i in -o in_min -minimize_corpus -- harness_c1.exe @@
```

---

## Running with WinAFL and TinyInst

### Prerequisites

- WinAFL built with TinyInst support
- TinyInst installed and accessible
- `dynamorio\` directory from DynamoRIO (if using DynamoRIO instead of TinyInst)

Refer to the [WinAFL documentation](https://github.com/googleprojectzero/winafl) and [TinyInst documentation](https://github.com/googleprojectzero/TinyInst) for installation. Follow their documentation precisely; the options listed below reflect current WinAFL/TinyInst behaviour but may change across releases.

### Key WinAFL/TinyInst parameters

| Parameter | Value | Explanation |
|---|---|---|
| `-coverage_module` | `windowscodecs.dll` | Module TinyInst instruments for coverage feedback. This is the real target. |
| `-target_module` | `harness_c1.exe` | Module containing the persistent-mode target function. |
| `-target_method` | `fuzz_target` | Name of the function WinAFL calls in a loop. Must match `WINAFL_TARGET_FUNCTION` in `config.h`. |
| `-nargs` | `1` | `fuzz_target` takes one argument (the file path as `WCHAR*`). |
| `@@` | (file path token) | WinAFL replaces `@@` with the path to the current mutated input file. |

### Campaign 1

```cmd
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

### Campaign 2

```cmd
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

The `-o` output directories must be kept separate. Coverage bitmaps from Campaign 1 and Campaign 2 are not comparable.

### Recommended WinAFL options to consider

Check the [WinAFL README](https://github.com/googleprojectzero/winafl/blob/master/readme_winafl.md) for the current complete option list. Some options worth reviewing:

- `-timeout`: per-iteration timeout in milliseconds. Raise if complex ICO files with many frames time out legitimately.
- `-t`: same as `-timeout` in some WinAFL builds. Consult the version you are using.
- `-no_rand_screen`: may improve stability on headless machines.
- Page Heap (`gflags /p /enable harness_c1.exe /full`): strongly recommended. Enables `ntdll` heap guard pages so heap overflows that would otherwise be silent produce an access violation immediately.

---

## Output and crashes

WinAFL writes output to the `-o` directory specified at launch:

```
findings_c1\
  crashes\      -- inputs that caused an access violation or unhandled exception
  hangs\        -- inputs that exceeded the iteration timeout
  queue\        -- current working corpus
```

A crash in `windowscodecs.dll` is the goal. Each file in `crashes\` is a minimised input that reproduced the crash during the run.

---

## Reproducing a crash manually

To replay a crash outside WinAFL (e.g. under WinDbg with Page Heap):

```cmd
gflags /p /enable harness_research.exe /full
windbg -g harness_research.exe path\to\crash_input.ico
```

Or without a debugger:

```cmd
harness_research.exe path\to\crash_input.ico
```

The research build wraps `fuzz_target()` in a structured exception handler that logs the exception code and the last WIC stage reached to `harness_trace.txt` before re-raising. This makes crash attribution straightforward.

To reproduce in the FUZZ build (exception propagates directly to the OS):

```cmd
harness_c1.exe path\to\crash_input.ico
```

---

## Configuration

All policy limits and feature flags are controlled via `harness.ini` placed next to the executable. The file is optional; compiled-in defaults are used when it is absent.

See `harness.ini` for the full list of keys with descriptions and default values.

Key policy defaults:

| Key | Default | Notes |
|---|---|---|
| `max_width` | 65535 | Accepts all valid and malformed ICO dimensions |
| `max_height` | 65535 | Same |
| `max_buffer_mb` | 256 | Per-frame pixel buffer cap |
| `max_stride_mb` | 256 | Per-frame row stride cap |
| `max_frames` | 256 | Frames processed per file |
| `max_palette_colors` | 4096 | Palette entries per frame |
| `max_color_contexts` | 64 | ICC context objects per call |
| `max_metadata_items` | 4096 | Metadata items per reader |
| `max_total_metadata_items` | 16384 | Total metadata items per iteration |

Do not lower these values aggressively. Tight caps cause the harness to skip inputs that are exactly the interesting malformed cases the fuzzer needs to reach. Raise `max_buffer_mb` only if OOM crashes are collapsing throughput unacceptably.

---

## Source file map

| File | Purpose |
|---|---|
| `main.c` | Harness entry point, `fuzz_target()`, all WIC exercise paths |
| `policy.c` / `policy.h` | Dimension validation, stride/buffer arithmetic (64-bit), bpp resolution |
| `ini.c` / `ini.h` | INI loader, `HARNESS_CONFIG` struct, `ini_load_policy()` |
| `config.h` | Compile-time defaults for all policy limits and feature flags |
| `trace.c` / `trace.h` | Structured trace log (disabled in FUZZ builds for throughput) |
| `harness.ini` | Runtime configuration (optional) |
