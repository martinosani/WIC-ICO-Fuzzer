WIC ICO Decoder Research Harness
Overview

This project contains a native x64 fuzzing harness written in C designed to exercise the Windows Imaging Component (WIC) ICO decoder through its COM interfaces.

The harness is intended for:

vulnerability research

coverage-guided fuzzing

decoder behavioral analysis

crash triage

differential testing of metadata cache modes

The main fuzz entry point is:

void fuzz_target(const WCHAR *filePath)

The harness architecture follows a persistent fuzzing pattern:

Process start
 ├─ Initialize COM
 ├─ Create IWICImagingFactory
 └─ Loop:
      fuzz_target()

This makes the harness compatible with:

TinyInst

WinAFL persistent mode

standalone testing

Repository Structure
config.h
ini.c
ini.h
main.c
policy.c
policy.h
trace.c
trace.h
harness.ini
README.md
File Descriptions
main.c

Contains:

wmain() entrypoint

harness initialization

persistent fuzz loop

fuzz_target() implementation

WIC decoder logic

policy.c / policy.h

Defines:

safety limits

buffer size checks

stride calculations

pixel format resolution

trace.c / trace.h

Provides:

logging

execution stage tracing

decoder capability output

metadata enumeration logs

Useful for:

crash triage

manual decoder analysis

ini.c / ini.h

Simple configuration parser used to load:

harness.ini

Configuration is optional.

config.h

Compile-time configuration values including:

fuzz mode

metadata cache mode

feature enable flags

default policy limits

harness.ini

Runtime configuration file controlling:

feature toggles

iteration count

trace behavior

Decoder Code Paths Exercised

The harness exercises multiple WIC interfaces:

IWICImagingFactory
IWICImagingFactory2
IWICBitmapDecoder
IWICBitmapDecoderInfo
IWICBitmapFrameDecode
IWICBitmapSource
IWICFormatConverter
IWICMetadataQueryReader
IWICEnumMetadataItem
IWICPalette
IWICColorContext
IWICBitmapSourceTransform
IWICProgressiveLevelControl

This ensures coverage of:

frame parsing

metadata parsing

pixel format conversions

transform operations

progressive decode paths

Execution Flow

For each input file the harness performs:

Create decoder

Query decoder capability

Query container format

Query decoder info

Exercise container metadata

Enumerate frames

For each frame:

Get size

Get pixel format

Get resolution

Enumerate metadata

Extract palette

Extract thumbnail

Extract color contexts

Perform full CopyPixels

Perform partial CopyPixels

Run bitmap transform

Run progressive decode path

Run format conversion

Run WICConvertBitmapSource

This provides much broader coverage than simply decoding frame 0.

Build Requirements

Required environment:

Windows 10+
Visual Studio 2019 or 2022
Windows SDK
x64 target

The harness is intended for x64 builds only.

Required Libraries

Add these libraries to the linker:

windowscodecs.lib
shlwapi.lib
ole32.lib
oleaut32.lib
shell32.lib
Why they are needed
windowscodecs.lib

Provides:

WIC COM interfaces

WIC GUID definitions

WICConvertBitmapSource

shlwapi.lib

Provides:

SHCreateStreamOnFileW

Used to create streams for decoder capability checks.

ole32.lib

Provides:

CoInitializeEx
CoCreateInstance

Required for COM initialization.

oleaut32.lib

Used by COM interfaces and metadata handling.

Building with Visual Studio

Create a Console Application project.

Add these source files:

main.c
policy.c
trace.c
ini.c

Set platform to:

x64

Then configure linker dependencies:

windowscodecs.lib
shlwapi.lib
ole32.lib
oleaut32.lib
shell32.lib
Command Line Build Example

Research build:

cl /nologo /W3 /Zi /EHa /DUNICODE /D_UNICODE /DHARNESS_MODE_RESEARCH ^
 main.c policy.c trace.c ini.c ^
 /link windowscodecs.lib shlwapi.lib ole32.lib oleaut32.lib shell32.lib ^
 /out:harness_research.exe

Fuzz build:

cl /nologo /W3 /O2 /EHa /DUNICODE /D_UNICODE /DHARNESS_MODE_FUZZ ^
 main.c policy.c trace.c ini.c ^
 /link windowscodecs.lib shlwapi.lib ole32.lib oleaut32.lib shell32.lib ^
 /out:harness.exe

CacheOnDemand fuzz build:

cl /nologo /W3 /O2 /EHa /DUNICODE /D_UNICODE /DHARNESS_MODE_FUZZ /DHARNESS_CACHE_ON_DEMAND ^
 main.c policy.c trace.c ini.c ^
 /link windowscodecs.lib shlwapi.lib ole32.lib oleaut32.lib shell32.lib ^
 /out:harness_ondemand.exe
Runtime Configuration

The harness optionally reads:

harness.ini

Example:

[harness]
iterations=5000
trace_enabled=1
metadata_enum=1
palette_path=1
color_context_path=1
thumbnail_path=1
decoder_info_path=1
transform_path=1
progressive_path=1
wic_convert_path=1
mode=FUZZ

Important:

iterations=1

should be used when fuzzing because the fuzzer controls iteration.

Running the Harness Standalone

Basic usage:

harness_research.exe sample.ico

or

harness.exe sample.ico

Execution steps:

Initialize COM

Create WIC factory

Load configuration

Run fuzz_target()

Cleanup

Important: Keep the .ico Extension

The harness uses:

CreateDecoderFromFilename

The WIC decoder selection sometimes depends on file extension.

Always keep inputs as:

sample.ico

instead of random extensions.

Using TinyInst

TinyInst is recommended for fuzzing this harness because:

persistent execution is supported

Windows native instrumentation

compatible with WinAFL

TinyInst Instrumentation Model

Instrument:

windowscodecs.dll

Target function:

fuzz_target

Target module:

harness.exe

Argument count:

-nargs 1
TinyInst Dry Run (litecov)

Before running the fuzzer verify instrumentation:

litecov.exe ^
 -instrument_module windowscodecs.dll ^
 -target_module harness.exe ^
 -target_method fuzz_target ^
 -nargs 1 ^
 -iterations 10 ^
 -persist ^
 -loop ^
 -- harness.exe corpus\seed.ico

Expected result:

function reached repeatedly

coverage discovered

process stable

Running WinAFL with TinyInst

Example command:

afl-fuzz.exe ^
 -y ^
 -i corpus ^
 -o findings ^
 -t 30000 ^
 -- ^
 -instrument_module windowscodecs.dll ^
 -target_module harness.exe ^
 -target_method fuzz_target ^
 -nargs 1 ^
 -iterations 1000 ^
 -persist ^
 -loop ^
 -- harness.exe @@
CacheOnDemand Campaign

Run a separate campaign with the alternate binary:

afl-fuzz.exe ^
 -y ^
 -i corpus ^
 -o findings_ondemand ^
 -t 30000 ^
 -- ^
 -instrument_module windowscodecs.dll ^
 -target_module harness_ondemand.exe ^
 -target_method fuzz_target ^
 -nargs 1 ^
 -iterations 1000 ^
 -persist ^
 -loop ^
 -- harness_ondemand.exe @@

Do not mix results between the two campaigns.

PageHeap (Recommended)

Enable PageHeap:

gflags /p /enable harness.exe /full

Disable:

gflags /p /disable harness.exe

PageHeap improves detection of:

heap corruption

use-after-free

buffer overflows

Crash Triage

Reproduce a crash:

harness_research.exe findings\crashes\id_000000.ico

Run under debugger:

windbg -g -G harness_research.exe crash.ico

Enable trace logging in harness.ini to identify the last successful stage.

Seed Corpus Recommendations

Start with diverse ICO files:

16x16 icons

32x32 icons

PNG-in-ICO

multi-frame icons

palette icons

alpha channel icons

truncated ICO files

Small diverse corpus > large random corpus.

Known Limitations

harness uses file path instead of in-memory stream

.ico extension must be preserved

TinyInst persistence requires iterations=1

CacheOnLoad and CacheOnDemand require separate campaigns

Disclaimer

This harness is intended only for security research.

Use it only against software and environments you are authorized to test.