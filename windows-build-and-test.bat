@echo off
rem ==========================================================================
rem  windows-build-and-test.bat -- build rsync on Windows and run its tests.
rem
rem  Usage:
rem      windows-build-and-test.bat [options]
rem
rem  Options:
rem      --arch ARCH        x64, x86, arm64, all (default), or both
rem      --clean            delete the build directory first
rem      --config CFG       Release (default), Debug or RelWithDebInfo
rem      --build-dir DIR    build directory (default: build)
rem      --host USER@HOST   also run the ssh transfer tests against HOST
rem      --tests PATTERN    run only matching tests (may be repeated)
rem      --no-tests         build only
rem      -h, --help         show this text
rem
rem  Requires Visual Studio 2022 with the C++ tools, and Python 3.6+.
rem  CMake and Ninja ship with Visual Studio, and the MSVC environment is set
rem  up automatically via vswhere, so this does not have to be run from a
rem  Developer Command Prompt.
rem
rem  Three architectures, and each gets its own everything:
rem
rem      x64   build-x64\rsync.exe         the build most people want
rem      x86   build-x86\rsync-x86.exe     for 32-bit Windows, and for the
rem                                        occasional 64-bit machine running
rem                                        something that will only load a
rem                                        32-bit image
rem      arm64 build-arm64\rsync-arm64.exe for Windows on ARM, where the x64
rem                                        build would otherwise run emulated
rem
rem  Ninja generates for one compiler, and which compiler that is comes from
rem  the environment vcvars set up -- so "all" cannot be one configure.  This
rem  script calls itself once per architecture instead, each call with its own
rem  vcvars, its own build directory and its own run of the test suite.
rem
rem  A build is only run and tested where it can be: nothing executes an ARM64
rem  binary on an x64 machine, so there the ARM64 build is built and the suite
rem  is skipped with a line saying why.  An ARM64 host runs all three --
rem  Windows on ARM emulates x64 and x86 -- so a run there tests the lot.
rem
rem  Note on style: variables are expanded as !VAR! rather than %VAR% inside
rem  every parenthesised block.  %VAR% is substituted while the block is being
rem  parsed, so a value containing parentheses -- "C:\Program Files (x86)\..."
rem  being the obvious one -- would close the block early.
rem
rem  Copyright (C) 2026 Max Vilimpoc, rsync CMake/Windows port.
rem  Distributed under the same GPL-3.0-or-later terms as the rest of rsync.
rem ==========================================================================

setlocal EnableExtensions EnableDelayedExpansion

set "SRC_DIR=%~dp0"
if "%SRC_DIR:~-1%"=="\" set "SRC_DIR=%SRC_DIR:~0,-1%"

rem Kept verbatim so an "--arch all" run can hand them to its children.  Each
rem child gets "--arch <one>" appended, and the last --arch wins.
rem
rem SELF has to be taken before the argument loop: `shift` renumbers %0 along
rem with everything else, so by the time parsing is done %~f0 names an option
rem rather than this script.
set "SELF=%~f0"
set "ORIG_ARGS=%*"

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"

set "BUILD_DIR=build"
set "CONFIG=Release"
set "ARCH=all"
set "RUN_TESTS=1"
set "DO_CLEAN=0"
set "TEST_ARGS="

rem ---------------------------------------------------------------- options

:parse_args
if "%~1"=="" goto args_done
if /i "%~1"=="-h"          goto usage
if /i "%~1"=="--help"      goto usage
if /i "%~1"=="--clean" (
    set "DO_CLEAN=1"
    shift
    goto parse_args
)
if /i "%~1"=="--no-tests" (
    set "RUN_TESTS=0"
    shift
    goto parse_args
)
if /i "%~1"=="--config" (
    if "%~2"=="" goto missing_value
    set "CONFIG=%~2"
    shift
    shift
    goto parse_args
)
if /i "%~1"=="--arch" (
    if "%~2"=="" goto missing_value
    set "ARCH=%~2"
    shift
    shift
    goto parse_args
)
if /i "%~1"=="--build-dir" (
    if "%~2"=="" goto missing_value
    set "BUILD_DIR=%~2"
    shift
    shift
    goto parse_args
)
if /i "%~1"=="--host" (
    if "%~2"=="" goto missing_value
    set "RSYNC_WIN_TEST_HOST=%~2"
    shift
    shift
    goto parse_args
)
if /i "%~1"=="--tests" (
    if "%~2"=="" goto missing_value
    set "TEST_ARGS=!TEST_ARGS! %~2"
    shift
    shift
    goto parse_args
)
echo ERROR: unknown option "%~1"
echo.
goto usage

:missing_value
echo ERROR: option "%~1" needs a value
echo.
goto usage

:args_done

rem "both" is what "all" was called when there were two architectures.  It is
rem still accepted and still means those two, so an old command line -- or an
rem old habit -- does not silently start building a third.
set "ARCH_LIST="
if /i "!ARCH!"=="all"   set "ARCH_LIST=x64 x86 arm64"
if /i "!ARCH!"=="both"  set "ARCH_LIST=x64 x86"
if defined ARCH_LIST    goto build_list
if /i "!ARCH!"=="x64"   goto arch_ok
if /i "!ARCH!"=="x86"   goto arch_ok
if /i "!ARCH!"=="arm64" goto arch_ok
echo ERROR: --arch must be x64, x86, arm64, all or both, not "!ARCH!"
echo.
goto usage

rem -------------------------------------------------------- each, in turn
rem
rem Once per architecture, by calling this script again with the architecture
rem pinned.  Each call gets its own setlocal, so the vcvars environment it sets
rem up is discarded at its endlocal and the next call starts from a clean one --
rem which matters, because vcvars is what decides which compiler a configure
rem finds.  x64 goes first, so the build most people want fails fast.

:build_list
set "COUNT=0"
for %%a in (!ARCH_LIST!) do set /a COUNT+=1
set "STEP=0"
for %%a in (!ARCH_LIST!) do (
    set /a STEP+=1
    echo ##########################################################################
    echo #  !STEP! of !COUNT!: %%a
    echo ##########################################################################
    echo.
    call "!SELF!" !ORIG_ARGS! --arch %%a
    if errorlevel 1 goto fail
    echo.
)
echo Done: !ARCH_LIST!
goto success

:arch_ok

rem This machine's own architecture.  It decides two things below: which host
rem toolchain to prefer, and whether the result can be run here at all.  A
rem 32-bit process on 64-bit Windows sees x86 in PROCESSOR_ARCHITECTURE and
rem the truth in PROCESSOR_ARCHITEW6432.
set "HOST_ARCH=%PROCESSOR_ARCHITECTURE%"
if defined PROCESSOR_ARCHITEW6432 set "HOST_ARCH=%PROCESSOR_ARCHITEW6432%"
if /i "!HOST_ARCH!"=="AMD64" set "HOST_ARCH=x64"
if /i "!HOST_ARCH!"=="ARM64" set "HOST_ARCH=arm64"

rem vcvars comes as one file per (host, target) pair: vcvars64.bat is the
rem x64-hosted toolchain for an x64 target, vcvarsarm64_amd64.bat the
rem ARM64-hosted one for the same target, and so on.  Prefer the toolchain
rem hosted on this machine's own architecture -- on an ARM64 box the x64 tools
rem run under emulation -- and fall back to the x64-hosted one, which is what
rem every Visual Studio with the C++ workload installs.
set "HOST_PART=amd64"
if /i "!HOST_ARCH!"=="arm64" set "HOST_PART=arm64"
if /i "!HOST_ARCH!"=="x86"   set "HOST_PART=x86"

rem Each architecture needs its own build directory -- Ninja caches the
rem compiler it configured with -- and its own name for the result.  The
rem directory is the --build-dir prefix plus the architecture, so no build is
rem the unmarked one and a stale tree cannot be mistaken for another
rem architecture's.  VS_REQUIRES is the Visual Studio component that provides
rem the tools for this target, so a missing one is reported by name.
set "VCVARS_ALT2="
set "VS_REQUIRES=Microsoft.VisualStudio.Component.VC.Tools.x86.x64"
if /i "!ARCH!"=="x86" (
    set "BUILD_DIR=!BUILD_DIR!-x86"
    set "EXE_NAME=rsync-x86.exe"
    set "VCVARS=vcvars!HOST_PART!_x86.bat"
    set "VCVARS_ALT=vcvarsamd64_x86.bat"
    set "VCVARS_ALT2=vcvars32.bat"
) else if /i "!ARCH!"=="arm64" (
    set "BUILD_DIR=!BUILD_DIR!-arm64"
    set "EXE_NAME=rsync-arm64.exe"
    set "VCVARS=vcvars!HOST_PART!_arm64.bat"
    set "VCVARS_ALT=vcvarsamd64_arm64.bat"
    set "VS_REQUIRES=Microsoft.VisualStudio.Component.VC.Tools.ARM64"
) else (
    set "BUILD_DIR=!BUILD_DIR!-x64"
    set "EXE_NAME=rsync.exe"
    set "VCVARS=vcvars!HOST_PART!_amd64.bat"
    set "VCVARS_ALT=vcvars64.bat"
)

rem Only the cross pairs are spelled that way; a toolchain that targets its
rem own host has a short name of its own, and there is no vcvarsamd64_amd64.
if /i "!HOST_ARCH!"=="!ARCH!" (
    if /i "!ARCH!"=="x64"   set "VCVARS=vcvars64.bat"
    if /i "!ARCH!"=="x86"   set "VCVARS=vcvars32.bat"
    if /i "!ARCH!"=="arm64" set "VCVARS=vcvarsarm64.bat"
)

rem Can this machine run what it is about to build?  Windows on ARM emulates
rem both x86 and x64, and 64-bit Windows runs 32-bit binaries, but nothing
rem runs an ARM64 image on an x64 machine.  A build that cannot be run cannot
rem be tested either, and the two places that would try say so instead.
set "CAN_RUN=0"
if /i "!ARCH!"=="!HOST_ARCH!" set "CAN_RUN=1"
if /i "!HOST_ARCH!"=="arm64" set "CAN_RUN=1"
if /i "!HOST_ARCH!"=="x64" if /i "!ARCH!"=="x86" set "CAN_RUN=1"

rem Make the build directory absolute, so a step that needs a different
rem working directory still finds it.
for %%d in ("!BUILD_DIR!") do set "BUILD_DIR=%%~fd"

echo ==========================================================================
echo  rsync for Windows
echo    source     : !SRC_DIR!
echo    build      : !BUILD_DIR!
echo    config     : !CONFIG!
echo    target     : !ARCH! ^(!EXE_NAME!^) on a !HOST_ARCH! machine
echo ==========================================================================
echo.

rem ------------------------------------------------------- MSVC environment

rem An environment that is already set up is only usable if it targets the
rem architecture being built -- otherwise a Developer Command Prompt, or the
rem parent of an "--arch all" run, would silently hand x64 tools to the x86
rem build.  vcvars records its target in VSCMD_ARG_TGT_ARCH; re-running it for
rem a different target in the same process is supported and does the right
rem thing, so a mismatch is not an error, just a reason to run it again.
if defined INCLUDE (
    if /i "!VSCMD_ARG_TGT_ARCH!"=="!ARCH!" (
        echo [1/5] MSVC environment already targets !ARCH!, using it.
        goto have_msvc
    )
    echo [1/5] MSVC environment targets "!VSCMD_ARG_TGT_ARCH!", re-targeting to !ARCH!...
    goto setup_msvc
)

echo [1/5] Setting up the MSVC environment for !ARCH!...

:setup_msvc
if not exist "!VSWHERE!" (
    echo ERROR: cannot find vswhere.exe at:
    echo        !VSWHERE!
    echo        Install Visual Studio 2022 with the "Desktop development with
    echo        C++" workload, or run this from a Developer Command Prompt.
    goto fail
)

set "VS_PATH="
for /f "usebackq tokens=*" %%i in (`"!VSWHERE!" -latest -products * -requires !VS_REQUIRES! -property installationPath 2^>nul`) do set "VS_PATH=%%i"

if not defined VS_PATH (
    echo ERROR: no Visual Studio installation providing !VS_REQUIRES!
    echo        was found. Install the "Desktop development with C++" workload;
    if /i "!ARCH!"=="arm64" echo        an ARM64 build also needs its "MSVC v14x - VS 2022 C++
    if /i "!ARCH!"=="arm64" echo        ARM64/ARM64EC build tools" component.
    goto fail
)

rem The first of the candidates that is actually installed wins: the
rem host-native toolchain for this target, then the x64-hosted one, then --
rem for a 32-bit target only -- the 32-bit-hosted one.  A cross toolchain is
rem the same compiler with more address space to work in, so which host it
rem runs on changes nothing about what comes out.
set "VCVARS_FILE="
for %%v in ("!VCVARS!" "!VCVARS_ALT!" "!VCVARS_ALT2!") do (
    if not defined VCVARS_FILE if not "%%~v"=="" (
        if exist "!VS_PATH!\VC\Auxiliary\Build\%%~v" set "VCVARS_FILE=%%~v"
    )
)
if not defined VCVARS_FILE (
    echo ERROR: found Visual Studio at "!VS_PATH!"
    echo        but none of !VCVARS! !VCVARS_ALT! !VCVARS_ALT2!
    echo        under VC\Auxiliary\Build.
    goto fail
)

call "!VS_PATH!\VC\Auxiliary\Build\!VCVARS_FILE!" >nul
if errorlevel 1 (
    echo ERROR: !VCVARS_FILE! failed.
    goto fail
)
echo       using !VS_PATH! ^(!VCVARS_FILE!^)

:have_msvc

rem ------------------------------------------------------------------ tools

echo [2/5] Locating the build tools...

where cmake >nul 2>&1
if errorlevel 1 (
    echo ERROR: cmake is not on PATH. It ships with Visual Studio under
    echo        Common7\IDE\CommonExtensions\Microsoft\CMake, or install it
    echo        separately.
    goto fail
)

where ninja >nul 2>&1
if errorlevel 1 (
    echo ERROR: ninja is not on PATH. It ships with Visual Studio under
    echo        Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja.
    goto fail
)

set "PYTHON="
where python >nul 2>&1
if not errorlevel 1 set "PYTHON=python"
if not defined PYTHON (
    where py >nul 2>&1
    if not errorlevel 1 set "PYTHON=py -3"
)
if not defined PYTHON (
    echo ERROR: no Python interpreter found. Python 3.6+ is required: CMake
    echo        uses it to generate proto.h and friends, in place of awk.
    goto fail
)
echo       cmake, ninja and !PYTHON! found.

rem --------------------------------------------------------------- clean up

if "!DO_CLEAN!"=="1" (
    echo [3/5] Removing "!BUILD_DIR!"...
    if exist "!BUILD_DIR!" rmdir /s /q "!BUILD_DIR!"
    if exist "!BUILD_DIR!" (
        echo ERROR: could not remove "!BUILD_DIR!".
        goto fail
    )
) else (
    echo [3/5] Keeping any existing build directory ^(use --clean to wipe^).
)

rem --------------------------------------------------------------- configure

echo [4/5] Configuring...
rem The two SIMD options are passed explicitly rather than left to their
rem defaults: a CMake option keeps whatever value a build directory's cache
rem already holds, so a directory configured before the defaults became ON
rem would silently keep building the scalar checksums.  This script builds
rem what the release ships, and the release has them on.
cmake -S "!SRC_DIR!" -B "!BUILD_DIR!" -G Ninja -DCMAKE_BUILD_TYPE=!CONFIG! ^
    -DRSYNC_ENABLE_SIMD=ON -DRSYNC_XXH_DISPATCH=ON
if errorlevel 1 (
    echo.
    echo ERROR: cmake configure failed.
    echo        If it complained about a stale config.h or proto.h in the
    echo        source tree, those are left over from an autoconf build and
    echo        would shadow the generated ones; delete them and retry.
    goto fail
)

rem ------------------------------------------------------------------- build

echo.
echo [5/5] Building...
cmake --build "!BUILD_DIR!"
if errorlevel 1 (
    echo.
    echo ERROR: the build failed.
    goto fail
)

if not exist "!BUILD_DIR!\!EXE_NAME!" (
    echo ERROR: the build reported success but !EXE_NAME! is missing from
    echo        "!BUILD_DIR!".
    goto fail
)

echo.
if "!CAN_RUN!"=="1" (
    "!BUILD_DIR!\!EXE_NAME!" --version
    if errorlevel 1 (
        echo ERROR: the freshly built !EXE_NAME! would not run.
        goto fail
    )
) else (
    echo Not run: a !ARCH! binary does not execute on a !HOST_ARCH! machine.
)

rem ------------------------------------------------------------------- tests

if "!RUN_TESTS!"=="0" (
    echo.
    echo Build complete ^(tests skipped^): !BUILD_DIR!\!EXE_NAME!
    goto success
)

if "!CAN_RUN!"=="0" (
    echo.
    echo Build complete: !BUILD_DIR!\!EXE_NAME!
    echo Tests skipped: this is a !HOST_ARCH! machine and a !ARCH! binary
    echo cannot run on it. Build on a !ARCH! machine to run the suite.
    goto success
)

echo.
if defined RSYNC_WIN_TEST_HOST (
    echo Running the !ARCH! test suite, including ssh transfers to !RSYNC_WIN_TEST_HOST!...
) else (
    echo Running the !ARCH! test suite ^(pass --host USER@HOST to add the ssh tests^)...
)
echo.

!PYTHON! "!SRC_DIR!\win32\tests\run.py" --rsync-bin "!BUILD_DIR!\!EXE_NAME!"!TEST_ARGS!
if errorlevel 1 (
    echo.
    echo ERROR: one or more !ARCH! tests failed.
    goto fail
)

echo.
echo Build and tests passed: !BUILD_DIR!\!EXE_NAME!
goto success

rem ----------------------------------------------------------------- usage

:usage
echo Build rsync on Windows and run its test suite.
echo.
echo   windows-build-and-test.bat [options]
echo.
echo   --arch ARCH        x64, x86, arm64, all ^(default^), or both
echo                      ^(= x64 and x86, as "both" always meant^)
echo   --clean            delete the build directory first
echo   --config CFG       Release ^(default^), Debug or RelWithDebInfo
echo   --build-dir DIR    build directory prefix ^(default: build, giving
echo                      build-x64, build-x86 and build-arm64^)
echo   --host USER@HOST   also run the ssh transfer tests against HOST
echo   --tests PATTERN    run only matching tests ^(may be repeated^)
echo   --no-tests         build only
echo   -h, --help         show this text
echo.
echo x64 builds build-x64\rsync.exe, x86 build-x86\rsync-x86.exe, and arm64
echo build-arm64\rsync-arm64.exe; all builds and tests each in turn.  A build
echo this machine cannot run -- ARM64 on an x64 host -- is built but not tested.
echo.
echo Requires Visual Studio 2022 with the C++ tools, and Python 3.6+.
echo CMake and Ninja ship with Visual Studio; the MSVC environment is set up
echo automatically, so a Developer Command Prompt is not needed.
endlocal
exit /b 2

:fail
echo.
endlocal
exit /b 1

:success
endlocal
exit /b 0
