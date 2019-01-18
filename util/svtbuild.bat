setlocal

set COUNT=0
for %%x in (%*) do set /A COUNT+=1

if %COUNT% LSS 3 (
    echo "ERROR: Expected 3 arguments, received %COUNT%" && exit /b 1
)

set type=%1
set mode=%2
set vcvarsall=%~3

if NOT EXIST "%vcvarsall%" (
    echo "ERROR: File not found: %vcvarsall%" && exit /b 1
)

if defined BUILD_DIR (
    set FOMDIR=%BUILD_DIR%\%type%\%mode%\fips-install
    set SSLDIR=%BUILD_DIR%\%type%\%mode%\openssl-install
) else (
    set FOMDIR=%CD%\%type%\%mode%\fips-install
    set SSLDIR=%CD%\%type%\%mode%\openssl-install
)

if "%type%" == "Static" (
    set NTMAK=nt.mak
) else (
    set NTMAK=ntdll.mak
)
if "%mode%" == "Debug" set DEBUGOPT=debug-

set PATH=%PERL_DIR%;%PATH%;%ProgramFiles%\Git\usr\bin

call "%vcvarsall%" amd64
call nasm -v
call perl -v

:BUILDLIB
perl Configure %DEBUGOPT%VC-WIN64A no-shared no-asm no-zlib --prefix=%SSLDIR%
call ms\do_win64a.bat
nmake -f ms\%NTMAK% clean
nmake -f ms\%NTMAK%
nmake -f ms\%NTMAK% install
