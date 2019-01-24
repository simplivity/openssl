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

if defined PROJECT_DIR (
	set SOURCE_DIR=%PROJECT_DIR%
) else (
	set SOURCE_DIR=%CD%
)

if defined BUILD_DIR (
    set FOMDIR=%BUILD_DIR%\%type%\%mode%\fips-install
    set SSLDIR=%BUILD_DIR%\%type%\%mode%\openssl-install
) else (
    set FOMDIR=%CD%\%type%\%mode%\fips-install
    set SSLDIR=%CD%\%type%\%mode%\openssl-install
)

if "%type%" == "Static" set SHARED=no-shared
if "%mode%" == "Debug" set DEBUGOPT=--debug

set PATH=%PERL_DIR%;%PATH%;%ProgramFiles%\Git\usr\bin

call "%vcvarsall%" amd64
call nasm -v
call perl -v

:BUILDLIB
perl "%SOURCE_DIR%\Configure" VC-WIN64A %DEBUGOPT% %SHARED% no-dynamic-engine no-asm no-idea no-mdc2 no-rc5 no-zlib no-ssl3 no-ssl3-method enable-rfc3779 enable-cms --prefix=%SSLDIR% --openssldir=%SSLDIR%\ssl

nmake
nmake install_sw
