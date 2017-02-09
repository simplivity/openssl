setlocal

set type=%1
set mode=%2

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

set PATH=%PERL_DIR%;%PATH%;E:\Git\bin

call "C:\Program Files (x86)\Microsoft Visual Studio 10.0\VC\vcvarsall.bat" amd64
call nasm -v
call perl -v

cd fom
tar -xvf openssl-fips-*.tar.gz

:BUILDFOM
cd openssl-fips-*
perl Configure %DEBUGOPT%VC-WIN64A fipscanisteronly no-shared no-asm no-zlib --prefix=%FOMDIR%
call ms\do_win64a.bat
nmake -f ms\%NTMAK% clean
nmake -f ms\%NTMAK%
nmake -f ms\%NTMAK% install
REM Copy additional tools to make FIPS linking easier
perl util\copy.pl util\msincore util\hmac_sha1.pl %FOMDIR%\bin
cd ..\..

:BUILDLIB
perl Configure %DEBUGOPT%VC-WIN64A fips no-shared no-asm no-zlib --with-fipsdir=%FOMDIR% --prefix=%SSLDIR%
call ms\do_win64a.bat
nmake -f ms\%NTMAK% clean
nmake -f ms\%NTMAK%
nmake -f ms\%NTMAK% install
