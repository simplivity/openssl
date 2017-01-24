set type=%1
set mode=%2

cd fom
set FOMDIR=%cd%\fips-install

echo %NASM_DIR%
set PATH=e:\Git\bin;%NASM_DIR%;%PATH%

call nasm -v
call perl -v

if exist openssl-fips-*-test goto BUILDFOM
gzip -d openssl-fips-*.tar.gz
tar -xvf openssl-fips-*.tar

:BUILDFOM
cd openssl-fips-*
perl Configure VC-WIN64A no-asm --prefix=%FOMDIR%
call ms\do_win64a.bat
nmake -f ms\ntdll.mak clean
nmake -f ms\ntdll.mak
nmake -f ms\ntdll.mak install
cd ..\..

if "%type%" == "Static" set STATICOPT=no-shared
if "%mode%" == "Debug" set DEBUGOPT=debug-

:BUILDLIB
perl Configure %DEBUGOPT%VC-WIN64A fips %STATICOPT% no-asm --with-fipsdir=%FOMDIR% --prefix=build\%type%\%mode% 
call ms\do_win64a.bat
nmake -f ms\ntdll.mak clean
nmake -f ms\ntdll.mak
nmake -f ms\ntdll.mak install

