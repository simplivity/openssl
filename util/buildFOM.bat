set type=%1
set mode=%2

cd fom

if exist openssl-fips-* goto BUILDFOM
gzip -d openssl-fips-*.tar.gz
tar -xvf openssl-fips-*.tar

:BUILDFOM
cd openssl-fips-*
perl Configure VC-WIN64A no-asm
call ms\do_win64a.bat
nmake -f ms\ntdll.mak clean
nmake -f ms\ntdll.mak
nmake -f ms\ntdll.mak install
cd ../..


:BUILDLIB
perl Configure VC-WIN64A fips no-asm --prefix=build\%type%\%mode% 
call ms\do_win64a.bat
nmake -f ms\ntdll.mak clean
nmake -f ms\ntdll.mak
nmake -f ms\ntdll.mak install

