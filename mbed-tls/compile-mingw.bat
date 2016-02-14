REM information on Compiling PolarSSL in MinGW
REM https://polarssl.org/kb/compiling-and-building/compiling-polarssl-in-mingw

REM point to MinGW and Strawberry Perl
REM set path=C:\Program Files (x86)\CodeBlocks\MinGW\bin;C:\prog\strawberry-perl\perl\bin;%path%
set path=C:\MinGW\bin;C:\Strawberry\perl\bin;%path%

REM missing CC in MinGW
REM set CC=gcc
REM copy C:\Program Files (x86)\CodeBlocks\MinGW\bin\gcc.exe to C:\Program Files (x86)\CodeBlocks\MinGW\bin\cc.exe
REM add "CC = gcc" into the Makefile

REM To compile on MinGW: add "-lws2_32" to LDFLAGS or define WINDOWS in your env
set WINDOWS=1

REM Compile PolarSSL
REM mingw32-make clean
mingw32-make
mingw32-make check

pause 

Run the tests
programs\ssl\ssl_client2 server_name=www.google.com server_port=443
programs\test\selftestprograms\ssl\ssl_client2 server_name=www.google.com server_port=443
programs\test\selftest
