@echo off
if defined VS150COMNTOOLS (
call "%VS150COMNTOOLS%\vsvars32.bat")
buildwin 150 build static_mt release Win32 nosamples
