@echo off
if defined VS90COMNTOOLS (
call "%VS90COMNTOOLS%\vsvars32.bat")
buildwin 90 build static_mt release Win32 nosamples
