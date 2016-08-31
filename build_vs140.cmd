@echo off
if defined VS140COMNTOOLS (
call "%VS140COMNTOOLS%\vsvars32.bat")
buildwin 140 build static_mt release Win32 nosamples
