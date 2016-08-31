@echo off
if defined VS120COMNTOOLS (
call "%VS120COMNTOOLS%\vsvars32.bat")
buildwin 120 build static_mt release Win32 nosamples
