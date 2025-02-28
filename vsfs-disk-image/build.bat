@echo off
if not exist build\ mkdir build
pushd build
cl /std:c11 /nologo /Zi /W3 /WX /I.. /Fevsfs_disk_image.exe "%~dp0main.c" 
popd
