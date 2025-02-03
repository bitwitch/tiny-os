@echo off
setlocal EnableDelayedExpansion

set QEMU="C:\Program Files\qemu\qemu-system-riscv32.exe"
set CC="C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\Llvm\x64\bin\clang.exe"
set "CFLAGS=-std=c11 -O2 -g3 -Wall -Wextra --target=riscv32 -ffreestanding -nostdlib"

%CC% %CFLAGS% -Wl,-Tkernel.ld -Wl,-Map=kernel.map -o kernel.elf kernel.c
if %errorlevel% neq 0 exit /b %errorlevel%

%QEMU% -machine virt -bios default -nographic -serial mon:stdio --no-reboot -d unimp,guest_errors,int,cpu_reset -D qemu.log -kernel kernel.elf
