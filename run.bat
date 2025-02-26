@echo off
setlocal EnableDelayedExpansion

set QEMU="C:\Program Files\qemu\qemu-system-riscv32.exe"
set CC="C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\Llvm\x64\bin\clang.exe"
set OBJCOPY="C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\Llvm\x64\bin\llvm-objcopy.exe"
set "CFLAGS=-std=c11 -O2 -g3 -Wall -Wextra --target=riscv32 -ffreestanding -nostdlib"

REM Build the shell userland program
%CC% %CFLAGS% -Wl,-Tuser.ld -Wl,-Map=shell.map -o shell.elf shell.c user.c common.c
if %errorlevel% neq 0 exit /b %errorlevel%
%OBJCOPY% --set-section-flags .bss=alloc,contents -O binary shell.elf shell.bin
if %errorlevel% neq 0 exit /b %errorlevel%
%OBJCOPY% -Ibinary -Oelf32-littleriscv shell.bin shell.bin.o
if %errorlevel% neq 0 exit /b %errorlevel%

REM Build the tar 'filesystem'
tar -c -f disk.tar --format ustar -C disk *
if %errorlevel% neq 0 exit /b %errorlevel%

REM Build the kernel
%CC% %CFLAGS% -Wl,-Tkernel.ld -Wl,-Map=kernel.map -o kernel.elf kernel.c common.c shell.bin.o
if %errorlevel% neq 0 exit /b %errorlevel%

       REM -d unimp,guest_errors,int,cpu_reset -D qemu.log ^
%QEMU% -machine virt -bios default -nographic -serial mon:stdio --no-reboot ^
       -drive id=drive0,file=disk.tar,format=raw,if=none ^
       -device virtio-blk-device,drive=drive0,bus=virtio-mmio-bus.0 ^
       -kernel kernel.elf
