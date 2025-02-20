An operating system based on [OS in 1,000 Lines](https://operating-system-in-1000-lines.vercel.app/en/) and branched off from there.

### Running on Windows
1. Make sure you have:  
	- Clang and LLVM tools: Install through visual studio
	- tar to build the filesystem
	- QEMU, make sure you select riscv32 as one of the targets to install: https://qemu.weilnetz.de/w64/qemu-w64-setup-20241220.exe

2. Configure the paths in run.bat to point to where qemu and clang are located on your system.

3. Exectute run.bat

Note: If you want to use qemu monitor for debugging stuff, then using cmd.exe as a shell is a problem because it doesn't support the terminal escape sequences qemu is using so the escape sequences all get printed to the console. I switch over to [Cmder](https://cmder.app/) when I want to use qemu moniter.

### Links
[OS in 1,000 Lines](https://operating-system-in-1000-lines.vercel.app/en/)  
[virtio spec](https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.html)  
[RISC-V spec](https://lf-riscv.atlassian.net/wiki/spaces/HOME/pages/16154769/RISC-V+Technical+Specifications)  
[tar file format](https://en.wikipedia.org/wiki/Tar_%28computing%29)  
[xv6 source code](https://github.com/mit-pdos/xv6-riscv)  
[full boot process](https://web.archive.org/web/20240225130852/https://popovicu.com/posts/risc-v-sbi-and-full-boot-process/)  
