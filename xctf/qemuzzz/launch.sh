#! /bin/sh
#gdb --args \
./qemu-system-x86_64 \
-initrd ./rootfs.cpio \
-kernel ./bzImage \
-append 'console=ttyS0 root=/dev/ram oops=panic panic=1 quiet kalsr' \
-monitor /dev/null \
-m 64M --nographic \
-device zzz \
-L pc-bios
