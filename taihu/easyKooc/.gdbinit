set arch mips
set endian little
set sysroot ./mipsel-linux-gnu
target remote localhost:1234
b *0x401120

