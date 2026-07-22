#!/bin/sh

cd rootfs/home
gcc exploit.c -o exploit -static

cp exploit ...

cd ..

sudo sh -c 'find . | cpio -H newc -o > ../rootfs.cpio'
cd ..

qemu-system-x86_64 \
    -m 64M \
    -nographic \
    -kernel bzImage \
    -append "console=ttyS0 loglevel=3 oops=panic panic=-1 pti=on kaslr" \
    -no-reboot \
    -cpu qemu64,+smap,+smep \
    -smp 1 \
    -monitor /dev/null \
    -initrd rootfs.cpio \
    -net nic,model=virtio \
    -net user \
    -gdb tcp::1337
