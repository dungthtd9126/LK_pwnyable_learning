#!/bin/sh
cd rootfs/home
gcc handler_exploit.c -o handler_exploit -static -g -O0

cp handler_exploit ../../.

cd ..

sudo sh -c 'find . | cpio -H newc -o > ../rootfs.cpio'
cd ..

qemu-system-x86_64 \
    -m 64M \
    -nographic \
    -kernel bzImage \
    -append "console=ttyS0 loglevel=3 oops=panic panic=-1 pti=on nokaslr" \
    -no-reboot \
    -smp 1 \
    -monitor /dev/null \
    -initrd rootfs.cpio \
    -net nic,model=virtio \
    -net user \
    -cpu kvm64,+smep \
    -gdb tcp::3636
