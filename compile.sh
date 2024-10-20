#!/bin/bash
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit
fi
gcc -fPIE -static-pie -Wall -Wl,-z,relro,-z,now -oprng ./prng.c -fstack-protector-all
checksec ./prng
chown root:root ./prng
chmod 4755 ./prng
echo this_is_our_flag > ./flag.txt
chmod 600 ./flag.txt
