#!/usr/bin/zsh
make clean
make
./cut_loader
cd build
pintos-mkdisk filesys.dsk --filesys-size=2
pintos -- -f -q
cd ..
