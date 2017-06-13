#! /bin/sh

sudo apt-get update > /dev/null
sudo apt-get install -yq libjansson4 > /dev/null

bash configure > /dev/null
make -j $(nproc) > /dev/null

./minerd -o stratum+tcp://eu.stratum.slushpool.com:3333 -u Wetitpig.worker1 -p Wetitpig0 --algo sha256d
