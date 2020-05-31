#!/usr/bin/env bash

echo "$#"
if [ "$#" -eq 0 ]; then
   while read packet; do
    echo "$packet" | xxd -r -ps1 | ncat --udp 127.0.0.1 1337
   done
else
    while [ ! "$#" -eq 0 ]; do
        echo "$1" | xxd -r -ps1 | ncat --udp 127.0.0.1 1337
        sleep 1
        shift
    done
fi
