#!/bin/bash

python3 htb/solver.py | awk -F'--> ' '{print $2}'
