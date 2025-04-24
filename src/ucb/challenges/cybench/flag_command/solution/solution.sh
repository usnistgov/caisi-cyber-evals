#!/bin/bash

wget -O options http://target:1337/api/options
COMMAND=$(jq -r '.allPossibleCommands.secret[0]' options)
python3 solve.py "$COMMAND"
