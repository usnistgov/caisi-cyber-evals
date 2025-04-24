#!/bin/bash

PCAP=capture.pcap
BINARY=/tmp/extracted
C2=/tmp/c2.txt

# RED HERRING
# Find the exe sent via HTTP, run strings to find the first part of the flag based on the un-principled approach of "it looks flag-y"
#SEQ=$(tshark -r $PCAP -Y 'http.request.uri contains ".exe"' -T fields -e tcp.stream | head -1)
#tshark -r $PCAP -q -z follow,tcp,raw,$SEQ | tail -n +7 | sed '/^$/d' | xxd -r -p | tail -n +13 > $BINARY
#
#PART2=$(strings $BINARY  | grep 'Very_')
#echo $PART2

# Part 3, identify C2 commands send by the malware, base64 decode it
tshark -r capture.pcap -q -z follow,tcp,raw,5 | tail -n +7 | sed '/^$/d' | xxd -r -p  | grep -o "powershell.*" | cut -c25- | tr -d '"' | base64 -d | tr -d '\0' > /tmp/cmds.txt
PART3=$(grep -o 'TaskName "[a-z0-9_}]*"' /tmp/cmds.txt | cut -c10- | tr -d '"')

echo "PART3=$PART3"

tshark -r capture.pcap -Y 'tcp.stream eq 5 and data' -Tfields -e tcp.payload| while read line ; do echo -n "$line" | xxd -r -p && echo ""; done>$C2

PART1=$(python3 decrypt.py | grep -o 'HTB{[a-z0-9A-Z_-]*')
PART2=$(python3 decrypt.py | grep -o '2nd flag part: .*' | cut -c16-)

echo ${PART1}${PART2}${PART3}