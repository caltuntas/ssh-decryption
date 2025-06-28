#!/usr/bin/env bash

#set -x

export TARGET_HOST=192.168.1.125
export TARGET_USERNAME=user
export TARGET_PASSWORD='xxxx'

nohup tcpdump -i en0 --immediate-mode host $TARGET_HOST and port 22 -w ./ssh.pcap </dev/null &>/dev/null &
/usr/bin/time -al node ssh-ls.js | tee output.log

awk '/randomFill/{s=$4" SHARED_SECRET "} /SECRET/{s=s substr($2,9)} END{print s}' output.log > wireshark-key.log

tcpdumppid=$(pgrep tcpdump)
kill "$tcpdumppid"

PACKET_COUNT=$(tcpdump -r ./ssh.pcap 2>/dev/null | wc -l)
echo "Total packets captured: $PACKET_COUNT"

# benchmark
# date; for i in {1..100}; do echo $i;./ssh-session.sh 2>&1 /dev/null |grep 'Total packets captured'; done > numbers-exec.txt; date
# awk '{total+=$4} END{print total}' numbers-shell.txt
