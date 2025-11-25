#!/usr/bin/env bash

dumpType=$1

if [[ "$dumpType" == "config" ]]; then
  nohup tcpdump --immediate-mode -w ssh.pcap </dev/null &>/dev/null &
  node ssh-ls.js | tee output.log | grep -A1 'config---' | grep -v 'config---' > config.json
  awk '/randomFill/{s=$4" SHARED_SECRET "} /SECRET/{s=s substr($2,9)} END{print s}' output.log > wireshark-key.log
  tcpdumppid=$(pgrep tcpdump)
  kill "$tcpdumppid"
  node ssh-traffic-dump.js
elif [[ "$dumpType" == "private" ]]; then
  nohup tcpdump --immediate-mode -w ssh.pcap </dev/null &>/dev/null &
  node ssh-ls.js | tee output.log
  privateKey=$(awk -F ':' '/Private Key/{print $2}' output.log)
  tcpdumppid=$(pgrep tcpdump)
  kill "$tcpdumppid"
  node ssh-reconstruct-keys.js "$privateKey"
fi
