#!/usr/bin/env bash

nohup tcpdump --immediate-mode -w ssh.pcap </dev/null &>/dev/null &
node ssh-ls.js | tee output.log | grep -A1 'config---' | grep -v 'config---' > config.json
tcpdumppid=$(pgrep tcpdump)
kill "$tcpdumppid"
node ssh-traffic-dump.js
