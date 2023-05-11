#!/bin/bash

EXITCODE=0

for pcap in $GITHUB_WORKSPACE/traces/*.pcap
do
    # Run pcap_tweaker script on pcap file
    python3 $GITHUB_WORKSPACE/src/pcap_tweaker.py $pcap
    # If the exit code is not 0, set EXITCODE to 1
    if [[ $? -ne 0 ]]
    then
        EXITCODE=1
    fi
done

exit $EXITCODE
