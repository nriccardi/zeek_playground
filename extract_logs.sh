#!/bin/bash

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <pcap-file-path> [output_json=False]"
    exit 1
fi

PCAP_FILE=$1

OUTPUT_JSON_OPTION="LogAscii::use_json=T"
if [ "$2" == "output_json=False" ]; then
    OUTPUT_JSON_OPTION=""
fi

# Run the zeek command
zeek -C -r "$PCAP_FILE" $OUTPUT_JSON_OPTION
