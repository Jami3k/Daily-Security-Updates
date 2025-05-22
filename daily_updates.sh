#!/bin/bash

break() {
    exit 0                                                  # defines killing function
}


trap break SIGINT SIGTERM
while true; do
    python3 securityUpdates.py > /dev/null 2>> updates_log.txt &           # sends you a daily security update 
    sleep 86400
done
