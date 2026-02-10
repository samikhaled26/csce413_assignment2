#!/bin/bash
set -e

# Start sshd in background
/usr/sbin/sshd -D -p 2222 &

# Start knock server (foreground)
python3 /app/knock_server.py --protected-port 2222 --sequence 1234,5678,9012 --window 10 --open-seconds 30
