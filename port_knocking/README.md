# Port Knocking Implementation

## Purpose
This component implements a port knocking system to protect the hidden SSH service running on port **2222**.  
The SSH port remains closed by default and only opens after a correct knock sequence.

## Design

- **Protected Service:** SSH on port 2222  
- **Knock Sequence:** 1234 → 5678 → 9012  
- **Time Window:** 10 seconds  
- **Auto-Close Time:** 30 seconds  

### Components

- **knock_server.py**
  - Listens on knock ports  
  - Tracks knock progress per IP  
  - Verifies correct sequence and timing  
  - Uses iptables to open port 2222 only for the authorized IP  

- **knock_client.py**
  - Sends knock sequence to the target host  
  - Allows connection to SSH after successful knocking  

- **Dockerfile**
  - Runs the server with NET_ADMIN capability to modify firewall rules  

## How It Works

1. Port 2222 is blocked by default using iptables.  
2. Client performs the knock sequence.  
3. If the sequence is correct and within the time window, the server opens port 2222 for that IP.  
4. Access is granted temporarily and automatically closed after timeout.

## Usage

Before knocking (should fail):

ssh sshuser@<target_ip> -p 2222

Perform knock sequence:

python3 knock_client.py --target <target_ip> --sequence 1234,5678,9012

After knocking (should succeed):

ssh sshuser@<target_ip> -p 2222