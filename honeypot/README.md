# SSH Honeypot Design

## Overview

This honeypot was implemented to simulate a realistic SSH service and detect unauthorized access attempts.  
The goal of the design is to appear as a legitimate OpenSSH server while secretly logging all attacker interactions for security analysis.

The honeypot runs inside a Docker container and listens on port 22. It never allows real authentication, but instead records detailed information about each connection attempt.

---

## Design Goals

The honeypot was designed with the following objectives:

- Simulate a real SSH server convincingly  
- Capture and log all connection and authentication attempts  
- Detect suspicious behavior such as repeated failed logins  
- Remain simple, lightweight, and easy to deploy  
- Avoid revealing that it is a honeypot  

---

## Architecture

The honeypot is implemented using Python and the Paramiko SSH library.

The system consists of the following components:

1. **SSH Protocol Simulation**
   - The honeypot presents a realistic SSH banner that mimics OpenSSH.
   - It accepts incoming SSH connections like a normal server.
   - All authentication attempts are intentionally rejected.

2. **Connection Handling**
   - Each incoming connection is processed in a separate thread.
   - Metadata such as source IP, port, and timestamps are recorded.

3. **Logging Mechanism**
   - A structured logging system writes all events to `/app/logs/honeypot.log`.
   - The following information is captured:
     - Connection open and close events  
     - Authentication attempts  
     - Usernames and passwords used  
     - Connection duration  
     - Repeated failure alerts  

4. **Alerting System**
   - The honeypot tracks failed login attempts per IP address.
   - If multiple failures occur within a short time window, an alert is generated and logged.

---

## Implementation Decisions

Several design choices were made to meet assignment requirements:

- **Protocol Choice: SSH**
  - SSH was selected because it is a common target for attackers.
  - It allows realistic interaction while being easy to simulate.

- **Use of Paramiko**
  - Paramiko provides built-in SSH server functionality.
  - It enables accurate simulation of authentication behavior.

- **Realistic Behavior**
  - The honeypot mimics real OpenSSH banners and responses.
  - Delays and error messages resemble those of an actual server.

- **Non-Intrusive Design**
  - No actual user accounts or shells are provided.
  - All access attempts are safely logged without granting access.

---

## What the Honeypot Detects

The system is capable of logging and detecting:

- Basic SSH connection attempts  
- Username and password guessing attacks  
- Brute force login attempts  
- Repeated failed authentication patterns  
- Potential automated attack tools  

---

## Files Included

- `honeypot.py` – Main honeypot implementation  
- `logger.py` – Logging helper functions  
- `Dockerfile` – Container configuration  
- `logs/` – Directory for captured log files  
- `analysis.md` – Summary and analysis of captured attacks  

---

## Summary

This honeypot provides a realistic and effective mechanism for detecting unauthorized SSH access attempts.  
It satisfies the assignment requirements by:

- Simulating a real service  
- Logging detailed attacker activity  
- Remaining convincing and non-obvious  
- Providing useful data for security analysis  

The collected logs can be used to study attack behavior and improve overall system security.
