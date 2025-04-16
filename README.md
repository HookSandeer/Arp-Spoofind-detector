# ARP Spoofing Detector

A simple ARP spoofing (Man-in-the-Middle attack) detector written in Python 3 for Linux-based systems.

## Requirements

- A working **msmtp** configuration to allow sending alert emails.

## Python Modules Used

- `scapy`  
- `os`  
- `email` *(built-in)*

## How to Use

1. **Install `msmtp` and the required Python modules:**
   ```bash
   sudo apt install msmtp
   pip3 install scapy
   ```
2. **Configure `msmtp` so the script can send alert emails.**

    Edit the script:
    Replace the value of the iface variable with the name of your network interface.

3. **Configure your network interface:**

        Set it to link-only mode (no IP address).

        Configure port mirroring on your switch so that all traffic is copied to this interface.

## Notes

    This script is intended for use in a monitored or lab environment.

    Root privileges may be required to capture packets and send alerts.