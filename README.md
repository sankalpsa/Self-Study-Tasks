📞 VoIP Softphone - Internet Ready (SIP & RTP)

A complete, responsive, cross-platform VoIP softphone application built with Python (PyQt5) and leveraging custom SIP and RTP protocol implementations for robust voice communication over the internet.

✨ Features

Custom SIP & RTP Implementation: Minimalist, hand-coded signaling (SIP) and media transport (RTP) for educational and practical purposes.

Audio Processing: Utilizes PyAudio for real-time audio I/O and implements G.711 $\mu$-law encoding/decoding.

Quality of Service (QoS): Includes a Jitter Buffer for packet delay compensation and Forward Error Correction (FEC) via XOR redundancy to mitigate packet loss.

NAT Traversal: Built-in STUN (Session Traversal Utilities for NAT) mechanism to automatically discover and use the public IP address and port, simplifying connection setup across different networks.

Cross-Network Connectivity: Supports multiple connection methods: Localhost, Local Network (LAN), and Internet-based communication with Public IP/Port Forwarding.

Responsive UI: A clean, modern, and responsive interface built with PyQt5 featuring a dial pad, contact manager, and real-time status/debug logging.

Real-time Status: Displays local/public IP, call status, and call duration.

🚀 Getting Started

Prerequisites

You need Python 3.x installed on your system.

Installation

Install the required Python libraries using pip:

pip install pyaudio PyQt5 requests


⚠️ Windows Users (PyAudio Specifics):

If you encounter issues installing pyaudio on Windows, you may need to use pipwin:

pip install pipwin
pipwin install pyaudio


Running the Application

Execute the main Python script (replace your_softphone_file_name.py with your actual file name):

python your_softphone_file_name.py


🌐 Network Setup Guide

Connecting two softphones over the internet can be challenging due to Network Address Translation (NAT). This application provides multiple methods, with the built-in STUN being the most convenient.

⭐ Recommended Method: Built-in STUN (Automatic)

This method attempts to automatically discover your public IP and port, enabling NAT traversal without manual router configuration.

Start the App: Both users launch the softphone.

Get Public IP: Click the "🔄 Refresh" button to run the STUN query and detect your Public IP.

Share IPs: Share the displayed Public IP with the other person.

Connect: Each user enters the other's Public IP into the input field and clicks "📞 Call".

🛠️ Manual Method: Public IP + Port Forwarding

This method ensures reliable connectivity but requires access to your router settings.

Find your Public IP: Use the displayed IP or visit a site like https://whatismyipaddress.com/.

Port Forwarding: On your home router, forward the following UDP ports to your computer's Local IP (e.g., 192.168.1.100):

RTP Media Port: 5004 (UDP)

SIP Signaling Port: 5062 (UDP)

Connect: Both users enter each other's Public IP and initiate the call.

🧪 Simple Testing: Local Network (LAN) or VPN

For simple testing, use one of these methods:

Local Test: Use 127.0.0.1 in the IP field to call yourself (requires two instances or loopback configuration).

Same WiFi/LAN: Use the Local IP (e.g., 192.168.x.x) of the other computer.

VPN: Both users connect to the same VPN (e.g., Hamachi, ZeroTier, Tailscale) and use the VPN-assigned IP addresses.

⚠️ Carrier-Grade NAT (CGNAT) Warning:
Mobile hotspots and some ISPs use CGNAT, which often blocks incoming connections, making the Public IP/Port Forwarding method impossible. In such cases, one user must be on a network that permits port forwarding, or both must use a VPN solution.

⚙️ Technical Details

Protocol/Function

Technology/Port

Purpose

SIP

Custom UDP / 5062

Signaling (INVITE, 200 OK, BYE)

RTP

Custom UDP / 5004

Real-time media transport

Codec

G.711 $\mu$-law

Audio encoding/decoding

NAT Traversal

STUN / 19302

Public IP and port discovery

QoS

Jitter Buffer

Compensates for network delay variation

QoS

Forward Error Correction (FEC)

Mitigates packet loss

UI

PyQt5

Cross-platform desktop interface

🤝 Contribution

This project is primarily a demonstration of core VoIP and networking concepts. Feel free to fork, modify, and experiment. If you find a bug or have a suggestion, please open an issue!

📝 License

This project is open-source. See the repository for specific licensing details.

Built with passion for networking and real-time communication.
