# VoIP Audio Streaming with SIP, RTP, and FEC

This project is a real-time, one-way Voice over IP (VoIP) audio streaming application built in Python. It uses a client-server model to stream audio from a microphone to a speaker, implementing standard communication protocols and advanced features for reliability.

The `Server_Receiver.py` script listens for an incoming call, while the `Client_Sender.py` script captures audio and streams it to the server. The system is designed for resilience against network packet loss through a custom Forward Error Correction (FEC) implementation.

## Features

### Core Functionality
- **SIP Call Management**: A lightweight implementation of the Session Initiation Protocol (SIP) handles call initiation (`INVITE`) and termination (`BYE`), ensuring a proper session is established before audio streaming begins.
- **RTP Audio Streaming**: Audio is captured from the microphone, packetized according to the Real-time Transport Protocol (RTP), and streamed over UDP for low-latency transmission.
- **Dynamic Audio Configuration**: The sender and receiver automatically detect the host machine's default microphone and speaker settings (sample rate, channels), making it plug-and-play without manual configuration.

### Advanced Features
- **Forward Error Correction (FEC)**: The sender periodically generates FEC packets by XORing a batch of recent audio packets. If the receiver detects a lost audio packet, it can use the corresponding FEC packet to reconstruct the missing data, significantly improving audio quality on unreliable networks.
- **Jitter Buffer**: The receiver implements a dynamic jitter buffer to handle network jitter (variable packet arrival times). This ensures smooth, uninterrupted audio playback by absorbing delays and reordering packets if necessary.
- **Packet Loss Detection & Recovery**: The receiver actively monitors RTP sequence numbers to detect lost packets. Upon detection, it attempts to recover the lost packet using the FEC mechanism.
- **Graceful Shutdown**: The application supports a clean shutdown process. Pressing `Ctrl+C` in either terminal sends a SIP `BYE` message to terminate the call and properly closes all network sockets and audio streams.
- **Real-time Statistics**: On shutdown, the receiver prints a final report detailing the number of packets received, lost, and successfully recovered via FEC, providing clear insight into the stream's performance.

## How to Run

Follow these instructions to set up and run the VoIP application.

### Prerequisites

You must have Python 3 installed on your system. The only external library required is `PyAudio`.

### Installation

1.  **Install PyAudio:**
    You can install the necessary library using pip.

    ```
    pip install pyaudio
    ```
    > **Note**: On some operating systems (like Linux or macOS), `PyAudio` may require you to install system dependencies first. For example, on Debian/Ubuntu, you might need to run: `sudo apt-get install portaudio19-dev python3-pyaudio`.

### Usage

The client and server are configured to run on the same machine (`localhost`). To run them on different machines, change the `RECEIVER_IP` variable in `Client_Sender.py` to the IP address of the server machine.

1.  **Start the Server**
    Open a terminal and run the `Server_Receiver.py` script. The server will initialize and wait for an incoming call.

    ```
    python Server_Receiver.py
    ```
    You will see the following output, confirming the server is ready:
    ```
    🚀 VoIP Receiver Ready | Waiting for call...
    📞 SIP: Server listening on 0.0.0.0:5060
    🎧 RTP: Receiver waiting on 0.0.0.0:5000
    ```

2.  **Start the Client**
    Open a **new terminal** and run the `Client_Sender.py` script. This will initiate the SIP call to the server.

    ```
    python Client_Sender.py
    ```
    Once the server accepts the call, the client will start capturing audio from your default microphone and streaming it. Both terminals will display real-time logs of the packets being sent and received.

### Stopping the Application

To end the session, press `Ctrl+C` in **either** the client or the server terminal. This will trigger a graceful shutdown, terminate the call via a SIP `BYE` message, and close both applications. The server will then display the final stream quality statistics.
