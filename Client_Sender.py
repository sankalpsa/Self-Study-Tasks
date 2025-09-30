import pyaudio
import socket
import sys
import time
import threading
import struct
import signal
import hashlib

# --- Parameters (Audio settings will now be determined dynamically) ---
CHUNK = 1024
RECEIVER_IP = '127.0.0.1'
PORT_RTP = 5000
PORT_SIP = 5060
FEC_RATIO = 10
FEC_PAYLOAD_TYPE = 127

# --- Global Events ---
start_streaming = threading.Event()
end_call = threading.Event()


class FECGenerator:
    def __init__(self, ratio=10):
        self.ratio = ratio
        self.packet_buffer = []
        self.fec_counter = 0

    def add_packet(self, sequence_num, payload):
        self.packet_buffer.append({'seq': sequence_num, 'payload': payload})
        if len(self.packet_buffer) > self.ratio:
            self.packet_buffer.pop(0)

    def should_send_fec(self):
        self.fec_counter += 1
        return self.fec_counter % self.ratio == 0

    def generate_fec_packet(self):
        if len(self.packet_buffer) < 2: return None, None
        fec_payload = bytearray(len(self.packet_buffer[0]['payload']))
        protected_sequences = []
        for packet in self.packet_buffer:
            protected_sequences.append(packet['seq'])
            for i in range(len(packet['payload'])):
                fec_payload[i] ^= packet['payload'][i]
        fec_header = struct.pack('!H', len(protected_sequences))
        for seq in protected_sequences:
            fec_header += struct.pack('!H', seq)
        return fec_header + bytes(fec_payload), protected_sequences


class SIPClient:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.settimeout(5.0)
        self.server_addr = None

    def run(self):
        try:
            sip_message = f"INVITE sip:receiver@{RECEIVER_IP} SIP/2.0\r\nCall-ID: {hashlib.md5(str(time.time()).encode()).hexdigest()}\r\nCSeq: 1 INVITE\r\n\r\n".encode()
            print("📞 SIP: Sending INVITE...")
            self.socket.sendto(sip_message, (RECEIVER_IP, PORT_SIP))

            while not end_call.is_set() and not start_streaming.is_set():
                try:
                    response, addr = self.socket.recvfrom(1024)
                    self.server_addr = addr
                    if b"200 OK" in response:
                        print("✅ SIP: Call established!")
                        start_streaming.set()
                except socket.timeout:
                    print("📞 SIP: Timeout, retrying INVITE...")
                    self.socket.sendto(sip_message, (RECEIVER_IP, PORT_SIP))
            end_call.wait()
            self.send_bye()
        finally:
            self.socket.close()

    def send_bye(self):
        if self.server_addr:
            bye_message = f"BYE sip:receiver@{RECEIVER_IP} SIP/2.0\r\nCall-ID: {hashlib.md5(str(time.time()).encode()).hexdigest()}\r\nCSeq: 2 BYE\r\n\r\n".encode()
            print("📞 SIP: Sending BYE...")
            self.socket.sendto(bye_message, self.server_addr)


class RTPClient:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.audio = pyaudio.PyAudio()
        self.input_stream = None
        self.fec_generator = FECGenerator(FEC_RATIO)
        self.ssrc = int(time.time()) & 0xFFFFFFFF

    def run(self):
        if not start_streaming.wait(timeout=30):
            print("❌ RTP: Timeout waiting for SIP call.")
            return

        try:
            device_info = self.audio.get_default_input_device_info()
            rate = int(device_info['defaultSampleRate'])
            channels = device_info['maxInputChannels']

            if channels > 1:
                channels = 1

            print("\n" + "=" * 50)
            print("🎤 DYNAMIC AUDIO INPUT CONFIGURATION")
            print(f"  - Device Name: {device_info['name']}")
            print(f"  - Using Sample Rate: {rate} Hz")
            print(f"  - Using Channels: {channels}")
            print("=" * 50 + "\n")

            self.input_stream = self.audio.open(
                format=pyaudio.paInt16,
                channels=channels,
                rate=rate,
                input=True,
                frames_per_buffer=CHUNK,
                input_device_index=device_info['index']
            )
            print("🎙️  Microphone is open. Streaming audio...")

            packet_count = 0
            while not end_call.is_set():
                raw_data = self.input_stream.read(CHUNK, exception_on_overflow=False)

                sequence_number = packet_count & 0xFFFF
                timestamp = int(time.time() * rate) & 0xFFFFFFFF
                header = struct.pack('!BBHII', 0x80, 0, sequence_number, timestamp, self.ssrc)
                audio_packet = header + raw_data
                self.socket.sendto(audio_packet, (RECEIVER_IP, PORT_RTP))

                print(f"⬆️  [SENT]  Type: AUDIO | Seq: {sequence_number} | Size: {len(audio_packet)} bytes")

                self.fec_generator.add_packet(sequence_number, raw_data)
                if self.fec_generator.should_send_fec():
                    fec_payload, protected_seqs = self.fec_generator.generate_fec_packet()
                    if fec_payload:
                        fec_seq = (packet_count + 30000) & 0xFFFF
                        fec_header = struct.pack('!BBHII', 0x80, FEC_PAYLOAD_TYPE, fec_seq, timestamp, self.ssrc)
                        fec_packet = fec_header + fec_payload
                        self.socket.sendto(fec_packet, (RECEIVER_IP, PORT_RTP))

                        protected_str = ','.join(map(str, protected_seqs))
                        print(
                            f"⬆️  [SENT]  Type: FEC   | Seq: {fec_seq} | Size: {len(fec_packet)} bytes | Protects: [{protected_str}]")

                packet_count += 1

        except Exception as e:
            print(f"\n--- FATAL ERROR in RTPClient ---")
            print(f"Error: {e}")
            print("This is likely a problem with your microphone setup or permissions.")
            print("Troubleshooting steps:")
            print("1. Ensure no other app is using your microphone.")
            print("2. Check your OS microphone permissions for your terminal/IDE.")
            print("3. Unplug and replug your microphone if it's external.")
            print("---------------------------------\n")

        finally:
            self.cleanup()

    def cleanup(self):
        if self.input_stream: self.input_stream.close()
        self.audio.terminate()
        self.socket.close()
        print("🔴 RTP Sender: Cleaned up.")


def signal_handler(sig, frame):
    if not end_call.is_set():
        print("\n🚨 Ctrl+C detected! Shutting down...")
        end_call.set()


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)

    sip_client = SIPClient()
    rtp_client = RTPClient()

    sip_thread = threading.Thread(target=sip_client.run, daemon=True)
    rtp_thread = threading.Thread(target=rtp_client.run, daemon=True)

    print("🚀 VoIP Sender Initializing...")
    sip_thread.start()
    rtp_thread.start()

    end_call.wait()
    print("🏁 Sender application terminated.")