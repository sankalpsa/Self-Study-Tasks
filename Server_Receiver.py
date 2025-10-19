import pyaudio
import socket
import threading
import struct
import signal
import time
from collections import deque

# --- Parameters ---
CHUNK = 1024  # Match sender's CHUNK
FORMAT = pyaudio.paInt16
HOST_IP = '0.0.0.0'
PORT_RTP = 5000
PORT_SIP = 5060
FEC_PAYLOAD_TYPE = 127

# --- Jitter Buffer Parameters ---
JITTER_BUFFER_TARGET_SIZE = 1  # lower to start playback sooner
JITTER_BUFFER_MAX_SIZE = 20

# --- Global Events & Shared State ---
end_call = threading.Event()
start_streaming = threading.Event()
packet_queue = deque(maxlen=JITTER_BUFFER_MAX_SIZE * 2)


class JitterBuffer:
    def __init__(self):
        self.audio_buffer = {}
        self.fec_buffer = {}
        self.playout_pointer = -1
        self.lock = threading.Lock()
        self.stats = {'received': 0, 'lost': 0, 'recovered': 0, 'underruns': 0}

    def add(self, seq, payload, is_fec):
        with self.lock:
            # Normalize payload size for audio packets so frames match expected CHUNK
            if not is_fec:
                expected = CHUNK * 2
                if len(payload) != expected:
                    if len(payload) < expected:
                        payload = payload + (b'\x00' * (expected - len(payload)))
                        print(f"[JitterBuffer] Padding audio payload seq={seq} from {len(payload)-(expected - len(payload))} to {expected} bytes")
                    else:
                        payload = payload[:expected]
                        print(f"[JitterBuffer] Trimming audio payload seq={seq} from {len(payload)+(len(payload)-expected)} to {expected} bytes")
            if self.playout_pointer == -1 and not is_fec:
                self.playout_pointer = seq

            if is_fec:
                self.fec_buffer[seq] = payload
                num_protected = struct.unpack('!H', payload[:2])[0]
                header_end = 2 + (num_protected * 2)
                protected_seqs = struct.unpack(f'!{num_protected}H', payload[2:header_end])
                protected_str = ','.join(map(str, protected_seqs))
                print(
                    f"⬇️  [RCVD]  Type: FEC   | Seq: {seq} | Size: {len(payload) + 12} bytes | Protects: [{protected_str}]")
            else:
                self.audio_buffer[seq] = payload
                self.stats['received'] += 1
                print(f"⬇️  [RCVD]  Type: AUDIO | Seq: {seq} | Size: {len(payload) + 12} bytes | Buffer size: {len(self.audio_buffer)}")

            if len(self.fec_buffer) > JITTER_BUFFER_MAX_SIZE:
                oldest_fec = min(self.fec_buffer.keys())
                del self.fec_buffer[oldest_fec]

    def get_next_frame(self):
        with self.lock:
            if self.playout_pointer == -1 or len(self.audio_buffer) < JITTER_BUFFER_TARGET_SIZE:
                self.stats['underruns'] += 1
                print(f"[JitterBuffer] Underrun or not enough packets. Playout pointer: {self.playout_pointer}, Buffer size: {len(self.audio_buffer)}")
                return b'\x00' * CHUNK * 2  # Use correct CHUNK size
            if self.playout_pointer in self.audio_buffer:
                frame = self.audio_buffer.pop(self.playout_pointer)
                # ensure returned frame is exact size
                if len(frame) != CHUNK * 2:
                    frame = frame[:CHUNK * 2].ljust(CHUNK * 2, b'\x00')
                print(f"[JitterBuffer] Playing out seq {self.playout_pointer}")
                self.playout_pointer = (self.playout_pointer + 1) & 0xFFFF
                return frame

            self.stats['lost'] += 1
            print(f"⚠️  [LOSS]  Packet {self.playout_pointer} is lost. Attempting recovery...")
            for fec_seq, fec_packet in list(self.fec_buffer.items()):
                num_protected = struct.unpack('!H', fec_packet[:2])[0]
                header_end = 2 + (num_protected * 2)
                protected_seqs = struct.unpack(f'!{num_protected}H', fec_packet[2:header_end])

                if self.playout_pointer in protected_seqs:
                    recovered = self._recover_with_fec(fec_packet[header_end:], protected_seqs)
                    if recovered:
                        # ensure recovered size is correct
                        if len(recovered) != CHUNK * 2:
                            recovered = recovered[:CHUNK * 2].ljust(CHUNK * 2, b'\x00')
                        self.stats['recovered'] += 1
                        print(f"✅ [RECOVER] Packet {self.playout_pointer} successfully recovered using FEC {fec_seq}.")
                        del self.fec_buffer[fec_seq]
                        self.playout_pointer = (self.playout_pointer + 1) & 0xFFFF
                        return recovered

            print(f"❌ [FAILED]  Recovery failed for packet {self.playout_pointer}. Playing silence.")
            self.playout_pointer = (self.playout_pointer + 1) & 0xFFFF
            return b'\x00' * CHUNK * 2  # Use correct CHUNK size

    def _recover_with_fec(self, fec_payload, protected_seqs):
        missing_seq = self.playout_pointer
        reconstructed = bytearray(fec_payload)
        for seq in protected_seqs:
            if seq != missing_seq:
                if seq in self.audio_buffer:
                    for i in range(len(reconstructed)):
                        reconstructed[i] ^= self.audio_buffer[seq][i]
                else:
                    return None
        return bytes(reconstructed)


class RTPReceiver:
    def __init__(self, jitter_buffer):
        # allow quick reuse and bind
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.audio = pyaudio.PyAudio()
        self.output_stream = None
        self.jitter_buffer = jitter_buffer
        self.sender_addr = None  # Store sender address for ACKs

    def audio_callback(self, in_data, frame_count, time_info, status):
        if status == pyaudio.paOutputUnderflow:
            print("⚠️ WARNING: Audio output underflow! Jitter buffer may be empty.", flush=True)
        frame = self.jitter_buffer.get_next_frame()
        return (frame, pyaudio.paContinue)

    def run(self):
        self.socket.bind((HOST_IP, PORT_RTP))
        print(f"🎧 RTP: Receiver waiting on {HOST_IP}:{PORT_RTP}")
        print(f"🎧 RTP: Local address is {self.socket.getsockname()}")

        if not start_streaming.wait(timeout=60):
            print("❌ RTP: Timed out. Exiting.")
            return

        print("✅ RTP: SIP handshake complete, ready to receive RTP packets.")

        try:
            # --- CRITICAL FIX: DYNAMICALLY GET OUTPUT DEVICE SPECS ---
            dev_info = self.audio.get_default_output_device_info()
            rate = int(dev_info['defaultSampleRate'])
            channels = int(dev_info['maxOutputChannels'])
            if channels > 1:
                channels = 1

            print("\n" + "=" * 50)
            print("🔊 DYNAMIC AUDIO OUTPUT CONFIGURATION")
            print(f"  - Device Name: {dev_info['name']}")
            print(f"  - Using Sample Rate: {rate} Hz")
            print(f"  - Using Channels: {channels}")
            print("=" * 50 + "\n")

            self.output_stream = self.audio.open(
                format=FORMAT,
                channels=channels,
                rate=rate,
                output=True,
                frames_per_buffer=CHUNK,  # Use correct CHUNK size
                stream_callback=self.audio_callback
            )
            self.output_stream.start_stream()
            print("▶️ Audio stream started. Playback is active.", flush=True)

            receiver_thread = threading.Thread(target=self.receive_packets, daemon=True)
            receiver_thread.start()

            while self.output_stream.is_active() and not end_call.is_set():
                jb_size = len(self.jitter_buffer.audio_buffer)
                print(f"\r📊 Jitter Buffer Size: {jb_size} packets", end="", flush=True)
                time.sleep(1)

        finally:
            self.cleanup()

    def receive_packets(self):
        # increase recv buffer and timeout
        self.socket.settimeout(5.0)
        last_packet_time = time.time()
        while not end_call.is_set():
            try:
                packet, sender_addr = self.socket.recvfrom(8192)
                self.sender_addr = sender_addr  # Save sender address for ACKs
                last_packet_time = time.time()
                if len(packet) < 12:
                    print(f"[RTPReceiver] Received packet too short: {len(packet)} bytes")
                    continue
                header = struct.unpack('!BBHII', packet[:12])
                payload_type, seq = header[1] & 0x7F, header[2]
                if payload_type == FEC_PAYLOAD_TYPE:
                    print(f"[RTPReceiver] Received FEC packet, seq={seq}, size={len(packet)}")
                else:
                    print(f"[RTPReceiver] Received AUDIO packet, seq={seq}, size={len(packet)}")
                self.jitter_buffer.add(seq, packet[12:], payload_type == FEC_PAYLOAD_TYPE)
                # --- Send ACK for AUDIO packets only ---
                if payload_type != FEC_PAYLOAD_TYPE and self.sender_addr:
                    ack_msg = struct.pack('!4sH', b'ACK!', seq)
                    self.socket.sendto(ack_msg, self.sender_addr)
            except socket.timeout:
                now = time.time()
                if now - last_packet_time > 5:
                    print("[RTPReceiver] No RTP packets received in the last 5 seconds.")
                    last_packet_time = now
            except Exception as e:
                print(f"[RTPReceiver] Exception in receive_packets: {e}")
                break

    def cleanup(self):
        print("\nCleaning up RTP Receiver...")
        if self.output_stream:
            self.output_stream.stop_stream()
            self.output_stream.close()
        self.audio.terminate()
        self.socket.close()

        stats = self.jitter_buffer.stats
        print("\n" + "=" * 50 + "\n📊 FINAL STREAM STATISTICS\n" +
              f"  - Packets Received: {stats['received']}\n" +
              f"  - Packets Lost: {stats['lost']}\n" +
              f"  - Packets Recovered (FEC): {stats['recovered']}\n" +
              f"  - Audio Underruns: {stats['underruns']}\n" + "=" * 50)


class SIPServer:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def run(self):
        self.socket.bind((HOST_IP, PORT_SIP))
        print(f"📞 SIP: Server listening on {HOST_IP}:{PORT_SIP}")
        while not end_call.is_set():
            try:
                self.socket.settimeout(1.0)
                message, client_addr = self.socket.recvfrom(1024)
                if b"INVITE" in message:
                    print(f"✅ SIP: Call from {client_addr}. Sending 200 OK.")
                    self.socket.sendto(b"SIP/2.0 200 OK\r\n\r\n", client_addr)
                    start_streaming.set()
                elif b"BYE" in message:
                    print("📞 SIP: Received BYE. Ending call.")
                    end_call.set()
                    break
            except socket.timeout:
                continue
        self.socket.close()


def signal_handler(sig, frame):
    print("\n🚨 Ctrl+C! Shutting down...")
    end_call.set()


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)

    jitter_buffer = JitterBuffer()
    sip_server = SIPServer()
    rtp_receiver = RTPReceiver(jitter_buffer)

    sip_thread = threading.Thread(target=sip_server.run, daemon=True)
    rtp_thread = threading.Thread(target=rtp_receiver.run, daemon=True)

    print("🚀 VoIP Receiver Ready | Waiting for call...")
    sip_thread.start()
    rtp_thread.start()

    end_call.wait()

    print("\nTermination signal received. Waiting for threads to clean up...")
    sip_thread.join(timeout=2)
    rtp_thread.join(timeout=2)
    print("🏁 Receiver application terminated.")
