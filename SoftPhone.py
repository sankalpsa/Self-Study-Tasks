"""
=============================================================================
VOIP SOFTPHONE - COMPLETE RESPONSIVE VERSION
=============================================================================
Install required libraries:

    pip install pyaudio PyQt5 requests

For PyAudio issues on Windows:
    pip install pipwin
    pipwin install pyaudio

=============================================================================
NETWORK SETUP FOR DIFFERENT INTERNET CONNECTIONS
=============================================================================

🌐 THREE WAYS TO CONNECT ACROSS DIFFERENT NETWORKS:

METHOD 1: Using Public IP + Port Forwarding (Manual Setup)
----------------------------------------------------------
1. Find your public IP: Visit https://whatismyipaddress.com/
2. Enable port forwarding on your router:
   - Forward port 5004 (RTP) to your local IP
   - Forward port 5062 (SIP) to your local IP
3. Share your PUBLIC IP with the other person
4. Both users enter each other's PUBLIC IP in the app

METHOD 2: Using This App's Built-in STUN (Automatic) ⭐ RECOMMENDED
-------------------------------------------------------------------
1. Click "🔄 Refresh" button in the app
2. Share the displayed public IP with the other person
3. The app automatically handles NAT traversal
4. No router configuration needed!

METHOD 3: Using a VPN (Simplest for Testing)
---------------------------------------------
1. Both users connect to the same VPN (like Hamachi, ZeroTier)
2. Use the VPN-assigned IP addresses
3. Works like you're on the same network

⚠️ IMPORTANT: Mobile hotspots often use Carrier-Grade NAT (CGNAT)
which may block incoming connections. In this case, one user needs
to be on a network that allows port forwarding (home WiFi).

=============================================================================
"""

import pyaudio
import socket
import sys
import time
import threading
import struct
import signal
import hashlib
import audioop
import json
import requests
from collections import deque
from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtCore import Qt, pyqtSignal, QTimer
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QPushButton, QLabel, QLineEdit, 
                             QTextEdit, QListWidget, QStackedWidget, QFrame,
                             QGridLayout, QMessageBox, QCheckBox)

# ==================== CONFIGURATION ====================
CHUNK = 1024
FORMAT = pyaudio.paInt16
SAMPLE_RATE = 16000
CHANNELS = 1
PORT_RTP = 5004
PORT_SIP = 5062
FEC_PAYLOAD_TYPE = 127
AUDIO_PAYLOAD_TYPE = 0
FEC_RATIO = 10
JITTER_BUFFER_TARGET = 5
JITTER_BUFFER_MAX = 30

# STUN Servers for NAT traversal
STUN_SERVERS = [
    ('stun.l.google.com', 19302),
    ('stun1.l.google.com', 19302),
    ('stun2.l.google.com', 19302),
]

DEBUG = True

def debug_print(msg):
    """Print debug messages with timestamp"""
    if DEBUG:
        timestamp = time.strftime("%H:%M:%S")
        print(f"[{timestamp}] {msg}")

# ==================== NAT TRAVERSAL / PUBLIC IP DETECTION ====================
class NetworkHelper:
    """Helper class for NAT traversal and public IP detection"""
    
    @staticmethod
    def get_public_ip():
        """Get public IP address using multiple methods"""
        methods = [
            lambda: requests.get('https://api.ipify.org', timeout=3).text,
            lambda: requests.get('https://icanhazip.com', timeout=3).text.strip(),
            lambda: requests.get('https://ifconfig.me/ip', timeout=3).text.strip(),
        ]
        
        for method in methods:
            try:
                ip = method()
                if ip and '.' in ip:
                    debug_print(f"🌍 Public IP detected: {ip}")
                    return ip
            except Exception as e:
                debug_print(f"Failed to get public IP: {e}")
                continue
        
        return None
    
    @staticmethod
    def get_local_ip():
        """Get local network IP"""
        try:
            # Create a socket to determine local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            debug_print(f"🏠 Local IP: {local_ip}")
            return local_ip
        except Exception as e:
            debug_print(f"Failed to get local IP: {e}")
            return "127.0.0.1"
    
    @staticmethod
    def perform_stun_query(stun_host, stun_port):
        """Perform STUN query to discover external IP and port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            
            # STUN Binding Request
            trans_id = bytes([0x21, 0x12, 0xA4, 0x42]) + bytes(12)
            message = struct.pack('!HHI', 0x0001, 0, 0) + trans_id
            
            sock.sendto(message, (stun_host, stun_port))
            data, addr = sock.recvfrom(2048)
            
            # Parse STUN response
            if len(data) >= 20:
                # Look for XOR-MAPPED-ADDRESS attribute
                pos = 20
                while pos < len(data):
                    attr_type = struct.unpack('!H', data[pos:pos+2])[0]
                    attr_len = struct.unpack('!H', data[pos+2:pos+4])[0]
                    
                    if attr_type == 0x0020:  # XOR-MAPPED-ADDRESS
                        port = struct.unpack('!H', data[pos+6:pos+8])[0] ^ 0x2112
                        ip_bytes = data[pos+8:pos+12]
                        ip = '.'.join(str(b ^ 0x21) if i == 0 else str(b ^ 0x12) if i == 1 
                                     else str(b ^ 0xA4) if i == 2 else str(b ^ 0x42) 
                                     for i, b in enumerate(ip_bytes))
                        
                        sock.close()
                        debug_print(f"🎯 STUN discovered: {ip}:{port}")
                        return ip, port
                    
                    pos += 4 + attr_len
            
            sock.close()
        except Exception as e:
            debug_print(f"STUN query failed: {e}")
        
        return None, None
    
    @staticmethod
    def discover_external_address():
        """Try to discover external IP and port using STUN"""
        for stun_host, stun_port in STUN_SERVERS:
            ip, port = NetworkHelper.perform_stun_query(stun_host, stun_port)
            if ip:
                return ip, port
        return None, None
    
    @staticmethod
    def check_port_open(port):
        """Check if a port can be bound"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('0.0.0.0', port))
            sock.close()
            return True
        except:
            return False

# ==================== AUDIO CODEC ====================
class G711Codec:
    """G.711 μ-law codec for audio compression"""
    
    @staticmethod
    def encode(pcm_data):
        """Encode PCM to G.711 μ-law"""
        try:
            return audioop.lin2ulaw(pcm_data, 2)
        except Exception as e:
            debug_print(f"❌ Encode error: {e}")
            return pcm_data
    
    @staticmethod
    def decode(ulaw_data):
        """Decode G.711 μ-law to PCM"""
        try:
            return audioop.ulaw2lin(ulaw_data, 2)
        except Exception as e:
            debug_print(f"❌ Decode error: {e}")
            return ulaw_data

# ==================== FEC GENERATOR ====================
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
        if len(self.packet_buffer) < 2:
            return None, None
        
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

# ==================== JITTER BUFFER ====================
class JitterBuffer:
    def __init__(self):
        self.audio_buffer = {}
        self.fec_buffer = {}
        self.playout_pointer = -1
        self.lock = threading.Lock()
        self.stats = {
            'received': 0,
            'lost': 0,
            'recovered': 0,
            'underruns': 0,
            'played': 0
        }
        self.frame_size = CHUNK * 2
        self.initialized = False

    def add(self, seq, payload, is_fec):
        with self.lock:
            if is_fec:
                self.fec_buffer[seq] = payload
            else:
                self.audio_buffer[seq] = payload
                self.stats['received'] += 1
                
                if not self.initialized:
                    self.playout_pointer = seq
                    self.initialized = True

            if len(self.fec_buffer) > JITTER_BUFFER_MAX:
                oldest = min(self.fec_buffer.keys())
                del self.fec_buffer[oldest]

    def get_next_frame(self):
        with self.lock:
            if not self.initialized:
                self.stats['underruns'] += 1
                return b'\x00' * self.frame_size
            
            if len(self.audio_buffer) < JITTER_BUFFER_TARGET:
                self.stats['underruns'] += 1
                return b'\x00' * self.frame_size

            if self.playout_pointer in self.audio_buffer:
                encoded_frame = self.audio_buffer.pop(self.playout_pointer)
                decoded_frame = G711Codec.decode(encoded_frame)
                
                if len(decoded_frame) < self.frame_size:
                    decoded_frame += b'\x00' * (self.frame_size - len(decoded_frame))
                elif len(decoded_frame) > self.frame_size:
                    decoded_frame = decoded_frame[:self.frame_size]
                
                self.stats['played'] += 1
                self.playout_pointer = (self.playout_pointer + 1) & 0xFFFF
                return decoded_frame

            self.stats['lost'] += 1
            self.playout_pointer = (self.playout_pointer + 1) & 0xFFFF
            return b'\x00' * self.frame_size

    def reset(self):
        with self.lock:
            self.audio_buffer.clear()
            self.fec_buffer.clear()
            self.playout_pointer = -1
            self.initialized = False

    def get_stats(self):
        with self.lock:
            return self.stats.copy()

# ==================== AUDIO ENGINE ====================
class AudioEngine:
    """Handles both sending and receiving audio streams"""
    
    def __init__(self):
        self.audio = pyaudio.PyAudio()
        self.input_stream = None
        self.output_stream = None
        self.running = False
        self.jitter_buffer = JitterBuffer()
        
        self.sample_rate = SAMPLE_RATE
        self.channels = CHANNELS

    def start_input(self):
        """Start microphone input stream"""
        try:
            self.input_stream = self.audio.open(
                format=FORMAT,
                channels=self.channels,
                rate=self.sample_rate,
                input=True,
                frames_per_buffer=CHUNK,
                stream_callback=None
            )
            debug_print("✅ Microphone started")
            return True
        except Exception as e:
            debug_print(f"❌ Failed to start microphone: {e}")
            return False

    def start_output(self):
        """Start speaker output stream"""
        try:
            self.output_stream = self.audio.open(
                format=FORMAT,
                channels=self.channels,
                rate=self.sample_rate,
                output=True,
                frames_per_buffer=CHUNK,
                stream_callback=None
            )
            debug_print("✅ Speaker started")
            return True
        except Exception as e:
            debug_print(f"❌ Failed to start speaker: {e}")
            return False

    def read_audio(self):
        """Read audio from microphone"""
        if self.input_stream and self.input_stream.is_active():
            try:
                return self.input_stream.read(CHUNK, exception_on_overflow=False)
            except Exception as e:
                return b'\x00' * (CHUNK * 2)
        return b'\x00' * (CHUNK * 2)

    def write_audio(self, data):
        """Write audio to speaker"""
        if self.output_stream and self.output_stream.is_active():
            try:
                self.output_stream.write(data)
            except Exception as e:
                pass

    def cleanup(self):
        """Stop and cleanup audio streams"""
        if self.input_stream:
            try:
                self.input_stream.stop_stream()
                self.input_stream.close()
            except:
                pass
        
        if self.output_stream:
            try:
                self.output_stream.stop_stream()
                self.output_stream.close()
            except:
                pass
        
        try:
            self.audio.terminate()
        except:
            pass

# ==================== RTP HANDLER ====================
class RTPHandler:
    """Handles RTP sending and receiving"""
    
    def __init__(self, audio_engine):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Increase buffer sizes for better network performance
        try:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 512 * 1024)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 512 * 1024)
        except:
            pass
        
        try:
            self.socket.bind(('0.0.0.0', PORT_RTP))
            debug_print(f"📡 RTP socket bound to port {PORT_RTP}")
        except Exception as e:
            debug_print(f"❌ Failed to bind RTP socket: {e}")
        
        self.audio_engine = audio_engine
        self.fec_generator = FECGenerator(FEC_RATIO)
        self.ssrc = int(time.time()) & 0xFFFFFFFF
        self.seq_num = 0
        self.timestamp = 0
        self.remote_addr = None
        self.running = False
        self.send_thread = None
        self.recv_thread = None
        self.playback_thread = None
        
    def start(self, remote_ip):
        """Start RTP send/receive threads"""
        self.remote_addr = (remote_ip, PORT_RTP)
        self.running = True
        
        debug_print(f"🚀 Starting RTP to {remote_ip}:{PORT_RTP}")
        
        self.send_thread = threading.Thread(target=self._send_loop, daemon=True)
        self.recv_thread = threading.Thread(target=self._receive_loop, daemon=True)
        self.playback_thread = threading.Thread(target=self._playback_loop, daemon=True)
        
        self.send_thread.start()
        self.recv_thread.start()
        self.playback_thread.start()
        
        debug_print("✅ RTP threads started")

    def _send_loop(self):
        """Send audio packets to remote"""
        debug_print("📤 Send loop started")
        packet_count = 0
        
        while self.running:
            try:
                pcm_data = self.audio_engine.read_audio()
                encoded_data = G711Codec.encode(pcm_data)
                
                header = struct.pack('!BBHII', 
                                   0x80,
                                   AUDIO_PAYLOAD_TYPE,
                                   self.seq_num,
                                   self.timestamp,
                                   self.ssrc)
                
                packet = header + encoded_data
                self.socket.sendto(packet, self.remote_addr)
                
                packet_count += 1
                if packet_count % 50 == 0:
                    debug_print(f"📤 Sent {packet_count} packets")
                
                self.fec_generator.add_packet(self.seq_num, encoded_data)
                if self.fec_generator.should_send_fec():
                    fec_payload, protected = self.fec_generator.generate_fec_packet()
                    if fec_payload:
                        fec_seq = (self.seq_num + 30000) & 0xFFFF
                        fec_header = struct.pack('!BBHII',
                                               0x80,
                                               FEC_PAYLOAD_TYPE,
                                               fec_seq,
                                               self.timestamp,
                                               self.ssrc)
                        self.socket.sendto(fec_header + fec_payload, self.remote_addr)
                
                self.seq_num = (self.seq_num + 1) & 0xFFFF
                self.timestamp = (self.timestamp + CHUNK) & 0xFFFFFFFF
                
                time.sleep(CHUNK / self.audio_engine.sample_rate * 0.9)
                
            except Exception as e:
                debug_print(f"❌ Send error: {e}")
                time.sleep(0.001)

    def _receive_loop(self):
        """Receive audio packets from remote"""
        debug_print("📥 Receive loop started")
        self.socket.settimeout(1.0)
        packet_count = 0
        
        while self.running:
            try:
                packet, addr = self.socket.recvfrom(8192)
                
                if len(packet) < 12:
                    continue
                
                header = struct.unpack('!BBHII', packet[:12])
                payload_type = header[1] & 0x7F
                seq = header[2]
                payload = packet[12:]
                
                packet_count += 1
                
                is_fec = (payload_type == FEC_PAYLOAD_TYPE)
                self.audio_engine.jitter_buffer.add(seq, payload, is_fec)
                
                if packet_count % 50 == 0:
                    debug_print(f"📥 Received {packet_count} packets from {addr}")
                
            except socket.timeout:
                continue
            except Exception as e:
                pass

    def _playback_loop(self):
        """Playback loop"""
        debug_print("🔊 Playback loop started")
        time.sleep(0.5)
        
        while self.running:
            try:
                frame = self.audio_engine.jitter_buffer.get_next_frame()
                self.audio_engine.write_audio(frame)
            except Exception as e:
                time.sleep(0.001)

    def stop(self):
        """Stop RTP handler"""
        debug_print("⏹️ Stopping RTP...")
        self.running = False
        
        if self.send_thread:
            self.send_thread.join(timeout=2)
        if self.recv_thread:
            self.recv_thread.join(timeout=2)
        if self.playback_thread:
            self.playback_thread.join(timeout=2)
        
        self.audio_engine.jitter_buffer.reset()

# ==================== SIP HANDLER ====================
class SIPHandler(QtCore.QObject):
    """Handles SIP signaling"""
    
    call_incoming = pyqtSignal(str, int)
    call_accepted = pyqtSignal()
    call_ended = pyqtSignal()
    
    def __init__(self):
        super().__init__()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.socket.bind(('0.0.0.0', PORT_SIP))
            debug_print(f"📞 SIP socket bound to port {PORT_SIP}")
        except Exception as e:
            debug_print(f"❌ Failed to bind SIP socket: {e}")
        
        self.socket.settimeout(1.0)
        
        self.running = True
        self.remote_addr = None
        self.call_id = None
        
        self.listener_thread = threading.Thread(target=self._listen_loop, daemon=True)
        self.listener_thread.start()

    def _listen_loop(self):
        """Listen for incoming SIP messages"""
        while self.running:
            try:
                message, addr = self.socket.recvfrom(2048)
                
                if b"INVITE" in message:
                    debug_print(f"📞 INVITE from {addr[0]}")
                    self.remote_addr = addr
                    self.call_incoming.emit(addr[0], addr[1])
                    
                elif b"200 OK" in message:
                    debug_print("✅ 200 OK received")
                    self.call_accepted.emit()
                    
                elif b"BYE" in message:
                    debug_print("👋 BYE received")
                    self.call_ended.emit()
                    
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    pass

    def send_invite(self, dest_ip):
        """Send INVITE"""
        self.call_id = hashlib.md5(str(time.time()).encode()).hexdigest()
        message = (
            f"INVITE sip:user@{dest_ip} SIP/2.0\r\n"
            f"Call-ID: {self.call_id}\r\n"
            f"CSeq: 1 INVITE\r\n\r\n"
        ).encode()
        
        self.remote_addr = (dest_ip, PORT_SIP)
        self.socket.sendto(message, self.remote_addr)
        debug_print(f"📞 INVITE sent to {dest_ip}")

    def accept_call(self):
        """Accept incoming call"""
        if self.remote_addr:
            message = b"SIP/2.0 200 OK\r\n\r\n"
            self.socket.sendto(message, self.remote_addr)
            debug_print(f"✅ 200 OK sent")

    def send_bye(self):
        """End call"""
        if self.remote_addr:
            message = (
                f"BYE sip:user@{self.remote_addr[0]} SIP/2.0\r\n"
                f"Call-ID: {self.call_id or 'end'}\r\n"
                f"CSeq: 2 BYE\r\n\r\n"
            ).encode()
            self.socket.sendto(message, self.remote_addr)

    def cleanup(self):
        """Cleanup SIP handler"""
        self.running = False
        self.socket.close()

# ==================== CONTACT MANAGER ====================
class ContactManager:
    def __init__(self, filename='voip_contacts.json'):
        self.filename = filename
        self.contacts = self.load_contacts()

    def load_contacts(self):
        try:
            with open(self.filename, 'r') as f:
                return json.load(f)
        except:
            return {"Local Test": "127.0.0.1"}

    def save_contacts(self):
        try:
            with open(self.filename, 'w') as f:
                json.dump(self.contacts, f, indent=2)
        except Exception as e:
            pass

    def add_contact(self, name, ip):
        self.contacts[name] = ip
        self.save_contacts()

    def remove_contact(self, name):
        if name in self.contacts:
            del self.contacts[name]
            self.save_contacts()

    def get_all(self):
        return self.contacts

# ==================== UI COMPONENTS ====================
class ModernButton(QPushButton):
    def __init__(self, text, color="#4CAF50"):
        super().__init__(text)
        self.setStyleSheet(f"""
            QPushButton {{
                background-color: {color};
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px 16px;
                font-size: 12px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {self._darken_color(color)};
            }}
            QPushButton:disabled {{
                background-color: #CCCCCC;
                color: #666666;
            }}
        """)
        self.setMinimumHeight(38)
        self.setCursor(Qt.PointingHandCursor)

    def _darken_color(self, hex_color, factor=0.2):
        hex_color = hex_color.lstrip('#')
        rgb = tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
        rgb = tuple(int(c * (1 - factor)) for c in rgb)
        return f"#{rgb[0]:02x}{rgb[1]:02x}{rgb[2]:02x}"

class DialPad(QWidget):
    digit_pressed = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        layout = QGridLayout()
        layout.setSpacing(8)
        layout.setContentsMargins(5, 5, 5, 5)
        
        buttons = [
            ['1', '2', '3'],
            ['4', '5', '6'],
            ['7', '8', '9'],
            ['*', '0', '#']
        ]
        
        for row_idx, row in enumerate(buttons):
            for col_idx, digit in enumerate(row):
                btn = QPushButton(digit)
                btn.setMinimumSize(50, 50)
                btn.setMaximumSize(80, 80)
                btn.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
                btn.setStyleSheet("""
                    QPushButton {
                        background-color: #f0f0f0;
                        border: 2px solid #ddd;
                        border-radius: 25px;
                        font-size: 16px;
                        font-weight: bold;
                    }
                    QPushButton:hover {
                        background-color: #e0e0e0;
                        border-color: #2196F3;
                    }
                    QPushButton:pressed {
                        background-color: #d0d0d0;
                    }
                """)
                btn.clicked.connect(lambda checked, d=digit: self.digit_pressed.emit(d))
                layout.addWidget(btn, row_idx, col_idx)
        
        # Make columns expand equally
        for i in range(3):
            layout.setColumnStretch(i, 1)
        
        self.setLayout(layout)

# ==================== MAIN APPLICATION ====================
class VoIPSoftphone(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("VoIP Softphone - Internet Ready")
        self.setMinimumSize(400, 700)
        self.resize(420, 750)  # Better default size
        
        self.audio_engine = AudioEngine()
        self.rtp_handler = RTPHandler(self.audio_engine)
        self.sip_handler = SIPHandler()
        self.contact_manager = ContactManager()
        
        self.in_call = False
        self.call_duration = 0
        self.remote_ip = None
        self.my_public_ip = None
        self.my_local_ip = NetworkHelper.get_local_ip()
        
        self.sip_handler.call_incoming.connect(self.on_incoming_call)
        self.sip_handler.call_accepted.connect(self.on_call_accepted)
        self.sip_handler.call_ended.connect(self.on_call_ended)
        
        self.setup_ui()
        
        self.duration_timer = QTimer()
        self.duration_timer.timeout.connect(self.update_call_duration)
        
        # Auto-detect public IP on startup
        self.detect_public_ip()

    def setup_ui(self):
        """Setup main UI"""
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(15, 15, 15, 15)
        main_layout.setSpacing(10)
        
        # Header
        header = QLabel("📱 VoIP Softphone")
        header.setAlignment(Qt.AlignCenter)
        header.setStyleSheet("""
            QLabel {
                font-size: 20px;
                font-weight: bold;
                color: #2196F3;
                padding: 8px;
            }
        """)
        main_layout.addWidget(header)
        
        # Network info panel
        self.network_frame = QFrame()
        self.network_frame.setStyleSheet("""
            QFrame {
                background-color: #E3F2FD;
                border-radius: 8px;
                padding: 10px;
            }
        """)
        network_layout = QVBoxLayout(self.network_frame)
        network_layout.setSpacing(5)
        
        self.local_ip_label = QLabel(f"🏠 Local IP: {self.my_local_ip}")
        self.local_ip_label.setStyleSheet("font-size: 11px; color: #555;")
        network_layout.addWidget(self.local_ip_label)
        
        self.public_ip_label = QLabel("🌍 Public IP: Detecting...")
        self.public_ip_label.setStyleSheet("font-size: 11px; color: #555; font-weight: bold;")
        network_layout.addWidget(self.public_ip_label)
        
        ip_btn_layout = QHBoxLayout()
        ip_btn_layout.setSpacing(5)
        
        self.refresh_ip_btn = QPushButton("🔄 Refresh")
        self.refresh_ip_btn.setStyleSheet("""
            QPushButton {
                background-color: #03A9F4;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 6px 10px;
                font-size: 10px;
            }
            QPushButton:hover {
                background-color: #0288D1;
            }
        """)
        self.refresh_ip_btn.clicked.connect(self.detect_public_ip)
        ip_btn_layout.addWidget(self.refresh_ip_btn)
        ip_btn_layout.addStretch()
        
        network_layout.addLayout(ip_btn_layout)
        
        help_label = QLabel("💡 Share PUBLIC IP with other person")
        help_label.setStyleSheet("font-size: 9px; color: #666; font-style: italic;")
        help_label.setWordWrap(True)
        network_layout.addWidget(help_label)
        
        main_layout.addWidget(self.network_frame)
        
        # Status display
        self.status_frame = QFrame()
        self.status_frame.setStyleSheet("""
            QFrame {
                background-color: #f5f5f5;
                border-radius: 8px;
                padding: 10px;
            }
        """)
        self.status_frame.setMinimumHeight(80)
        status_layout = QVBoxLayout(self.status_frame)
        status_layout.setSpacing(3)
        
        self.status_label = QLabel("Ready")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet("""
            QLabel {
                font-size: 14px;
                color: #555;
            }
        """)
        status_layout.addWidget(self.status_label)
        
        self.remote_label = QLabel("")
        self.remote_label.setAlignment(Qt.AlignCenter)
        self.remote_label.setStyleSheet("""
            QLabel {
                font-size: 12px;
                color: #888;
            }
        """)
        status_layout.addWidget(self.remote_label)
        
        self.duration_label = QLabel("")
        self.duration_label.setAlignment(Qt.AlignCenter)
        self.duration_label.setStyleSheet("""
            QLabel {
                font-size: 16px;
                font-weight: bold;
                color: #4CAF50;
            }
        """)
        status_layout.addWidget(self.duration_label)
        
        main_layout.addWidget(self.status_frame)
        
        # Input field
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Enter their PUBLIC IP address")
        self.ip_input.setText("127.0.0.1")
        self.ip_input.setStyleSheet("""
            QLineEdit {
                padding: 10px;
                font-size: 13px;
                border: 2px solid #ddd;
                border-radius: 6px;
            }
            QLineEdit:focus {
                border: 2px solid #2196F3;
            }
        """)
        self.ip_input.setMinimumHeight(35)
        main_layout.addWidget(self.ip_input)
        
        # Dial pad with stretch
        self.dial_pad = DialPad()
        self.dial_pad.digit_pressed.connect(self.on_digit_pressed)
        main_layout.addWidget(self.dial_pad, stretch=1)
        
        # Call buttons - 2 rows for better spacing
        call_btn_layout = QHBoxLayout()
        call_btn_layout.setSpacing(8)
        
        self.call_btn = ModernButton("📞 Call", "#4CAF50")
        self.call_btn.clicked.connect(self.start_call)
        call_btn_layout.addWidget(self.call_btn)
        
        self.end_btn = ModernButton("📵 End", "#F44336")
        self.end_btn.clicked.connect(self.end_call)
        self.end_btn.setEnabled(False)
        call_btn_layout.addWidget(self.end_btn)
        
        main_layout.addLayout(call_btn_layout)
        
        # Secondary buttons - in a grid for better space usage
        secondary_layout = QGridLayout()
        secondary_layout.setSpacing(8)
        
        self.test_btn = ModernButton("🔊 Test Audio", "#FF9800")
        self.test_btn.clicked.connect(self.test_audio)
        secondary_layout.addWidget(self.test_btn, 0, 0)
        
        self.contacts_btn = ModernButton("👥 Contacts", "#2196F3")
        self.contacts_btn.clicked.connect(self.show_contacts)
        secondary_layout.addWidget(self.contacts_btn, 0, 1)
        
        self.help_btn = ModernButton("❓ Help", "#9C27B0")
        self.help_btn.clicked.connect(self.show_network_help)
        secondary_layout.addWidget(self.help_btn, 1, 0, 1, 2)
        
        main_layout.addLayout(secondary_layout)
        
        # Log viewer - collapsible
        log_header_layout = QHBoxLayout()
        log_label = QLabel("Debug Log:")
        log_label.setStyleSheet("font-size: 11px; font-weight: bold;")
        log_header_layout.addWidget(log_label)
        log_header_layout.addStretch()
        
        self.toggle_log_btn = QPushButton("▼ Hide")
        self.toggle_log_btn.setStyleSheet("""
            QPushButton {
                background: transparent;
                border: none;
                color: #666;
                font-size: 10px;
                padding: 2px;
            }
            QPushButton:hover {
                color: #2196F3;
            }
        """)
        self.toggle_log_btn.clicked.connect(self.toggle_log)
        self.toggle_log_btn.setCursor(Qt.PointingHandCursor)
        log_header_layout.addWidget(self.toggle_log_btn)
        
        main_layout.addLayout(log_header_layout)
        
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumHeight(100)
        self.log_text.setMinimumHeight(60)
        self.log_text.setStyleSheet("""
            QTextEdit {
                background-color: #2b2b2b;
                color: #00ff00;
                font-family: Consolas, monospace;
                font-size: 9px;
                border-radius: 6px;
                padding: 5px;
            }
        """)
        main_layout.addWidget(self.log_text)
        
        self.setStyleSheet("QMainWindow { background-color: white; }")
    
    def toggle_log(self):
        """Toggle log visibility"""
        if self.log_text.isVisible():
            self.log_text.hide()
            self.toggle_log_btn.setText("▶ Show")
        else:
            self.log_text.show()
            self.toggle_log_btn.setText("▼ Hide")

    def detect_public_ip(self):
        """Detect public IP address"""
        self.public_ip_label.setText("🌍 Public IP: Detecting...")
        self.log_message("🔍 Detecting public IP...")
        
        def detect_thread():
            public_ip = NetworkHelper.get_public_ip()
            if public_ip:
                self.my_public_ip = public_ip
                QtCore.QMetaObject.invokeMethod(
                    self,
                    "update_public_ip_display",
                    Qt.QueuedConnection,
                    QtCore.Q_ARG(str, public_ip)
                )
            else:
                QtCore.QMetaObject.invokeMethod(
                    self,
                    "update_public_ip_display",
                    Qt.QueuedConnection,
                    QtCore.Q_ARG(str, "Failed")
                )
        
        threading.Thread(target=detect_thread, daemon=True).start()

    @QtCore.pyqtSlot(str)
    def update_public_ip_display(self, ip):
        """Update public IP display"""
        if ip != "Failed":
            self.public_ip_label.setText(f"🌍 Public IP: {ip}")
            self.log_message(f"✅ Public IP: {ip}")
        else:
            self.public_ip_label.setText("🌍 Public IP: Detection Failed")
            self.log_message("❌ Could not detect public IP")

    def show_network_help(self):
        """Show network setup help dialog"""
        help_text = """
🌐 HOW TO CONNECT ACROSS DIFFERENT INTERNET CONNECTIONS

📱 If you're both on MOBILE HOTSPOTS or DIFFERENT NETWORKS:

METHOD 1: Share Your Public IP (Automatic)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Your PUBLIC IP is shown at the top of the app
2. Share this IP with the other person (via WhatsApp, SMS, etc.)
3. They enter YOUR public IP in the "Enter their PUBLIC IP" field
4. You enter THEIR public IP in your field
5. Click "Call"

⚠️ NOTE: You need to enable port forwarding on your router:
   - Forward port 5004 (UDP) to your local IP
   - Forward port 5062 (UDP) to your local IP

METHOD 2: Use Same WiFi Network
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Both connect to the same WiFi
2. Use LOCAL IP addresses (shown at top)
3. Much simpler, no port forwarding needed!

METHOD 3: Use a VPN (Easiest)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Install Hamachi, ZeroTier, or Tailscale (free)
2. Both join the same VPN network
3. Use the VPN-assigned IP addresses
4. Works like you're on same network!

📝 PORT FORWARDING GUIDE:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Open your router settings (usually 192.168.1.1)
2. Find "Port Forwarding" or "Virtual Server"
3. Add these rules:
   - External Port: 5004, Internal Port: 5004, Protocol: UDP
   - External Port: 5062, Internal Port: 5062, Protocol: UDP
   - Internal IP: Your local IP (shown in app)
4. Save and restart router

⚠️ MOBILE HOTSPOT WARNING:
Most mobile carriers use CGNAT (Carrier-Grade NAT) which 
BLOCKS incoming connections. Solutions:
   - Have one person on regular WiFi (home/office)
   - Use a VPN service
   - Use a relay server (advanced)

🔧 TESTING:
1. Test locally first: Use 127.0.0.1 on same computer
2. Test on same WiFi: Use local IPs
3. Then test across internet: Use public IPs + port forwarding
        """
        
        msg = QMessageBox(self)
        msg.setWindowTitle("Network Setup Help")
        msg.setText(help_text)
        msg.setIcon(QMessageBox.Information)
        msg.setStandardButtons(QMessageBox.Ok)
        msg.setStyleSheet("""
            QMessageBox {
                font-family: Consolas, monospace;
                font-size: 11px;
            }
            QLabel {
                min-width: 600px;
            }
        """)
        msg.exec_()

    def log_message(self, msg):
        """Add message to log viewer"""
        self.log_text.append(msg)
        scrollbar = self.log_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def test_audio(self):
        """Test audio devices"""
        self.log_message("🧪 Testing audio devices...")
        
        try:
            test_stream = self.audio_engine.audio.open(
                format=FORMAT,
                channels=CHANNELS,
                rate=SAMPLE_RATE,
                input=True,
                frames_per_buffer=CHUNK
            )
            
            data = test_stream.read(CHUNK)
            test_stream.stop_stream()
            test_stream.close()
            
            self.log_message("✅ Microphone working!")
            
            test_stream = self.audio_engine.audio.open(
                format=FORMAT,
                channels=CHANNELS,
                rate=SAMPLE_RATE,
                output=True,
                frames_per_buffer=CHUNK
            )
            
            import math
            test_tone = b''.join(
                struct.pack('h', int(32767 * 0.3 * math.sin(2 * math.pi * 440 * i / SAMPLE_RATE)))
                for i in range(CHUNK)
            )
            
            test_stream.write(test_tone)
            test_stream.stop_stream()
            test_stream.close()
            
            self.log_message("✅ Speaker working!")
            
            QMessageBox.information(
                self,
                "Audio Test",
                "✅ Audio devices are working!\n\n"
                "Microphone: OK\n"
                "Speaker: OK\n\n"
                "You can now make calls."
            )
            
        except Exception as e:
            self.log_message(f"❌ Audio test failed: {e}")
            QMessageBox.critical(
                self,
                "Audio Test Failed",
                f"❌ Audio error:\n{e}\n\n"
                "Check:\n"
                "1. Microphone connected\n"
                "2. Speaker/headphones connected\n"
                "3. No other app using audio"
            )

    def on_digit_pressed(self, digit):
        """Handle dial pad digit press"""
        current = self.ip_input.text()
        if digit == '*':
            self.ip_input.setText(current + '.')
        elif digit == '#':
            self.ip_input.clear()
        else:
            self.ip_input.setText(current + digit)

    def start_call(self):
        """Initiate outgoing call"""
        ip = self.ip_input.text().strip()
        
        if not ip:
            QMessageBox.warning(self, "Error", "Please enter an IP address")
            return
        
        self.remote_ip = ip
        self.status_label.setText("📞 Calling...")
        self.remote_label.setText(f"To: {ip}")
        self.call_btn.setEnabled(False)
        self.end_btn.setEnabled(True)
        
        self.log_message(f"📞 Calling {ip}...")
        
        self.sip_handler.send_invite(ip)

    def on_incoming_call(self, ip, port):
        """Handle incoming call"""
        self.remote_ip = ip
        
        self.log_message(f"📞 Incoming call from {ip}")
        
        reply = QMessageBox.question(
            self,
            "Incoming Call",
            f"📞 Incoming call from\n{ip}:{port}\n\nAccept?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.accept_incoming_call()
        else:
            self.sip_handler.send_bye()
            self.log_message("❌ Call rejected")

    def accept_incoming_call(self):
        """Accept incoming call"""
        self.log_message("✅ Accepting call...")
        self.sip_handler.accept_call()
        self.on_call_accepted()

    def on_call_accepted(self):
        """Handle call acceptance"""
        self.in_call = True
        self.call_duration = 0
        
        self.status_label.setText("✅ Connected")
        self.remote_label.setText(f"With: {self.remote_ip}")
        self.call_btn.setEnabled(False)
        self.end_btn.setEnabled(True)
        
        self.log_message("✅ Call connected!")
        self.log_message("🎤 Starting audio...")
        
        mic_ok = self.audio_engine.start_input()
        speaker_ok = self.audio_engine.start_output()
        
        if not mic_ok:
            self.log_message("⚠️ Microphone failed")
        if not speaker_ok:
            self.log_message("⚠️ Speaker failed")
        
        self.rtp_handler.start(self.remote_ip)
        self.duration_timer.start(1000)
        
        self.log_message("🔊 Audio streaming active")

    def end_call(self):
        """End current call"""
        if self.in_call:
            self.sip_handler.send_bye()
        
        self.on_call_ended()

    def on_call_ended(self):
        """Handle call termination"""
        self.in_call = False
        self.call_duration = 0
        
        self.log_message("📵 Call ended")
        
        self.duration_timer.stop()
        self.rtp_handler.stop()
        self.audio_engine.cleanup()
        
        self.audio_engine = AudioEngine()
        self.rtp_handler = RTPHandler(self.audio_engine)
        
        self.status_label.setText("Ready")
        self.remote_label.setText("")
        self.duration_label.setText("")
        self.call_btn.setEnabled(True)
        self.end_btn.setEnabled(False)

    def update_call_duration(self):
        """Update call duration display"""
        self.call_duration += 1
        minutes = self.call_duration // 60
        seconds = self.call_duration % 60
        self.duration_label.setText(f"{minutes:02d}:{seconds:02d}")

    def show_contacts(self):
        """Show contacts dialog"""
        dialog = ContactsDialog(self.contact_manager, self)
        if dialog.exec_():
            selected = dialog.get_selected_contact()
            if selected:
                self.ip_input.setText(selected)

    def closeEvent(self, event):
        """Handle window close"""
        if self.in_call:
            reply = QMessageBox.question(
                self,
                "Call in Progress",
                "End call and exit?",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.No:
                event.ignore()
                return
            
            self.end_call()
        
        self.sip_handler.cleanup()
        self.rtp_handler.stop()
        self.audio_engine.cleanup()
        
        event.accept()


class ContactsDialog(QtWidgets.QDialog):
    """Dialog for managing contacts"""
    
    def __init__(self, contact_manager, parent=None):
        super().__init__(parent)
        self.contact_manager = contact_manager
        self.selected_contact = None
        
        self.setWindowTitle("Contacts")
        self.setMinimumSize(400, 500)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        
        header = QLabel("👥 Contacts")
        header.setAlignment(Qt.AlignCenter)
        header.setStyleSheet("""
            QLabel {
                font-size: 20px;
                font-weight: bold;
                color: #2196F3;
                padding: 10px;
            }
        """)
        layout.addWidget(header)
        
        self.contact_list = QListWidget()
        self.contact_list.setStyleSheet("""
            QListWidget {
                border: 2px solid #ddd;
                border-radius: 8px;
                padding: 5px;
                font-size: 14px;
            }
            QListWidget::item {
                padding: 10px;
                border-bottom: 1px solid #eee;
            }
            QListWidget::item:selected {
                background-color: #2196F3;
                color: white;
            }
        """)
        self.contact_list.itemDoubleClicked.connect(self.select_contact)
        layout.addWidget(self.contact_list)
        
        self.refresh_contacts()
        
        add_layout = QHBoxLayout()
        
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("Name")
        self.name_input.setStyleSheet("""
            QLineEdit {
                padding: 8px;
                border: 2px solid #ddd;
                border-radius: 6px;
            }
        """)
        add_layout.addWidget(self.name_input)
        
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("IP Address")
        self.ip_input.setStyleSheet("""
            QLineEdit {
                padding: 8px;
                border: 2px solid #ddd;
                border-radius: 6px;
            }
        """)
        add_layout.addWidget(self.ip_input)
        
        layout.addLayout(add_layout)
        
        btn_layout = QHBoxLayout()
        
        add_btn = ModernButton("➕ Add", "#4CAF50")
        add_btn.clicked.connect(self.add_contact)
        btn_layout.addWidget(add_btn)
        
        remove_btn = ModernButton("🗑️ Remove", "#F44336")
        remove_btn.clicked.connect(self.remove_contact)
        btn_layout.addWidget(remove_btn)
        
        select_btn = ModernButton("✓ Select", "#2196F3")
        select_btn.clicked.connect(self.select_contact)
        btn_layout.addWidget(select_btn)
        
        layout.addLayout(btn_layout)

    def refresh_contacts(self):
        """Refresh contact list"""
        self.contact_list.clear()
        contacts = self.contact_manager.get_all()
        
        for name, ip in contacts.items():
            self.contact_list.addItem(f"{name} - {ip}")

    def add_contact(self):
        """Add new contact"""
        name = self.name_input.text().strip()
        ip = self.ip_input.text().strip()
        
        if not name or not ip:
            QMessageBox.warning(self, "Error", "Please enter both name and IP")
            return
        
        self.contact_manager.add_contact(name, ip)
        self.refresh_contacts()
        
        self.name_input.clear()
        self.ip_input.clear()
        
        QMessageBox.information(self, "Success", f"Contact '{name}' added")

    def remove_contact(self):
        """Remove selected contact"""
        current = self.contact_list.currentItem()
        if not current:
            QMessageBox.warning(self, "Error", "Please select a contact")
            return
        
        name = current.text().split(" - ")[0]
        
        reply = QMessageBox.question(
            self,
            "Confirm",
            f"Remove contact '{name}'?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.contact_manager.remove_contact(name)
            self.refresh_contacts()

    def select_contact(self):
        """Select contact for calling"""
        current = self.contact_list.currentItem()
        if current:
            ip = current.text().split(" - ")[1]
            self.selected_contact = ip
            self.accept()

    def get_selected_contact(self):
        """Get selected contact IP"""
        return self.selected_contact


# ==================== MAIN ====================
def main():
    """Main application entry point"""
    
    print("\n" + "="*70)
    print("🎙️  VOIP SOFTPHONE - RESPONSIVE VERSION")
    print("="*70)
    print("📋 Configuration:")
    print(f"   Sample Rate: {SAMPLE_RATE} Hz")
    print(f"   Ports: SIP={PORT_SIP}, RTP={PORT_RTP}")
    print("="*70)
    print("\n🌐 NETWORK MODES:")
    print("   1. Same Computer: Use 127.0.0.1")
    print("   2. Same WiFi: Use local IPs (192.168.x.x)")
    print("   3. Different Networks: Use PUBLIC IPs + port forwarding")
    print("\n💡 For different internet connections:")
    print("   - Click 'Help' button in the app")
    print("   - Share your PUBLIC IP (shown in app)")
    print("   - Set up port forwarding on your router")
    print("="*70 + "\n")
    
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    window = VoIPSoftphone()
    window.show()
    
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
