import select
import socket
import struct
import time
from constants import ScanResult


class UDPRawScanner:
    def __init__(self, timeout=2.0, verbose=False):
        self._timeout = timeout
        self._verbose = verbose
        self._udp_socket = None  # Для отправки UDP
        self._icmp_socket = None  # Для приема ICMP ответов
        self.init_sockets()

    def init_sockets(self):
        try:
            self._icmp_socket = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP
            )
            self._icmp_socket.settimeout(0.1)

            self._udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._udp_socket.settimeout(0.1)

        except PermissionError:
            print("ERROR: Need root privileges for UDP scan! Use sudo.")

    @staticmethod
    def create_udp_payload(port: int) -> bytes:
        if port == 53:  # DNS
            return b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01"
        else:
            return b"SCAN_UDP"

    def send_udp_packet(self, target_ip: str, port: int) -> float:
        payload = self.create_udp_payload(port)
        send_time = time.time()

        try:
            self._udp_socket.sendto(payload, (target_ip, port))
        except Exception as e:
            if self._verbose:
                print(f"UDP send error to {port}: {e}")

        return send_time

    @staticmethod
    def parse_icmp_response(packet: bytes, target_ip: str, port: int) -> bool:
        if len(packet) < 28:
            return False

        try:
            ip_header = packet[:20]
            iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
            protocol = iph[6]
            source_ip = socket.inet_ntoa(iph[8])

            if protocol != socket.IPPROTO_ICMP or source_ip != target_ip:
                return False

            icmp_header = packet[20:28]
            icmph = struct.unpack("!BBHHH", icmp_header)
            icmp_type, icmp_code = icmph[0], icmph[1]

            # ICMP Port Unreachable
            if icmp_type == 3 and icmp_code == 3:
                if len(packet) >= 56:
                    original_udp = packet[48:56]
                    original_udph = struct.unpack("!HHHH", original_udp)
                    original_port = original_udph[1]

                    if original_port == port:
                        return True
        except:
            pass

        return False

    def check_udp_response(self) -> bool:
        try:
            ready, _, _ = select.select([self._udp_socket], [], [], 0.1)
            if ready:
                data, addr = self._udp_socket.recvfrom(1024)
                return bool(data)
        except:
            pass
        return False

    def scan_port(self, target_ip: str, port: int) -> ScanResult:
        if not self._icmp_socket:
            return ScanResult(protocol="UDP", port=port, is_open=False, response_time=0)

        send_time = self.send_udp_packet(target_ip, port)
        start_time = time.time()

        while time.time() - start_time < self._timeout:
            try:
                # Check ICMP responses
                ready, _, _ = select.select([self._icmp_socket], [], [], 0.1)
                if ready:
                    packet, addr = self._icmp_socket.recvfrom(1024)
                    if self.parse_icmp_response(packet, target_ip, port):
                        response_time = (time.time() - send_time) * 1000
                        return ScanResult(
                            protocol="UDP",
                            port=port,
                            is_open=False,
                            response_time=response_time,
                        )

                # Check UDP responses
                if self.check_udp_response():
                    response_time = (time.time() - send_time) * 1000
                    return ScanResult(
                        protocol="UDP",
                        port=port,
                        is_open=True,
                        response_time=response_time,
                    )

            except:
                continue

        return ScanResult(protocol="UDP", port=port, is_open=True, response_time=0)

    def scan_ports(self, target_ip: str, ports: list[int]) -> list[ScanResult]:
        return [self.scan_port(target_ip, port) for port in ports]

    def close(self):
        if self._udp_socket:
            self._udp_socket.close()
        if self._icmp_socket:
            self._icmp_socket.close()
