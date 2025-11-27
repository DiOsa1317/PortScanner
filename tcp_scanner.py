import random
import select
import socket
import struct
import time

from constants import ScanResult


class TCPRawScanner:
    def __init__(self, timeout: float = 2.0, verbose: bool = False):
        self._timeout = timeout
        self._verbose = verbose
        self._socket = None
        self.init_socket()

    def init_socket(self):
        try:
            self._socket = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP
            )
            self._socket.settimeout(0.1)
        except PermissionError:
            print("ERROR: Need root privileges for TCP SYN scan! Use sudo.")
            self._socket = None

    @staticmethod
    def create_syn_packet(dest_ip: str, dest_port: int) -> bytes:
        source_port = random.randint(1024, 65535)

        tcp_header = struct.pack(
            "!HHLLBBHHH",
            source_port,
            dest_port,
            random.randint(0, 4294967295),  # seq_num
            0,  # ack_num
            0x50,  # offset=5
            0x02,  # SYN flag
            5840,  # window
            0,  # checksum
            0,  # urg_ptr
        )

        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            20 + len(tcp_header),  # version_ihl, tos, total_len
            random.randint(1, 65535),
            0x4000,  # id, flags
            64,
            socket.IPPROTO_TCP,
            0,  # ttl, protocol, checksum
            socket.inet_aton("0.0.0.0"),  # source ip
            socket.inet_aton(dest_ip),
        )

        return ip_header + tcp_header

    @staticmethod
    def parse_response(packet: bytes, target_ip: str) -> tuple[int, bool]:
        if len(packet) < 40:
            return 0, False
        try:
            ip_header = packet[0:20]
            iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
            protocol = iph[6]
            source_ip = socket.inet_ntoa(iph[8])

            if protocol != socket.IPPROTO_TCP or source_ip != target_ip:
                return 0, False

            tcp_header = packet[20:40]
            tcph = struct.unpack("!HHLLBBHHH", tcp_header)
            source_port, flags = tcph[0], tcph[5]

            if flags == 0x12:  # SYN-ACK
                return source_port, True
            elif flags == 0x14:  # RST
                return source_port, False
        except:
            pass

        return 0, False

    def scan_port(self, target_ip: str, port: int) -> ScanResult:
        if not self._socket:
            return ScanResult(protocol="tcp", port=port, is_open=False, response_time=0)

        try:
            # Отправляем SYN
            packet = TCPRawScanner.create_syn_packet(target_ip, port)
            send_time = time.time()
            self._socket.sendto(packet, (target_ip, 0))

            start_time = time.time()
            while time.time() - start_time < self._timeout:
                try:
                    ready, _, _ = select.select([self._socket], [], [], 0.1)
                    if not ready:
                        continue
                    response, address = self._socket.recvfrom(1024)
                    response_port, is_response_port_open = TCPRawScanner.parse_response(
                        response, target_ip
                    )
                    if response_port != port:
                        continue
                    response_time = (time.time() - send_time) * 10000
                    return ScanResult(
                        protocol="tcp",
                        port=port,
                        is_open=is_response_port_open,
                        response_time=response_time,
                    )
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"TCP: Receive error on {port} : {e}")
                    continue

                    # Таймаут - порт закрыт или фильтруется
            return ScanResult(protocol="tcp", port=port, is_open=False, response_time=0)

        except Exception as e:
            print(f"TCP: Send error on port {port}: {e}")
            return ScanResult(protocol="tcp", port=port, is_open=False, response_time=0)

    def scan_ports(self, target_ip: str, ports: list[int]) -> list[ScanResult]:
        return [self.scan_port(target_ip, port) for port in ports]

    def close(self):
        if self._socket:
            self._socket.close()
            self._socket = None
