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
            print("✓ TCP Raw socket created successfully")  # DEBUG
        except PermissionError:
            print("ERROR: Need root privileges for TCP SYN scan! Use sudo.")
            self._socket = None
        except Exception as e:
            print(f"ERROR creating TCP socket: {e}")
            self._socket = None

    @staticmethod
    def create_syn_packet(dest_port: int) -> bytes:
        source_port = random.randint(1024, 65535)
        seq_num = random.randint(0, 4294967295)

        # Упрощенный TCP header без checksum (система может сама его посчитать)
        tcp_header = struct.pack(
            "!HHLLBBHHH",
            source_port,  # source port
            dest_port,  # dest port
            seq_num,  # sequence number
            0,  # ack number
            5 << 4,  # data offset
            0x02,  # SYN flag
            8192,  # window size
            0,  # checksum = 0 (система посчитает)
            0,  # urgent pointer
        )

        return tcp_header

    @staticmethod
    def parse_response(packet: bytes) -> tuple[int, bool]:
        print(f"DEBUG: Response length: {len(packet)} bytes")

        try:
            # Если пакет содержит IP заголовок (обычно 20+ байт)
            if len(packet) >= 40:
                # Пропускаем IP заголовок (20 байт) и берем TCP заголовок
                tcp_header = packet[20:40]
            else:
                # Предполагаем что это только TCP заголовок
                tcp_header = packet

            if len(tcp_header) < 20:
                return 0, False

            # Распарсим TCP заголовок
            # Формат: src_port(2), dest_port(2), seq(4), ack(4), data_offset_reserved_flags(2), window(2), checksum(2), urg_ptr(2)
            src_port, dest_port, seq, ack, offset_flags, window, checksum, urg_ptr = (
                struct.unpack("!HHLLHHHH", tcp_header)
            )

            # Извлекаем флаги (младшие 6 бит из offset_flags)
            flags = offset_flags & 0x3F

            print(
                f"DEBUG: Ports: src={src_port}, dest={dest_port}, flags=0x{flags:02x}"
            )

            if flags == 0x12:  # SYN-ACK (SYN=1, ACK=1)
                print(f"DEBUG: SYN-ACK received for port {dest_port}")
                return dest_port, True
            elif flags == 0x14:  # RST-ACK (RST=1, ACK=1)
                print(f"DEBUG: RST received for port {dest_port}")
                return dest_port, False

        except Exception as e:
            print(f"DEBUG: Parse error: {e}")

        return 0, False

    def scan_port(self, target_ip: str, port: int) -> ScanResult:
        if not self._socket:
            return ScanResult(protocol="tcp", port=port, is_open=False, response_time=0)

        try:
            # Отправляем SYN
            packet = TCPRawScanner.create_syn_packet(port)
            send_time = time.time()
            self._socket.sendto(packet, (target_ip, port))

            start_time = time.time()
            while time.time() - start_time < self._timeout:
                try:
                    ready, _, _ = select.select([self._socket], [], [], 0.1)
                    if not ready:
                        continue
                    response, address = self._socket.recvfrom(1024)
                    response_port, is_response_port_open = TCPRawScanner.parse_response(
                        response
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
