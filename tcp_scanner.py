from scapy.all import IP, TCP, UDP, ICMP, send, sr1  # type: ignore
import time
from scan_result import ScanResult


class TCPScapyScanner:
    def __init__(self, timeout: float = 2.0, verbose: bool = False):
        self._timeout = timeout
        self._verbose = verbose
        # Не нужны raw sockets - scapy сам все обработает

    def scan_port(self, target_ip: str, port: int) -> ScanResult:

        start_time = time.time()

        try:
            # Создаем и отправляем SYN пакет
            syn_packet = IP(dst=target_ip) / TCP(dport=port, flags="S")
            response = sr1(syn_packet, timeout=self._timeout, verbose=0)

            response_time = (time.time() - start_time) * 1000

            if response is None:
                # Таймаут - порт фильтруется или нет ответа
                return ScanResult(
                    protocol="TCP", port=port, is_open=False, response_time=0
                )

            if response.haslayer(TCP):
                tcp_layer = response[TCP]

                if tcp_layer.flags == 0x12:  # SYN-ACK
                    # Отправляем RST чтобы закрыть соединение
                    rst_packet = IP(dst=target_ip) / TCP(dport=port, flags="R")
                    send(rst_packet, verbose=0)

                    return ScanResult(
                        protocol="TCP",
                        port=port,
                        is_open=True,
                        response_time=response_time,
                    )

                elif tcp_layer.flags == 0x14:  # RST
                    return ScanResult(
                        protocol="TCP",
                        port=port,
                        is_open=False,
                        response_time=response_time,
                    )

        except Exception as e:
            pass

        return ScanResult(protocol="TCP", port=port, is_open=False, response_time=0)

    def scan_ports(self, target_ip: str, ports: list[int]) -> list[ScanResult]:
        return [self.scan_port(target_ip, port) for port in ports]

