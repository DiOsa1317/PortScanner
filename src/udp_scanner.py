from scapy.all import IP, UDP, TCP, Raw, sr1, ICMP  # type: ignore
import time
from src.scan_result import ScanResult


class UDPScapyScanner:
    def __init__(self, timeout: float = 2.0, verbose: bool = False):
        self._timeout = timeout
        self._verbose = verbose

    def create_udp_payload(self, port: int) -> bytes:
        if port == 53:  # DNS
            return b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01"
        else:
            return b"SCAN_UDP"

    def scan_port(self, target_ip: str, port: int) -> ScanResult:

        start_time = time.time()

        try:
            # Отправляем UDP пакет
            payload = self.create_udp_payload(port)
            udp_packet = IP(dst=target_ip) / UDP(dport=port) / Raw(load=payload)
            response = sr1(udp_packet, timeout=self._timeout, verbose=0)

            response_time = (time.time() - start_time) * 1000

            if response is None:
                # Нет ответа - порт может быть открыт
                return ScanResult(
                    protocol="UDP",
                    port=port,
                    is_open=True,  # UDP без ответа = открыт/фильтруется
                    response_time=0,
                )

            if response.haslayer(ICMP):
                icmp_layer = response[ICMP]
                # ICMP Port Unreachable
                if icmp_layer.type == 3 and icmp_layer.code == 3:
                    return ScanResult(
                        protocol="UDP",
                        port=port,
                        is_open=False,
                        response_time=response_time,
                    )

            if response.haslayer(UDP):
                # Получили UDP ответ - порт открыт
                return ScanResult(
                    protocol="UDP", port=port, is_open=True, response_time=response_time
                )

        except Exception as e:
            pass

        return ScanResult(
            protocol="UDP",
            port=port,
            is_open=True,  # По умолчанию считаем открытым
            response_time=0,
        )
