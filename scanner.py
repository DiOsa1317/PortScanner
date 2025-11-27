from constants import ScanResult
from tcp_scanner import TCPRawScanner
from udp_scanner import UDPRawScanner
from protocol_detector import ProtocolDetector
from console_query_classes import Port


class PortScanner:
    def __init__(self, timeout=2.0, verbose=False, guess=False, num_threads=1):
        self.timeout = timeout
        self.verbose = verbose
        self.guess = guess
        self.num_threads = num_threads

        self.tcp_scanner = TCPRawScanner(timeout, verbose)
        self.udp_scanner = UDPRawScanner(timeout, verbose)
        self.protocol_detector = ProtocolDetector(timeout)

        if verbose:
            print(f"Scanner initialized: timeout={timeout}s, threads={num_threads}")

    def scan(self, target_ip: str, ports: list[Port]) -> list[ScanResult]:
        all_results = []

        for port_spec in ports:
            protocol = "UDP" if port_spec.is_udp_protocol else "TCP"

            if self.verbose:
                print(f"Scanning {protocol} port {port_spec.start_port_address}...")

            # Сканируем один порт (start_port_address == end_port_address после парсинга)
            if port_spec.is_udp_protocol:
                result = self.udp_scanner.scan_port(
                    target_ip, port_spec.start_port_address
                )
            else:
                result = self.tcp_scanner.scan_port(
                    target_ip, port_spec.start_port_address
                )

            all_results.append(result)

        if self.guess:
            self._detect_protocols(target_ip, all_results)

        return all_results

    def _detect_protocols(self, target_ip: str, results: list[ScanResult]):
        for result in results:
            if result.is_open:
                result.app_protocol = self.protocol_detector.detect(
                    target_ip, result.port, result.protocol
                )

    def print_results(self, results: list[ScanResult]):
        for result in results:
            if not result.is_open:
                continue  # Выводим только открытые порты

            output = f"{result.protocol} {result.port}"

            if self.verbose and result.response_time > 0:
                output += f" {result.response_time:.1f}ms"

            if self.guess:
                output += f" {result.app_protocol}"

            print(output)

    def close(self):
        self.tcp_scanner.close()
        self.udp_scanner.close()
