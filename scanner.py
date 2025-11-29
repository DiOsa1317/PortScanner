from constants import ScanResult
from tcp_scanner import TCPRawScanner
from udp_scanner import UDPRawScanner
from protocol_detector import ProtocolDetector
from console_query_classes import Port
from concurrent.futures import ThreadPoolExecutor


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

        if self.num_threads > 1:
            # Многопоточное сканирование
            with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
                futures = []
                for port_spec in ports:
                    future = executor.submit(
                        self._scan_single_port, target_ip, port_spec
                    )
                    futures.append(future)

                for future in futures:
                    all_results.append(future.result())
        else:
            # Однопоточное сканирование
            for port_spec in ports:
                result = self._scan_single_port(target_ip, port_spec)
                all_results.append(result)

        if self.guess:
            self._detect_protocols(target_ip, all_results)

        return all_results

    def _scan_single_port(self, target_ip: str, port_spec: Port) -> ScanResult:
        protocol = "UDP" if port_spec.is_udp_protocol else "TCP"

        if self.verbose:
            print(f"Scanning {protocol} port {port_spec.start_port_address}...")

        # Сканируем один порт
        if port_spec.is_udp_protocol:
            result = self.udp_scanner.scan_port(target_ip, port_spec.start_port_address)
        else:
            result = self.tcp_scanner.scan_port(target_ip, port_spec.start_port_address)

        return result

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
