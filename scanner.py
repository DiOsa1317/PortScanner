from constants import ScanResult
from tcp_scanner import TCPScapyScanner
from udp_scanner import UDPScapyScanner
from protocol_detector import ProtocolDetector
from console_query_classes import Port
from concurrent.futures import ThreadPoolExecutor, as_completed


class PortScanner:
    def __init__(self, timeout=2.0, verbose=False, guess=False, num_threads=1):
        self.timeout = timeout
        self.verbose = verbose
        self.guess = guess
        self.num_threads = num_threads

        # Используем scapy сканеры
        self.tcp_scanner = TCPScapyScanner(timeout, verbose)
        self.udp_scanner = UDPScapyScanner(timeout, verbose)
        self.protocol_detector = ProtocolDetector(timeout)

    def scan(self, target_ip: str, ports: list[Port]) -> list[ScanResult]:

        if self.num_threads > 1:
            all_results = self._scan_multithreaded(target_ip, ports)
        else:
            all_results = self._scan_singlethreaded(target_ip, ports)

        if self.guess:
            self._detect_protocols(target_ip, all_results)

        return all_results

    def _scan_singlethreaded(
        self, target_ip: str, ports: list[Port]
    ) -> list[ScanResult]:
        """Однопоточное сканирование"""
        results = []

        for i, port_spec in enumerate(ports):

            result = self._scan_single_port(target_ip, port_spec)
            results.append(result)

        return results

    def _scan_multithreaded(
        self, target_ip: str, ports: list[Port]
    ) -> list[ScanResult]:
        """Многопоточное сканирование"""
        results = []

        with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            # Создаем future для каждого порта
            future_to_port = {
                executor.submit(self._scan_single_port, target_ip, port_spec): port_spec
                for port_spec in ports
            }

            # Собираем результаты по мере завершения
            completed = 0

            for future in as_completed(future_to_port):
                try:
                    result = future.result()
                    results.append(result)
                    completed += 1

                except Exception as e:
                    port_spec = future_to_port[future]
                    # Добавляем результат с ошибкой
                    results.append(
                        ScanResult(
                            protocol="TCP" if not port_spec.is_udp_protocol else "UDP",
                            port=port_spec.start_port_address,
                            is_open=False,
                            response_time=0,
                        )
                    )

        return results

    def _scan_single_port(self, target_ip: str, port_spec: Port) -> ScanResult:
        """Сканирование одного порта"""
        port = port_spec.start_port_address

        if port_spec.is_udp_protocol:
            result = self.udp_scanner.scan_port(target_ip, port)
        else:
            result = self.tcp_scanner.scan_port(target_ip, port)

        return result

    def _detect_protocols(self, target_ip: str, results: list[ScanResult]):
        """Определение протоколов прикладного уровня"""

        open_ports = [r for r in results if r.is_open]

        for i, result in enumerate(open_ports):

            result.app_protocol = self.protocol_detector.detect(
                target_ip, result.port, result.protocol
            )

    def print_results(self, results: list[ScanResult]):
        """Вывод результатов в требуемом формате"""
        open_ports = [r for r in results if r.is_open]

        # Сортируем результаты: сначала TCP, потом UDP, по номеру порта
        open_ports.sort(key=lambda x: (x.protocol != "TCP", x.port))

        # Выводим открытые порты
        for result in open_ports:
            output = f"{result.protocol} {result.port}"

            # Добавляем время ответа если verbose режим и есть время
            if self.verbose and result.response_time > 0:
                output += f" {result.response_time:.1f}ms"

            # Добавляем протокол если guess режим
            if self.guess:
                output += f" {result.app_protocol}"

            print(output)

        if not open_ports:
            if self.verbose:
                print("No open ports found")
            else:
                # В не-verbose режиме ничего не выводим если нет открытых портов
                pass

    @staticmethod
    def get_scan_summary(results: list[ScanResult]) -> dict:
        """Возвращает статистику сканирования"""
        open_ports = [r for r in results if r.is_open]
        closed_ports = len(results) - len(open_ports)

        tcp_open = [r for r in open_ports if r.protocol == "TCP"]
        udp_open = [r for r in open_ports if r.protocol == "UDP"]

        return {
            "total_scanned": len(results),
            "open_ports": len(open_ports),
            "closed_ports": closed_ports,
            "tcp_open": len(tcp_open),
            "udp_open": len(udp_open),
            "open_ports_list": open_ports,
        }

    def close(self):
        """Закрытие ресурсов"""
        self.tcp_scanner.close()
        self.udp_scanner.close()
