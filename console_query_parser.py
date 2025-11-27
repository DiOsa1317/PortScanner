from console_query_classes import ConsoleQuery, Options, Port

class ConsoleQueryParser:

    @staticmethod
    def convert_args_to_console_query(arguments):
        # Проверяем что первый аргумент это "portscan"
        if len(arguments) < 1:
            raise ValueError("Usage: portscan [OPTIONS] IP_ADDRESS [PORT_SPECS...]")

        # Если первый аргумент не "portscan", все равно пытаемся парсить
        # (на случай если файл переименовали)
        arg_len = len(arguments)
        timeout = 2.0
        threads_number = 1
        verbose = False
        guess = False
        arg_index = 0  # Начинаем с 0

        positional_args = []

        while arg_index < arg_len:
            arg = arguments[arg_index]
            if arg == "--timeout":
                try:
                    timeout = float(arguments[arg_index + 1])
                    arg_index += 2
                except (IndexError, ValueError):
                    raise ValueError("Timeout value is required and must be a number")
                continue
            if arg in ["-j", "--num-threads"]:
                try:
                    threads_number = int(arguments[arg_index + 1])
                    arg_index += 2
                except (IndexError, ValueError):
                    raise ValueError("Threads number is required and must be an integer")
                continue
            if arg in ["-v", "--verbose"]:
                verbose = True
                arg_index += 1
                continue
            if arg in ["-g", "--guess"]:
                guess = True
                arg_index += 1
                continue

            # Все что не опция - позиционные аргументы
            positional_args.append(arguments[arg_index])
            arg_index += 1

        if not positional_args:
            raise ValueError("IP address is required")

        ip_address, ports = ConsoleQueryParser.parse_positional_args(positional_args)

        return ConsoleQuery(
            options=Options(
                timeout=timeout,
                num_threads=threads_number,
                guess=guess,
                verbose=verbose
            ),
            ip_address=ip_address,
            ports=ports
        )

    @staticmethod
    def parse_positional_args(positional_args):
        ip_address = positional_args[0]
        ports = []

        for arg in positional_args[1:]:  # Пропускаем IP адрес
            ports.extend(ConsoleQueryParser.parse_port(arg))

        return ip_address, ports

    @staticmethod
    def parse_port(not_parsed_port: str):
        parts = not_parsed_port.split("/")
        if len(parts) != 2:
            raise ValueError("Port should be written as tcp/ports or udp/ports")

        protocol = parts[0]
        if protocol not in ["tcp", "udp"]:
            raise ValueError("Protocol should be 'tcp' or 'udp'")

        is_udp = (protocol == "udp")
        ports_spec = parts[1]
        ports = []

        # Если ports_spec пустой - сканируем все порты (1-65535)
        if not ports_spec:
            # Для производительности ограничим диапазон
            if is_udp:
                # Для UDP обычно сканируют только основные порты
                common_udp_ports = [53, 67, 68, 69, 123, 161, 162, 500, 514, 520, 1900, 4500]
                for port in common_udp_ports:
                    ports.append(Port(
                        is_udp_protocol=is_udp,
                        start_port_address=port,
                        end_port_address=port
                    ))
            else:
                # Для TCP ограничим 1-1024 портами
                ports.append(Port(
                    is_udp_protocol=is_udp,
                    start_port_address=1,
                    end_port_address=1024
                ))
            return ports

        # Обработка списка портов: 80,443,1000-2000
        for part in ports_spec.split(","):
            if "-" in part:
                # Диапазон портов: 1000-2000
                addresses = part.split("-")
                if len(addresses) != 2:
                    raise ValueError("Invalid port range format. Use 'start-end'")

                try:
                    start_point = int(addresses[0])
                    end_point = int(addresses[1])
                except ValueError:
                    raise ValueError("Port numbers must be integers")

                ConsoleQueryParser.validate_port(start_point, end_point)

                # Создаем отдельный Port для каждого порта в диапазоне
                for port in range(start_point, end_point + 1):
                    ports.append(Port(
                        is_udp_protocol=is_udp,
                        start_port_address=port,
                        end_port_address=port
                    ))
            else:
                # Одиночный порт: 80
                try:
                    port_num = int(part)
                except ValueError:
                    raise ValueError(f"Port must be a number: {part}")

                ConsoleQueryParser.validate_port(port_num, port_num)
                ports.append(Port(
                    is_udp_protocol=is_udp,
                    start_port_address=port_num,
                    end_port_address=port_num
                ))

        return ports

    @staticmethod
    def validate_port(start_point, end_point):
        if start_point < 1 or end_point > 65535:
            raise ValueError("Ports should be between 1 and 65535")
        if start_point > end_point:
            raise ValueError("Start port cannot be greater than end port")