from console_query_classes import ConsoleQuery, Options, Port


class ConsoleQueryParser:

    @staticmethod
    def convert_args_to_console_query(arguments):
        print(f"DEBUG: All arguments: {arguments}")  # ДОБАВИТЬ ЭТУ СТРОКУ

        if len(arguments) < 3:
            raise ValueError("Usage: portscan [OPTIONS] IP_ADDRESS [PORT_SPECS...]")

        arg_len = len(arguments)
        timeout = 2.0
        threads_number = 1
        verbose = False
        guess = False
        if "portscan" not in arguments[0]:
            raise ValueError("Usage: portscan [OPTIONS] IP_ADDRESS [PORT_SPECS...]")
        arg_index = 1

        positional_args = []

        while arg_index < arg_len:
            arg = arguments[arg_index]
            print(f"DEBUG: Processing argument {arg_index}: '{arg}'")  # ДОБАВИТЬ

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
                    raise ValueError(
                        "Threads number is required and must be an integer"
                    )
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

        print(f"DEBUG: Positional args: {positional_args}")  # ДОБАВИТЬ

        if not positional_args:
            raise ValueError("IP address is required")

        ip_address, ports = ConsoleQueryParser.parse_positional_args(positional_args)
        return ConsoleQuery(
            options=Options(
                timeout=timeout,
                num_threads=threads_number,
                guess=guess,
                verbose=verbose,
            ),
            ip_address=ip_address,
            ports=ports,
        )

    @staticmethod
    def parse_positional_args(positional_args):
        print(f"DEBUG: Parsing positional: {positional_args}")  # ДОБАВИТЬ

        ip_address = positional_args[0]
        ports = []

        for arg in positional_args[1:]:
            print(f"DEBUG: Parsing port spec: '{arg}'")  # ДОБАВИТЬ
            ports.extend(ConsoleQueryParser.parse_port(arg))

        return ip_address, ports

    @staticmethod
    def parse_port(not_parsed_port: str):
        parts = not_parsed_port.split("/")
        if len(parts) != 2:
            raise ValueError(
                f"Port should be written as tcp/ports or udp/ports: {not_parsed_port}"
            )

        protocol = parts[0]
        if protocol not in ["tcp", "udp"]:
            raise ValueError("Protocol should be 'tcp' or 'udp'")

        is_udp = protocol == "udp"
        ports_spec = parts[1]
        ports = []

        print(f"DEBUG: Parsing {protocol} ports: '{ports_spec}'")  # DEBUG

        # Обработка списка портов: 80,443,1000-2000
        for part in ports_spec.split(","):
            print(f"DEBUG: Processing part: '{part}'")  # DEBUG
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

                print(f"DEBUG: Range {start_point}-{end_point}")  # DEBUG

                # Создаем отдельный Port для каждого порта в диапазоне
                for port in range(start_point, end_point + 1):
                    ports.append(
                        Port(
                            is_udp_protocol=is_udp,
                            start_port_address=port,
                            end_port_address=port,
                        )
                    )
            else:
                # Одиночный порт: 80
                try:
                    port_num = int(part)
                except ValueError:
                    raise ValueError(f"Port must be a number: {part}")

                ConsoleQueryParser.validate_port(port_num, port_num)
                print(f"DEBUG: Single port {port_num}")  # DEBUG
                ports.append(
                    Port(
                        is_udp_protocol=is_udp,
                        start_port_address=port_num,
                        end_port_address=port_num,
                    )
                )

        print(f"DEBUG: Total ports to scan: {len(ports)}")  # DEBUG
        return ports

    @staticmethod
    def validate_port(start_point, end_point):
        if start_point < 1 or end_point > 65535:
            raise ValueError("Ports should be between 1 and 65535")
        if start_point > end_point:
            raise ValueError("Start port cannot be greater than end port")
