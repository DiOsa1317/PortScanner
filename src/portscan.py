import sys

from src.console_query_parser import ConsoleQueryParser
from src.scanner import PortScanner

def main():
    try:
        # Парсим аргументы командной строки (первый аргумент - "portscan")
        console_query = ConsoleQueryParser.convert_args_to_console_query(sys.argv)


        scanner = PortScanner(
            timeout=console_query.options.timeout,
            verbose=console_query.options.verbose,
            guess=console_query.options.guess,
            num_threads=console_query.options.num_threads
        )

        results = scanner.scan(console_query.ip_address, console_query.ports)

        scanner.print_results(results)

    except KeyboardInterrupt as e:
        print(e)
        sys.exit(1)
    except Exception as e:
        print(e)
        sys.exit(1)

if __name__ == "__main__":
    main()