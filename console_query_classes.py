from dataclasses import dataclass


@dataclass
class Options:
    timeout: float
    num_threads: int
    guess: bool
    verbose: bool


@dataclass
class Port:
    is_udp_protocol: bool
    start_port_address: int
    end_port_address: int


@dataclass
class ConsoleQuery:
    options: Options
    ip_address: str
    ports: list[Port]
