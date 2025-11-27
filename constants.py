from dataclasses import dataclass

TIMEOUT = "--timeout"
J = "-j"
NUM_THREADS = "--num-threads"
G = "-g"
GUESS = "--guess"
V = "-v"
VERBOSE = "--verbose"

@dataclass
class ScanResult:
    protocol: str  # "TCP" или "UDP"
    port: int
    is_open: bool  # True = считаем открытым
    response_time: float = 0.0  # ms
    app_protocol: str = "-"  # "HTTP", "DNS", "ECHO", "-"
