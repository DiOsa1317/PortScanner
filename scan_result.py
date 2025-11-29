from dataclasses import dataclass

@dataclass
class ScanResult:
    protocol: str  # "TCP" или "UDP"
    port: int
    is_open: bool
    response_time: float = 0.0  # ms
    app_protocol: str = "-"  # "HTTP", "DNS", "ECHO", "-"
