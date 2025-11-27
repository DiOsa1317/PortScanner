import socket


class ProtocolDetector:
    def __init__(self, timeout=2.0):
        self.timeout = timeout

    def detect_http(self, host: str, port: int) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            sock.send(b"GET / HTTP/1.0\r\n\r\n")
            response = sock.recv(1024)
            sock.close()
            return b"HTTP" in response
        except:
            return False

    def detect_dns(self, host: str, port: int) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)

            query = b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01"
            sock.sendto(query, (host, port))
            response, _ = sock.recvfrom(1024)
            sock.close()
            return len(response) > 0
        except:
            return False

    def detect_echo(self, host: str, port: int) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))

            test_data = b"ECHO_TEST"
            sock.send(test_data)
            response = sock.recv(1024)
            sock.close()
            return response == test_data
        except:
            return False

    def detect(self, host: str, port: int, transport: str) -> str:
        if transport == "TCP":
            if self.detect_http(host, port):
                return "HTTP"
            elif self.detect_echo(host, port):
                return "ECHO"
        elif transport == "UDP":
            if self.detect_dns(host, port):
                return "DNS"

        return "-"
