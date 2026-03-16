import socket

def detect_service(host, port):

    try:

        sock = socket.socket()
        sock.settimeout(3)
        sock.connect((host, port))

        banner = sock.recv(1024).decode(errors="ignore")

        if "ssh" in banner.lower():
            return "SSH"

        if "smtp" in banner.lower():
            return "SMTP"

        if port in [80,8080]:
            return "HTTP"

        if port in [443,8443]:
            return "HTTPS"

        return "UNKNOWN"

    except:
        return None