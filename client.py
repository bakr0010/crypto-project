import socket
import threading
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from protocol import handshake_client, SecureSession

HOST = "127.0.0.1"
PORT = 9999

def load_psk():
    path = os.path.join(os.path.dirname(__file__), "psk.bin")
    if not os.path.exists(path):
        print("psk.bin not found. Run: python generate_psk.py")
        sys.exit(1)
    with open(path, "rb") as f:
        return f.read()

def recv_loop(session, sock):
    try:
        while True:
            msg = session.recv(sock)
            if msg is None:
                print("\n[server disconnected]")
                break
            print(f"\nserver: {msg.decode('utf-8', errors='replace')}")
            print("you: ", end="", flush=True)
    except Exception as e:
        print(f"\n[recv error: {e}]")

def main():
    psk = load_psk()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    print(f"[client] connected to {HOST}:{PORT}")

    try:
        client_key, server_key, nonce_base = handshake_client(sock, psk)
        print("[client] handshake complete — channel is secure")
        session = SecureSession(client_key, server_key, nonce_base)

        t = threading.Thread(target=recv_loop, args=(session, sock), daemon=True)
        t.start()

        while True:
            try:
                text = input("you: ")
            except EOFError:
                break
            if text.lower() == "/quit":
                session.close(sock)
                break
            session.send(sock, text.encode())
    except Exception as e:
        print(f"[error] {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    main()
