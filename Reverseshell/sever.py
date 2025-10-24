# echo_server.py
import socket
import threading
import base64
import os

HOST = '0.0.0.0'  # listen on all interfaces for lab use
PORT = 9009
WORKDIR = '.'  # serves files from current directory only

def handle_client(conn, addr):
    print(f"[+] Connected from {addr}")
    with conn:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            text = data.decode('utf-8', errors='ignore').strip()
            if text.lower() == 'quit':
                conn.sendall(b'Goodbye\n')
                break
            if text.startswith("GETFILE "):
                filename = text.split(" ",1)[1].strip()
                safe_path = os.path.abspath(os.path.join(WORKDIR, filename))
                if not safe_path.startswith(os.path.abspath(WORKDIR)) or not os.path.isfile(safe_path):
                    conn.sendall(b"ERROR: file not found or access denied\n")
                    continue
                with open(safe_path, 'rb') as f:
                    b = f.read()
                encoded = base64.b64encode(b)
                conn.sendall(b"FILEBEGIN\n")
                for i in range(0, len(encoded), 4096):
                    conn.sendall(encoded[i:i+4096])
                conn.sendall(b"\nFILEEND\n")
            else:
                conn.sendall(b"ECHO: " + data)

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(5)
        print(f"[+] Echo server listening on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=handle_client, args=(conn,addr), daemon=True)
            t.start()

if __name__ == "__main__":
    main()
