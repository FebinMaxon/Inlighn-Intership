# echo_client.py
import socket
import base64

HOST = '127.0.0.1'  # server address (use 127.0.0.1 for same machine)
PORT = 9009

def recv_all(sock):
    parts = []
    sock.settimeout(0.5)
    try:
        while True:
            data = sock.recv(4096)
            if not data:
                break
            parts.append(data)
    except Exception:
        pass
    sock.settimeout(None)
    return b''.join(parts)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    print("[+] Connected to server. Type messages, 'GETFILE filename', or 'quit'.")
    while True:
        msg = input("> ").strip()
        if not msg:
            continue
        s.sendall((msg + "\n").encode('utf-8'))
        resp = s.recv(4096)
        if not resp:
            print("[-] Server closed connection")
            break
        text = resp.decode('utf-8', errors='ignore')
        if text.startswith("FILEBEGIN"):
            rest = recv_all(s).decode('utf-8', errors='ignore')
            if "FILEEND" in rest:
                b64 = rest.split("FILEEND")[0].strip()
            else:
                b64 = rest.strip()
            try:
                content = base64.b64decode(b64)
                fname = "downloaded_file"
                with open(fname, "wb") as f:
                    f.write(content)
                print(f"[+] File saved as {fname} ({len(content)} bytes)")
            except Exception as e:
                print("[-] Failed to decode file:", e)
        else:
            print(text.strip())
        if msg.lower() == "quit":
            break
