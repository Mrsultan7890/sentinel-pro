#!/usr/bin/env python3
"""
Pure Python HTTP/HTTPS proxy — no mitmproxy dependency.
Set browser proxy to 127.0.0.1:8082
"""
import socket
import threading
import sys
import ssl
import os

HOST = '127.0.0.1'
PORT = 8082
count = [0]

def handle_client(client_sock):
    try:
        data = client_sock.recv(65536)
        if not data:
            client_sock.close()
            return

        first_line = data.split(b'\n')[0].decode('utf-8', errors='replace')
        method = first_line.split(' ')[0]

        if method == 'CONNECT':
            # HTTPS tunnel
            host_port = first_line.split(' ')[1]
            host, port = host_port.split(':')
            port = int(port)

            try:
                remote = socket.create_connection((host, port), timeout=10)
                client_sock.send(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                count[0] += 1
                print(f'[{count[0]}] HTTPS TUNNEL {host}:{port}', flush=True)
                # Bidirectional tunnel
                def forward(src, dst):
                    try:
                        while True:
                            d = src.recv(65536)
                            if not d:
                                break
                            dst.send(d)
                    except:
                        pass
                    finally:
                        try: src.close()
                        except: pass
                        try: dst.close()
                        except: pass

                t = threading.Thread(target=forward, args=(remote, client_sock), daemon=True)
                t.start()
                forward(client_sock, remote)
            except Exception as e:
                client_sock.send(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                client_sock.close()
        else:
            # HTTP
            try:
                # Parse host from request
                host = ''
                port = 80
                for line in data.split(b'\n'):
                    if line.lower().startswith(b'host:'):
                        host_val = line.split(b':', 1)[1].strip().decode('utf-8', errors='replace')
                        if ':' in host_val:
                            host, port = host_val.rsplit(':', 1)
                            port = int(port)
                        else:
                            host = host_val
                        break

                if not host:
                    client_sock.close()
                    return

                remote = socket.create_connection((host, port), timeout=10)
                remote.send(data)
                count[0] += 1
                print(f'[{count[0]}] HTTP {method} http://{host}', flush=True)

                while True:
                    resp = remote.recv(65536)
                    if not resp:
                        break
                    client_sock.send(resp)

                remote.close()
                client_sock.close()
            except Exception as e:
                client_sock.close()
    except Exception as e:
        try: client_sock.close()
        except: pass


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(100)
    print(f'Proxy listening on {HOST}:{PORT}')
    print('Set Firefox proxy: 127.0.0.1:8082')
    print('Ctrl+C to stop\n')

    try:
        while True:
            client, addr = server.accept()
            t = threading.Thread(target=handle_client, args=(client,), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print(f'\nStopped. Total: {count[0]} requests')
        server.close()

if __name__ == '__main__':
    main()
