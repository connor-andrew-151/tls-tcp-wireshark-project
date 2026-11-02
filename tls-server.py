

import socket
import ssl
import sys
import threading
from datetime import datetime

HOST = '10.186.137.89'
PORT = 4433
CERT_FILE = 'server.crt'
KEY_FILE = 'server.key'
MAX_CONNECTIONS = 5
BUFFER_SIZE = 4096

def create_tls_context(cert_file, key_file):
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert_file, keyfile=key_file)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        
        context.set_ciphers('DEFAULT@SECLEVEL=1')
        
        print(f"[+] TLS context created successfully")
        print(f"    Certificate: {cert_file}")
        print(f"    Private key: {key_file}")
        return context
    
    except FileNotFoundError as e:
        print(f"[-] Certificate/key file not found: {e}")
        sys.exit(1)
    except ssl.SSLError as e:
        print(f"[-] SSL error creating context: {e}")
        sys.exit(1)

def create_server_socket(host, port):
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((host, port))
        server_socket.listen(MAX_CONNECTIONS)
        print(f"[+] Server socket bound to {host}:{port}")
        return server_socket
    
    except socket.error as e:
        print(f"[-] Socket error: {e}")
        sys.exit(1)

def wrap_client_with_tls(raw_client, tls_context):
    try:
        tls_client = tls_context.wrap_socket(raw_client, server_side=True)
        return tls_client
    
    except ssl.SSLError as e:
        print(f"[-] Error wrapping client with TLS: {e}")
        raw_client.close()
        raise

def handle_client(client_conn, client_address):
    
    client_ip, client_port = client_address
    print(f"\n[+] Client connected: {client_ip}:{client_port}")
    
    try:
        
        tls_version = client_conn.version()
        cipher = client_conn.cipher()
        print(f"    TLS Version: {tls_version}")
        print(f"    Cipher Suite: {cipher[0]} ({cipher[1]} bits)")
        
        
        welcome_msg = f"Welcome to TLS Server! Connected via {tls_version}.\n"
        client_conn.sendall(welcome_msg.encode('utf-8'))
        
        while True:
            
            data = client_conn.recv(BUFFER_SIZE)
            
            if not data:
                print(f"    Client {client_ip} closed connection")
                break
            
            message = data.decode('utf-8').strip()
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"    [{timestamp}] Received from {client_ip}: {message}")
            
            
            response = f"[Echo] {message}\n"
            client_conn.sendall(response.encode('utf-8'))
            
            
            if message.lower() == 'quit':
                print(f"    Client requested to quit")
                break
        
    except ssl.SSLError as e:
        print(f"    SSL error with client {client_ip}: {e}")
    except ConnectionResetError:
        print(f"    Connection reset by client {client_ip}")
    except Exception as e:
        print(f"    Error handling client {client_ip}: {e}")
    finally:
        try:
            client_conn.shutdown(socket.SHUT_RDWR)
        except:
            pass
        client_conn.close()
        print(f"[-] Connection closed: {client_ip}:{client_port}\n")

def accept_loop(server_socket, tls_context):
    
    print(f"[+] Waiting for TLS client connections...")
    print(f"    Press Ctrl+C to stop the server\n")
    
    active_threads = []
    
    try:
        while True:
            
            raw_client, client_address = server_socket.accept()
            
            
            try:
                client_conn = wrap_client_with_tls(raw_client, tls_context)
                print(f"[+] TLS handshake completed with {client_address}")
            except ssl.SSLError as e:
                print(f"[-] TLS handshake failed with {client_address}: {e}")
                continue
            
            
            thread = threading.Thread(
                target=handle_client,
                args=(client_conn, client_address),
                daemon=True
            )
            thread.start()
            active_threads.append(thread)
    
    except KeyboardInterrupt:
        print(f"\n[+] Server shutting down...")
    finally:
        
        for t in active_threads:
            t.join(timeout=2)

def cleanup(server_socket):
    
    print(f"[+] Closing server...")
    try:
        server_socket.shutdown(socket.SHUT_RDWR)
    except:
        pass
    server_socket.close()
    print(f"[-] Server closed")

def main():
    
    print("=" * 60)
    print(f"TLS Server - Phase 2")
    print(f"Listening on {HOST}:{PORT}")
    print("=" * 60)
    
    
    tls_context = create_tls_context(CERT_FILE, KEY_FILE)
    
    
    server_socket = create_server_socket(HOST, PORT)
    
    
    accept_loop(server_socket, tls_context)
    
    
    cleanup(server_socket)

if __name__ == '__main__':
    main()
