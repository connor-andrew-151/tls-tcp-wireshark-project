

import socket
import ssl
import sys
from datetime import datetime

SERVER_HOST = '10.186.137.89'
SERVER_PORT = 4433
CERT_FILE = 'server.crt'  
BUFFER_SIZE = 4096

def create_tls_context(verify_server=False, cert_file=None):
    
    try:
        
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        if verify_server and cert_file:
            
            context.load_verify_locations(cafile=cert_file)
            print(f"[+] Certificate verification enabled (CA: {cert_file})")
        else:
            
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            print(f"[+] Using self-signed certificate (verification disabled)")
        
        return context
    
    except ssl.SSLError as e:
        print(f"[-] SSL error creating context: {e}")
        sys.exit(1)

def connect_to_server(host, port, tls_context):
    
    try:
        
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_socket.settimeout(10.0)  
        
        print(f"[+] Connecting to {host}:{port}...")
        tcp_socket.connect((host, port))
        print(f"[+] TCP connection established")
        
        
        tls_socket = tls_context.wrap_socket(
            tcp_socket,
            server_hostname=host
        )
        
        print(f"[+] TLS handshake completed successfully!")
        return tls_socket
    
    except socket.timeout:
        print(f"[-] Connection timed out")
        sys.exit(1)
    except ssl.SSLError as e:
        print(f"[-] TLS handshake failed: {e}")
        sys.exit(1)
    except ConnectionRefusedError:
        print(f"[-] Connection refused. Is the server running?")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Connection error: {e}")
        sys.exit(1)

def display_connection_info(tls_socket):
    
    try:
        print(f"\n[+] Connection Details:")
        print(f"    TLS Version: {tls_socket.version()}")
        cipher_info = tls_socket.cipher()
        print(f"    Cipher Suite: {cipher_info[0]}")
        print(f"    Key Exchange: {cipher_info[1]} bits")
        
        
        cert = tls_socket.getpeercert()
        if cert:
            print(f"    Server Certificate Subject: {cert.get('subject', 'N/A')}")
    except Exception as e:
        print(f"    (Could not retrieve all connection info: {e})")

def send_message(tls_socket, message):
    
    try:
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"\n[{timestamp}] Sending: {message}")
        
        tls_socket.sendall(message.encode('utf-8'))
        
        
        response_data = tls_socket.recv(BUFFER_SIZE)
        if not response_data:
            return None
        
        response = response_data.decode('utf-8').strip()
        print(f"[{timestamp}] Received: {response}")
        return response
    
    except socket.timeout:
        print(f"[-] Timeout waiting for server response")
    except ssl.SSLError as e:
        print(f"[-] SSL error during communication: {e}")
    except Exception as e:
        print(f"[-] Error sending/receiving: {e}")
    
    return None

def close_connection(tls_socket):
    
    try:
        
        tls_socket.shutdown(socket.SHUT_RDWR)
    except:
        pass
    finally:
        tls_socket.close()
        print(f"\n[-] TLS connection closed")

def interactive_mode(tls_socket):
    
    print(f"\n[+] Interactive mode active. Type 'quit' to exit.")
    print(f"    Messages are encrypted over TLS {tls_socket.version()}\n")
    
    while True:
        try:
            
            message = input("You: ").strip()
            
            if not message:
                continue
            
            
            response = send_message(tls_socket, message)
            
            if response is None or message.lower() == 'quit':
                break
        
        except KeyboardInterrupt:
            print(f"\n[+] Interrupted by user")
            break
        except EOFError:
            print(f"\n[+] End of input")
            break

def main():
    
    print("=" * 60)
    print(f"TLS Client - Phase 2")
    print(f"Connecting to {SERVER_HOST}:{SERVER_PORT}")
    print("=" * 60)
    
    
    tls_context = create_tls_context(verify_server=False)
    
    
    tls_socket = connect_to_server(SERVER_HOST, SERVER_PORT, tls_context)
    
    
    display_connection_info(tls_socket)
    
    try:
        
        interactive_mode(tls_socket)
    
    finally:
        
        close_connection(tls_socket)

if __name__ == '__main__':
    main()
