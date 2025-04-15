import socket
import threading
import sys
import signal
from lib.common import log


# Global variable to indicate if the server should stop
server_running = True

def listen(host, port, worker):
    global server_running
    
    
    # Create a basic TCP socket.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Reuse address

    try:
        sock.bind((host, port))
        sock.listen()
        log(f"{host} listening on 0.0.0.0:{port}")        
        
        while True:    
            try:    
                # Accept a new connection.
                client_socket, addr = sock.accept()
                #log(f"Connection accepted from {addr}")

                # Create a Worker instance for the new client
                worker.client_socket = client_socket

                # Start a new thread with the worker's handle_client method as the target
                client_thread = threading.Thread(target=worker.handle_client)
                client_thread.start()

            except Exception as e:
                if server_running:
                    log(f"Error accepting connection: {e}")

            if not server_running:
                sock.close()
                break;    
    except KeyboardInterrupt:
        log("Server shutting down gracefully...")
    finally:            
        sock.close()
        log("Server socket closed.")         
        
            
def shutdown_server(signal_received, frame):
    """Handle server shutdown on Ctrl+C"""  
    global server_running   
    log("Shutting down server...")    
    server_running = False
    sys.exit(0)

# Register signal handler for Ctrl+C (SIGINT)
signal.signal(signal.SIGINT, shutdown_server)
