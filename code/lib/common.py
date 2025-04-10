import logging
import sys
import os
import json

logging.basicConfig(
    #filename=os.getenv("RUN_MODE") + ".log",
    #filemode='a',
    level=logging.DEBUG,  # Set log level
    format="%(asctime)s - %(levelname)s - %(message)s",  # Format the log output
    handlers=[logging.StreamHandler(sys.stdout)]  # Log to stdout
)

def get_from_environment(param):
    #$env:SERVER_ID="ubuntu-cloud-server"
    value = os.environ.get(param)   
    if value is None:
        print(f"Error: cannot get {param} from environment")
        #print('Help: $env:CLIENT_ID="[you_client_id]"')
        sys.exit(1)
    return value 


debug = True
def log(*args):
    if debug:
        logging.info(''.join(map(str, args)))

def error(*args):
    logging.critical(''.join(map(str, args)))


# -----------------------------
# Socket Helper Functions
# -----------------------------

# Define the server address and port.
server_identity = get_from_environment("SERVER_ID")
server_address = ('0.0.0.0', 65432)
peer_address = ('0.0.0.0', 65431)

def recv_json(conn):
    buffer = ""
    while True:
        chunk = conn.recv(1024).decode()
        if not chunk:
            return None
        buffer += chunk
        if "\n" in buffer:
            line, buffer = buffer.split("\n", 1)
            #log(line)
            return json.loads(line)
