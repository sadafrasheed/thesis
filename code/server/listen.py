import lib.listen
from lib.common import log, server_address, server_identity
from server.worker import Worker


def main():
    worker = Worker()
    lib.listen.listen("0.0.0.0", server_address[1], worker)
    # Create a Worker instance for the new client
    
      


if __name__ == '__main__':
    main()
