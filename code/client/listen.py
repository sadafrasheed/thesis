import lib.listen
from lib.common import log, peer_address
from client.worker import Worker


def main():
    worker = Worker()
    lib.listen.listen("0.0.0.0", peer_address[1], worker)
    # Create a Worker instance for the new client
    
      


if __name__ == '__main__':
    main()

