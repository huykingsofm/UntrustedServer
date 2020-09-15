import threading
from Server import ResponseServer, ServerManager, ListenServer


if __name__ == "__main__":
    server_manager = ServerManager(8, ("127.0.0.1", 9999))
    t = threading.Thread(target= server_manager.start)
    t.start()
    
    listen_server = ListenServer(("127.0.0.1", 9999), server_manager)
    listen_server.start()
    pass
