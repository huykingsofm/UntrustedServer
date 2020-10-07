import threading
from Server import ResponseServer, ServerManager, ListenServer


if __name__ == "__main__":
    localhost = "127.0.0.1"
    ip = "192.168.137.1"
    server_manager = ServerManager(8, (ip, 9999))
    t = threading.Thread(target= server_manager.start)
    t.start()
    
    listen_server = ListenServer((ip, 9999), server_manager)
    listen_server.start()
    pass
