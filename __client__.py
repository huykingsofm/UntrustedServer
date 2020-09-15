from Client import Client

if __name__ == "__main__":
    client = Client(("127.0.0.1", 9999), verbosities= ("warning", "error", "notification"))
    client.start()
    pass