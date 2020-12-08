import argparse
import threading

from .Server import ResponseServer, ServerManager, ListenServer

def set_args(parser):
    parser.add_argument(
        "--ipaddress",
        "-ip",
        help = "Ip address of server (localhost is default)",
        default= "127.0.0.1"
    )

    parser.add_argument(
        "--port",
        "-p",
        help = "Port of server storage service (4499 is default)",
        default = 4499,
        type = int
    )

    parser.add_argument(
        "--max-clients",
        "-c",
        help = "Maximum of clients which server can serve (8 is default).",
        default = 8,
        type = int
    )

    verbosities_group = parser.add_argument_group("Verbosity")
    verbosities_group.add_argument(
        "--no-error",
        dest = "error",
        help = "Dont print error",
        action = "store_false"
    )
    verbosities_group.add_argument(
        "--no-warning",
        dest = "warning",
        help = "Dont print warning",
        action = "store_false"
    )
    verbosities_group.add_argument(
        "--no-notification",
        dest = "notification",
        help = "Dont print notification",
        action = "store_false"
    )

def check_condition(args):
    if args.max_clients <= 0:
        print("Max clients must be positive")
        exit(1)

def engine(args):
    check_condition(args)
    verbosities = []
    if args.error:
        verbosities.append("error")
    if args.warning:
        verbosities.append("warning")
    if args.notification:
        verbosities.append("notification")
    verbosities = tuple(verbosities)

    server_manager = ServerManager(args.max_clients, (args.ipaddress, args.port), verbosities)
    threading.Thread(target= server_manager.start).start()

    print("Server will start at {}:{}. To stop, please close the terminal!".format(args.ipaddress, args.port))

    listen_server = ListenServer((args.ipaddress, args.port), server_manager, verbosities)
    listen_server.start()

if __name__ == "__main__":
    parser = argparse.ArgumentParser("A tool for start server")
    set_args(parser)
    args = parser.parse_args()
    engine(args)