import argparse

from . import simulator_server as server
from . import simulator_client as client

def check_condition(args):
    if not hasattr(args, "simulator"):
        print("You must be choose an simulator")
        exit(1)

def set_args(parser):
    commands = parser.add_subparsers(title= "simulator")
    server_command = commands.add_parser("server")
    server_command.set_defaults(simulator = "server")
    server.set_args(server_command)

    client_command = commands.add_parser("client")
    client_command.set_defaults(simulator = "client")
    client.set_args(client_command)

def engine(args):
    check_condition(args)

    if args.simulator == "server":  
        server.engine(args)

    if args.simulator == "client":
        client.engine(args)

if __name__ == "__main__":
    parser = argparse.ArgumentParser("A tool for start simulator")
    set_args(parser)
    args = parser.parse_args()
    engine(args)