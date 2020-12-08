import argparse

import main.config as config
import main.simulator as simulator
import main.analyzing as analyzing

def check_condition(args):
    if not hasattr(args, "engine"):
        print("You must be choose an engine")
        exit(1)

def set_args(parser):
    commands = parser.add_subparsers(title= "engine")
    analyzing_command = commands.add_parser("analyzing")
    analyzing_command.set_defaults(engine = "analyzing")
    analyzing.set_args(analyzing_command)

    config_command = commands.add_parser("config")
    config_command.set_defaults(engine = "config")
    config.set_args(config_command)

    simulator_command = commands.add_parser("simulator")
    simulator_command.set_defaults(engine = "simulator")
    simulator.set_args(simulator_command)
    

def engine(args):
    check_condition(args)

    if args.engine == "engine":  
        analyzing.engine(args)

    if args.engine == "config":
        config.engine(args)

    if args.engine == "simulator":
        simulator.engine(args)

if __name__ == "__main__":
    parser = argparse.ArgumentParser("A general tool of project")
    set_args(parser)
    args = parser.parse_args()
    engine(args)