import argparse

import main.config as config
import main.simulator as simulator
import main.analysis as analysis
import main.display as display

def check_condition(args):
    if not hasattr(args, "engine"):
        print("You must be choose an engine")
        exit(1)

def set_args(parser):
    commands = parser.add_subparsers(title= "engine")
    analysis_command = commands.add_parser("analysis")
    analysis_command.set_defaults(engine = "analysis")
    analysis.set_args(analysis_command)

    config_command = commands.add_parser("config")
    config_command.set_defaults(engine = "config")
    config.set_args(config_command)

    simulator_command = commands.add_parser("simulator")
    simulator_command.set_defaults(engine = "simulator")
    simulator.set_args(simulator_command)
    
    display_command = commands.add_parser("display")
    display_command.set_defaults(engine = "display")
    display.set_args(display_command)

def engine(args):
    check_condition(args)

    if args.engine == "analysis":  
        analysis.engine(args)

    if args.engine == "config":
        config.engine(args)

    if args.engine == "simulator":
        simulator.engine(args)

    if args.engine == "display":
        display.engine(args)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description= "A general tool of project")
    set_args(parser)
    args = parser.parse_args()
    engine(args)