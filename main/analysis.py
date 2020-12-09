import argparse

from . import analysis_crypto

def check_condition(args):
    if not hasattr(args, "category"):
        print("You must be choose a category")
        exit(0)

def set_args(parser):
    commands = parser.add_subparsers(title= "categories")
    crypto_command = commands.add_parser("crypto")
    crypto_command.set_defaults(category = "crypto")
    analysis_crypto.set_args(crypto_command)

def engine(args):
    if args.category == "crypto":  
        analysis_crypto.engine(args)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description= "A tool for analyzing on your devices")
    set_args(parser)
    args = parser.parse_args()
    engine(args)