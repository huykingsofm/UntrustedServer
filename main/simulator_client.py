import argparse
from .Client import Client
from .constant import DEFAULT_SIZE_OF_SIGNAL_NUMBER, DEFAULT_N_BLOCKS, DEFAULT_N_PROOFS, DEFAULT_N_VERIFIED_BLOCKS

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

    proof_group = parser.add_argument_group("Proof")
    proof_group.add_argument(
        "--n-blocks",
        help= "The number of blocks in precomputed proofs",
        default= DEFAULT_N_BLOCKS,
        type= int
    )
    proof_group.add_argument(
        "--n-vblocks",
        help= "The number of blocks which you want server to prove",
        default= DEFAULT_N_VERIFIED_BLOCKS,
        type= int
    )
    proof_group.add_argument(
        "--n-proofs",
        help= "The number of precomputed proofs",
        default= DEFAULT_N_PROOFS,
        type= int
    )
    proof_group.add_argument(
        "--key-size",
        help= "The size of signal number/key length",
        default= DEFAULT_SIZE_OF_SIGNAL_NUMBER,
        type= int
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
    if args.n_blocks <= 0 or args.n_proofs <= 0 or args.n_vblocks <= 0 or args.key_size <= 0:
        print("Proof arguments must be the positive numbers")
        exit(0)

def engine(args):
    check_condition(args)
    verbosities = {
        "user": [],
        "dev": ["error", "warning"]
    }
    if args.error:
        verbosities["user"].append("error")
    if args.warning:
        verbosities["user"].append("warning")
    if args.notification:
        verbosities["user"].append("notification")

    client = Client(
        server_address= (args.ipaddress, args.port), 
        n_blocks= args.n_blocks,
        n_vblocks= args.n_vblocks,
        n_proofs = args.n_proofs,
        key_size = args.key_size,
        verbosities = verbosities
        )
    client.start()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description= "A tool for start client")
    set_args(parser)
    args = parser.parse_args()
    engine(args)