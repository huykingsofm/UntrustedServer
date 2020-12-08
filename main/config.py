import os
import shutil
import argparse

from .FileStorage import File
from .FileStorage import FileStorage
from .Client import __try_encrypting_file__, IV, KEY

def set_args(parser):
    parser.add_argument(
        "resource",
        help= "Path of resource file which will store at server"
    )

    parser.add_argument(
        "--storage-name",
        "-n",
        help= "Name of storage database (Storage is default).",
        default= "Storage"
    )

    parser.add_argument(
        "--nsplits",
        "-s",
        help= "N-splits of tree structure in storage (100 is default).",
        type= int,
        default= 100
    )

    parser.add_argument(
        "--idlen",
        "-l",
        help= "Length of identifier of file (100 is default).",
        type = int,
        default= 100
    )

def check_condition(args):
    if args.nsplits <= 0 or args.nsplits >= 256:
        print("n split must be in range 1-255")
        exit(1)

    if args.idlen <= 0:
        print("idlen must be a positive number")
        exit(1)

def engine(args):
    check_condition(args)

    print("Remove directory of previous {}... ".format(args.storage_name), end = "")
    try:
        shutil.rmtree(args.storage_name)
    except FileNotFoundError:
        pass
    print("OK")

    fs = FileStorage(args.storage_name, n_splits= args.nsplits)
    
    N = len(list(os.listdir(args.resource)))
    n = 0
    print("Store file to Storage ...")
    for file in os.listdir(args.resource):
        path = os.path.join(args.resource, file)
        print("\rProcess {:2.2f}% [{}/{}]".format((n + 1)/N * 100, n + 1, N), end = "")
        if os.path.isfile(path):
            try:
                __try_encrypting_file__(path, ".tmp")
            except:
                continue
            last_bytes = File.get_elements_at_the_end(".tmp", args.idlen)
            new_path = fs.create_new_path(last_bytes)
            shutil.move(".tmp", new_path)
            fs.save_info(new_path)
            n += 1

if __name__ == "__main__":
    parser = argparse.ArgumentParser("A tool for configuring server (cloud)")
    set_args(parser)
    args = parser.parse_args()
    engine(args)