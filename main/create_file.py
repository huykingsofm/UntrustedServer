import os
import psutil
import argparse

FILE_NAME_FORMAT = "__file.{}"

def __check_free_space__(start, end, step):
    total = sum(range(start, end + 1, step))
    free = psutil.disk_usage('/').free

    if free < total:
        return 1

    if total / free >= 0.8:
        return 2

    return 0

def create_a_file(name, size, block_size = 1024, verbosity = True):
    if size == 0:
        size = 1

    notification = "\rCreate {} ... ".format(name)
    n = int(size/block_size)
    with open(name, "wb") as f:
        for i in range(n):
            block = os.urandom(block_size)
            f.write(block)
            if verbosity:
                print(notification, end = "")
                print("[{}/{}] {:.3f}%".format(i + 1, n, (i + 1) * 100 / n), end = "")
    
    if verbosity:
        print(notification, end = "")
        print("OK                                ")

def set_args(parser):
    parser.add_argument(
        "--start-size",
        "-ss",
        help= "Start of files size for analyzing. Unit is MB (0 is default).",
        default= 0,
        type= int
    )

    parser.add_argument(
        "--end-size",
        "-es",
        help= "End of files size for analyzing. Unit is MB (500 is default).",
        default= 500,
        type= int
    )

    parser.add_argument(
        "--step-size",
        help= "Step in range. Unit is MB (50 is default).",
        default= 50,
        type = int
    )

def check_condition(args):
    if args.start_size < 0 or args.end_size < 0:
        print("Size must be not-negative")
        exit(1)

    if args.start_size > args.end_size:
        print("Start size must be smaller than end size")
        exit(1)

    if args.step_size <= 0:
        print("Step size must be positive")
        exit(1)

    result = __check_free_space__(args.start_size, args.end_size, args.step_size)
    if result == 2:
        print("Not enough space disk for creating file")
        exit(0)

    if result == 1:
        print("Warning: Space disk is nearly full")

def engine(args):
    check_condition(args)

    sizes = list(range(args.start_size, args.end_size + 1, args.step_size))
    sizes_in_str = ["{}MB".format(size) for size in sizes]

    for i in range(len(sizes_in_str)):
        if os.path.isfile(FILE_NAME_FORMAT.format(sizes_in_str[i])) == False:
            create_a_file(FILE_NAME_FORMAT.format(sizes_in_str[i]), size= sizes[i] * 1024 ** 2, block_size= 3 * 1024 ** 2)

if __name__ == "__main__":
    parser = argparse.ArgumentParser("A tool for creating files with multiple size")
    set_args(parser)
    args = parser.parse_args()
    engine(args)