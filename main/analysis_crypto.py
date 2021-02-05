import os
import argparse

from . import create_file
from .create_file import FILE_NAME_FORMAT

import matplotlib.pyplot as plt
from scipy.stats.mstats import hmean, gmean
from scipy.stats import variation
from numpy import mean

from .Timer import Timer
from .Client import __hash_a_file__
from .Client import __try_encrypting_file__, __try_decrypting_file__

def __round_int__(number, digit):
    unit = number % (10 ** digit)
    if unit >= 5 * (10 ** (digit - 1)):
        number = number - unit + 10 ** digit
    else:
        number = number - unit
    return number

def __check_display_plt__():
    return os.system('python -c "import matplotlib.pyplot as plt;plt.figure()"') == 0

def set_args(parser):
    file_group = parser.add_argument_group("File options")
    analyzing_group = parser.add_argument_group("Analyzing options")
    other_options_group = parser.add_argument_group("Other options")

    file_group.add_argument(
        "--start-size",
        "-ss",
        help= "Start of files size for analyzing. Unit is MB (0 is default).",
        default= 0,
        type= int
    )

    file_group.add_argument(
        "--end-size",
        "-es",
        help= "End of files size for analyzing. Unit is MB (500 is default).",
        default= 500,
        type= int
    )

    file_group.add_argument(
        "--step-size",
        help= "Step in range. Unit is MB (50 is default).",
        default= 50,
        type = int
    )

    file_group.add_argument(
        "--remove",
        "-r",
        help= "Remove files after analyzing (False is default).",
        action= "store_true"
    )

    analyzing_group.add_argument(
        "--ntrial",
        help = "The number of trial before getting average cost (5 is default).",
        default= 5,
        type = int
    )

    analyzing_group.add_argument(
        "--mean",
        "-m",
        help= "AM (Arithmetic mean), GM (Geometric mean), HM (Harmonic mean).  AM is default.",
        default= "AM",
        choices = ["AM", "GM", "HM"]
    )

    other_options_group.add_argument(
        "--display",
        help= "Display the figure for visualizing.",
        action= "store_true"
    )

    other_options_group.add_argument(
        "--function",
        "-f",
        help = "e (encryption), d (decryption) or h (hash). e is default.",
        default = "e",
        choices= ["e", "d", "h"]
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

    if args.ntrial <= 0:
        print("The number of trial must be positive")
        exit(1)

    if args.display and __check_display_plt__() == False:
        print("Your device can not display figure")
        exit(1)

    if args.remove:
        result = create_file.__check_free_space__(args.end_size, args.end_size, 1)
    else:
        result = create_file.__check_free_space__(args.start_size, args.end_size, args.step_size)

    if result == 2:
        print("Not enough space for creating file")
        exit(1)
    
    if result == 1:
        if args.function == "h":
            print("Warning: Free space disk is nearly full.")
        else:
            print("Warning: Free space disk is nearly full. This make impossible to store encrypted or decrypted file.")

def engine(args):
    check_condition(args)

    if not args.remove:
        create_file.engine(args)
    
    sizes = list(range(args.start_size, args.end_size + 1, args.step_size))
    sizes_in_str = ["{}MB".format(size) for size in sizes]
    
    TIMER = Timer()
    
    NAME_OF_FUNCTION = "hash" if args.function == "h" else "encryption" if args.function == "e" else "decryption"
    elapsed_time = []
    for size, size_str in zip(sizes, sizes_in_str):
        tmp_elapsed_time = []
        file_name = FILE_NAME_FORMAT.format(size_str)
        
        if args.remove:
            if os.path.isfile(file_name) == False:
                create_file.create_a_file(file_name, size * 1024 ** 2, 3 * 1024 ** 2)
        
        for _ in range(args.ntrial):
            TIMER.start(size_str)
            if args.function == "e":
                __try_encrypting_file__(file_name, ".tmp")
            elif args.function == "d":
                __try_decrypting_file__(file_name, ".tmp")
            elif args.function == "h":
                __hash_a_file__(file_name)
            TIMER.end(size_str)

            if args.function in ["e", "d"]:
                if os.path.isfile(".tmp"):
                    os.remove(".tmp")

            tmp_elapsed_time.append(TIMER.get(size_str))
        
        if args.remove:
            if os.path.isfile(file_name):
                os.remove(file_name)

        if args.mean == "AM":
            elapsed_time.append(mean(tmp_elapsed_time))
        elif args.mean == "GM":
            elapsed_time.append(gmean(tmp_elapsed_time))
        else:
            elapsed_time.append(hmean(tmp_elapsed_time))
        print("Elapsed time for {} of {} is {:.2f}s".format(NAME_OF_FUNCTION, file_name, elapsed_time[-1]))
        print("Variation of elapsed time is {:.2f}".format(variation(tmp_elapsed_time)))
        print("-----------------------------------------------------------")

    print("Variation of all elapsed time is {:.2f}".format(variation(elapsed_time)))

    if args.display:
        plt.plot(sizes, elapsed_time)
        plt.xticks(sizes[::4], sizes_in_str[::4])
        plt.ylabel("{} time (s)".format(NAME_OF_FUNCTION))
        plt.xlabel("Size of data (MB)")

        nticks = 5
        mintick = args.start_size
        maxtick = max(range(args.start_size, args.end_size + 1, args.step_size))
        steptick = __round_int__((maxtick - mintick) // nticks, 1)
        ticks = range(mintick, maxtick + 1, steptick)
        labelticks = ["{}".format(tick) for tick in ticks]

        plt.xticks(ticks, labelticks)
        plt.show()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description= "A tool for analyzing cost of some functions in your device")
    set_args(parser)
    args = parser.parse_args()
    engine(args)