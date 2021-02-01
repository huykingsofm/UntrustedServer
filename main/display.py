import os
import argparse
import matplotlib.pyplot as plt

def __round_int__(number, digit):
    unit = number % 10 ** digit
    if unit >= 5 * 10 ** (digit - 1):
        number = number - unit + 10 ** digit
    else:
        number = number - unit
    return number

def __check_display_plt__():
    return os.system('python -c "import matplotlib.pyplot as plt;plt.figure()"') == 0

def set_args(parser):
    parser.add_argument(
        "--xarray",
        "-x",
        help= "The array of x-axis you want to display",
        nargs= "+",
        type = float
    )

    parser.add_argument(
        "--yarray",
        "-y",
        help= "The array of y-axis you want to display",
        nargs= "+",
        type = float
    )

    parser.add_argument(
        "--xlabel",
        help= "The label of x axis",
        nargs= "+"
    )

    parser.add_argument(
        "--xticks",
        help= "Set tick locations of x axis",
        nargs= "+",
        type= float
    )

    parser.add_argument(
        "--xticklabels",
        help= "Set tick labels of x axis. Set this option if you specify --xticks",
        nargs= "+"
    )

    parser.add_argument(
        "--ylabel",
        help= "The label of y axis",
        nargs= "+"
    )

    parser.add_argument(
        "--yticks",
        help= "Set tick locations of y axis",
        nargs= "+",
        type = float
    )

    parser.add_argument(
        "--yticklabels",
        help= "Set tick labels of y axis. Set this option if you specify --yticks",
        nargs= "+"
    )

def check_condition(args):
    if args.yarray == None:
        print("You must specify yarray")
        exit(1)

    if args.xticks == None and args.xticklabels != None:
        print("Please set this --xticklabels only if you specified --xticks")
        exit(1)

    if args.xticklabels != None and len(args.xticklabels) != len(args.xticks):
        print("X-ticklabels length ({}) must be same with X-ticks length ({})"
        .format(len(args.xticklabels), len(args.xticks)))
        exit(1)

    if args.yticks == None and args.yticklabels != None:
        print("Please set this --yticklabels only if you specified --yticks")
        exit(1)

    if args.yticklabels != None and len(args.yticklabels) != len(args.yticks):
        print("Y-ticklabels length ({}) must be same with Y-ticks length ({})"
        .format(len(args.yticklabels), len(args.yticks)))
        exit(1)

def engine(args):
    check_condition(args)
    
    if args.xlabel:
        args.xlabel = " ".join(args.xlabel)

    if args.ylabel:
        args.ylabel = " ".join(args.ylabel)

    if args.xarray:
        plt.plot(args.xarray, args.yarray, marker = "s")
    else:
        plt.plot(args.yarray, marker = "s")

    if args.xlabel:
        plt.xlabel(args.xlabel)
    
    if args.ylabel:
        plt.ylabel(args.ylabel)

    if args.xticks and args.xticklabels:
        plt.xticks(args.xticks, args.xticklabels)
    elif args.xticks and not args.xticklabels:
        plt.xticks(args.xticks)

    if args.yticks and args.yticklabels:
        plt.yticks(args.yticks, args.yticklabels)
    elif args.yticks and not args.yticklabels:
        plt.yticks(args.yticks)

    plt.show()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description= "A tool for display the array as a figure")
    set_args(parser)
    args = parser.parse_args()
    engine(args)