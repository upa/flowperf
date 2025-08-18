#!/usr/bin/env python3

import os
import matplotlib.pyplot as plt
import argparse
import sys

def main():

    parser = argparse.ArgumentParser(description="plot distributions")
    parser.add_argument("-o", "--output", default="dist.pdf",
                        help="output pdf filename, default 'dist.pdf'")
    parser.add_argument("distfile", nargs="+",
                        help="dist files to plot")

    args = parser.parse_args()

    if len(sys.argv) < 2:
        print(f"{sys.argv[0]} [DIST FILE...]")

    width = 6.4
    aspect = 0.5
    fig = plt.figure(figsize = (width, width * aspect))
    ax = fig.subplots()

    def plot(filename, label:str):
        x: list[float] = []
        y: list[float] = []
        with open(filename, "r") as f:
            for line in f:
                size, prob = map(float, line.strip().split())
                x.append(size)
                if not y:
                    y.append(prob)
                else:
                    y.append(prob + y[-1])

        ax.plot(x, y, label=label, marker="o", markersize=2.5, linewidth=1)

    for dist in args.distfile:
        plot(dist, os.path.basename(dist))

    ax.set_ylabel("CDF")
    ax.set_xlabel("flow size (bytes)")
    ax.set_xscale("log")
    ax.legend()

    print(f"save to {args.output}")
    plt.savefig(args.output, bbox_inches = "tight", pad_inches = 0.05)


main()
