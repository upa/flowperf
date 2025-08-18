#!/usr/bin/env python3


import argparse
from typing import TextIO

def parse_and_print(distfile:TextIO, size_factor:int, q_num:int):

    cdfs: list[tuple[float, float]] = []
    for line in distfile:
        s = line.strip().split()
        if len(s) == 1:
            continue # the first line is the average size of messages
        size, cdf = map(float, s)
        if cdf == 0:
            continue
        cdfs.append((size * size_factor, cdf))

    if q_num > 0:
        cdfs = quantnize(q_num, cdfs)

    pdfs = [cdfs[0]]
    for i in range(1, len(cdfs)):
        pdfs.append((cdfs[i][0], cdfs[i][1] - cdfs[i-1][1]))

    for pdf in pdfs:
        print("{}\t{:.10f}".format(pdf[0], pdf[1]))


def quantnize(
        nr_split: int, cdfs: list[tuple[float, float]]
) -> list[tuple[float, float]]:

    new_cdfs: list[tuple[float, float]] = []

    top = 1.0 / nr_split
    
    for i in range(len(cdfs) - 1):
        if top <= cdfs[i+1][1]:
            new_cdfs.append(cdfs[i+1])
            top = 1.0 / nr_split * (len(new_cdfs) + 1)

    return new_cdfs
            


def main():

    desc = "parse flow size distributioin txt from https://github.com/PlatformLab/HomaSimulation/tree/omnet_simulations/RpcTransportDesign/OMNeT%2B%2BSimulation/homatransport/sizeDistributions."
    parser = argparse.ArgumentParser(description=desc)

    parser.add_argument("distfile", type=argparse.FileType('r'),
                        help = "path to dist txt")
    parser.add_argument("-q", "--quantnize", type=int, default=0,
                        help = "quantnize the cdf with specified number of bins")
    parser.add_argument("--size-factor", type=int, default=1,
                        help = "msg size factor. set 1460 for DCTCP_MsgSizeDist.txt")
    args = parser.parse_args()
    
    parse_and_print(args.distfile, args.size_factor, args.quantnize)


main()
