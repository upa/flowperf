#!/usr/bin/env python3


import argparse
from typing import TextIO

def parse_and_print(distfile:TextIO, size_factor:int):

    cdfs = []
    for line in distfile:
        s = line.strip().split()
        if len(s) == 1:
            continue # the first line is the average size of messages
        size, cdf = map(float, s)
        cdfs.append((size * size_factor, cdf))

    pdfs = [cdfs[0]]
    for i in range(1, len(cdfs)):
        pdfs.append((cdfs[i][0], cdfs[i][1] - cdfs[i-1][1]))

    for pdf in pdfs:
        print("{}\t{:f}".format(pdf[0], pdf[1]))


def main():

    desc = "parse flow size distributioin txt from https://github.com/PlatformLab/HomaSimulation/tree/omnet_simulations/RpcTransportDesign/OMNeT%2B%2BSimulation/homatransport/sizeDistributions."
    parser = argparse.ArgumentParser(description=desc)

    parser.add_argument("distfile", type=argparse.FileType('r'),
                        help = "path to dist txt")
    parser.add_argument("--size-factor", type=int, default=1,
                        help = "msg size factor. set 1460 for DCTCP_MsgSizeDist.txt")
    args = parser.parse_args()
    
    parse_and_print(args.distfile, args.size_factor)


main()
