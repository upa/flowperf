#!/usr/bin/env bash

set -xeu

./cdf2pdf.py original/FacebookKeyValue_Sampled.txt > fb-memcache
./cdf2pdf.py original/Google_SearchRPC.txt > google-search
./cdf2pdf.py original/Google_AllRPC.txt > google-all
./cdf2pdf.py original/Facebook_HadoopDist_All.txt > fb-hadoop
./cdf2pdf.py original/DCTCP_MsgSizeDist.txt --size-factor 1460 > dctcp


for q in 10 25 50 100; do
	./cdf2pdf.py -q $q original/FacebookKeyValue_Sampled.txt > fb-memcacheQ$q
	./cdf2pdf.py -q $q original/Google_SearchRPC.txt > google-searchQ$q
	./cdf2pdf.py -q $q original/Google_AllRPC.txt > google-allQ$q
	./cdf2pdf.py -q $q original/Facebook_HadoopDist_All.txt > fb-hadoopQ$q
	./cdf2pdf.py -q $q original/DCTCP_MsgSizeDist.txt --size-factor 1460 > dctcpQ$q
done
