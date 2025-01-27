

This directory contains example probablity distributions of message
sizes (flow sizes). The examples are derived from [the artifact for
the HOMA paper](https://github.com/PlatformLab/homa-paper-artifact). The
original message size distributions can be found
[here](https://github.com/PlatformLab/HomaSimulation/tree/omnet_simulations/RpcTransportDesign/OMNeT%2B%2BSimulation/homatransport/sizeDistributions).

```console
# SizeDistDir=[Path to a directory of https://github.com/PlatformLab/HomaSimulation/tree/omnet_simulations/RpcTransportDesign/OMNeT%2B%2BSimulation/homatransport/sizeDistributions]

./cdf2pdf.py ${SizeDistDir}/FacebookKeyValue_Sampled.txt > fb-memcache.txt
./cdf2pdf.py ${SizeDistDir}/Google_SearchRPC.txt > google-rpc.txt
./cdf2pdf.py ${SizeDistDir}/Google_AllRPC.txt > google-all.txt
./cdf2pdf.py ${SizeDistDir}/Facebook_HadoopDist_All.txt > fb-hadoop.txt
./cdf2pdf.py ${SizeDistDir}/DCTCP_MsgSizeDist.txt --size-factor 1460 > dctcp.txt
```

`--size-factor` for DCTCP refrects [lies of code](https://github.com/PlatformLab/HomaSimulation/blob/omnet_simulations/RpcTransportDesign/OMNeT%2B%2BSimulation/homatransport/sizeDistributions/adjustLoadFac.py#L95-L102).
