

This directory contains example probablity distributions of message
sizes (flow sizes). The examples are derived from [the artifact for
the HOMA paper](https://github.com/PlatformLab/homa-paper-artifact),
and original message size distributions can be found
[here](https://github.com/PlatformLab/HomaSimulation/tree/omnet_simulations/RpcTransportDesign/OMNeT%2B%2BSimulation/homatransport/sizeDistributions).

```console
./cdf2pdf.py original/FacebookKeyValue_Sampled.txt > fb-memcache
./cdf2pdf.py original/Google_SearchRPC.txt > google-search
./cdf2pdf.py original/Google_AllRPC.txt > google-all
./cdf2pdf.py original/Facebook_HadoopDist_All.txt > fb-hadoop
./cdf2pdf.py original/DCTCP_MsgSizeDist.txt --size-factor 1460 > dctcp
```

`--size-factor` for DCTCP reflects [here](https://github.com/PlatformLab/HomaSimulation/blob/omnet_simulations/RpcTransportDesign/OMNeT%2B%2BSimulation/homatransport/sizeDistributions/adjustLoadFac.py#L95-L102).
