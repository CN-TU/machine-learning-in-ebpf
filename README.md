# machine-learning-in-ebpf
Contact: Maximilian Bachl

This repository contains the code for the upcoming paper *A flow-based IDS using Machine Learning in eBPF* ([arXiv](https://arxiv.org/abs/2102.09980)).

Requires Linux kernel >= 5.3 because 5.3 adds limited support for loops is eBPF. 

Tested with Python 3.7.9; Python 3.8 or newer does not seem to work. Requires the py-virtnet 1.0.1 (Install with ```sudo pip3.7 install py-virtnet```).

Compiled with g++ 10.2.1. 

You'll need the bcc library, which can be installed with ```sudo apt install bcc``` on Debian. 

Moreover you need the bcc headers, which can be installed with ```sudo apt install libbpfcc-dev``` on Debian. 

## Run in userspace

    g++ -DUSERSPACE -fpermissive -I/usr/include/bcc ebpf_wrapper.cc -lbcc -o ebpf_wrapper
    
    sudo python3.7 test.py --run_scenario just_one_flow
    
## Run as eBPF

    g++ -fpermissive -I/usr/include/bcc ebpf_wrapper.cc -lbcc -o ebpf_wrapper
    
    sudo python3.7 test.py --run_scenario just_one_flow

