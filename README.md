# machine-learning-in-ebpf
Contact: Maximilian Bachl

This repository contains the code for the paper *A flow-based IDS using Machine Learning in eBPF* ([arXiv](https://arxiv.org/abs/2102.09980)).

Requires Linux kernel >= 5.3 because 5.3 adds support for loops in eBPF. All code was run on *Debian Buster*. 

Tested with Python 3.7.9; Python 3.8 or newer does not seem to work. Requires py-virtnet 1.0.1 (Install with ```sudo pip3.7 install py-virtnet```).

Compiled with g++ 10.2.1. 

You'll need the bcc library, which can be installed with ```sudo apt install bcc``` on Debian. 

Moreover you need the bcc headers, which can be installed with ```sudo apt install libbpfcc-dev``` on Debian. 

Also, some generic kernel headers might be needed. Install them with `sudo apt install linux-headers-$(uname -r)` on Debian. 

If you encounter some problems, [the resolution of this issue](https://github.com/CN-TU/machine-learning-in-ebpf/issues/1) might help. 

## Run in userspace

    g++ -DUSERSPACE -fpermissive -I/usr/include/bcc ebpf_wrapper.cc -lbcc -o ebpf_wrapper
    
    sudo python3.7 test.py --run_scenario just_one_flow
    
## Run as eBPF

    g++ -fpermissive -I/usr/include/bcc ebpf_wrapper.cc -lbcc -o ebpf_wrapper
    
    sudo python3.7 test.py --run_scenario just_one_flow

By default packets are not dropped for benchmarking reasons. If you want to actually drop packets, you have to make sure to return 0 for "malicious" packets (see ebpf.c, search for a comment starting with "IMPORTANT"). 

## Train a decision tree

To train a decision tree, check out the [decision_tree branch of the adversarial-recurrent-ids repository](https://github.com/CN-TU/adversarial-recurrent-ids/tree/decision_tree) and follow the instructions there to make it work. Train a decision tree like this: 

    ./learn.py --dataroot flows.pickle --function train_dt
    
Your trained decision tree will be output in the ```runs``` folder. Change the ```prefix_path``` in ```ebpf_wrapper.cc``` to point to the directory containing your new decision tree and recompile it (see above ([Run in userspace](#run-in-userspace)) or ([Run as eBPF](#run-as-ebpf))). 
