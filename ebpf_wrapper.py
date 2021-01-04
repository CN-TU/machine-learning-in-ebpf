import bcc
import socket
import os
import numpy as np
import ctypes as ct
import atexit
import signal
import time
import sys

time_to_run = float(sys.argv[1])

starttime = time.time()

interface="eth0"
print(f"binding socket to {interface}")

prefix_path = "/home/max/repos/adversarial-recurrent-ids/runs/Dec29_19-15-36_hyperion_0_3"

with open('%s_childrenLeft' % prefix_path, 'rb') as f:
	children_left = np.fromfile(f, dtype=np.int64)
with open('%s_childrenRight' % prefix_path, 'rb') as f:
	children_right = np.fromfile(f, dtype=np.int64)
with open('%s_value' % prefix_path, 'rb') as f:
	value = np.fromfile(f, dtype=np.int64)
with open('%s_feature' % prefix_path, 'rb') as f:
	feature = np.fromfile(f, dtype=np.int64)
with open('%s_threshold' % prefix_path, 'rb') as f:
	threshold = np.fromfile(f, dtype=np.int64)

maps_string = f"""
BPF_ARRAY(all_features, s64, 12);
BPF_ARRAY(children_left, s64, {len(children_left)});
BPF_ARRAY(children_right, s64, {len(children_right)});
BPF_ARRAY(value, s64, {len(value)});
BPF_ARRAY(feature, s64, {len(feature)});
BPF_ARRAY(threshold, s64, {len(threshold)});
"""

with open("ebpf.c") as f:
	actual_bpf_text = f.read()

ebpf_program = maps_string + actual_bpf_text

# initialize BPF - load source code from http-parse-simple.c
bpf = bcc.BPF(text=ebpf_program, debug=False)

children_left_table = bpf.get_table("children_left")
for i in range(len(children_left)):
	children_left_table[i] = ct.c_long(children_left[i].item())
children_right_table = bpf.get_table("children_right")
for i in range(len(children_right)):
	children_right_table[i] = ct.c_long(children_right[i].item())
value_table = bpf.get_table("value")
for i in range(len(value)):
	value_table[i] = ct.c_long(value[i].item())
threshold_table = bpf.get_table("threshold")
for i in range(len(threshold)):
	threshold_table[i] = ct.c_long(threshold[i].item())
feature_table = bpf.get_table("feature")
for i in range(len(feature)):
	feature_table[i] = ct.c_long(feature[i].item())

bpf.get_table("num_processed")[0] = ct.c_ulong(0)

def show_counter():
	ran_for = time.time() - starttime
	print(f"Ran for {ran_for}s. Processed: {bpf.get_table('num_processed')[0].value}")
	sys.stdout.flush()
atexit.register(show_counter)

#load eBPF program http_filter of type SOCKET_FILTER into the kernel eBPF vm
#more info about eBPF program types
#http://man7.org/linux/man-pages/man2/bpf.2.html
function_filter = bpf.load_func("filter", bcc.BPF.SOCKET_FILTER)

#create raw socket, bind it to interface
#attach bpf program to socket created
bcc.BPF.attach_raw_socket(function_filter, interface)

# #get file descriptor of the socket previously created inside BPF.attach_raw_socket
# socket_fd = function_filter.sock

# #create python socket object, from the file descriptor
# sock = socket.fromfd(socket_fd,socket.PF_PACKET,socket.SOCK_RAW,socket.IPPROTO_IP)
# #set it as blocking socket
# sock.setblocking(False)

# signal.pause()
time.sleep(time_to_run - (time.time()-starttime))
# i = 0
# while True:
# 	#retrieve raw packet from socket
# 	packet_str = os.read(socket_fd,2048)

# 	if i%1000 == 0:
# 		print("spam")