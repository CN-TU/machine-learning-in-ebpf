"""Example file for testing

This creates a small testnet with ipaddresses from 192.168.0.0/24,
one switch, and three hosts.
"""

import sys, os
import io
import time
import math
import signal
import numpy as np
import fnmatch
sys.path.insert(0, os.path.dirname(os.path.abspath(os.path.dirname(__file__))))

import subprocess
import virtnet
import statistics
import argparse



parser = argparse.ArgumentParser()
parser.add_argument('--bytes_to_capture', type=int, default=100)
parser.add_argument('--delay', type=int, default=100)
parser.add_argument('--rate', type=float, default=8)
parser.add_argument('--time', type=float, default=10)
parser.add_argument('--qdisc', type=str, default="fq")
parser.add_argument('--cport', type=int, default=9000)
parser.add_argument('--buffer_size', type=int, default=10)
parser.add_argument('--run_scenario', type=str, default="")
parser.add_argument('--store_pcaps', action='store_true')

opt = parser.parse_args()
print(opt)

def run_commands(cmds, Popen=False):
	if type(cmds) is not list:
		cmds = [cmds]
	return_stuff = []
	for cmd in cmds:
		if type(cmd) is tuple:
			cmd, kwargs = cmd
		else:
			kwargs = {}
		try:
			print("cmd", cmd)#, "kwargs", kwargs)
			if not Popen:
				output = subprocess.run(cmd.split(" "), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True, **kwargs)
				# print("output", output)
				return_stuff.append(output)
			else:
				popen = subprocess.Popen(cmd.split(" "), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **kwargs)
				return_stuff.append(popen)
		except subprocess.CalledProcessError as e:
			print(e.cmd, e.returncode, e.output)
			raise e
	return return_stuff

# print("os.environ", os.environ)

def execute_popen_and_show_result(command, host=None):
	parent = host if host is not None else subprocess
	print(f"Executing{f' on host {host.name}' if host else ''}", command)
	with parent.Popen(command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE) as cmd:
		out, err = cmd.stdout.read(), cmd.stderr.read()
		if out:
			print("out", out.decode("utf-8"))
		if err:
			print("err", err.decode("utf-8"))

def run(vnet, prefix=""):

		start_time = int(time.time() * 1000)

		print("Building network...")
		network = vnet.Network("192.168.0.0/24")
		switch = vnet.Switch("sw")
		hosts = []
		for i in range(2):
			host = vnet.Host("host{}".format(i))
			host.connect(vnet.VirtualLink, switch, "eth0")
			host["eth0"].add_ip(network)
			hosts.append(host)

		hosts[0].Popen(f"ip link set dev eth0 address c6:fe:e0:c2:90:75".split())
		hosts[1].Popen(f"ip link set dev eth0 address c6:fe:e0:c2:90:76".split())
		subprocess.Popen(f"ip link set dev host00 address 06:3c:28:c6:b1:e7".split())
		subprocess.Popen(f"ip link set dev host10 address 06:3c:28:c6:b1:e8".split())

		vnet.update_hosts()

		# for interface in switch.interfaces:
		# 	print("interface", interface)

		# 	run_commands([f"tc qdisc add dev {interface} root handle 1: netem{f' delay {int(round(opt.delay/2))}ms'}", f"tc qdisc add dev {interface} parent 1: handle 2: htb default 21", f"tc class add dev {interface} parent 2: classid 2:21 htb rate {opt.rate if interface=='host10' else 100}mbit", f"tc qdisc add dev {interface} parent 2:21 handle 3: {opt.qdisc if interface=='host10' else 'fq'}{f' flow_limit {int(math.ceil(opt.buffer_size))}' if (interface=='host10' and opt.qdisc=='fq') else ''}{f' limit {int(math.ceil(opt.buffer_size))}' if (interface=='host10' and opt.qdisc=='pfifo') else ''}"])

		# for i in range(len(hosts)):
		# 	with hosts[i].Popen("tc qdisc show dev eth0".split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE) as qdisc_info:
		# 		qdisc_info_output = qdisc_info.stdout.read().decode("utf-8").split("\n")
		# 		print(f"qdisc_info_output host {i}", qdisc_info_output)

		with hosts[0].Popen("ping -c 100 -i 0 host1".split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE) as ping:
			ping_output = ping.stdout.read().decode("utf-8").split("\n")
			ping_output = [float(item.split()[-2][5:]) for item in ping_output if "time=" in item]
			mean_rtt = statistics.mean(ping_output)
			print("mean rtt", mean_rtt)
			# assert mean_rtt >= opt.delay, f"mean_rtt: {mean_rtt}, opt.delay: {opt.delay}"

		server_popen = hosts[1].Popen("iperf3 -V -4 -s".split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE)

		ebpf_popen = hosts[1].Popen(f"./ebpf_wrapper {opt.time-5}".split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		# ebpf_popen = hosts[1].Popen(f"python3 ebpf_wrapper.py {opt.time-1}".split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE)

		os.environ["file_name_for_logging"] = f"pcaps/{opt.qdisc}_{opt.delay}_{opt.rate}_{opt.time}_{start_time}.txt"
		if opt.store_pcaps:
			os.makedirs("pcaps", exist_ok=True)
			tcpdump_sender_popens = []
			tcpdump_receiver_popens = []

			tcpdump_sender_popens.append(hosts[0].Popen(f"/usr/sbin/tcpdump -s {opt.bytes_to_capture} -i eth0 -w pcaps/sender_{prefix}_tcp_port{opt.cport+10}_{opt.qdisc}_{opt.delay}_{opt.rate}_{opt.time}_{start_time}.pcap tcp and dst port {opt.cport} or src port {opt.cport}".split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE))
			tcpdump_receiver_popens.append(hosts[1].Popen(f"/usr/sbin/tcpdump -s {opt.bytes_to_capture} -i eth0 -w pcaps/receiver_{prefix}_tcp_port{opt.cport+10}_{opt.qdisc}_{opt.delay}_{opt.rate}_{opt.time}_{start_time}.pcap tcp and dst port {opt.cport} or src port {opt.cport}".split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE))

		client_popen = hosts[0].Popen(f"iperf3 -V -4 -t {opt.time} --cport {opt.cport} -c host1".split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE)

		# ebpf_popen = hosts[1].Popen(["bash","-c",f"./ebpf_wrapper {opt.time-1}"])

		time.sleep(opt.time)

		client_popen.terminate()
		out, err = client_popen.stdout.read(), client_popen.stderr.read()
		if out:
			print("client out", out.decode("utf-8"))
		if err:
			print("client err", err.decode("utf-8"))
		client_out = out

		server_popen.terminate()
		out, err = server_popen.stdout.read(), server_popen.stderr.read()
		if out:
			print("server out", out.decode("utf-8"))
		if err:
			print("server err", err.decode("utf-8"))

		ebpf_popen.terminate()
		# print("ebpf_popen.returncode", ebpf_popen.returncode)
		out, err = ebpf_popen.stdout.read(), ebpf_popen.stderr.read()
		if out:
			print("ebpf out", out.decode("utf-8"))
		if err:
			print("ebpf err", err.decode("utf-8"))

		if opt.store_pcaps:
			for tcpdump_sender_popen in tcpdump_sender_popens:
				tcpdump_sender_popen.terminate()
				out, err = tcpdump_sender_popen.stdout.read(), tcpdump_sender_popen.stderr.read()
				if out:
					print("tcpdump out", out.decode("utf-8"))
				if err:
					print("tcpdump err", err.decode("utf-8"))

			for tcpdump_receiver_popen in tcpdump_receiver_popens:
				tcpdump_receiver_popen.terminate()
				out, err = tcpdump_receiver_popen.stdout.read(), tcpdump_receiver_popen.stderr.read()
				if out:
					print("tcpdump out", out.decode("utf-8"))
				if err:
					print("tcpdump err", err.decode("utf-8"))

			subprocess.check_output("chmod -R o+rw pcaps".split())

		return client_out.decode("utf-8"), start_time

if opt.run_scenario == "":
	with virtnet.Manager() as context:
		run(context)
elif opt.run_scenario == "just_one_flow":
	opt.time = 15
	opt.store_pcaps = False
	opt.buffer_size = 100
	opt.rate = 10
	opt.delay = 10

	opt.qdisc = "fq"
	with virtnet.Manager() as context:
		client_output, timestamp = run(context, "just_one_flow")
