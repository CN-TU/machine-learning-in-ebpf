#include <iostream>
#include <string.h>
#include <cassert>
#include <fstream>
#include <vector>
#include <thread>
#include <chrono>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "BPF.h"

using namespace std;

#ifdef USERSPACE
#include "hashmap.c"
#include "openstate.h"
#include "jhash.h"
#include "ebpf.c"

static uint64_t hash_fn(const void *k, void *ctx)
{
	// XXX: This is bad since it only returns 32 bits
	return (uint64_t) jhash(k, sizeof(XFSMTableKey), 0);
}

static bool equal_fn(const void *a, const void *b, void *ctx)
{
	XFSMTableKey* as = (XFSMTableKey*) a;
	XFSMTableKey* bs = (XFSMTableKey*) b;
	return as->l4_proto == bs->l4_proto && as->ip_src == bs->ip_src && as->ip_dst == bs->ip_dst && as->src_port == bs->src_port && as->dst_port == bs->dst_port;
}

// int open_raw_sock(const char *name)
// {
//   struct sockaddr_ll sll;
//   int sock;

//   sock = socket(PF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ALL));
//   if (sock < 0) {
//     fprintf(stderr, "cannot create raw socket\n");
//     return -1;
//   }

//   /* Do not bind on empty interface names */
//   if (!name || *name == '\0')
//     return sock;

//   memset(&sll, 0, sizeof(sll));
//   sll.sll_family = AF_PACKET;
//   sll.sll_ifindex = if_nametoindex(name);
//   if (sll.sll_ifindex == 0) {
//     fprintf(stderr, "Resolving device name to index: %s\n", strerror(errno));
//     close(sock);
//     return -1;
//   }
//   sll.sll_protocol = htons(ETH_P_ALL);
//   if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
//     fprintf(stderr, "bind to %s: %s\n", name, strerror(errno));
//     close(sock);
//     return -1;
//   }

//   return sock;
// }

#include <unistd.h>
#include <fcntl.h>
bool set_blocking_mode(int socket)
{
    bool ret = true;

    const int flags = fcntl(socket, F_GETFL, 0);
    // if ((flags & O_NONBLOCK) && !is_blocking) { info("set_blocking_mode(): socket was already in non-blocking mode"); return ret; }
    // if (!(flags & O_NONBLOCK) && is_blocking) { info("set_blocking_mode(): socket was already in blocking mode"); return ret; }
    // ret = 0 == fcntl(socket, F_SETFL, is_blocking ? flags ^ O_NONBLOCK : flags | O_NONBLOCK));
    ret = 0 == fcntl(socket, F_SETFL, flags & (~O_NONBLOCK));

    return ret;
}
#endif

double time_to_run;
const char interface[] = "eth0";
string prefix_path = "/home/max/repos/adversarial-recurrent-ids/runs/Dec29_19-15-36_hyperion_0_3";

std::vector<int64_t> read_file(string filename)
{
		// open the file:
		std::streampos fileSize;
		std::ifstream file(filename, std::ios::binary);

		// get its size:
		file.seekg(0, std::ios::end);
		fileSize = file.tellg();
		file.seekg(0, std::ios::beg);

		// read the data:
		std::vector<int64_t> fileData(fileSize/sizeof(int64_t));
		file.read((char*) &fileData[0], fileSize);
		return fileData;
}

int main(int argc, char *argv[])
{

	auto starttime = std::chrono::system_clock::now();

	assert(argc >= 2);
	sscanf(argv[1],"%lf",&time_to_run);

	vector<int64_t> children_left = read_file(prefix_path + "_childrenLeft");
	vector<int64_t> children_right = read_file(prefix_path + "_childrenRight");
	vector<int64_t> value = read_file(prefix_path + "_value");
	vector<int64_t> feature = read_file(prefix_path + "_feature");
	vector<int64_t> threshold = read_file(prefix_path + "_threshold");

	#ifndef USERSPACE

	string maps_string = string("#include \"openstate.h\"\n") +
  "BPF_TABLE(\"lru_hash\", struct XFSMTableKey,  struct XFSMTableLeaf,  xfsm_table,  10000);" +
	"BPF_ARRAY(num_processed, u64, 1);" +
	"BPF_ARRAY(all_features, s64, 12);" +
	"BPF_ARRAY(children_left, s64, " + to_string(children_left.size()) + ");" +
	"BPF_ARRAY(children_right, s64, " + to_string(children_right.size()) + ");" +
	"BPF_ARRAY(value, s64, " + to_string(value.size()) + ");" +
	"BPF_ARRAY(feature, s64, " + to_string(feature.size()) + ");" +
	"BPF_ARRAY(threshold, s64, " + to_string(threshold.size()) + ");\n";

	std::ifstream source_stream("ebpf.c");
	std::string ebpf_program((std::istreambuf_iterator<char>(source_stream)),
									std::istreambuf_iterator<char>());

	ebpf_program = maps_string + ebpf_program;

	ebpf::BPF bpf;
	auto res = bpf.init(ebpf_program);
	if (res.code() != 0) {
		std::cerr << res.msg() << std::endl;
		return 1;
	}

	ebpf::BPFArrayTable<int64_t> children_left_table = bpf.get_array_table<int64_t>("children_left");
	for (size_t i = 0; i < children_left.size(); i++)
	{
 		res = children_left_table.update_value(i, children_left[i]);
		assert(res.code() == 0);
	}
	ebpf::BPFArrayTable<int64_t> children_right_table = bpf.get_array_table<int64_t>("children_right");
	for (size_t i = 0; i < children_right.size(); i++)
	{
 		res = children_right_table.update_value(i, children_right[i]);
		assert(res.code() == 0);
	}
	ebpf::BPFArrayTable<int64_t> value_table = bpf.get_array_table<int64_t>("value");
	for (size_t i = 0; i < value.size(); i++)
	{
 		res = value_table.update_value(i, value[i]);
		assert(res.code() == 0);
	}
	ebpf::BPFArrayTable<int64_t> threshold_table = bpf.get_array_table<int64_t>("threshold");
	for (size_t i = 0; i < threshold.size(); i++)
	{
 		res = threshold_table.update_value(i, threshold[i]);
		assert(res.code() == 0);
	}
	ebpf::BPFArrayTable<int64_t> feature_table = bpf.get_array_table<int64_t>("feature");
	for (size_t i = 0; i < feature.size(); i++)
	{
 		res = feature_table.update_value(i, feature[i]);
		assert(res.code() == 0);
	}

  int fd;
  res = bpf.load_func("filter", BPF_PROG_TYPE_SOCKET_FILTER, fd);
  assert(res.code() == 0);

	int sd = -1;
	sd = bpf_open_raw_sock("eth0");

	int ret;
	ret = setsockopt(sd, SOL_SOCKET, SO_ATTACH_BPF, &fd, sizeof(fd));
	assert(ret>=0);

	auto current_time = std::chrono::system_clock::now();
	starttime = std::chrono::system_clock::now();

	std::this_thread::sleep_for(std::chrono::duration<double>(time_to_run) - (current_time - starttime));

	ebpf::BPFArrayTable<uint64_t> num_processed_table = bpf.get_array_table<uint64_t>("num_processed");
	uint64_t actual_num_processed;
	res = num_processed_table.get_value(0, actual_num_processed);
	assert(res.code() == 0);

	cout << "Finished kernel" << endl << flush;

	#else

	hashmap* map = hashmap__new(hash_fn, equal_fn, NULL);
	struct shared_struct ss = {map, 0, &children_left[0], children_left.size(), &children_right[0], children_right.size(), &value[0], value.size(), &feature[0], feature.size(), &threshold[0], threshold.size()};

	void* buffer = (void*)malloc(65536);

	int sd = -1;
	sd = bpf_open_raw_sock("eth0");
	set_blocking_mode(sd);

	auto duration = std::chrono::duration<double>(time_to_run);
	starttime = std::chrono::system_clock::now();

	// cout << "Initialized everything" << endl << flush;
	for(size_t i=0;;i++) {
		int length = 0; /*length of the received frame*/

		length = recv(sd, buffer, 65536, 0);
		if (length == -1) { perror("recv"); }

		// cout << "before" << endl << flush;
		filter(buffer, &ss);
		// cout << "after" << endl << flush;

		if (i % 1000 == 0) {
			auto current_time = std::chrono::system_clock::now();
			// cout << "duration " << duration.count() << " difference " << ((double) (current_time - starttime).count())/1000000000 << endl << flush;
			if(duration.count() < ((double) (current_time - starttime).count())/1000000000) {
				// cout << "Breaking" << endl << flush;
				break;
			}
		}
	}
	cout << "Finished userspace" << endl << flush;

	uint64_t actual_num_processed = ss.num_processed;

	#endif

	auto final_time = std::chrono::system_clock::now();

	cout << "Ran for " << ((double) (final_time-starttime).count())/1000000000 << "s, processed " << actual_num_processed << " packets" << endl << flush;

}
