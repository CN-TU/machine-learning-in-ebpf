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

	string maps_string = string("BPF_ARRAY(all_features, s64, 12);") +
	"BPF_ARRAY(children_left, s64, " + to_string(children_left.size()) + ");" +
	"BPF_ARRAY(children_right, s64, " + to_string(children_right.size()) + ");" +
	"BPF_ARRAY(value, s64, " + to_string(value.size()) + ");" +
	"BPF_ARRAY(feature, s64, " + to_string(feature.size()) + ");" +
	"BPF_ARRAY(threshold, s64, " + to_string(threshold.size()) + ");";

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

	std::this_thread::sleep_for(std::chrono::duration<double>(time_to_run) - (current_time - starttime));
	// std::this_thread::sleep_for(std::chrono::seconds(100));

	auto final_time = std::chrono::system_clock::now();
	ebpf::BPFArrayTable<uint64_t> num_processed_table = bpf.get_array_table<uint64_t>("num_processed");
	uint64_t actual_num_processed;
	res = num_processed_table.get_value(0, actual_num_processed);
	assert(res.code() == 0);

	cout << "Ran for " << ((double) (final_time-starttime).count())/1000000000 << "s, processed " << actual_num_processed << " packets" << endl;

}
