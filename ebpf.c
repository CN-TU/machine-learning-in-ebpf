
#ifdef USERSPACE
#include "openstate.h"
#include <sys/socket.h>
#include <time.h>
#include "proto.h"
#include <iostream>

using namespace std;

static unsigned long get_nsecs(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000UL + ts.tv_nsec;
}

#define cursor_advance(_cursor, _len) \
  ({ void *_tmp = _cursor; _cursor += _len; _tmp; })
#else
#include <net/sock.h>
#include <bcc/proto.h>
#endif

// #define abs(x) ((x)<0 ? -(x) : (x))

#define MAX_TREE_DEPTH 20

#define IP_TCP 6
#define ETH_HLEN 14

#define TREE_LEAF -1
#define TREE_UNDEFINED -2

#define FIXED_POINT_DIGITS 16

/*eBPF program.
By default DOES NOT drop malicious packets to enable better benchmarking
return  0 -> DROP the packet
return -1 -> KEEP the packet and return it to user space (userspace can read it from the socket_fd )
*/
#ifdef USERSPACE
int filter(uint8_t* skb, struct shared_struct* actual_struct) {
#else
int filter(struct __sk_buff *skb) {
#endif

	#ifndef USERSPACE
	uint64_t ts = bpf_ktime_get_ns();
	#else
	uint64_t ts = get_nsecs();
	// cout << "survived get_nsecs" << endl << flush;
	#endif
	int zero = 0;

	#ifndef USERSPACE
	uint64_t* current_value = num_processed.lookup(&zero);
	if (current_value != NULL) {
		(*current_value) += 1;
	}
	#else
	actual_struct->num_processed += 1;
	// cout << "survived actual_struct->num_processed" << endl << flush;
	#endif

	#ifndef USERSPACE
	uint8_t *cursor = 0;
	#else
	uint8_t *cursor = skb;
	#endif


	/* Initialize most fields to 0 in case we do not parse associated headers.
	 * The alternative is to set it to 0 once we know we will not meet the header
	 * (e.g. when we see ARP, we won't have dst IP / port...). It would prevent
	 * to affect a value twice in some cases, but it is prone to error when
	 * adding parsing for other protocols.
	 */
	// struct StateTableKey state_idx;
	// // state_idx.ether_type // Will be set anyway
	// state_idx.__padding16 = 0;
	// state_idx.ip_src = 0;
	// state_idx.ip_dst = 0;

	struct XFSMTableKey xfsm_idx;
	// xfsm_idx.state // Will be set anyway before XFSM lookup
	xfsm_idx.l4_proto = 0;
	xfsm_idx.ip_src = 0;
	xfsm_idx.ip_dst = 0;
	xfsm_idx.src_port = 0;
	xfsm_idx.dst_port = 0;
	xfsm_idx.__padding8  = 0;
	xfsm_idx.__padding16 = 0;

	struct ethernet_t *ethernet;
	struct ip_t       *ip;
	struct udp_t      *l4;

	/* Headers parsing */

	ethernet: {
		ethernet = cursor_advance(cursor, sizeof(*ethernet));

		#ifdef USERSPACE
		// cout << "ethernet" << endl << flush;
		ethernet->type = ntohs(ethernet->type);
		#endif

		switch (ethernet->type) {
			case ETH_P_IP:   goto ip;
			case ETH_P_ARP:  goto arp;
			default:         goto EOP;
		}
	}

	ip: {
		ip = cursor_advance(cursor, sizeof(*ip));

		#ifdef USERSPACE
		// cout << "ip" << endl << flush;
		ip->src = ntohl(ip->src);
		ip->dst = ntohl(ip->dst);
		ip->tlen = ntohs(ip->tlen);
		#endif

		xfsm_idx.ip_src = ip->src;
		xfsm_idx.ip_dst = ip->dst;

		switch (ip->nextp) {
			case IPPROTO_TCP: goto l4;
			case IPPROTO_UDP: goto l4;
			// FIXME: Is this correct?
			default:          goto l4;
		}
	}

	arp: {
		/* We could parse ARP packet here if we needed to retrieve some fields from
		 * the ARP header for the lookup.
		 */
		goto EOP;
	}

	l4: {
		l4 = cursor_advance(cursor, sizeof(*l4));
		#ifdef USERSPACE
		// cout << "l4" << endl << flush;
		l4->sport = ntohs(l4->sport);
		l4->dport = ntohs(l4->dport);
		#endif
		goto xfsmlookup;
	}

	xfsmlookup: {
		// cout << "xfsmlookup" << endl << flush;
		xfsm_idx.l4_proto = ip->nextp;
		xfsm_idx.src_port = l4->sport;
		xfsm_idx.dst_port = l4->dport;
		if (l4->sport > l4->dport) {
			xfsm_idx.src_port = l4->dport;
			xfsm_idx.dst_port = l4->sport;
		}
		if (ip->src > ip->dst) {
			xfsm_idx.ip_src = ip->dst;
			xfsm_idx.ip_dst = ip->src;
		}
		xfsm_idx.__padding8  = 0;
		xfsm_idx.__padding16 = 0;

		// bpf_trace_printk("Received packet with length %u from port %u to port %u\n", ip->tlen, (uint32_t) l4->sport, (uint32_t) l4->dport);
		// printf("Received packet with length %u from port %u to port %u\n", ip->tlen, (uint32_t) l4->sport, (uint32_t) l4->dport);

		#ifdef USERSPACE
		struct XFSMTableLeaf *xfsm_val = NULL;
		bool ret = hashmap__find(actual_struct->xfsm_table, &xfsm_idx, &xfsm_val);
		#else
		struct XFSMTableLeaf *xfsm_val = xfsm_table.lookup(&xfsm_idx);
		#endif

		if (!xfsm_val) {
			#ifndef USERSPACE
			struct XFSMTableLeaf zero = {0, 0, {0,0,0,0,0,0}, 0, 0, 0, 0, false};
			zero.actual_src_port = l4->sport;
			zero.actual_dst_port = l4->dport;
			zero.actual_src_ip = ip->src;
			zero.actual_dst_ip = ip->dst;
			xfsm_table.insert(&xfsm_idx, &zero);
			xfsm_val = xfsm_table.lookup(&xfsm_idx);
			#else
			// cout << "before allocation" << endl << flush;
			XFSMTableKey* xfsm_key_allocated = (XFSMTableKey*) calloc(1, sizeof(XFSMTableKey));
			*xfsm_key_allocated = xfsm_idx;
			XFSMTableLeaf* zero = (XFSMTableLeaf*) calloc(1, sizeof(XFSMTableLeaf));
			zero->actual_src_port = l4->sport;
			zero->actual_dst_port = l4->dport;
			zero->actual_src_ip = ip->src;
			zero->actual_dst_ip = ip->dst;
			int err = hashmap__add(actual_struct->xfsm_table, xfsm_key_allocated, zero);
			assert(err==0);
			bool ret = hashmap__find(actual_struct->xfsm_table, xfsm_key_allocated, &xfsm_val);
			// cout << "after allocation" << endl << flush;
			#endif
		}

		if (xfsm_val != NULL) {
			xfsm_val->num_packets += 1;

			// bpf_trace_printk("Received %lu packets from port %u to port %u\n", xfsm_val->num_packets, (uint32_t) l4->sport, (uint32_t) l4->dport);
			// printf("Received %lu packets from port %u to port %u\n", xfsm_val->num_packets, (uint32_t) l4->sport, (uint32_t) l4->dport);

			int64_t sport = xfsm_val->actual_src_port;
			int64_t dport = xfsm_val->actual_dst_port;
			int64_t protocol_identifier = ip->nextp;
			int64_t total_length = ip->tlen;

			int64_t delta = 0;
			if (xfsm_val->last_packet_timestamp > 0) {
				delta = ts - xfsm_val->last_packet_timestamp;
			}
			xfsm_val->last_packet_timestamp = ts;

			int64_t direction = l4->sport == xfsm_val->actual_src_port;

			sport <<= FIXED_POINT_DIGITS;
			dport <<= FIXED_POINT_DIGITS;
			protocol_identifier <<= FIXED_POINT_DIGITS;
			total_length <<= FIXED_POINT_DIGITS;
			delta <<= FIXED_POINT_DIGITS;
			direction <<= FIXED_POINT_DIGITS;

			xfsm_val->features[0] += total_length;
			xfsm_val->features[1] += delta;
			xfsm_val->features[2] += direction;

			int64_t avg_total_length = xfsm_val->features[0]/xfsm_val->num_packets;
			int64_t avg_delta = xfsm_val->features[1]/xfsm_val->num_packets;
			int64_t avg_direction = xfsm_val->features[2]/xfsm_val->num_packets;

			xfsm_val->features[3] += abs(total_length-avg_total_length);
			xfsm_val->features[4] += abs(delta-avg_delta);
			xfsm_val->features[5] += abs(direction-avg_direction);

			int64_t avg_dev_total_length = xfsm_val->features[3]/xfsm_val->num_packets;
			int64_t avg_dev_delta = xfsm_val->features[4]/xfsm_val->num_packets;
			int64_t avg_dev_direction = xfsm_val->features[5]/xfsm_val->num_packets;

			#ifndef USERSPACE
			int zero_index = 0;
			all_features.update(&zero_index, &sport);
			int one_index = 1;
			all_features.update(&one_index, &dport);
			int two_index = 2;
			all_features.update(&two_index, &protocol_identifier);
			int three_index = 3;
			all_features.update(&three_index, &total_length);
			int four_index = 4;
			all_features.update(&four_index, &delta);
			int five_index = 5;
			all_features.update(&five_index, &direction);
			int six_index = 6;
			all_features.update(&six_index, &avg_total_length);
			int seven_index = 7;
			all_features.update(&seven_index, &avg_delta);
			int eight_index = 8;
			all_features.update(&eight_index, &avg_direction);
			int nine_index = 9;
			all_features.update(&nine_index, &avg_dev_total_length);
			int ten_index = 10;
			all_features.update(&ten_index, &avg_dev_delta);
			int eleven_index = 11;
			all_features.update(&eleven_index, &avg_dev_direction);
			#else
			int64_t all_features[12] = {sport, dport, protocol_identifier, total_length, delta, direction, avg_total_length, avg_delta, avg_direction, avg_dev_total_length, avg_dev_delta, avg_dev_direction};
			#endif

			int current_node = 0;

			#ifndef USERSPACE
			for (uint64_t i = 0; i < MAX_TREE_DEPTH; i++) {
				// bpf_trace_printk("i: %lu\n", i);
				int64_t* current_left_child = children_left.lookup(&current_node);
				int64_t* current_right_child = children_right.lookup(&current_node);

				int64_t* current_feature = feature.lookup(&current_node);
				int64_t* current_threshold = threshold.lookup(&current_node);

				if (current_feature == NULL || current_threshold == NULL || current_left_child == NULL || current_right_child == NULL || *current_left_child == TREE_LEAF) {
					break;
				} else {
					int64_t* real_feature_value = all_features.lookup((int*) current_feature);
					if (real_feature_value != NULL) {
						if (*real_feature_value <= *current_threshold) {
							current_node = (int) *current_left_child;
						} else {
							current_node = (int) *current_right_child;
						}
					} else {
						break;
					}
				}
			}

			int64_t* correct_value = value.lookup(&current_node);

			if (correct_value != NULL) {
				xfsm_val->is_anomaly = (bool) correct_value;
				// IMPORTANT: You'll need to uncomment lines like the following if you actually want to drop packets. They're commented because it's better for benchmarking. 
		        	// if (xfsm_val->is_anomaly) {
				//     return 0; // Drop the packet if it is considered malicious
		        	// }
			}
						#else
			for (uint64_t i = 0; i < MAX_TREE_DEPTH; i++) {
				// bpf_trace_printk("i: %lu\n", i);
				int64_t current_left_child = actual_struct->children_left[current_node];
				int64_t current_right_child = actual_struct->children_right[current_node];

				int64_t current_feature = actual_struct->feature[current_node];
				int64_t current_threshold = actual_struct->threshold[current_node];

				if (current_left_child == TREE_LEAF) {
					break;
				} else {
					int64_t real_feature_value = all_features[current_feature];
					if (real_feature_value <= current_threshold) {
						current_node = (int) current_left_child;
					} else {
						current_node = (int) current_right_child;
					}
				}
			}

			int64_t correct_value = actual_struct->value[current_node];
			xfsm_val->is_anomaly = (bool) correct_value;
			#endif
		}

		return TC_CLS_NOMATCH;
	}

EOP:
	// cout << "EOP" << endl << flush;
	return TC_CLS_NOMATCH;
}
