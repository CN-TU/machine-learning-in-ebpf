// #include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include "openstate.h"

// #define abs(x) ((x)<0 ? -(x) : (x))

#define MAX_TREE_DEPTH 20

#define IP_TCP 6
#define ETH_HLEN 14

#define TREE_LEAF -1
#define TREE_UNDEFINED -2

#define FIXED_POINT_DIGITS 16

BPF_ARRAY(num_processed, u64, 1);

/*eBPF program.
	Filter IP and TCP packets, having payload not empty
	and containing "HTTP", "GET", "POST" ... as first bytes of payload
	if the program is loaded as PROG_TYPE_SOCKET_FILTER
	and attached to a socket
	return  0 -> DROP the packet
	return -1 -> KEEP the packet and return it to user space (userspace can read it from the socket_fd )
*/
int filter(struct __sk_buff *skb) {

	u64 ts = bpf_ktime_get_ns();
	int zero = 0;
	u64* current_value = num_processed.lookup(&zero);
	if (current_value != NULL) {
		(*current_value) += 1;
		// num_processed.update(&zero, current_value);
	}

	u8 *cursor = 0;
	// int current_state;

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
		// state_idx.ether_type = ethernet->type;

		switch (ethernet->type) {
			case ETH_P_IP:   goto ip;
			case ETH_P_ARP:  goto arp;
			default:         goto EOP;
		}
	}

	ip: {
		ip = cursor_advance(cursor, sizeof(*ip));
		// state_idx.ip_src = ip->src;
		// state_idx.ip_dst = ip->dst;

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
		goto xfsmlookup;
	}

	l4: {
		l4 = cursor_advance(cursor, sizeof(*l4));
		goto xfsmlookup;
	}

	xfsmlookup: {
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

		// bpf_trace_printk("Received packet with length %u from port %u to port %u\n", ip->tlen, (u32) l4->sport, (u32) l4->dport);

		struct XFSMTableLeaf *xfsm_val = xfsm_table.lookup(&xfsm_idx);

		if (!xfsm_val) {
			struct XFSMTableLeaf zero = {0, 0, {0,0,0,0,0,0}, 0, 0, 0, 0, false};
			// XXX: WTF is this necessary?
			zero.actual_src_port = l4->sport;
			zero.actual_dst_port = l4->dport;
			zero.actual_src_ip = ip->src;
			zero.actual_dst_ip = ip->dst;
			// struct XFSMTableLeaf zero = {0, 0, {0,0,0,0,0,0}, false};
			xfsm_table.insert(&xfsm_idx, &zero);
			xfsm_val = xfsm_table.lookup(&xfsm_idx);
		}

		if (xfsm_val != NULL) {
			xfsm_val->num_packets += 1;

			// bpf_trace_printk("Received %lu packets from port %u to port %u\n", xfsm_val->num_packets, (u32) l4->sport, (u32) l4->dport);

			s64 sport = xfsm_val->actual_src_port;
			s64 dport = xfsm_val->actual_dst_port;
			s64 protocol_identifier = ip->nextp;
			s64 total_length = ip->tlen;

			s64 delta = 0;
			if (xfsm_val->last_packet_timestamp > 0) {
				delta = ts - xfsm_val->last_packet_timestamp;
			}
			xfsm_val->last_packet_timestamp = ts;

			s64 direction = l4->sport == xfsm_val->actual_src_port;

			sport <<= FIXED_POINT_DIGITS;
			dport <<= FIXED_POINT_DIGITS;
			protocol_identifier <<= FIXED_POINT_DIGITS;
			total_length <<= FIXED_POINT_DIGITS;
			delta <<= FIXED_POINT_DIGITS;
			direction <<= FIXED_POINT_DIGITS;

			xfsm_val->features[0] += total_length;
			xfsm_val->features[1] += delta;
			xfsm_val->features[2] += direction;

			s64 avg_total_length = xfsm_val->features[0]/xfsm_val->num_packets;
			s64 avg_delta = xfsm_val->features[1]/xfsm_val->num_packets;
			s64 avg_direction = xfsm_val->features[2]/xfsm_val->num_packets;

			xfsm_val->features[3] += abs(total_length-avg_total_length);
			xfsm_val->features[4] += abs(delta-avg_delta);
			xfsm_val->features[5] += abs(direction-avg_direction);

			s64 avg_dev_total_length = xfsm_val->features[3]/xfsm_val->num_packets;
			s64 avg_dev_delta = xfsm_val->features[4]/xfsm_val->num_packets;
			s64 avg_dev_direction = xfsm_val->features[5]/xfsm_val->num_packets;

			int zero_index = 0;
			all_features.update(&zero_index, &sport);
			int one_index = 0;
			all_features.update(&one_index, &dport);
			int two_index = 0;
			all_features.update(&two_index, &protocol_identifier);
			int three_index = 0;
			all_features.update(&three_index, &total_length);
			int four_index = 0;
			all_features.update(&four_index, &delta);
			int five_index = 0;
			all_features.update(&five_index, &direction);
			int six_index = 0;
			all_features.update(&six_index, &avg_total_length);
			int seven_index = 0;
			all_features.update(&seven_index, &avg_delta);
			int eight_index = 0;
			all_features.update(&eight_index, &avg_direction);
			int nine_index = 0;
			all_features.update(&nine_index, &avg_dev_total_length);
			int ten_index = 0;
			all_features.update(&ten_index, &avg_dev_delta);
			int eleven_index = 0;
			all_features.update(&eleven_index, &avg_dev_direction);

			// s64 all_features[12] = {sport, dport, protocol_identifier, total_length, delta, direction, avg_total_length, avg_delta, avg_direction, avg_dev_total_length, avg_dev_delta, avg_dev_direction};

			int current_node = 0;

			bool valid = true;

			// bpf_trace_printk("eggs\n");
			for (u64 i = 0; i < MAX_TREE_DEPTH; i++) {
				// bpf_trace_printk("i: %lu\n", i);
				s64* current_left_child = children_left.lookup(&current_node);
				s64* current_right_child = children_right.lookup(&current_node);

				s64* current_feature = feature.lookup(&current_node);
				s64* current_threshold = threshold.lookup(&current_node);

				if (current_feature == NULL || current_threshold == NULL || current_left_child == NULL || current_right_child == NULL || *current_left_child == TREE_LEAF) {
					break;
				} else {
					s64* real_feature_value = all_features.lookup((int*) current_feature);
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

			s64* correct_value = value.lookup(&current_node);

			if (correct_value != NULL) {
				xfsm_val->is_anomaly = (bool) correct_value;
			}
		}

		// node = self.nodes
		// # While node not a leaf
		// while node.left_child != _TREE_LEAF:
		// 		# ... and node.right_child != _TREE_LEAF:
		// 		if X_ndarray[i, node.feature] <= node.threshold:
		// 				node = &self.nodes[node.left_child]
		// 		else:
		// 				node = &self.nodes[node.right_child]

		return TC_CLS_NOMATCH;
	}

EOP:
	return TC_CLS_NOMATCH;
}