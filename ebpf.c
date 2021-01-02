// #include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include "openstate.h"

// #define abs(x) ((x)<0 ? -(x) : (x))

#define MAX_TREE_DEPTH 100

#define IP_TCP 6
#define ETH_HLEN 14

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
		num_processed.update(&zero, current_value);
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
		/* Here We only need dst and src ports from L4, and they are at the same
		 * location for TCP and UDP; so do not switch on cases, just use UDP
		 * cursor.
		 */
		l4 = cursor_advance(cursor, sizeof(*l4));
		goto xfsmlookup;
	}

	/* Tables lookups */

	// statelookup: {
	//   struct StateTableLeaf *state_val = state_table.lookup(&state_idx);

	//   if (state_val) {
	//     current_state = state_val->state;
	//     /* If we found a state, go on and search XFSM table for this state and
	//      * for current event.
	//      */
	//     goto xfsmlookup;
	//   }
	//   goto EOP;
	// }

	xfsmlookup: {
		/* We don't want to match on L4 src port, so set it at 0 here and in XFSM
		 * initialization, since we have no wildcard mechanism. */
		// xfsm_idx.state    = current_state;
		xfsm_idx.l4_proto = ip->nextp;
		xfsm_idx.src_port = l4->sport;
		xfsm_idx.dst_port = l4->dport;
		if (l4->sport > l4->dport) {
			xfsm_idx.src_port = l4->dport;
			xfsm_idx.dst_port = l4->sport;
		}
		xfsm_idx.__padding8  = 0;
		xfsm_idx.__padding16 = 0;

		// bpf_trace_printk("Received packet with length %u from port %u to port %u\n", ip->tlen, (u32) l4->sport, (u32) l4->dport);

		struct XFSMTableLeaf *xfsm_val = xfsm_table.lookup(&xfsm_idx);

		if (!xfsm_val) {
			struct XFSMTableLeaf zero = {0, 0, {0,0,0,0,0,0}, 0, 0, false};
			// XXX: WTF is this necessary?
			zero.actual_src_port = l4->sport;
			zero.actual_dst_port = l4->dport;
			// struct XFSMTableLeaf zero = {0, 0, {0,0,0,0,0,0}, false};
			xfsm_table.insert(&xfsm_idx, &zero);
			xfsm_val = xfsm_table.lookup(&xfsm_idx);
		}

		if (xfsm_val != NULL) {
			xfsm_val->num_packets += 1;

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

			s64 all_features[12] = {sport, dport, protocol_identifier, total_length, delta, direction, avg_total_length, avg_delta, avg_direction, avg_dev_total_length, avg_dev_delta, avg_dev_direction};
		}

		// node = self.nodes
		// # While node not a leaf
		// while node.left_child != _TREE_LEAF:
		// 		# ... and node.right_child != _TREE_LEAF:
		// 		if X_ndarray[i, node.feature] <= node.threshold:
		// 				node = &self.nodes[node.left_child]
		// 		else:
		// 				node = &self.nodes[node.right_child]

		// if (xfsm_val) {
			/* Update state table. We re-use the StateTableKey we had initialized
			 * already. We update this rule with the new state provided by XFSM
			 * table.
			 */
			// struct StateTableLeaf new_state = { xfsm_val->next_state };
			// state_table.update(&state_idx, &new_state);

			/* At last, execute the action for the current state, that we obtained
			 * from the XFSM table.
			 * Users should add new actions here.
			 */
			// switch (xfsm_val->action) {
			//   case ACTION_DROP:
			//     return TC_CLS_DEFAULT;
			//   case ACTION_FORWARD:
			//     return TC_CLS_NOMATCH;
			//   default:
			//     return TC_CLS_NOMATCH; // XXX Should actually return an error code.
			// }
		// }

		/* So we did not find a match in XFSM table... For port knocking, default
		 * action is "return to initial state". We have yet to find a way to
		 * properly implement a default action. XXX
		 */
		// enum states {
		//   DEFAULT,
		//   STEP_1,
		//   STEP_2,
		//   OPEN
		// };
		// struct StateTableLeaf new_state = { DEFAULT };
		// state_table.update(&state_idx, &new_state);
		return TC_CLS_NOMATCH;
	}

EOP:
	return TC_CLS_NOMATCH;
}