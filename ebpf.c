#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include "openstate.h"

#define IP_TCP 6
#define ETH_HLEN 14

/*eBPF program.
	Filter IP and TCP packets, having payload not empty
	and containing "HTTP", "GET", "POST" ... as first bytes of payload
	if the program is loaded as PROG_TYPE_SOCKET_FILTER
	and attached to a socket
	return  0 -> DROP the packet
	return -1 -> KEEP the packet and return it to user space (userspace can read it from the socket_fd )
*/
int filter(struct __sk_buff *skb) {

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
		xfsm_idx.__padding8  = 0;
		xfsm_idx.__padding16 = 0;

		// bpf_trace_printk("Received packet with length %u from port %u to port %u\n", ip->tlen, (u32) l4->sport, (u32) l4->dport);

		struct XFSMTableLeaf *xfsm_val = xfsm_table.lookup(&xfsm_idx);

		if (!xfsm_val) {
			struct XFSMTableLeaf zero = {0, {0,0,0,0,0,0,0,0,0,0,0,0}, false};
			xfsm_table.insert(&xfsm_idx, &zero);
			xfsm_val = xfsm_table.lookup(&xfsm_idx);
		}

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