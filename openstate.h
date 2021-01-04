/*-
 *   BSD LICENSE
 *
 *   Copyright (c) 2016, 6WIND S.A.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of 6WIND S.A. nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef OPENSTATE_H
#define OPENSTATE_H

/* Return values
 * -1 means "use defautt classid provided on tc command line"
 *  0 means "no match found for this packet"
 * Any other value overrides the default classid provided on the command line.
 */
#define TC_CLS_DEFAULT -1
#define TC_CLS_NOMATCH  0

/* Default available actions. Other user-defined action codes can be appended
 * here or defined in the main program, with higher values.
 */
// #define ACTION_DROP    0
// #define ACTION_FORWARD 1

// /* Structures for index and value (a.k.a key and leaf) for state table */
// struct StateTableKey {
//   u16 ether_type;
//   u16 __padding16;
//   u32 ip_src;
//   u32 ip_dst;
// };

// struct StateTableLeaf {
//   int state;
// };

/* Structures for index and value (a.k.a key and leaf) for XFSM stable */
struct XFSMTableKey {
  u8  l4_proto;
  u8  __padding8;
  u16 __padding16;
  u32 ip_src;
  u32 ip_dst;
  u16 src_port;
  u16 dst_port;
};

struct XFSMTableLeaf {
  u64 num_packets;
  u64 last_packet_timestamp;
  s64 features[6];
  u16 actual_src_port;
  u16 actual_dst_port;
  u32 actual_src_ip;
  u32 actual_dst_ip;
  bool is_anomaly;
};

// /* State table */
// BPF_TABLE("hash", struct StateTableKey, struct StateTableLeaf, state_table, 256);

/* XFSM table */
BPF_TABLE("lru_hash", struct XFSMTableKey,  struct XFSMTableLeaf,  xfsm_table,  256);

#endif /* OPENSTATE_H */
