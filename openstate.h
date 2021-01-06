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

/* Structures for index and value (a.k.a key and leaf) for XFSM stable */
struct XFSMTableKey {
  uint8_t  l4_proto;
  uint8_t  __padding8;
  uint16_t __padding16;
  uint32_t ip_src;
  uint32_t ip_dst;
  uint16_t src_port;
  uint16_t dst_port;
};

struct XFSMTableLeaf {
  uint64_t num_packets;
  uint64_t last_packet_timestamp;
  int64_t features[6];
  uint16_t actual_src_port;
  uint16_t actual_dst_port;
  uint32_t actual_src_ip;
  uint32_t actual_dst_ip;
  bool is_anomaly;
};

#ifdef USERSPACE

#include "hashmap.h"

struct shared_struct {
	struct hashmap* xfsm_table;
	uint64_t num_processed;
	int64_t* children_left;
	uint64_t children_left_len;
	int64_t* children_right;
	uint64_t children_right_len;
	int64_t* value;
	uint64_t value_len;
	int64_t* feature;
	uint64_t feature_len;
	int64_t* threshold;
	uint64_t threshold_len;
};

#endif

#endif /* OPENSTATE_H */
