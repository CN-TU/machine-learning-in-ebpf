import bcc
import socket
import os

interface="eth0"

print(f"binding socket to #{interface}")

# initialize BPF - load source code from http-parse-simple.c
bpf = bcc.BPF(src_file = "ebpf.c",debug = 0)

#load eBPF program http_filter of type SOCKET_FILTER into the kernel eBPF vm
#more info about eBPF program types
#http://man7.org/linux/man-pages/man2/bpf.2.html
function_filter = bpf.load_func("filter", bcc.BPF.SOCKET_FILTER)

#create raw socket, bind it to interface
#attach bpf program to socket created
bcc.BPF.attach_raw_socket(function_filter, interface)

#get file descriptor of the socket previously created inside BPF.attach_raw_socket
socket_fd = function_filter.sock

#create python socket object, from the file descriptor
sock = socket.fromfd(socket_fd,socket.PF_PACKET,socket.SOCK_RAW,socket.IPPROTO_IP)
#set it as blocking socket
sock.setblocking(True)

while True:
	#retrieve raw packet from socket
	packet_str = os.read(socket_fd,2048)

	#DEBUG - print raw packet in hex format
	#packet_hex = toHex(packet_str)
	#print ("%s" % packet_hex)

	#convert packet into bytearray
	packet_bytearray = bytearray(packet_str)

	#ethernet header length
	ETH_HLEN = 14

	#IP HEADER
	#https://tools.ietf.org/html/rfc791
	# 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	# |Version|  IHL  |Type of Service|          Total Length         |
	# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	#
	#IHL : Internet Header Length is the length of the internet header
	#value to multiply * 4 byte
	#e.g. IHL = 5 ; IP Header Length = 5 * 4 byte = 20 byte
	#
	#Total length: This 16-bit field defines the entire packet size,
	#including header and data, in bytes.

	#calculate packet total length
	total_length = packet_bytearray[ETH_HLEN + 2]               #load MSB
	total_length = total_length << 8                            #shift MSB
	total_length = total_length + packet_bytearray[ETH_HLEN+3]  #add LSB

	#calculate ip header length
	ip_header_length = packet_bytearray[ETH_HLEN]               #load Byte
	ip_header_length = ip_header_length & 0x0F                  #mask bits 0..3
	ip_header_length = ip_header_length << 2                    #shift to obtain length

	#TCP HEADER
	#https://www.rfc-editor.org/rfc/rfc793.txt
	#  12              13              14              15
	#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	# |  Data |           |U|A|P|R|S|F|                               |
	# | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
	# |       |           |G|K|H|T|N|N|                               |
	# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	#
	#Data Offset: This indicates where the data begins.
	#The TCP header is an integral number of 32 bits long.
	#value to multiply * 4 byte
	#e.g. DataOffset = 5 ; TCP Header Length = 5 * 4 byte = 20 byte

	#calculate tcp header length
	tcp_header_length = packet_bytearray[ETH_HLEN + ip_header_length + 12]  #load Byte
	tcp_header_length = tcp_header_length & 0xF0                            #mask bit 4..7
	tcp_header_length = tcp_header_length >> 2                              #SHR 4 ; SHL 2 -> SHR 2

	#calculate payload offset
	payload_offset = ETH_HLEN + ip_header_length + tcp_header_length

	#print first line of the HTTP GET/POST request
	#line ends with 0xOD 0xOA (\r\n)
	#(if we want to print all the header print until \r\n\r\n)
	# for i in range (payload_offset,len(packet_bytearray)-1):
	#   if (packet_bytearray[i]== 0x0A):
	#     if (packet_bytearray[i-1] == 0x0D):
	#       break
	#   print ("%c" % chr(packet_bytearray[i]), end = "")
	# print("")

	# print("Got packet in python", total_length)