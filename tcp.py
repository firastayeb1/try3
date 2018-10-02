#!/usr/bin/python3.7
import socket
import struct
import textwrap

def ethernet_frame (data):
	dest_mac, src_mac, proto = struct.unpack('! 6s 6s H',data[:14])
#	print(mac)
#	dest_mac, src_mac = format(mac[:6],'b'),format(mac[6:],'b')
	return get_mac_addr(dest_mac),get_mac_addr(src_mac),socket.htons(proto),data[14:]

def get_mac_addr (bytes_addr):
	#print("!!!!!!!!")	
	#print(bytes_addr)
	bytes_str = map('{:02X}'.format, [int(i) for i in bytes_addr])
	return ':'.join(bytes_str).upper()

def main ():
	conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)) 
	while True:
		raw_data, addr = conn.recvfrom(65536)
		[dest_mac, src_mac, eth_proto, dataa] = ethernet_frame(raw_data)
		print('\nEthernet Frame:')
		print('Destination: {}, Source: {}, protocol: {}'.format(dest_mac, src_mac, eth_proto))

main ()
