#!/usr/bin/python3.7
import sys

sys.path.append('/usr/local/lib/python2.7/dist-packages')

import socket
from general import *
from networking.ethernet import Ethernet
from networking.ipv4 import IPv4
from networking.icmp import ICMP
from networking.tcp import TCP
from networking.udp import UDP
from networking.pcap import Pcap
from networking.http import HTTP

from pcapfile import savefile

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '


def main(file_name, type_addr = None, src = None, dest = None):
	file = open(file_name , 'rb')
	pcapfile = savefile.load_savefile(file,verbose=True)
	
	b = True
	i=1
	try:
		packet = pcapfile.packets[0]
		raw_data = packet.raw()
	except:
		print("end of file ")
		b = False
	while b:
	
		eth = Ethernet(raw_data)
		if (type_addr == '-m' and src == eth.src_mac and dest == eth.dest_mac) or type_addr == None or type_addr == 'ip':
			print('\nEthernet Frame:')
			print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(eth.dest_mac, eth.src_mac, eth.proto))

        	# IPv4
			if eth.proto == 8 :
				ipv4 = IPv4(eth.data)
				if(type_addr == 'ip' and src == ipv4.src and dest == ipv4.target) or type_addr == '-m' or type_addr == None:
					print(TAB_1 + 'IPv4 Packet:')
					print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {},'.format(ipv4.version, ipv4.header_length, ipv4.ttl))
					print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(ipv4.proto, ipv4.src, ipv4.target))

					

					# TCP
					#elif ipv4.proto == 6:
					if ipv4.proto == 6:
						tcp = TCP(ipv4.data)
						print(TAB_1 + 'TCP Segment:')
						print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(tcp.src_port, tcp.dest_port))
						print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(tcp.sequence, tcp.acknowledgment))
						print(TAB_2 + 'Flags:')
						print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(tcp.flag_urg, tcp.flag_ack, tcp.flag_psh))
						print(TAB_3 + 'RST: {}, SYN: {}, FIN:{}'.format(tcp.flag_rst, tcp.flag_syn, tcp.flag_fin))
						#if len(tcp.data) > 0 :
						#	print(TAB_3 + 'WINDOW: {}'.format(struct.unpack('! H', tcp.data[:2]))

						if len(tcp.data) > 0 :
							print(TAB_3 + 'WINDOW: {}'.format(tcp.win))
							

            		# UDP
					elif ipv4.proto == 17:
						udp = UDP(ipv4.data)
						print(TAB_1 + 'UDP Segment:')
						print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(udp.src_port, udp.dest_port, udp.size))

		try:
			packet = pcapfile.packets[i]
			raw_data = packet.raw()
			i+=1
		except:
			print("end of file ")
			b = False
	file.close()
if len(sys.argv)==1:
	print("print a name of file pcap!")
elif len(sys.argv) == 2:
	main(sys.argv[1])
elif  sys.argv[2] != '-m' and sys.argv[2] != '-ip':
	print('incorrect flag') 

else:
	main(sys.argv[1],sys.argv[2],sys.argv[3],sys.argv[4])

