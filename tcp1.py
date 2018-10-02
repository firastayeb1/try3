#!/etc/python3.7
import socket
from general import *
from networking.ethernet import Ethernet
from networking.ipv4 import IPv4
from networking.icmp import ICMP
from networking.tcp import TCP
from networking.udp import UDP
from networking.pcap import Pcap
from networking.http import HTTP

tab_1 = "\t - "
tab_2 = "\t\t - "
tab_3 = "\t\t\t - "
tab_4 = "\t\t\t\t - "

DATA_tab_1 = "\t   "
DATA_tab_2 = "\t\t   "
DATA_tab_3 = "\t\t\t   "
DATA_tab_4 = "\t\t\t\t   "


def main():
	pcap = Pcap('capture.pcap')
	conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

	while True:
		raw_data, addr = conn.recvfrom(65535)
		pcap.write(raw_data)
		eth = Ethernet(raw_data)

		print('\nEthernet Frame:')
		print(tab_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(eth.dest_mac, eth.src_mac, eth.proto))

        # IPv4
		if eth.proto == 8:
			ipv4 = IPv4(eth.data)
			print(tab_1 + 'IPv4 Packet:')
			print(tab_2 + 'Version: {}, Header Length: {}, TTL: {},'.format(ipv4.version, ipv4.header_length, ipv4.ttl))
			print(tab_2 + 'Protocol: {}, Source: {}, Target: {}'.format(ipv4.proto, ipv4.src, ipv4.target))

            # ICMP
			if ipv4.proto == 1:
				icmp = ICMP(ipv4.data)
				print(tab_1 + 'ICMP Packet:')
				print(tab_2 + 'Type: {}, Code: {}, Checksum: {},'.format(icmp.type, icmp.code, icmp.checksum))
				print(tab_2 + 'ICMP Data:')
				print(format_multi_line(DATA_tab_3, icmp.data))

            # TCP
			elif ipv4.proto == 6:
				tcp = TCP(ipv4.data)
				print(tab_1 + 'TCP Segment:')
				print(tab_2 + 'Source Port: {}, Destination Port: {}'.format(tcp.src_port, tcp.dest_port))
				print(tab_2 + 'Sequence: {}, Acknowledgment: {}'.format(tcp.sequence, tcp.acknowledgment))
				print(tab_2 + 'Flags:')
				print(tab_3 + 'URG: {}, ACK: {}, PSH: {}'.format(tcp.flag_urg, tcp.flag_ack, tcp.flag_psh))
				print(tab_3 + 'RST: {}, SYN: {}, FIN:{}'.format(tcp.flag_rst, tcp.flag_syn, tcp.flag_fin))

				if len(tcp.data) > 0:

                    # HTTP
					if tcp.src_port == 80 or tcp.dest_port == 80:
						print(tab_2 + 'HTTP Data:')
						try:
							http = HTTP(tcp.data)
							http_info = str(http.data).split('\n')
							for line in http_info:
								print(DATA_tab_3 + str(line))
						except:
							print(format_multi_line(DATA_tab_3, tcp.data))
					else:
						print(TAB_2 + 'TCP Data:')
						print(format_multi_line(DATA_tab_3, tcp.data))

            # UDP
			elif ipv4.proto == 17:
				udp = UDP(ipv4.data)
				print(tab_1 + 'UDP Segment:')
				print(tab_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(udp.src_port, udp.dest_port, udp.size))

            # Other IPv4
			else:
				print(tab_1 + 'Other IPv4 Data:')
				print(format_multi_line(DATA_tab_2, ipv4.data))

		else:
			print('Ethernet Data:')
			print(format_multi_line(DATA_tab_1, eth.data))

	pcap.close()


main()
