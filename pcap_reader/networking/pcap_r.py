import struct
import time
from .kamene import utils
from .kamene.utils import *

class Pcap:

	def __init__(self, filename, link_type=1):
		self.pcap_file = RawPcapReader(filename)
		#self.pcap_file.write(struct.pack('@ I H H i I I I', 0xa1b2c3d4, 2, 4, 0, 0, 65535, link_type))

	def write(self, data):
		ts_sec, ts_usec = map(int, str(time.time()).split('.'))
		length = len(data)
		self.pcap_file.write(struct.pack('@ I I I I', ts_sec, ts_usec, length, length))
		self.pcap_file.write(data)

	def read(self,i):
		return(self.pcap_file.read_packet(i))
		  
	def close(self):
		self.pcap_file.close()

