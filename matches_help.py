## matches_help.py
##
##  Created on: Aug 4, 2016
##      Author: Hillel Merran
##      		931112874
##      		hillelmerran@campus
##
##	Determine if two IP addresses are aliased or not
##


# help functions for match_decision
# PARAMETER pair - (IP1, IP2, ttl_difference, DNS_similarity, typeOfPacket1, typeOfPacket2)
# PARAMETER unionFind - a union-find structure of the addresses (by the indexes)
# PARAMETER AddressToIndex - a dicionary {key=IP : data=index}



from scapy.all import *
import time


### match test for UDP/UDP

def match_UDP(pair, unionFind, AddressToIndex):
	pkt1 = IP(dst=pair[0], ttl=255) / UDP(dport=33434)
	reply1 = sr1(pkt1, timeout=2)
	pkt2 = IP(dst=pair[1], ttl=255) / UDP(dport=33434)
	reply2 = sr1(pkt2, timeout=2)
	if reply1 is not None and reply2 is None:
		time.sleep(1)
		reply3 = sr1(pkt2, timeout=2)
		reply4 = sr1(pkt1, timeout=2)
		if reply3 is not None and reply4 is None:
			return 1
		else:
			return 0
	if reply1 is None or reply2 is None:
		return 0	
	if reply1.src == pair[1] or reply2.src == pair[0]:
		return 1
	if reply1.src in AddressToIndex.keys() and AddressToIndex[reply1.src] == unionFind.find(AddressToIndex[pair[1]]):
		return 1
	if reply2.src in AddressToIndex.keys() and AddressToIndex[reply2.src] == unionFind.find(AddressToIndex[pair[0]]):
		return 1
	x=reply1.id
	y=reply2.id
	if abs(pkt1.ttl-pkt2.ttl) > 6:
		return 0
	elif (y-x)%65536 > 1000:
		return 0
	else:
		reply3 = sr1(pkt1, timeout=2)
		reply4 = sr1(pkt2, timeout=2)
		if reply3 is None or reply4 is None:
			return 0
		if reply3.src == pair[1] or reply4.src == pair[0] or AddressToIndex[reply3.src] == unionFind.find(AddressToIndex[pair[1]]) or AddressToIndex[reply4.src] == unionFind.find(AddressToIndex[pair[0]]):
			return 1
		z=reply3.id
		w=reply4.id
		if (z-y)%65536 < 1000 and (w-z)%65536 < 1000:
			return 1
		else:
			return 0




### match test for TCP/TCP

def match_TCP(pair, unionFind, AddressToIndex):
	pkt1 = IP(dst=pair[0], ttl=255) / TCP(dport=80, flags='S', seq=1000)
	reply1 = sr1(pkt1, timeout=2)
	pkt2 = IP(dst=pair[1], ttl=255) / TCP(dport=80, flags='S', seq=1000)
	reply2 = sr1(pkt2, timeout=2)
	if reply1 is not None and reply2 is None:
		reply3 = sr1(pkt2, timeout=2)
		reply4 = sr1(pkt1, timeout=2)
		if reply3 is not None and reply4 is None:
			return 1
		else:
			return 0
	if reply1 is None or reply2 is None:
		return 0	
	if reply1.src == pair[1] or reply2.src == pair[0]:
		return 1
	if reply1.src in AddressToIndex.keys() and AddressToIndex[reply1.src] == unionFind.find(AddressToIndex[pair[1]]):
		return 1
	if reply2.src in AddressToIndex.keys() and AddressToIndex[reply2.src] == unionFind.find(AddressToIndex[pair[0]]):
		return 1
	x=reply1.id
	y=reply2.id
	if abs(pkt1.ttl-pkt2.ttl) > 6:
		return 0
	elif (y-x)%65536 > 1000:
		return 0
	else:
		reply3 = sr1(pkt1, timeout=2)
		reply4 = sr1(pkt2, timeout=2)
		if reply3 is None or reply4 is None:
			return 0
		if reply3.src == pair[1] or reply4.src == pair[0] or AddressToIndex[reply3.src] == unionFind.find(AddressToIndex[pair[1]]) or AddressToIndex[reply4.src] == unionFind.find(AddressToIndex[pair[0]]):
			return 1
		z=reply3.id
		w=reply4.id
		if (z-y)%65536 < 1000 and (w-z)%65536 < 1000:
			return 1
		else:
			return 0


