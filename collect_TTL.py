## collect_TTL.py
##
##  Created on: Aug 4, 2016
##      Author: Hillel Merran
##      		931112874
##      		hillelmerran@campus
##
##	Collect responsive addresses and informations on them for future match tests
##


# PARAMETER list_of_all_addresses - list of sets of addresses to collect responsive addresses and ttl
# PARAMETER without_geolocation - another set of addresses that have no geolocation to collect responsive addresses and ttl
# RETURN:
# responsive_addresses - (IP, TTL, inversed_DNS)
# addresses - set of the IP addresses of "responsive_addresses"
# AddressToData - a dictionary. keys are the IP addresses, and data is same as in "responsive_addresses"

# collect the addresses that response, their ttl and DNS name ("llun" if there is not)
# if some have not responded, wait few seconds (TimeToSleep variable) and collect again
# do it again until there are new responses
# remove those that are unresponsive

from scapy.all import *
from union_find import *
import time

def collect_ttl(list_of_all_addresses, without_geolocation):
	# collect ttl while there are new responses
	# for sets in "list_of_all_addresses"
	AddressToData = dict()
	addresses = set()
	timeToSleep = 2
	for s in list_of_all_addresses:
		unresponsive_addresses = set()
		unresponsive_tmp = s.copy()
		s.clear()
		while True:
			unresponsive_addresses = unresponsive_tmp.copy()
			time.sleep(timeToSleep)
			for address in unresponsive_addresses:  # (IP, DNS)
				ip = address[0]
				udp_port = 33434
				pktU = IP(dst=ip, ttl=255) / UDP(dport=udp_port)
				replyU = sr1(pktU, timeout=2)
				tcp_port = 80
				pktT = IP(dst=ip, ttl=255) / TCP(dport=tcp_port, flags='S', seq=1000)
				replyT = sr1(pktT, timeout=2)
				if replyU is not None and replyT is None:
					unresponsive_tmp.remove(address)
					s.add((ip, replyU.ttl, address[1][::-1], 1))  # (IP, TTL, inversed_DNS, typeOfPacket)
					addresses.add(ip)
					AddressToData[ip] = (ip, replyU.ttl, address[1][::-1], 1)
				elif replyU is None and replyT is not None:
					unresponsive_tmp.remove(address)
					s.add((ip, replyT.ttl, address[1][::-1], 2))  # (IP, TTL, inversed_DNS, typeOfPacket)
					addresses.add(ip)
					AddressToData[ip] = (ip, replyT.ttl, address[1][::-1], 2)
				elif replyU is not None and replyT is not None:
					unresponsive_tmp.remove(address)
					s.add((ip, replyU.ttl, address[1][::-1], 3))  # (IP, TTL, inversed_DNS, typeOfPacket)
					addresses.add(ip)
					AddressToData[ip] = (ip, replyU.ttl, address[1][::-1], 3)
			if len(unresponsive_addresses.difference(unresponsive_tmp)) == 0:
				break
	# same thing to "without_geolocation"
	unresponsive_addresses = set()
	unresponsive_tmp = without_geolocation.copy()
	without_geolocation.clear()
	while True:
		unresponsives_addresses = unresponsive_tmp.copy()
		time.sleep(timeToSleep)
		for address in unresponsive_tmp:  # (IP, DNS)
			ip = address[0]
			udp_port = 33434
			pktU = IP(dst=ip, ttl=255) / UDP(dport=udp_port)
			replyU = sr1(pktU, timeout=2)
			tcp_port = 80
			pktT = IP(dst=ip, ttl=255) / TCP(dport=tcp_port, flags='S', seq=1000)
			replyT = sr1(pktT, timeout=2)
			if replyU is not None and replyT is None:
				unresponsive_tmp.remove(address)
				without_geolocation.add((ip, replyU.ttl, address[1][::-1], 1))  # (IP, TTL, inversed_DNS, typeOfPacket)
				addresses.add(ip)
				AddressToData[ip] = (ip, replyU.ttl, address[1][::-1], 1)
			elif replyU is None and replyT is not None:
				unresponsive_tmp.remove(address)
				without_geolocation.add((ip, replyT.ttl, address[1][::-1], 2))  # (IP, TTL, inversed_DNS, typeOfPacket)
				addresses.add(ip)
				AddressToData[ip] = (ip, replyT.ttl, address[1][::-1], 2)
			elif replyU is not None and replyT is not None:
				unresponsive_tmp.remove(address)
				without_geolocation.add((ip, replyU.ttl, address[1][::-1], 3))  # (IP, TTL, inversed_DNS, typeOfPacket)
				addresses.add(ip)
				AddressToData[ip] = (ip, replyU.ttl, address[1][::-1], 3)
		if len(unresponsive_addresses.difference(unresponsive_tmp)) == 0:
			break
	# create a list of all the responsive addresses
	responsive_addresses = set()
	for s in list_of_all_addresses:
		responsive_addresses.update(s)
	responsive_addresses.update(without_geolocation)
	return responsive_addresses, addresses, AddressToData  # (IP, TTL, inversed_DNS, typeOfPacket), (IP), {IP:(IP, TTL, inversed_DNS, typeOfPacket)}

