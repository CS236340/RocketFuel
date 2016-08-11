## match.py
##
##  Created on: Aug 4, 2016
##      Author: Hillel Merran
##      		931112874
##      		hillelmerran@campus
##
##	Decide which match tests to perform for a given pair of IP addresses. The real operations are in matches_help.py
##


# PARAMETER pair - (IP1, IP2, ttl_difference, DNS_similarity, typeOfPacket1, typeOfPacket2)
# PARAMETER unionFind - a union-find structure of the addresses (by the indexes)
# PARAMETER AddressToIndex - a dicionary {key=IP : data=index}


from matches_help import *

def match_decision(pair, unionFind, AddressToIndex):
	if pair[4] == 2 and pair[5] == 2:
		return match_TCP(pair, unionFind, AddressToIndex)
	elif pair[4] == 1 and pair[5] == 2:
		return 0
	elif pair[4] == 2 and pair[5] == 1:
		return 0
	elif pair[4] == 3 and pair[5] == 3:
		result = match_UDP(pair, unionFind, AddressToIndex)
		if result == 1:
			return 1
		else:
			return match_TCP(pair, unionFind, AddressToIndex)
	elif (pair[4] == 2 or pair[4] == 3) and (pair[5] == 2 or pair[5] == 3):
		return match_TCP(pair, unionFind, AddressToIndex)
	else:
		return match_UDP(pair, unionFind, AddressToIndex)
