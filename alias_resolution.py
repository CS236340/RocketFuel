## alias_resolution.py
##
##  Created on: Aug 4, 2016
##      Author: Hillel Merran
##      		931112874
##      		hillelmerran@campus
##
## spine of the alias resolution module


# PARAMETER dirpath - path of the directory containing the following file
# dirpath is not used finally (must be current directory)
# PARAMETER filename - name of the file in dirpath that contains the IP addresses for checking aliases

# Group the addresses by geolocation
# Collect the addresses that respond, their ttl and DNS name
# Create a dictionnary "AddressToIndex": {IP_address:index} for the responsive addresses
# Create a union-find data structure "unionFind"
# Initially, each address is a group
# For each group of geolocation
# 	# Create all the possible pairs
# 	# Order by ttl_diff increasing, and similarity of DNS decreasing if TTLs equal
# 	# Run over pairs of addresses and take a match decision if it's possible
# Create a dictionary "IndexToAddress": {index:IP_address}
# Create a list of lists "result". Each element 'list' contains aliased IP addresses
# Return unionFind, IndexToAddress, AddressToIndex, result


from group_by_location import *
from union_find import *
from collect_TTL import *
from match import *

# The similar function determine how much two strings are similar
def similar(str1, str2):
	if str1 == "llun" or str2 == "llun": # if one of the arguments is "null" (inversed)
		return 0
	str1 = str1 + ' '*(len(str2)-len(str1))
	str2 = str2 + ' '*(len(str1)-len(str2))
	return sum([1 if i==j else 0 for i,j in zip(str1,str2)])/float(len(str1))

def alias_resolve(dirpath, filename):
	# Group the addresses by geolocation
	# the addresses without geolocation are returned in a set ("without_geolocation")
	# those with geolocation are grouped in list of sets ("list_of_all_addresses")
	without_geolocation, list_of_all_addresses = group_by_geolocation(dirpath, filename)

	# collect the addresses that respond, their ttl and DNS name ("llun" if there is not)
	# the function also updates the precedent sets
	responsive_addresses, addresses, AddressToData = collect_ttl(list_of_all_addresses, without_geolocation)

	# Create a dictionnary {IP_address:index} for the responsive addresses
	indexes = range(len(addresses))
	AddressToIndex = dict(zip(addresses, indexes))

	# Create a union-find data structure
	# Initially, each address is a group
	unionFind = UF(len(indexes))

	# For each group of geolocation
	for s in list_of_all_addresses:
		# join the addresses without geolocation that we haven't found match yet
		s.update(without_geolocation)
	
		# Create all the possible pairs
		pairs = []  # (IP1, IP2, ttl_diff, DNS_similarity, typeOfPacket1, typeOfPacket2)
		for address1 in s:  # (IP, ttl, DNS, typeOfPacket)
			ad1 = address1[0]
			for address2 in s:
				ad2 = address2[0]
				if ad1 < ad2:
					pairs.append((ad1, ad2, abs(AddressToData[ad1][1]-AddressToData[ad2][1]), similar(AddressToData[ad1][2], AddressToData[ad2][2]), address1[3], address2[3]))

		# Order by ttl_diff increasing, and similarity of DNS decreasing if TTLs equal
		pairs = sorted(pairs, key=lambda x: (x[2], -x[3]))
		# Run over pairs of addresses and take a match decision if it's possible
		for pair in pairs:
			if not unionFind.connected(AddressToIndex[pair[0]], AddressToIndex[pair[1]]) and match_decision(pair, unionFind, AddressToIndex):
				unionFind.union(AddressToIndex[pair[0]], AddressToIndex[pair[1]])
				# If we found an address belonging to a geolocation that was previously without geolocation, remove it from 					# "without_geolocation" in order to avoid future useless tests
				if (AddressToData[pair[0]] in without_geolocation and AddressToData[pair[1]] not in without_geolocation) or (AddressToData[pair[1]] in without_geolocation and AddressToData[pair[0]] not in without_geolocation):
					without_geolocation.remove(AddressToData[pair[0]])
					without_geolocation.remove(AddressToData[pair[1]])
	
	IndexToAddress = dict()
	for key, value in AddressToIndex.items():
		IndexToAddress[value] = key
	result = []
	for group in unionFind.get_components():
		r = []
		for i in group:
			r.append(IndexToAddress[i])
		result.append(r)
	return unionFind, IndexToAddress, AddressToIndex, result



if __name__ == "__main__":
	print(alias_resolve("/home/dublin/Desktop/rocket fuel/code/IP_addresses", "List_of_addresses.txt"))

