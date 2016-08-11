## group_by_location.py
##
##  Created on: Aug 4, 2016
##      Author: Hillel Merran
##      		931112874
##      		hillelmerran@campus
##
##	Group IP addresses by their geolocation in order to reduce number of match tests to perform
##


# Group the addresses by geolocation
# PARAMETER dirpath is the path of the directory containing filename - need to be current directory (not used, finally)
# PARAMETER filename is the file with all the IP_addresses list
# RETURN:
# the addresses without geolocation are returned in a set ("without_geolocation")
# those with geolocation are grouped in sets, the sets are grouped in a list ("list_of_all_addresses")

# create a tmp directory "group_by_geolocation" in the current directory
# "group_by_geolocation" contains files 'geolocation.txt'
# each file contains the subList of IP addresses that have the filename's geolocation


import os
import shutil
from union_find import *

def group_by_geolocation(dirpath, filename):
	if os.path.exists("group_by_geolocation"):
		shutil.rmtree("group_by_geolocation")
	os.makedirs("group_by_geolocation")
	with open(filename, 'r') as IP_address_file:
		for line in IP_address_file.readlines():  # line = "IP (space) geolocation (space) DNS"
			splitLine = line.split(' ')
			newFile = 'group_by_geolocation/' + splitLine[1] + '.txt'
			with open(newFile , 'a') as dest:
				dest.write(line)
# add all the addresses without geolocation to a set: "without_geolocation"
	without_geolocation = set()
	if os.path.isfile("group_by_geolocation/null.txt"):
		with open("group_by_geolocation/null.txt", 'r') as f:
			for line in f.read().splitlines():  # line = "IP (space) geolocation (space) DNS"
				splitLine = line.split(' ')
				without_geolocation.add((splitLine[0], splitLine[2]))  # (IP address, DNS name)
		os.remove("group_by_geolocation/null.txt")

# create a list of sets
# each 'element' set contains the addresses of a definite geolocation
	list_of_all_addresses = []
	i = 0
	for f in os.listdir("group_by_geolocation"):
		list_of_all_addresses.append(set())
		with open("group_by_geolocation/" + f, 'r') as myFile:
			for line in myFile.read().splitlines():  # line = "IP (space) geolocation (space) DNS"
				splitLine = line.split(' ')
				list_of_all_addresses[i].add((splitLine[0], splitLine[2]))  # (IP address, DNS name)
		i += 1
	shutil.rmtree("group_by_geolocation")
	return without_geolocation, list_of_all_addresses

