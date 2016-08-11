# RocketFuel
Mapping ISP topologies with RocketFuel

by:
Amit Licht
Hillel Merran
Avichai Yefet

Installation:
In order to run our rocketfuel you will nead python 2.7 and the following libraries installed:
 * scapy - http://www.secdev.org/projects/scapy/
 * matplotlib - http://matplotlib.org/
 * basemap - https://sourceforge.net/projects/matplotlib/files/matplotlib-toolkits/
 * networkX - https://networkx.github.io/
 * Beautiful soup - https://networkx.github.io/
 * python-geoip Geolite2 - http://pythonhosted.org/python-geoip/
 * traceroute - install from linux repository
Then extract all the rocketfuel python files to the same folder.

Running Rocketfuel:
First you must download a list of your target AS servers.
Open in a web browser the site address http://bgp.he.net/AS[target ASN]#_prefixes 
(example for 012-smile http://bgp.he.net/AS9116#_prefixes)
And save the page in your Rocketfuel directory under the name as[ASN].htm (Example: as9116.htm)
Open a terminal and go to the Rocketfuel folder. Run the program as root by typing: python RocketFuel.py
Rocket fuel will ask you for the AS number you wish to map and offer a list of possible geographical maps (Israel, USA, Australia and a world map).
From here, Rocketfuel will run its algorithm and print its output as it generates it.

Modules:
 RocketFuel.py - the main module of the program, call for it to run Rocketfuel. It contains the functions for dependent prefix, exit, ISP path detection
                 and the functions for printing the ISP graph and geomap.
 SubnetSoup.py - Processes and parses the information from the as[ASN].htm web page.
 alias_resolution.py - main code of the alias resolution module. This module try to solve the question "are in those IP addresses some aliases?"
 group_by_location.py - group IP addresses by their geolocation for the alias resolution module
 collect_TTL.py - collect informations about addresses for the alias resolution module
 match.py - run tests for the alias resolution module
 matches_help.py - tests for the alias resolution module
 union_find.py - a union find data structure

RocketFuel article - http://research.cs.washington.edu/networking/rocketfuel/papers/sigcomm2002.pdf
