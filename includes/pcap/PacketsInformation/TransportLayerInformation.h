/**********************************************************************************

* This file is part of c++ assignment 2 and assignment 3.
* This file is declaration of structure "TransportLayerInformation".
* This structure is used to store information that are retrieved from pcap file at transport layer level.
* Objective of this structure is to provide abstract form store port addresses and define protocol for this layer.
* also to derived information so as to write into a .csv file.

*******************************************************************************/

#ifndef TransportLayerInformation_H
#define TransportLayerInformation_H

#include<iostream>

using namespace std;

enum protocolType {TCP, UDP, OTHER};

struct TransportLayerInformation{
	
	protocolType protocol;		// can be used as filter tap to read or ignore information from this structure.
	unsigned short sourcePort, destinationPort;	// contains port addresses if protol is TCP or UDP else contains garbage value.
	
//The below two funtions write addresses into result array, to write into file.
	void getFormatedSource(unsigned char result[])
	{

		snprintf((char *)result, 5, "%02x", ntohl(sourcePort));
	}

	void getFormatedDestination(unsigned char result[])
	{
		snprintf((char *)result, 5, "%02x", ntohl(destinationPort));
	}

	TransportLayerInformation() { }
};


#endif //TransportLayerInformation_H
