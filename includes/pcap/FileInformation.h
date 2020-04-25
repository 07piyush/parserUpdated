#ifndef FileInformation_H
#define FileInformation_H

#include<iostream>
#include "PacketsInformation/IPv6.h"
//#include<map>

using namespace std;

struct FileInformation{

/* For each PCAP file there will be only one object of this structure
* as this structure will give over all information of one pcap file, that is being parsed.
* The overall information includes:
*
*	Name of pcap file.
*	Total Number of IPv4 packets.
*	Total Number of IPv6 packets.
*	Total Number of TCP packets.
*	Total Number of UDP packets.
*
*/

	const unsigned char * theFileName; // will point to name, read by user.
	unsigned int IPv4PacketsCount;
	unsigned int IPv6PacketsCount;
	unsigned int TCPpacketsCount;
	unsigned int UDPpacketsCount;
	unsigned int fileSize;
	
	FileInformation(){

	    IPv4PacketsCount = 0;
	    IPv6PacketsCount = 0;
	    TCPpacketsCount = 0;
	    UDPpacketsCount = 0;
	    fileSize = 0;
	}

	~FileInformation() { 	}
	
};



#endif
