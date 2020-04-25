/**********************************************************************************

* This file is part of c++ assignment 2 and assignment 3.
* This file is declaration of structure "NetworkLayerInformation".
* This structure is used to store information that are retrieved from pcap file at network layer level.
* Objective of this structure is to provide abstract form store port IP addresses and define protocol for this layer.
* also to derived information so as to write into a .csv file.

*******************************************************************************/

#ifndef NetworkLayerInformation_H
#define NetworkLayerInformation_H

#define IP_ADDR_FORMAT_LEN 50
#include "IPv6.h"
#include <arpa/inet.h>

using namespace std;


union IPaddress{	//An address retrieved from pcap will be either version 4 or 6.
		unsigned int ipv4;
		IPv6 ipv6;
};


struct NetworkLayerInformation{

	IPaddress source, destination;	// a source and destination can have different ip version
	unsigned char protocol;		// to identify wheather a packet is either ipv4 or ipv6 determined from DataLink layer.
	bool isIPv4;

	void printAddresses() { //Addresses are first formated by helper funtions and then printed

		unsigned char address[ IP_ADDR_FORMAT_LEN ];
		getFormatedIPv4SourceAddress(address);
		cout <<"Source IP: " << address << endl;
		getFormatedIPv4DestinationAddress(address);
		cout <<"Destination IP: "<< address << endl;
	}
	
	//Helper funtion used to convert binary form of address into represtable format and save in result array
	// provided by callee.
	void getFormatedIPv4SourceAddress(unsigned char result[]){
		unsigned char *temporaryPointer = (unsigned char *)&source.ipv4;
		int index = 0;
		unsigned short value;
		for(int byte = 0; byte < 3; byte++){
			
			index += snprintf((char *)result+index, 5, "%d.", temporaryPointer[byte]);
		}
		value = temporaryPointer[3];
		index += snprintf((char *)result+index, 5, "%d", value);
	}

	//Helper funtion used to convert binary form of address into represtable format and save in result array
	// provided by callee.
	void getFormatedIPv4DestinationAddress(unsigned char result[]){
		unsigned char *temporaryPointer = (unsigned char *)&destination.ipv4;
		int index = 0;
		unsigned short value;
		for(int byte = 0; byte < 3; byte++){
			
			index += snprintf((char *)result+index, 5, "%d.", temporaryPointer[byte]);
		}
		value = temporaryPointer[3];
		index += snprintf((char *)result+index, 5, "%d", value);
	}

	NetworkLayerInformation() {	}

	~NetworkLayerInformation(){  }

};


#endif //NetworkLayerInformation
