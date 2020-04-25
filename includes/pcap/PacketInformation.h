#ifndef PacketInformation_H
#define PacketInformation_H

#include<iostream>
#include "PacketsInformation/LinkLayerInformation.h"
#include "PacketsInformation/NetworkLayerInformation.h"
#include "PacketsInformation/TransportLayerInformation.h"

using namespace std;


struct PacketInformation{

	LinkLayerInformation theDataLinkLayer; // will be used
	NetworkLayerInformation theNetworkLayer; // to write information
	TransportLayerInformation theTrasportLayer; // in csv file.

	PacketInformation() {}
	~PacketInformation() {}	

};


#endif
