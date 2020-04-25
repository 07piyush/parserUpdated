#ifndef LinkLayerInformation_H
#define LinkLayerInformation_H

#include<iostream>

using namespace std;

struct LinkLayerInformation{
	
	unsigned char destination[6],
		       source[6];
	unsigned short connectionType;
	bool nextIsIP;

	LinkLayerInformation() {
		source[0] = '\0';
		destination[0] = '\0';
		connectionType = 0;
	 }
	
	void getSourceAddressFormated(unsigned char result[]){
		unsigned char value;
		int index = 0;
		for(int byte = 0; byte < 5; byte++){
			value = source[byte];
			index += snprintf((char *)result+index, 4, "%x:", value);
		}
		value = source[5];
		index += snprintf((char *)result+index, 4, "%x", value);
	}
	
	void getDestinationAddressFormated(unsigned char result[]){
		unsigned char value;
		int index = 0;
		for(int byte = 0; byte < 5; byte++){
			value = destination[byte];
			index += snprintf((char *)result+index, 4, "%x:", value);
		}
		value = destination[5];
		index += snprintf((char *)result+index, 4, "%x", value);
	}


	~LinkLayerInformation() { }
    
};


#endif //LinkLayerInformation
