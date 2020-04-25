/**********************************************************************************

* This file is part of c++ assignment 2 and assignment 3.
* This file is declaration of structure "IPv6".
* This structure is used to store 128 bit address, also to represent it in appropriate format.
* Objective of this structure is to provide abstract form to work with ipv6 address.
* also to derived information so as to write into a .csv file.
* It has seperate IPv6 hasher which uses nothing but std::string hasher

*******************************************************************************/


#ifndef IPv6_H
#define IPv6_H

#include <cstring>
#include <string>
using namespace std;


struct IPv6{
	
	unsigned char address[17];	// contains exaclty 128 bit of binary of the address.

	bool operator < (const IPv6&) const;
	
	//This funtion returns and save address in format into result, array provided.
	unsigned char *getaddressFormated(unsigned char result[]){
		
		int index = 0;
		unsigned char ch1, ch2;
		for(int byte = 0; byte < 14; byte+=2){
			unsigned char ch1, ch2;
			ch1 = address[byte]; ch2 = address[byte+1];
			index += snprintf((char *)result+index, 4, "%02x", ch1);
			index += snprintf((char *)result+index, 4, "%02x:", ch2);
		}
		ch1 = address[14]; ch2 = address[15];
		index += snprintf((char *)result+index, 4, "%02x", ch1);
		index += snprintf((char *)result+index, 4, "%02x", ch2);
		

	return result;
	}
	
};

inline bool IPv6::operator<(const IPv6& rhs) const
{
	return ( strcmp((char*) &this->address, (char*) &rhs.address) < 0 );
}

namespace std
{
    template <>
    struct hash<IPv6> : public unary_function<IPv6, size_t>
    {
        size_t operator()(const IPv6& obj) const
        {
		string targetString = (char *)obj.address;
		return std::hash<std::string>()( targetString );
        }
    };


template <>
struct equal_to<IPv6> : public unary_function<IPv6, bool>
{
	bool operator()(const IPv6& x, const IPv6& y) const
	{
        	return (strcmp((char *)x.address, (char *)y.address) == 0);
	}
};

} 


#endif
