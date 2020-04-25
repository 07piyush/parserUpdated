#include <iostream>
#include <fstream>
#include <sstream>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <arpa/inet.h>
#include <string>
#include "includes/pcap/PCapParser.h"
#include "includes/pcap/PacketsInformation/IPv6.h"

#define GLOBAL_HEADER_SIZE 24
#define PACKET_HEADER_SIZE 16
#define MAC_ADDR_FORMAT_LEN 18
#define IP_ADDR_FORMAT_LEN 50
#define TCP_ADDR_FORMAT_LEN 6
#define UDP_ADDR_FORMAT_LEN 6
#define MAX_TRY 3

using namespace std;


ifstream::pos_type PCapParser::getFileSize(char fileName[])
{
	
	ifstream in (fileName, ifstream::ate | ifstream::binary);
	int size = (int)in.tellg();
	in.close();
	return size;
}

PCapParser::PCapParser(char destinationFolder[]){
	csvFileInfo[0] = '\0';
	csvIPinfo=NULL;
	setCsvDestinationPath(destinationFolder);
	ipv6Count;
	ipv4Count;
}


void PCapParser::setCsvDestinationPath(char destinationFolder[]){
	
	csvDestinationPath = new char [strlen(destinationFolder)];
	strcpy(csvDestinationPath, destinationFolder);

}


FileInformation PCapParser::parse(char fileName[], int lengthOfFileName)
{					
	strcpy(pcapFilePath, fileName); // 'pcapFilePath': exact location of file(Path + file's Name)

	const char *pcapFile = strrchr(fileName, '/'); // last occurance of '/' to get file's name.
	strcpy(pcapFileName, pcapFile+1);	// 'pcapFileName' : just name of file

	cout << endl << "**** " << pcapFileName << " ****" << endl << endl;

	unsigned int fileTypeMagicNumber,
		     packetCount = 0;
		
	fileInfo.fileSize = (unsigned int) getFileSize(fileName);
	fileInfo.fileSize = fileInfo.fileSize - GLOBAL_HEADER_SIZE;

	ifstream myfile;
	myfile.open(fileName, ifstream::binary);
	
	myfile.read((char*) &fileTypeMagicNumber, 4);

	myfile.seekg(20, ios::cur);	// global header ends here

	while (fileInfo.fileSize > 0)
	{
		// while EOF is not encountered, do following for each packet

		//if(fileInfo.fileSize > (GLOBAL_HEADER_SIZE + PACKET_HEADER_SIZE)) break;

		//1. Packet Header
		//a. skip 8(4+4) bytes and then,
		//b. read incl_len.
		//c. skip next 4 bytes, packet header ends.
		//2. Packet Data: File contains exactly incl_len bytes of data.
		//a. get source mac first 6 bytes.
		//b. get destination mac

		PacketInformation packetInfo;

		packetCount++;

		myfile.seekg(8, ios::cur);	// a. skip 8(4+4) bytes and then,
		unsigned int packetLength = 1, pkl;

		myfile.read((char*) &packetLength, 4);	// b. read incl_len.

		pkl = packetLength;
		fileInfo.fileSize = fileInfo.fileSize - (pkl + PACKET_HEADER_SIZE);
		
		myfile.seekg(4, ios::cur);	// c skip next 4 bytes, packet header ends.

		//PacketBody starts
		//a. get destination mac first 6 bytes.
		myfile.read((char*) &packetInfo.theDataLinkLayer.destination, 6);
		packetLength = packetLength - 6;

		//a. get source mac 6 bytes.
		myfile.read((char*) &packetInfo.theDataLinkLayer.source, 6);
		packetLength = packetLength - 6;

		//Ethernet header ends
		myfile.read((char*) &packetInfo.theDataLinkLayer.connectionType, 2);
		packetLength = packetLength - 2;

		if (ntohl(packetInfo.theDataLinkLayer.connectionType) == 0x8000000)
		{
			//IPv4 packet
			packetInfo.theDataLinkLayer.nextIsIP = true;
			packetInfo.theNetworkLayer.isIPv4 = true;

			fileInfo.IPv4PacketsCount++;

			// skip according to IPv4 header 
			myfile.seekg(9, ios::cur);
			packetLength = packetLength - 9;

			myfile.read((char*) &packetInfo.theNetworkLayer.protocol, 1);
			packetLength = packetLength - 1;

			myfile.seekg(2, ios::cur);
			packetLength = packetLength - 2;	// skip according to IPv4 header

			myfile.read((char*) &packetInfo.theNetworkLayer.source.ipv4, 4);
			packetLength = packetLength - 4;

			myfile.read((char*) &packetInfo.theNetworkLayer.destination.ipv4, 4);
			packetLength = packetLength - 4;
			// IP header ends here

			ipv4Count[packetInfo.theNetworkLayer.source.ipv4]++;
			ipv4Count[packetInfo.theNetworkLayer.destination.ipv4]++;

			if (packetInfo.theNetworkLayer.protocol == 6 || packetInfo.theNetworkLayer.protocol == 17)
			{

				if (packetInfo.theNetworkLayer.protocol == 17)
					fileInfo.UDPpacketsCount++;
				else
					fileInfo.TCPpacketsCount++;

				myfile.read((char*) &packetInfo.theTrasportLayer.sourcePort, 2);
				packetLength = packetLength - 2;

				myfile.read((char*) &packetInfo.theTrasportLayer.destinationPort, 2);
				packetLength = packetLength - 2;

				myfile.seekg(4, ios::cur);
				packetLength = packetLength - 4;	//Transport layer Data unit header ends 

			
			}

			myfile.seekg(packetLength, ios::cur);
		}
		else if (ntohl(packetInfo.theDataLinkLayer.connectionType) == 0x86DD0000)
		{
			packetInfo.theDataLinkLayer.nextIsIP = true;
			unsigned int payloadLen;

			packetInfo.theNetworkLayer.isIPv4 = false;

			myfile.seekg(4, ios::cur);
			packetLength = packetLength - 4;

			myfile.read((char*) &payloadLen, 2); // it is the rest of the packet that follows the IPv6 header, in octets.
			packetLength = packetLength - 2;

			myfile.read((char*) &packetInfo.theNetworkLayer.protocol, 1);
			packetLength = packetLength - 1;
			
			myfile.seekg(1, ios::cur); // hop limit
			packetLength = packetLength - 1;


			myfile.read((char*) &packetInfo.theNetworkLayer.source.ipv6.address, 16);
			packetLength = packetLength - 16;

			myfile.read((char*) &packetInfo.theNetworkLayer.destination.ipv6.address, 16);
			packetLength = packetLength - 16;


			if (packetInfo.theNetworkLayer.protocol == 17 || packetInfo.theNetworkLayer.protocol == 6)
			{

				if (packetInfo.theNetworkLayer.protocol == 17)
					fileInfo.UDPpacketsCount++;
				else
					fileInfo.TCPpacketsCount++;

				myfile.read((char*) &packetInfo.theTrasportLayer.sourcePort, 2);
				packetLength = packetLength - 2;

				myfile.read((char*) &packetInfo.theTrasportLayer.destinationPort, 2);
				packetLength = packetLength - 2;

				myfile.seekg(4, ios::cur);
				packetLength = packetLength - 4;	//Transport layer Data unit header ends 

			}

			fileInfo.IPv6PacketsCount++;
			myfile.seekg(packetLength, ios::cur);


			ipv6Count[packetInfo.theNetworkLayer.source.ipv6]++;
			ipv6Count[packetInfo.theNetworkLayer.destination.ipv6]++;
		}
		else
		{
			packetInfo.theDataLinkLayer.nextIsIP = false;
			myfile.seekg(pkl - 14, ios::cur);
		}
			
		writeInfoToCSV(packetInfo, packetCount);

	}//end of while
	
	
	myfile.close();

	writeInfoToCSV(fileInfo);

	printFileInformation(packetCount);

	

}

void PCapParser::createCSVfile() {

	
}

void PCapParser::writeInfoToCSV(PacketInformation packetInfo, unsigned int serialNumber)
{

	char fileNameCsv[MAX_FILE_NAME_LEN] = "";
	int dotPos = strrchr(pcapFileName, '.') - pcapFileName;
	strncpy(fileNameCsv, pcapFileName, dotPos);
	strcat(fileNameCsv, "_PacketsInfo.csv");
	
	strcpy(csvFileInfo, fileNameCsv);

	char csvFileCompletePath[MAX_FILE_NAME_LEN] = "";
	strcat(csvFileCompletePath, csvDestinationPath);
	strcat(csvFileCompletePath, "/");
	strcat(csvFileCompletePath, csvFileInfo);

	fstream fout;
	fout.open(csvFileCompletePath, ios::out | ios::app);

	unsigned char sourceMAC[MAC_ADDR_FORMAT_LEN],
	 	destinationMAC[MAC_ADDR_FORMAT_LEN],
	 	sourceIP[IP_ADDR_FORMAT_LEN],
	 	destinationIP[IP_ADDR_FORMAT_LEN],
	 	transportType[4],
	 	sourcePort[TCP_ADDR_FORMAT_LEN],
	 	destinationPort[TCP_ADDR_FORMAT_LEN];
	
	packetInfo.theDataLinkLayer.getSourceAddressFormated(sourceMAC);
	packetInfo.theDataLinkLayer.getDestinationAddressFormated(destinationMAC);

	if( packetInfo.theDataLinkLayer.nextIsIP == true )
	{
		if(packetInfo.theNetworkLayer.isIPv4)
		{
			packetInfo.theNetworkLayer.getFormatedIPv4SourceAddress(sourceIP);
			packetInfo.theNetworkLayer.getFormatedIPv4DestinationAddress(destinationIP);
		}
		else
		{
			packetInfo.theNetworkLayer.source.ipv6.getaddressFormated(sourceIP);
			packetInfo.theNetworkLayer.destination.ipv6.getaddressFormated(destinationIP);
		}
	}
	else
	{
		strcpy((char *)sourceIP,"NA");
		strcpy((char *)destinationIP,"NA");
	}
	
	if(packetInfo.theNetworkLayer.protocol == 6 )
	{
		strcpy((char *)transportType,"TCP");
		packetInfo.theTrasportLayer.getFormatedSource(sourcePort);
		packetInfo.theTrasportLayer.getFormatedDestination(destinationPort);
	}
		

	else if(packetInfo.theNetworkLayer.protocol == 17)
	{
		strcpy((char *)transportType,"UDP"); 
		packetInfo.theTrasportLayer.getFormatedSource(sourcePort);
		packetInfo.theTrasportLayer.getFormatedDestination(destinationPort);
	}
	else
	{
		strcpy((char *)sourcePort,"NA");
		strcpy((char *)destinationPort,"NA");
	}
	
	
	fout << serialNumber << ", " <<
			 sourceMAC << ", " <<
			 destinationMAC << ", " <<
			 sourceIP << ", " <<
			 destinationIP << ", " <<
			 transportType << ", " <<
			 sourcePort << ", " <<
			 destinationPort << ", " <<
			"\n";
	

	/*cout<< endl << " \t **** Packet #" << serialNumber << " ****" << endl
			<<"source MAC: "<< sourceMAC << endl
			<<"destination MAC: "<< destinationMAC << endl
			<<"source IP: "<< sourceIP << endl
			<<"destination IP: "<< destinationIP << endl
			<<"transport Type: "<< transportType << endl
			<<"sourcePort : "<< sourcePort << endl
			<<"destinationPort : "<< destinationPort << endl;
	*/

}

void PCapParser::writeInfoToCSV(FileInformation fileInfo)
{

	char fileNameCsv[MAX_FILE_NAME_LEN] = "";	//get initials of file name	
	int dotPos = strrchr(pcapFileName, '.') - pcapFileName;	//get position of .(file extension)
	strncpy(fileNameCsv, pcapFileName, dotPos);	//remove .pcap from file
	strcat(fileNameCsv, "_IPcount.csv");		// update file name having .csv extension
	
	cout<<"fileNameCsv: "<<fileNameCsv<<endl;	
	char csvFileCompletePath[MAX_FILE_NAME_LEN] = "";
	strcat(csvFileCompletePath, csvDestinationPath);
	strcat(csvFileCompletePath, "/");
	strcat(csvFileCompletePath, fileNameCsv);
	
	csvIPinfo = new char[sizeof(strlen(fileNameCsv))];
	strcpy(csvIPinfo, fileNameCsv);

	fstream fout;
	fout.open(csvFileCompletePath, ios::out | ios::trunc);
	
	cout<<"Writing to: "<<csvFileCompletePath<<endl;

	int serialNumber = 1;
	for (pair<IPv6, unsigned int > keyVal: ipv6Count)
	{
		unsigned char *result = new unsigned char[IP_ADDR_FORMAT_LEN];
		fout << serialNumber++ << ", " <<
			keyVal.first.getaddressFormated(result) << ", " <<
			keyVal.second <<
			"\n";
		delete[] result;
	}

	for (pair < unsigned int, unsigned int > keyVal: ipv4Count)
	{

		unsigned char address[16];
		int index = 0;
		unsigned char *temporaryPointer = (unsigned char *) &keyVal.first;

		for (int byte = 0; byte < 3; byte++)
		{
			index += snprintf((char*) address + index, 5, "%d.", temporaryPointer[byte]);
		}
		index += snprintf((char*) address + index, 5, "%d", temporaryPointer[3]);

		fout << serialNumber++ << ", "
			<< address
			<< ", "
			<< keyVal.second
			<< "\n";
	}
}


void PCapParser::printFileInformation(unsigned int packetCount) {

	printf("\n\n****File info ****\n");
	printf("Unique IPv4 addresses: %lu \n", ipv4Count.size());
	printf("Unique IPv6 addresses: %lu \n", ipv6Count.size());
	printf("Total IPv6 packets: %d \n", fileInfo.IPv6PacketsCount);
	printf("Total IPv4 packets: %d \n", fileInfo.IPv4PacketsCount);	
	printf("Total Packets Count: %d\n\n", packetCount);
}
