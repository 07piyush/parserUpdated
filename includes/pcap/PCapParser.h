/**********************************************************************************

* This file is part of c++ assignment 2 and assignment 3.
* This file is declaration of class "PCapParser".
* This class will be accessed by another class "pcap" declared in 'pcap.h' file.
* Objective of this class is to parse a pacap file, and retrieve information of each packet in it.
* also to write derived information into a .csv file.
* This class uses three structure to store necessary information from each layer of TCP/IP model.
* Following structure are used for specific layer:

		'LinkLayerInformation'		: defined in LinkLayerInformation.h
		'NetworkLayerInformation'	: defined in NetworkLayerInformation.h
		'TransportLayerInformation'	: defined in TransportLayerInformation.h

* Details to each of these structures are well explained in their respective files.
*
*******************************************************************************/


#ifndef PCapParser_H
#define PCapParser_H


#include "FileInformation.h"
#include "PacketInformation.h"
#include "PacketsInformation/IPv6.h"
#include <fstream>
#include <unordered_map>
#include <map>

#define MAX_FILE_NAME_LEN 255


class PCapParser{

	public:
	        FileInformation parse(char fileName[], int length);
		void setCsvDestinationPath(char destinationDir[]);
	
		// will create csv in default dir.
	        PCapParser() { csvFileInfo[0] = '\0'; csvIPinfo=NULL; csvDestinationPath=NULL; ipv6Count; ipv4Count; } 
		PCapParser(char destinationFolder[]);	//used if a destination folder is to be choose to store .csv file.

		~PCapParser() {

		delete[] csvIPinfo;
		delete[] csvDestinationPath;
	}

	private:
		std::ifstream::pos_type getFileSize(char fileName[]);
	        void createCSVfile();
	        void writeInfoToCSV(PacketInformation packetInfo, unsigned int serialNumber);
		void writeInfoToCSV(FileInformation fileInfo);
	        void printFileInformation(unsigned int packetCount);

	private:
		char pcapFileName[MAX_FILE_NAME_LEN], 
		     pcapFilePath[MAX_FILE_NAME_LEN];	// will be set by either listing files in a folder, or by inotify.

		char csvFileInfo[MAX_FILE_NAME_LEN],	//just name of csv file
		     *csvIPinfo,		        //just name of csv file
		     *csvDestinationPath;           	// just directory path, of destination folder for csv.

	    unordered_map<IPv6, unsigned int> ipv6Count;
	    map<unsigned int, unsigned int> ipv4Count;
	    FileInformation fileInfo;

};




#endif
