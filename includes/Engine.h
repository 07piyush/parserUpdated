#include "pcap/PCapParser.h"
#include <vector>
#include <queue>
#include <chrono>
#include <unordered_set>


#ifndef Engine_H
#define Engine_H
#define MAX_FILE_LEN 100

/******************************************************************************
* This file is part of c++ assignment 2 and assignment 3.
* This file is declaration of class "Engine".
* Engine is the driver of the class PCapParser class.
* class Responsibilities:
	* Take source folder to look for pcap files.
	* Take destination folder to store csv files created.
	* List existing pcap files in the folder, run PCapParser over them.
	* Watch over the source folder for any new file.
* Functionality of Watcher is moduled in seperate funtion. : "void *watchSourceFolder(void *sourceFolder)"
*******************************************************************************/

struct Timer
{
	std::chrono::time_point<std::chrono::high_resolution_clock> start, end;
	std::chrono::duration<float> duration;

	Timer()
	{
		start = std::chrono::high_resolution_clock::now();
		
	}

	~Timer()
	{
		end = std::chrono::high_resolution_clock::now();
		duration = end - start;

		cout << chrono::duration_cast<chrono::microseconds>(end - start).count() << " ms" << endl;
	
	}
};


class Engine{

	public:
        	void initialize(); //will input and save values of data members
	
		void start();	  //will list all present files and start parsing each one in thread pool.
				  //will also check for any new file in sourceFolder folder.

		void loadAlreadyProcessed();	// will populate alreadyProcessed data member.
		void writeAlreadyProcessed();   // will write alreadyProcessed files into a file to skip parsing them.
		void setDestinationFolder(char destinationFolder[]);
		
        	Engine() { strcpy(sourceFolder, ""); strcpy(destinationFolder, ""); }

	~Engine() { }

	private:
		int getFiles(vector<string> &files);
		static void *watchSourceFolder(void *sourceFolder);
		void removeDeletedPcapFromMeta(vector<string> &files);
		//member functions		

	private: //data members
		char sourceFolder[MAX_FILE_LEN], destinationFolder[MAX_FILE_LEN];   // will be given by user.
		unordered_set<string> alreadyProcessed;
		pthread_t pthreadid;	
			
};

#endif
