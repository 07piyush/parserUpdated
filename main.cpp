/******************************************************************************
* This file is part of c++ assignment 2 and assignment 3.
* This Project contains two main classes:

	Engine: That drive PCapParser for a file.
	PCapParser: Class that run on a pcap file and generate statistics.

* Engine is the driver of the class PCapParser class.
* Engine class Responsibilities:
	* Take source folder to look for pcap files.
	* Take destination folder to store csv files created.
	* List existing pcap files in the folder, run PCapParser over them.
	* Watch over the source folder for any new file.
* PCapParser is runner, that run of a pcap file.
	* parse a pacap file, and retrieve information of each packet,
	* write derived information into a .csv file.

*******************************************************************************/



#include <iostream>
#include <fstream>
#include <pthread.h>
#include "includes/Engine.h"
#include <queue>
#include <pthread.h>
#include <chrono>

using namespace std;

// Global variable to be used in Engine.start() to maintain a queue of waiting files while previous are
// being processed.
queue<string> remainingFiles;
pthread_mutex_t lock;

void updateRemainingFiles(string operationOrFile)
{
	pthread_mutex_lock(&lock);
	if(operationOrFile == "pop")
	{
		remainingFiles.pop();
	}
	else
	{
		remainingFiles.push(operationOrFile);
	}
	pthread_mutex_unlock(&lock);
}


int main()
{
	Engine engine;
	engine.loadAlreadyProcessed();
	engine.initialize(); //ask for source folder, destination folder;
	engine.start();
	engine.writeAlreadyProcessed();

    return 0;
}

