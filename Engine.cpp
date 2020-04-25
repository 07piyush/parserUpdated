/******************************************************************************
* Funtions definitions in this file:
	* void Engine::initialize()
	* void Engine::start()
	* void *Engine::watchSourceFolder(void *sourceFolder)
	* int Engine::getFiles(vector<string> &files)
	* void Engine::setDestinationFolder(char destinationFolder[])
	

* Global variable: queue<string> remainingFiles.
* Static data member: pthread_mutex_t Engine::mutex. 
	
*******************************************************************************/

#include <iostream>
#include <cstring>
#include <vector>
#include <queue>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <fstream>
#include <algorithm>
#include <sys/inotify.h>
#include <unistd.h>
#include "includes/pcap/PCapParser.h"
#include "includes/Engine.h"


using namespace std;

#define MAX_PATH_LEN    255
#define NAME_LEN 	32
#define EVENT_SIZE	(sizeof(struct inotify_event))
#define BUF_LEN 	1024 *(EVENT_SIZE + NAME_LEN + 1)
#define MAX_FILE_NAME_LEN 255
#define META_FILE "meta/meta.txt"
#define EXCLUDE_FILE_LEN_CRITERIA 6

extern queue<string> remainingFiles;
extern void updateRemainingFiles(string operationOrFile);

void Engine::initialize()
{
	//This funtion simply read source folder and destination folder from user.
	// and set its values to data members.

	char path[MAX_PATH_LEN] = "/home/sharma7/Documents/PcapFiles";
	struct stat statbuf;
	int isDir = 0;
	

	while (true)
	{
		cout << "Enter folder path to process: /home/sharma7/Documents/PcapFiles" << endl;
		//cin>>path;

		if (stat(path, &statbuf) != -1)
		{
			if (S_ISDIR(statbuf.st_mode))
			{
				//sourceFolder = new char[strlen(path) + 1 ];
				strcpy(sourceFolder, path);
				break;
			}
		}
		else
		{
			cout << "Incorrect path!" << endl;
			/*
			   here you might check errno for the reason, ENOENT will mean the path
			   was bad, ENOTDIR means part of the path is not a directory, EACCESS     
			   would mean you can't access the path. Regardless, from the point of 
			   view of your app, the path is not a directory if stat fails. 
			*/
		}
	}
	
	while (true)
	{
		cout << "Enter folder path to store Statistics: /home/sharma7/Documents/experiment" << endl;
		//cin>>path;
		strcpy(path, "/home/sharma7/Documents/experiment");
		if (stat(path, &statbuf) != -1)
		{
			if (S_ISDIR(statbuf.st_mode))
			{
				//destinationFolder = new char[strlen(path) + 1];
				strcpy(destinationFolder, path);
				break;
			}
		}
		else
		{
			cout << "Incorrect path!" << endl;
		}
	}

}


void Engine::start()
{
	/*This is driver of the whole Engine.
	   Following are the tasks it perform.
		1) Initialize seperate thread for inotify to watch over sourceFolder.
		2) get list of all existing pcap files in the souce folder, store them in vector: files.

	*/
	vector<string> files;
	files.reserve(10);

	pthread_create(&pthreadid, NULL, watchSourceFolder, (void *)sourceFolder);

	getFiles(files); //get the existing files in the sourceFolder		

	removeDeletedPcapFromMeta(files);

	for(string file : files){

		char filePath[MAX_FILE_NAME_LEN];

		strcpy(filePath, sourceFolder);
		strcat(filePath, "/");

		strcat(filePath, file.c_str());

		if(alreadyProcessed.find(file) == alreadyProcessed.end() ) // not present in alreadyProcessed.
		{
			
			PCapParser parser(destinationFolder);
			alreadyProcessed.insert(file);
			parser.parse(filePath, file.size());
		
		}
		
	}

	int count = 0;
	while(true) {
		
		if(!remainingFiles.empty())
		{
		
			count = 0;
			char filePath[MAX_FILE_NAME_LEN] = "";
			strcpy(filePath, remainingFiles.front().c_str());
			PCapParser parser(destinationFolder);
			
			//get just file name to insert into alreadyProcessed.
			std::size_t found = remainingFiles.front().find_last_of("/");

			string targetFile(remainingFiles.front().substr(found+1));
			alreadyProcessed.insert(targetFile);
			updateRemainingFiles("pop");
			
			parser.parse(filePath, strlen(filePath));		
		}

		else
		{
			count++;
			sleep(1);
			if(count > 5)
			{
				char ch;
				cout<<"Do you want to quit? (y/n)"<<endl;
				cin>>ch;
				if(ch == 'y' || ch == 'Y')
					break;
				else 
					count = 0;
			}
		}
	}
	sleep(3);	//if Files are being written, wait;
	return;
	
}


void Engine::loadAlreadyProcessed()
{	// will populate alreadyProcessed data member.

	fstream fin;
	fin.open(META_FILE,ios::in);
	
	if (fin.is_open())
  	{
		while(!fin.eof())
		{
			string fileName;
			getline(fin,fileName);
			if(fileName.size() > EXCLUDE_FILE_LEN_CRITERIA) // file name atleast have 1 character (a.pcap)
				alreadyProcessed.insert(fileName);
		}
		cout<< "Total files: " << alreadyProcessed.size() << endl;
	}
	else
	{
		cout << "File not opened ";
	}
	fin.close();
	
}	
void Engine::writeAlreadyProcessed()
{	
	fstream fout;
	fout.open(META_FILE, ios::out | ios::trunc);

	if (fout.is_open())
	{
		for(string file : alreadyProcessed)
		{
			fout << file << "\n";
		}
			
	}
	else
	{
		cout<< "File Entry could not be saved!"<< endl;
	}
	fout.close();
}


int Engine::getFiles(vector<string> &files)
{
// This funtion lists all existing pcap files in the souce folder, store them in vector: files.
	
	DIR * dp;
	struct dirent * dirp;
	string directory(sourceFolder);

	if ((dp = opendir(directory.c_str())) == NULL)
	{
		cout << "Error(" << errno << ") opening " << directory << endl;
		return errno;
	}

	while ((dirp = readdir(dp)) != NULL)
	{
		//check if file is .pcap file then add to vector.
		int fileNameLen = strlen(dirp->d_name);
		char *dotPtr = strchr(dirp->d_name, '.');

		if (dotPtr != NULL && strcmp(dotPtr, ".pcap") == 0)
			files.push_back(string(dirp->d_name));
	}
	
	closedir(dp);
	return 0;
}

void Engine::removeDeletedPcapFromMeta(vector<string> &files)
{
//Function remove those fileNames (that were processed previously), 
// from alreadyProcessed that has been deleted from source folder.

	std::vector<string>::iterator filesIterator;
	vector<string> removeTheseFiles;
	removeTheseFiles.reserve(10);

	for(string fileName : alreadyProcessed)
	{
		filesIterator = std::find(files.begin(), files.end(), fileName);
		
		if(filesIterator != files.end())
		{ 
			// fileName is currently in source dir. and is processed already.
		}
		else
		{	//if fileName does not exists in source dir, and marked as processed. 
			removeTheseFiles.push_back(fileName);
		}
			
	}
	for(string file : removeTheseFiles)
		alreadyProcessed.erase(alreadyProcessed.find(file));
	
}

void *Engine::watchSourceFolder(void *sourceFolder)
{

/******************************************************************************
* This funtion run on seperate thread and keep a watch on any new pcap file creation.
* as soon as a new file is created, it is parsed and .csv are stored in destination folder.

********************************************************************************/

	int length, index = 0;
	int fd;
	int wd;
	char buffer[BUF_LEN];

	fd = inotify_init();

	if (fd < 0)
	{
		perror("inotify_init");
	}

	wd = inotify_add_watch(fd, (char *)sourceFolder, IN_CLOSE_WRITE);

	while (true)
	{

		index = 0;
		length = read(fd, buffer, BUF_LEN);

		if (length < 0)
		{
			perror("read");
		}

		while (index < length)
		{

			struct inotify_event *event = (struct inotify_event *) &buffer[index];

			if (event->len)
			{

				if (event->mask &IN_CLOSE_WRITE)
				{

					if (event->mask &IN_ISDIR)
					{
						// ignore
					}
					else
					{	
						//File is created check if it is pcap, parse if is true;
						char *dotPtr = strchr(event->name, '.');

						if (dotPtr != NULL && strcmp(dotPtr, ".pcap") == 0)
						{
							
							char * filePath = new char[strlen((char *)sourceFolder) + (int)strlen(event->name) + 1]; 
							strcpy(filePath, (char *)sourceFolder);
							strcat(filePath, "/");
							strcat(filePath, event->name);
							string filePathCopy(filePath);
							updateRemainingFiles(filePathCopy);
							delete[] filePath;
						}
					}
				}
				
			}
			index += EVENT_SIZE + event->len;
		}
	}

	(void) inotify_rm_watch(fd, wd);
	(void) close(fd);
	return NULL;

}

void Engine::setDestinationFolder(char destinationFolder[]) { strcpy(this->destinationFolder, destinationFolder); }

