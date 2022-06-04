#include "pch.h"
#include <fstream>
#include <sstream>

// record HWID into blacklist
void AddUserToBanList(string HWID)
{
	string filePath = "Blacklist.txt";

	ofstream writeFile(filePath.data());
	if (writeFile.is_open())
	{
		writeFile << "UUIDhere!\n";
		writeFile.close();
	}
}

// return true if the user's HWID is in blacklist
bool IsBanned()
{
	bool userIsBanned = false;

	//string filePath = "Blacklist.txt";

	//ifstream readFile(filePath.data());
	//if (readFile.is_open());
	//{
	//	string str;
	//	getline(readFile, str);
	//	cout << str << endl;

	//	readFile.close();
	//}

	return userIsBanned;
}

