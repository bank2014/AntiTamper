#pragma once

#include <thread>
#include <functional>

/*------------------
	ThreadManager
-------------------*/

class ThreadManager
{
public:
	ThreadManager();
	~ThreadManager();

	void	Join();
	// TODO launch

	static void InitTLS();
	static void DestroyTLS();

private:
	vector<thread>	_threads;
	
};

