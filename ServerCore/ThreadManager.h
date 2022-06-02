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
	void	Launch(function<void(void)> callback);

	static void InitTLS();
	static void DestroyTLS();

private:
	vector<thread>	_threads;
	Mutex			_lock;

};

