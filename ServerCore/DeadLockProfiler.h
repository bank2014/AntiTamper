#pragma once
#include <stack>
#include <map>
#include <vector>

/*--------------------
	DeadLockProfiler
---------------------*/

class DeadLockProfiler
{
public:
	// TODO
	void PushLock();
	void PopLock();
	void CheckCycle();

private:
	void Dfs();

private:
	// TODO
};

