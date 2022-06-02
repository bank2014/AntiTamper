#include "pch.h"
#include "CoreGlobal.h"
#include "ThreadManager.h"
#include "Memory.h"
#include "DeadLockProfiler.h"

ThreadManager*		GThreadManager = nullptr;
Memory*				GMemory = nullptr;
DeadLockProfiler*	GDeadLockProfiler = nullptr;

class CoreGlobal
{
public:
	CoreGlobal()
	{
		GThreadManager = new ThreadManager();
		GMemory = new Memory();
		GDeadLockProfiler = new DeadLockProfiler();
	}

	~CoreGlobal()
	{
		delete GThreadManager;
		delete GMemory;
		delete GDeadLockProfiler;
	}
} GCoreGlobal;