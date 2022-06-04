#pragma once

#include "Types.h"		/* Types.h 에 포함
							#include <mutex>
							#include <atomic>
						*/
#include "CoreMacro.h"
#include "CoreTLS.h"
#include "CoreGlobal.h"
#include "Container.h"	/* Container.h 에 포함
							#include <vector>
							#include <list>
							#include <queue>
							#include <stack>
							#include <map>
							#include <set>
							#include <unordered_map>
							#include <unordered_set>
						*/

#define _WINSOCKAPI_
#include <windows.h>
#include <iostream>
using namespace std;

#include "Lock.h"

#include "ObjectPool.h"
#include "TypeCast.h"

#include <winsock2.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")