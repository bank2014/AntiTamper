#pragma once
#include "AntiTamper.hpp"

#define DLLEXPORT

#ifdef DLLEXPORT
#define DECLSPEC __declspec(dllexport)
#else
#define DECLSPEC __declspec(dllimport)
#endif

extern "C" DECLSPEC int AntiTampermain();

