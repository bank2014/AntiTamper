#pragma once
#include <malloc.h>
#include "struct.h"
#include <intrin.h>

namespace string_typeCast
{
	template <typename str_type>
	inline  int str_length(str_type string) {
		int result = 0;
		for (int i = 0; string[i] != '\0'; result++, i++)
		{

		}
		return result;
	}

	inline wchar_t* CharToWChar_T(char* str) {
		int length = str_length(str);

		if (str == nullptr) {
			return nullptr;
		}

		wchar_t* wstr_t = (wchar_t*)malloc(sizeof(wchar_t) * length + 2);

		for (int i = 0; i < length; i++) {
			wstr_t[i] = str[i];
		}
		wstr_t[length] = '\0';
		return wstr_t;
	}

}







