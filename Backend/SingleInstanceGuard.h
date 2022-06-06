#pragma once

#include <windows.h>

namespace BackendUi
{
	class SingleInstanceGuard
	{
	public:
		SingleInstanceGuard(const wchar_t* mutexName, const wchar_t* windowClassName);
		~SingleInstanceGuard();

		SingleInstanceGuard(const SingleInstanceGuard&) = delete;
		SingleInstanceGuard& operator=(const SingleInstanceGuard&) = delete;

		bool Acquired() const;

	private:
		void FocusExistingWindow() const;

		const wchar_t* _windowClassName;
		HANDLE _mutex = nullptr;
		bool _acquired = false;
	};
}
