#include "pch.h"
#include "SingleInstanceGuard.h"

namespace BackendUi
{
	SingleInstanceGuard::SingleInstanceGuard(const wchar_t* mutexName, const wchar_t* windowClassName)
		: _windowClassName(windowClassName)
	{
		::SetLastError(ERROR_SUCCESS);
		_mutex = ::CreateMutexW(nullptr, TRUE, mutexName);
		if (_mutex == nullptr)
		{
			::MessageBoxW(nullptr, L"Could not create the backend single-instance guard.", L"AntiTamper Backend", MB_OK | MB_ICONERROR);
			return;
		}

		if (::GetLastError() == ERROR_ALREADY_EXISTS)
		{
			::CloseHandle(_mutex);
			_mutex = nullptr;
			FocusExistingWindow();
			return;
		}

		_acquired = true;
	}

	SingleInstanceGuard::~SingleInstanceGuard()
	{
		if (_mutex == nullptr)
			return;

		::ReleaseMutex(_mutex);
		::CloseHandle(_mutex);
	}

	bool SingleInstanceGuard::Acquired() const
	{
		return _acquired;
	}

	void SingleInstanceGuard::FocusExistingWindow() const
	{
		HWND existing = ::FindWindowW(_windowClassName, nullptr);
		if (existing == nullptr)
			return;

		::ShowWindow(existing, SW_RESTORE);
		::SetForegroundWindow(existing);
	}
}
