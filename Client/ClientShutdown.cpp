#include "pch.h"
#include "ClientShutdown.h"

#include <string>
#include <thread>

namespace AntiTamperShutdown
{
	namespace
	{
		struct EnumContext
		{
			DWORD processId = 0;
			bool postClose = false;
			int posted = 0;
			int visibleWindows = 0;
		};

		BOOL CALLBACK VisitProcessWindow(HWND hwnd, LPARAM lParam)
		{
			EnumContext* context = reinterpret_cast<EnumContext*>(lParam);
			if (context == nullptr || !::IsWindowVisible(hwnd))
				return TRUE;

			DWORD windowProcessId = 0;
			::GetWindowThreadProcessId(hwnd, &windowProcessId);
			if (windowProcessId != context->processId)
				return TRUE;

			++context->visibleWindows;
			if (context->postClose)
			{
				::PostMessageW(hwnd, WM_CLOSE, 0, 0);
				++context->posted;
			}
			return TRUE;
		}

		EnumContext EnumerateProcessWindows(bool postClose)
		{
			EnumContext context;
			context.processId = ::GetCurrentProcessId();
			context.postClose = postClose;
			::EnumWindows(VisitProcessWindow, reinterpret_cast<LPARAM>(&context));
			return context;
		}

		constexpr DWORD kWarningTimeoutMs = 3000;

		void ShowWarningAsync(const std::wstring& text)
		{
			try
			{
				std::thread([text]() {
					::MessageBoxW(nullptr, text.c_str(), L"AntiTamper", MB_OK | MB_ICONWARNING);
				}).detach();
			}
			catch (...)
			{
			}
		}

		void ShowWarningBeforeShutdown(const wchar_t* message)
		{
			const std::wstring text = (message != nullptr && message[0] != L'\0')
				? message
				: L"AntiTamper requested application shutdown.";

			using MessageBoxTimeoutWFn = int(WINAPI*)(HWND, LPCWSTR, LPCWSTR, UINT, WORD, DWORD);
			HMODULE user32 = ::GetModuleHandleW(L"user32.dll");
			MessageBoxTimeoutWFn messageBoxTimeout = user32 == nullptr
				? nullptr
				: reinterpret_cast<MessageBoxTimeoutWFn>(::GetProcAddress(user32, "MessageBoxTimeoutW"));
			if (messageBoxTimeout != nullptr)
			{
				messageBoxTimeout(
					nullptr,
					text.c_str(),
					L"AntiTamper",
					MB_OK | MB_ICONWARNING | MB_SETFOREGROUND,
					0,
					kWarningTimeoutMs);
				return;
			}

			ShowWarningAsync(text);
			::Sleep(250);
		}
	}

	bool RequestHostShutdown(const wchar_t* message, int fallbackExitCode)
	{
		ShowWarningBeforeShutdown(message);

		const EnumContext closeAttempt = EnumerateProcessWindows(true);
		if (closeAttempt.posted > 0)
		{
			const DWORD deadline = ::GetTickCount() + 5000;
			while (::GetTickCount() < deadline)
			{
				if (EnumerateProcessWindows(false).visibleWindows == 0)
					return true;
				::Sleep(100);
			}
		}

		::ExitProcess(static_cast<UINT>(fallbackExitCode));
		return false;
	}
}
