#include <windows.h>

#include <chrono>
#include <sstream>
#include <thread>

using AntiTamperEntry = int (*)();
using AntiTamperGuidEntry = const char* (*)();

namespace
{
	constexpr wchar_t kWindowClassName[] = L"AntiTamperTestClientWindow";
	constexpr UINT_PTR kElapsedTimerId = 1;
	constexpr UINT kElapsedTimerMs = 1000;

	HWND g_counterText = nullptr;
	HFONT g_counterFont = nullptr;
	std::chrono::steady_clock::time_point g_startTime;

	std::wstring AnsiToWide(const char* value)
	{
		if (value == nullptr || value[0] == '\0')
			return L"unknown-guid";

		const int required = ::MultiByteToWideChar(CP_UTF8, 0, value, -1, nullptr, 0);
		if (required <= 1)
			return L"unknown-guid";

		std::wstring result(static_cast<size_t>(required), L'\0');
		::MultiByteToWideChar(CP_UTF8, 0, value, -1, &result[0], required);
		if (!result.empty() && result.back() == L'\0')
			result.pop_back();
		return result;
	}

	void ShowLastErrorMessage(const wchar_t* title, const wchar_t* action)
	{
		std::wstringstream message;
		message << action << L" failed. Error code: " << ::GetLastError();
		::MessageBoxW(nullptr, message.str().c_str(), title, MB_OK | MB_ICONERROR);
	}

	int LoadAntiTamperDll()
	{
		HMODULE clientDll = ::LoadLibraryW(L"Client.dll");
		if (clientDll == nullptr)
		{
			ShowLastErrorMessage(L"AntiTamper", L"LoadLibrary(Client.dll)");
			return -1;
		}

		auto entry = reinterpret_cast<AntiTamperEntry>(::GetProcAddress(clientDll, "AntiTampermain"));
		if (entry == nullptr)
		{
			ShowLastErrorMessage(L"AntiTamper", L"GetProcAddress(AntiTampermain)");
			::FreeLibrary(clientDll);
			return -43;
		}

		const int result = entry();
		::FreeLibrary(clientDll);
		return result;
	}

	std::wstring ResolveClientGuid()
	{
		HMODULE clientDll = ::LoadLibraryW(L"Client.dll");
		if (clientDll == nullptr)
			return L"unknown-guid";

		auto guidEntry = reinterpret_cast<AntiTamperGuidEntry>(::GetProcAddress(clientDll, "AntiTamperClientGuid"));
		if (guidEntry == nullptr)
		{
			::FreeLibrary(clientDll);
			return L"unknown-guid";
		}

		const std::wstring guid = AnsiToWide(guidEntry());
		::FreeLibrary(clientDll);
		return guid;
	}

	void StartAntiTamper()
	{
		std::thread([]() {
			LoadAntiTamperDll();
		}).detach();
	}

	void UpdateCounterText()
	{
		const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
			std::chrono::steady_clock::now() - g_startTime);

		std::wstringstream text;
		text << elapsed.count();
		::SetWindowTextW(g_counterText, text.str().c_str());
	}

	void ResizeCounter(HWND hwnd)
	{
		RECT rect{};
		::GetClientRect(hwnd, &rect);
		::MoveWindow(g_counterText, 0, 0, rect.right - rect.left, rect.bottom - rect.top, TRUE);
	}

	LRESULT CALLBACK WindowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
	{
		switch (message)
		{
		case WM_CREATE:
			g_startTime = std::chrono::steady_clock::now();
			g_counterText = ::CreateWindowExW(
				0,
				L"STATIC",
				L"0",
				WS_CHILD | WS_VISIBLE | SS_CENTER | SS_CENTERIMAGE,
				0,
				0,
				0,
				0,
				hwnd,
				nullptr,
				reinterpret_cast<LPCREATESTRUCTW>(lParam)->hInstance,
				nullptr);

			if (g_counterText == nullptr)
				return -1;

			g_counterFont = ::CreateFontW(
				96,
				0,
				0,
				0,
				FW_SEMIBOLD,
				FALSE,
				FALSE,
				FALSE,
				DEFAULT_CHARSET,
				OUT_DEFAULT_PRECIS,
				CLIP_DEFAULT_PRECIS,
				CLEARTYPE_QUALITY,
				DEFAULT_PITCH | FF_SWISS,
				L"Segoe UI");
			if (g_counterFont != nullptr)
				::SendMessageW(g_counterText, WM_SETFONT, reinterpret_cast<WPARAM>(g_counterFont), TRUE);

			::SetTimer(hwnd, kElapsedTimerId, kElapsedTimerMs, nullptr);
			StartAntiTamper();
			return 0;

		case WM_SIZE:
			ResizeCounter(hwnd);
			return 0;

		case WM_TIMER:
			if (wParam == kElapsedTimerId)
				UpdateCounterText();
			return 0;

		case WM_DESTROY:
			::KillTimer(hwnd, kElapsedTimerId);
			if (g_counterFont != nullptr)
			{
				::DeleteObject(g_counterFont);
				g_counterFont = nullptr;
			}
			::PostQuitMessage(0);
			return 0;

		default:
			return ::DefWindowProcW(hwnd, message, wParam, lParam);
		}
	}
}

int APIENTRY wWinMain(HINSTANCE instance, HINSTANCE, LPWSTR, int showCommand)
{
	const std::wstring clientGuid = ResolveClientGuid();
	const std::wstring windowTitle = L"Test Client - " + clientGuid;

	WNDCLASSEXW windowClass{};
	windowClass.cbSize = sizeof(windowClass);
	windowClass.lpfnWndProc = WindowProc;
	windowClass.hInstance = instance;
	windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
	windowClass.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
	windowClass.lpszClassName = kWindowClassName;

	if (!::RegisterClassExW(&windowClass))
	{
		ShowLastErrorMessage(L"TestApplication", L"RegisterClassEx");
		return -1;
	}

	HWND hwnd = ::CreateWindowExW(
		0,
		kWindowClassName,
		windowTitle.c_str(),
		WS_OVERLAPPEDWINDOW,
		CW_USEDEFAULT,
		CW_USEDEFAULT,
		320,
		180,
		nullptr,
		nullptr,
		instance,
		nullptr);

	if (hwnd == nullptr)
	{
		ShowLastErrorMessage(L"TestApplication", L"CreateWindowEx");
		return -1;
	}

	::ShowWindow(hwnd, showCommand);
	::UpdateWindow(hwnd);

	MSG message{};
	while (::GetMessageW(&message, nullptr, 0, 0) > 0)
	{
		::TranslateMessage(&message);
		::DispatchMessageW(&message);
	}

	return static_cast<int>(message.wParam);
}
