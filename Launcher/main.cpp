#include <windows.h>

#include <sstream>
#include <string>
#include <vector>

namespace
{
	constexpr wchar_t kMainClassName[] = L"LauncherWindow";
	constexpr wchar_t kBackendClassName[] = L"AntiTamperBackendWindow";

	constexpr int kIdStartBackend = 1001;
	constexpr int kIdLaunchClient = 1002;

	HWND g_log = nullptr;

	std::wstring GetCurrentExePath()
	{
		std::vector<wchar_t> path(MAX_PATH);
		while (true)
		{
			const DWORD copied = ::GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
			if (copied == 0)
				return std::wstring();
			if (copied < path.size() - 1)
				return std::wstring(path.data(), copied);
			path.resize(path.size() * 2);
		}
	}

	std::wstring GetExeDirectory()
	{
		std::wstring path = GetCurrentExePath();
		const size_t slash = path.find_last_of(L"\\/");
		if (slash != std::wstring::npos)
			path.erase(slash);
		return path;
	}

	std::wstring GetSiblingPath(const wchar_t* fileName)
	{
		return GetExeDirectory() + L"\\" + fileName;
	}

	void AppendLog(const std::wstring& text)
	{
		if (g_log == nullptr)
			return;

		const int length = ::GetWindowTextLengthW(g_log);
		::SendMessageW(g_log, EM_SETSEL, length, length);
		::SendMessageW(g_log, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(text.c_str()));
		::SendMessageW(g_log, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(L"\r\n"));
	}

	void AppendLastError(const wchar_t* action)
	{
		std::wstringstream message;
		message << action << L" failed. Error=" << ::GetLastError();
		AppendLog(message.str());
	}

	bool FocusExistingWindow(const wchar_t* className)
	{
		HWND existing = ::FindWindowW(className, nullptr);
		if (existing == nullptr)
			return false;

		::ShowWindow(existing, SW_RESTORE);
		::SetForegroundWindow(existing);
		return true;
	}

	bool CreateProcessInDirectory(
		const std::wstring& exePath,
		const std::wstring& arguments,
		const std::wstring& workingDirectory,
		bool showWindow)
	{
		std::wstring commandLine = L"\"" + exePath + L"\"";
		if (!arguments.empty())
			commandLine += L" " + arguments;

		STARTUPINFOW startup{};
		startup.cb = sizeof(startup);
		if (!showWindow)
		{
			startup.dwFlags = STARTF_USESHOWWINDOW;
			startup.wShowWindow = SW_HIDE;
		}

		PROCESS_INFORMATION process{};
		const BOOL created = ::CreateProcessW(
			nullptr,
			&commandLine[0],
			nullptr,
			nullptr,
			FALSE,
			0,
			nullptr,
			workingDirectory.c_str(),
			&startup,
			&process);

		if (!created)
			return false;

		::CloseHandle(process.hThread);
		::CloseHandle(process.hProcess);
		return true;
	}

	bool CreateProcessInOutputDir(const std::wstring& exePath, const std::wstring& arguments, bool showWindow)
	{
		return CreateProcessInDirectory(exePath, arguments, GetExeDirectory(), showWindow);
	}

	bool StartBackendApp()
	{
		const std::wstring outputDir = GetExeDirectory();
		const std::wstring backendPath = GetSiblingPath(L"Backend.exe");
		return CreateProcessInDirectory(backendPath, L"", outputDir, true);
	}

	void HandleCommand(int id)
	{
		switch (id)
		{
		case kIdStartBackend:
			if (FocusExistingWindow(kBackendClassName))
				AppendLog(L"Server is already running.");
			else if (StartBackendApp())
				AppendLog(L"Started server (Backend.exe).");
			else
				AppendLastError(L"Start server");
			break;

		case kIdLaunchClient:
			if (CreateProcessInOutputDir(GetSiblingPath(L"TestApplication.exe"), L"", true))
				AppendLog(L"Launched client (TestApplication.exe).");
			else
				AppendLastError(L"Launch client");
			break;
		}
	}

	HWND AddButton(HWND parent, int id, const wchar_t* text, int x, int y, int width, int height)
	{
		return ::CreateWindowExW(
			0,
			L"BUTTON",
			text,
			WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
			x,
			y,
			width,
			height,
			parent,
			reinterpret_cast<HMENU>(static_cast<intptr_t>(id)),
			::GetModuleHandleW(nullptr),
			nullptr);
	}

	HWND AddGroupBox(HWND parent, const wchar_t* text, int x, int y, int width, int height)
	{
		return ::CreateWindowExW(
			0,
			L"BUTTON",
			text,
			WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
			x,
			y,
			width,
			height,
			parent,
			nullptr,
			::GetModuleHandleW(nullptr),
			nullptr);
	}

	LRESULT CALLBACK MainWindowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
	{
		switch (message)
		{
		case WM_CREATE:
			AddGroupBox(hwnd, L"Launch", 16, 16, 328, 96);
			AddButton(hwnd, kIdStartBackend, L"Start Server", 32, 48, 140, 32);
			AddButton(hwnd, kIdLaunchClient, L"Launch Client", 184, 48, 144, 32);

			g_log = ::CreateWindowExW(
				WS_EX_CLIENTEDGE,
				L"EDIT",
				L"",
				WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
				16,
				128,
				328,
				120,
				hwnd,
				nullptr,
				::GetModuleHandleW(nullptr),
				nullptr);

			AppendLog(L"Launcher ready.");
			return 0;

		case WM_COMMAND:
			if (HIWORD(wParam) == BN_CLICKED)
				HandleCommand(LOWORD(wParam));
			return 0;

		case WM_DESTROY:
			::PostQuitMessage(0);
			return 0;

		default:
			return ::DefWindowProcW(hwnd, message, wParam, lParam);
		}
	}
}

int APIENTRY wWinMain(HINSTANCE instance, HINSTANCE, LPWSTR, int showCommand)
{
	WNDCLASSEXW windowClass{};
	windowClass.cbSize = sizeof(windowClass);
	windowClass.lpfnWndProc = MainWindowProc;
	windowClass.hInstance = instance;
	windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
	windowClass.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
	windowClass.lpszClassName = kMainClassName;

	if (!::RegisterClassExW(&windowClass))
		return -1;

	HWND hwnd = ::CreateWindowExW(
		0,
		kMainClassName,
		L"Launcher",
		WS_OVERLAPPEDWINDOW,
		CW_USEDEFAULT,
		CW_USEDEFAULT,
		380,
		320,
		nullptr,
		nullptr,
		instance,
		nullptr);

	if (hwnd == nullptr)
		return -1;

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
