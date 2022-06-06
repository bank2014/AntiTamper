#include "pch.h"

#include "BackendCommon.h"
#include "BackendServer.h"
#include "SingleInstanceGuard.h"

#include <commctrl.h>

#include <sstream>
#include <vector>

#pragma comment(lib, "comctl32.lib")

namespace
{
	constexpr wchar_t kWindowClassName[] = L"AntiTamperBackendWindow";
	constexpr wchar_t kSingleInstanceMutexName[] = L"Local\\AntiTamperBackendSingleInstance";
	constexpr uint16_t kServerPort = 7777;
	constexpr UINT kRefreshMessage = WM_APP + 1;
	constexpr UINT kLogMessage = WM_APP + 2;

	constexpr int kClientListId = 1001;
	constexpr int kViolationListId = 1002;
	constexpr int kDisconnectButtonId = 1003;
	constexpr int kBanSessionButtonId = 1004;
	constexpr int kBanMachineButtonId = 1005;
	constexpr int kClearViolationsButtonId = 1006;
	constexpr int kLogEditId = 1007;
	constexpr int kBanListId = 1008;
	constexpr int kUnbanButtonId = 1009;

	HWND g_mainWindow = nullptr;
	HWND g_clientList = nullptr;
	HWND g_violationList = nullptr;
	HWND g_banList = nullptr;
	HWND g_logEdit = nullptr;
	HWND g_disconnectButton = nullptr;
	HWND g_banSessionButton = nullptr;
	HWND g_banMachineButton = nullptr;
	HWND g_clearViolationsButton = nullptr;
	HWND g_unbanButton = nullptr;

	Backend::BackendServer g_server;

	void PostRefresh()
	{
		if (g_mainWindow != nullptr)
			::PostMessageW(g_mainWindow, kRefreshMessage, 0, 0);
	}

	void PostLog(const std::string& text)
	{
		if (g_mainWindow == nullptr)
			return;

		std::wstring* message = new std::wstring(Backend::Utf8ToWide(text));
		if (!::PostMessageW(g_mainWindow, kLogMessage, 0, reinterpret_cast<LPARAM>(message)))
			delete message;
	}

	std::wstring ToWide(const std::string& text)
	{
		return Backend::Utf8ToWide(text);
	}

	std::string ToAscii(const std::wstring& text)
	{
		std::string result;
		result.reserve(text.size());
		for (wchar_t ch : text)
		{
			if (ch >= 0 && ch <= 127)
				result.push_back(static_cast<char>(ch));
		}
		return result;
	}

	void AppendLog(HWND edit, const std::wstring& text)
	{
		if (edit == nullptr)
			return;

		const int length = ::GetWindowTextLengthW(edit);
		::SendMessageW(edit, EM_SETSEL, length, length);
		::SendMessageW(edit, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(text.c_str()));
		::SendMessageW(edit, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(L"\r\n"));
	}

	HWND AddStatic(HWND parent, const wchar_t* text, int x, int y, int width, int height)
	{
		return ::CreateWindowExW(
			0,
			L"STATIC",
			text,
			WS_CHILD | WS_VISIBLE,
			x,
			y,
			width,
			height,
			parent,
			nullptr,
			::GetModuleHandleW(nullptr),
			nullptr);
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

	HWND AddListView(HWND parent, int id, int x, int y, int width, int height)
	{
		HWND hwnd = ::CreateWindowExW(
			WS_EX_CLIENTEDGE,
			WC_LISTVIEWW,
			L"",
			WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
			x,
			y,
			width,
			height,
			parent,
			reinterpret_cast<HMENU>(static_cast<intptr_t>(id)),
			::GetModuleHandleW(nullptr),
			nullptr);

		ListView_SetExtendedListViewStyle(hwnd, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
		return hwnd;
	}

	void AddColumn(HWND list, int index, const wchar_t* text, int width)
	{
		LVCOLUMNW column{};
		column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
		column.pszText = const_cast<LPWSTR>(text);
		column.cx = width;
		column.iSubItem = index;
		ListView_InsertColumn(list, index, &column);
	}

	void AddClientColumns(HWND list)
	{
		AddColumn(list, 0, L"Session", 70);
		AddColumn(list, 1, L"ClientGuid", 300);
		AddColumn(list, 2, L"MachineHwid", 240);
		AddColumn(list, 3, L"IP", 110);
		AddColumn(list, 4, L"Last Request", 110);
		AddColumn(list, 5, L"Last Seen", 90);
		AddColumn(list, 6, L"Status", 150);
	}

	void AddViolationColumns(HWND list)
	{
		AddColumn(list, 0, L"Time", 80);
		AddColumn(list, 1, L"Session", 70);
		AddColumn(list, 2, L"ClientGuid", 280);
		AddColumn(list, 3, L"MachineHwid", 240);
		AddColumn(list, 4, L"Severity", 110);
		AddColumn(list, 5, L"Reason", 350);
	}

	void AddBanColumns(HWND list)
	{
		AddColumn(list, 0, L"Type", 90);
		AddColumn(list, 1, L"Key", 430);
		AddColumn(list, 2, L"Storage", 220);
	}

	void SetListText(HWND list, int row, int column, const std::wstring& text)
	{
		ListView_SetItemText(list, row, column, const_cast<LPWSTR>(text.c_str()));
	}

	int AddListRow(HWND list, uint64_t rowId, const std::vector<std::wstring>& columns)
	{
		if (columns.empty())
			return -1;

		LVITEMW item{};
		item.mask = LVIF_TEXT | LVIF_PARAM;
		item.iItem = ListView_GetItemCount(list);
		item.iSubItem = 0;
		item.pszText = const_cast<LPWSTR>(columns[0].c_str());
		item.lParam = static_cast<LPARAM>(rowId);

		const int row = ListView_InsertItem(list, &item);
		for (size_t i = 1; i < columns.size(); ++i)
			SetListText(list, row, static_cast<int>(i), columns[i]);
		return row;
	}

	uint64_t GetSelectedSessionId()
	{
		if (g_clientList == nullptr)
			return 0;

		const int selected = ListView_GetNextItem(g_clientList, -1, LVNI_SELECTED);
		if (selected < 0)
			return 0;

		LVITEMW item{};
		item.mask = LVIF_PARAM;
		item.iItem = selected;
		if (!ListView_GetItem(g_clientList, &item))
			return 0;
		return static_cast<uint64_t>(item.lParam);
	}

	std::wstring GetListText(HWND list, int row, int column)
	{
		wchar_t text[512]{};
		ListView_GetItemText(list, row, column, text, _countof(text));
		return text;
	}

	struct SelectedBan
	{
		bool valid = false;
		std::string type;
		std::string key;
	};

	SelectedBan GetSelectedBan()
	{
		SelectedBan selectedBan;
		if (g_banList == nullptr)
			return selectedBan;

		const int selected = ListView_GetNextItem(g_banList, -1, LVNI_SELECTED);
		if (selected < 0)
			return selectedBan;

		selectedBan.valid = true;
		selectedBan.type = ToAscii(GetListText(g_banList, selected, 0));
		selectedBan.key = ToAscii(GetListText(g_banList, selected, 1));
		return selectedBan;
	}

	void SelectSession(uint64_t sessionId)
	{
		const int count = ListView_GetItemCount(g_clientList);
		for (int i = 0; i < count; ++i)
		{
			LVITEMW item{};
			item.mask = LVIF_PARAM;
			item.iItem = i;
			if (ListView_GetItem(g_clientList, &item) && static_cast<uint64_t>(item.lParam) == sessionId)
			{
				ListView_SetItemState(g_clientList, i, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
				return;
			}
		}
	}

	void EnableActionButtons()
	{
		const bool hasSelection = GetSelectedSessionId() != 0;
		::EnableWindow(g_disconnectButton, hasSelection);
		::EnableWindow(g_banSessionButton, hasSelection);
		::EnableWindow(g_banMachineButton, hasSelection);
		::EnableWindow(g_clearViolationsButton, hasSelection);
		::EnableWindow(g_unbanButton, GetSelectedBan().valid);
	}

	void RefreshUi()
	{
		if (g_clientList == nullptr || g_violationList == nullptr || g_banList == nullptr)
			return;

		const uint64_t previouslySelected = GetSelectedSessionId();
		ListView_DeleteAllItems(g_clientList);
		ListView_DeleteAllItems(g_banList);
		ListView_DeleteAllItems(g_violationList);

		for (const Backend::ClientRecord& client : g_server.Clients())
		{
			AddListRow(g_clientList, client.sessionId, {
				std::to_wstring(client.sessionId),
				ToWide(client.clientGuid),
				ToWide(client.machineHwid),
				ToWide(client.ip),
				ToWide(client.lastRequest),
				ToWide(client.lastSeen),
				ToWide(client.status)
			});
		}

		for (const Backend::BanRecord& ban : g_server.Bans())
		{
			AddListRow(g_banList, 0, {
				ToWide(ban.type),
				ToWide(ban.key),
				ToWide(ban.storage)
			});
		}

		for (const Backend::ViolationRecord& event : g_server.Violations())
		{
			std::ostringstream severity;
			severity << event.level << "(" << event.severity << ")";
			AddListRow(g_violationList, event.sessionId, {
				ToWide(event.time),
				std::to_wstring(event.sessionId),
				ToWide(event.clientGuid),
				ToWide(event.machineHwid),
				ToWide(severity.str()),
				ToWide(event.reason)
			});
		}

		if (previouslySelected != 0)
			SelectSession(previouslySelected);
		EnableActionButtons();
	}

	void DisconnectSelectedClient()
	{
		const uint64_t sessionId = GetSelectedSessionId();
		if (sessionId != 0)
			g_server.DisconnectSession(sessionId);
	}

	void BanSelectedSession()
	{
		const uint64_t sessionId = GetSelectedSessionId();
		if (sessionId == 0)
			return;

		if (!g_server.BanSession(sessionId))
			::MessageBoxW(g_mainWindow, L"ClientGuid is not known yet. Wait for CHECK/HEARTBEAT first.", L"Ban Session Failed", MB_OK | MB_ICONWARNING);
	}

	void BanSelectedMachine()
	{
		const uint64_t sessionId = GetSelectedSessionId();
		if (sessionId == 0)
			return;

		if (!g_server.BanMachine(sessionId))
			::MessageBoxW(g_mainWindow, L"MachineHwid is not known yet or Blacklist.txt could not be written.", L"Ban Machine Failed", MB_OK | MB_ICONWARNING);
	}

	void ClearSelectedClientViolations()
	{
		const uint64_t sessionId = GetSelectedSessionId();
		if (sessionId != 0)
			g_server.ClearViolations(sessionId);
	}

	void UnbanSelected()
	{
		const SelectedBan selectedBan = GetSelectedBan();
		if (!selectedBan.valid)
			return;

		bool succeeded = false;
		if (selectedBan.type == "Session")
			succeeded = g_server.UnbanSession(selectedBan.key);
		else if (selectedBan.type == "Machine")
			succeeded = g_server.UnbanMachine(selectedBan.key);

		if (!succeeded)
			::MessageBoxW(g_mainWindow, L"Selected ban could not be removed.", L"Unban Failed", MB_OK | MB_ICONWARNING);
	}

	void CreateMainControls(HWND hwnd)
	{
		AddStatic(hwnd, L"Connected Clients", 16, 16, 450, 20);
		g_clientList = AddListView(hwnd, kClientListId, 16, 40, 1140, 210);
		AddClientColumns(g_clientList);

		g_disconnectButton = AddButton(hwnd, kDisconnectButtonId, L"Disconnect", 16, 262, 130, 34);
		g_banSessionButton = AddButton(hwnd, kBanSessionButtonId, L"Ban Session", 158, 262, 130, 34);
		g_banMachineButton = AddButton(hwnd, kBanMachineButtonId, L"Ban Machine", 300, 262, 130, 34);
		g_clearViolationsButton = AddButton(hwnd, kClearViolationsButtonId, L"Clear Selected Violations", 442, 262, 190, 34);

		AddStatic(hwnd, L"Banned List", 16, 310, 450, 20);
		g_banList = AddListView(hwnd, kBanListId, 16, 334, 780, 130);
		AddBanColumns(g_banList);
		g_unbanButton = AddButton(hwnd, kUnbanButtonId, L"Unban Selected", 808, 334, 150, 34);

		AddStatic(hwnd, L"Violations", 16, 478, 450, 20);
		g_violationList = AddListView(hwnd, kViolationListId, 16, 502, 1140, 130);
		AddViolationColumns(g_violationList);

		AddStatic(hwnd, L"Server Log", 16, 646, 450, 20);
		g_logEdit = ::CreateWindowExW(
			WS_EX_CLIENTEDGE,
			L"EDIT",
			L"",
			WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
			16,
			670,
			1140,
			110,
			hwnd,
			reinterpret_cast<HMENU>(static_cast<intptr_t>(kLogEditId)),
			::GetModuleHandleW(nullptr),
			nullptr);
	}

	void StartBackendServer(HWND hwnd)
	{
		g_server.SetCallbacks(PostLog, PostRefresh);
		RefreshUi();

		const std::wstring blacklistPath = Backend::GetExeDirectory() + L"\\Blacklist.txt";
		if (!g_server.Start(kServerPort, blacklistPath))
			::MessageBoxW(hwnd, L"Backend server failed to start. Check the log, port 7777, and Blacklist.txt access.", L"Backend", MB_OK | MB_ICONERROR);
	}

	LRESULT CALLBACK MainWindowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
	{
		switch (message)
		{
		case WM_CREATE:
		{
			g_mainWindow = hwnd;
			CreateMainControls(hwnd);
			StartBackendServer(hwnd);
			return 0;
		}

		case WM_NOTIFY:
		{
			const NMHDR* header = reinterpret_cast<NMHDR*>(lParam);
			if (header != nullptr
				&& (header->idFrom == kClientListId || header->idFrom == kBanListId)
				&& header->code == LVN_ITEMCHANGED)
				EnableActionButtons();
			return 0;
		}

		case WM_COMMAND:
			if (HIWORD(wParam) == BN_CLICKED)
			{
				switch (LOWORD(wParam))
				{
				case kDisconnectButtonId:
					DisconnectSelectedClient();
					return 0;
				case kBanSessionButtonId:
					BanSelectedSession();
					return 0;
				case kBanMachineButtonId:
					BanSelectedMachine();
					return 0;
				case kClearViolationsButtonId:
					ClearSelectedClientViolations();
					return 0;
				case kUnbanButtonId:
					UnbanSelected();
					return 0;
				default:
					break;
				}
			}
			return 0;

		case kRefreshMessage:
			RefreshUi();
			return 0;

		case kLogMessage:
		{
			std::wstring* text = reinterpret_cast<std::wstring*>(lParam);
			if (text != nullptr)
			{
				AppendLog(g_logEdit, *text);
				delete text;
			}
			return 0;
		}

		case WM_DESTROY:
			g_server.Stop();
			::PostQuitMessage(0);
			return 0;

		default:
			return ::DefWindowProcW(hwnd, message, wParam, lParam);
		}
	}
}

int APIENTRY wWinMain(HINSTANCE instance, HINSTANCE, LPWSTR, int showCommand)
{
	BackendUi::SingleInstanceGuard singleInstance(kSingleInstanceMutexName, kWindowClassName);
	if (!singleInstance.Acquired())
		return 0;

	INITCOMMONCONTROLSEX controls{};
	controls.dwSize = sizeof(controls);
	controls.dwICC = ICC_LISTVIEW_CLASSES;
	::InitCommonControlsEx(&controls);

	WNDCLASSEXW windowClass{};
	windowClass.cbSize = sizeof(windowClass);
	windowClass.lpfnWndProc = MainWindowProc;
	windowClass.hInstance = instance;
	windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
	windowClass.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
	windowClass.lpszClassName = kWindowClassName;

	if (!::RegisterClassExW(&windowClass))
		return -1;

	HWND hwnd = ::CreateWindowExW(
		0,
		kWindowClassName,
		L"AntiTamper Backend",
		WS_OVERLAPPEDWINDOW,
		CW_USEDEFAULT,
		CW_USEDEFAULT,
		1200,
		840,
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
