#include <Windows.h>
#include <windowsx.h>
#include <VersionHelpers.h>

#include <shellapi.h>
#include <shlobj.h>

#include <cstdint>
#include <cstddef>
#include <cstdio>

#pragma warning (disable:6053) // snwprintf may not NUL-terminate
#pragma warning (disable:26819) // unannotated fall-through

HKEY data = NULL;       // TBD: custom colors
HKEY settings = NULL;   // options

ATOM ctrl; // control window atom
ATOM lamp; // lamp window atom

HMENU menu = NULL;
UINT WM_Terminate = WM_NULL;
UINT WM_TaskbarCreated = WM_NULL;

#define MAX_NAME_LENGTH 16384 // registry documentation
#define MAX_ENTRIES 0x1000

extern "C" IMAGE_DOS_HEADER __ImageBase;
const wchar_t * infostrings [10] = {};

NOTIFYICONDATA tray = {
    sizeof (NOTIFYICONDATA), NULL, 1,
    NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_STATE | NIF_SHOWTIP, WM_USER, NULL, { 0 },
    0u, 0u, { 0 }, { NOTIFYICON_VERSION_4 }, { 0 }, 0, { 0,0,0,{0} }, NULL
};

template <typename P>
bool Symbol (LPCTSTR module, P & pointer, const char * name) {
    if (auto h = GetModuleHandle (module)) {
        if (P p = reinterpret_cast <P> (GetProcAddress (h, name))) {
            pointer = p;
            return true;
        }
    }
    return false;
}
template <typename T>
T * next (T * p, wchar_t c) {
    while (*p && *p != c) {
        p++;
    }
    return p;
}
bool ends_with (const wchar_t * s, const wchar_t * e) {
    auto se = next (s, L'\0');
    auto ee = next (e, L'\0');

    while ((se != s) && (ee != e) && (*se == *ee)) {
        --se;
        --ee;
    }
    return (ee == e) && (*se == *ee);
}

DWORD RegGetSettingsValue (const wchar_t * name) {
    DWORD size = sizeof (DWORD);
    DWORD value = 0;
    RegQueryValueEx (settings, name, NULL, NULL, reinterpret_cast <BYTE *> (&value), &size);
    return value;
}
void RegSetSettingsValue (const wchar_t * name, DWORD value) {
    RegSetValueEx (settings, name, 0, REG_DWORD, reinterpret_cast <const BYTE *> (&value), sizeof value);
}

bool Initialize (ATOM & main, ATOM & lamp);
void TrackMenu (HWND hWnd, WPARAM wParam);
BOOL SetPrivilege (LPCTSTR lpszPrivilege, bool enable);
void Optimize ();

LRESULT CALLBACK MainProcedure (HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK LampProcedure (HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);

void Lamp () {
    
    // msvcrt.dll is dependency of advapi32.dll and shell32.dll
    // int (__cdecl * msvcrt_snwprintf) (wchar_t * buffer, size_t count, const wchar_t * format, ...) = nullptr;
    // Symbol (L"MSVCRT", msvcrt_snwprintf, "_snwprintf");

    // version info

    if (HRSRC hRsrc = FindResource (NULL, MAKEINTRESOURCE (1), RT_VERSION)) {
        if (HGLOBAL hGlobal = LoadResource (NULL, hRsrc)) {
            auto data = LockResource (hGlobal);
            auto size = SizeofResource (NULL, hRsrc);

            if (data && (size >= 92)) {
                struct Header {
                    WORD wLength;
                    WORD wValueLength;
                    WORD wType;
                };

                // StringFileInfo
                //  - not searching, leap of faith that the layout is stable

                auto pstrings = static_cast <const unsigned char *> (data) + 76
                              + reinterpret_cast <const Header *> (data)->wValueLength;
                auto p = reinterpret_cast <const wchar_t *> (pstrings) + 12;
                auto e = p + reinterpret_cast <const Header *> (pstrings)->wLength / 2 - 12;
                auto i = 0u;

                const Header * header = nullptr;
                do {
                    header = reinterpret_cast <const Header *> (p);
                    auto length = header->wLength / 2;

                    if (header->wValueLength) {
                        infostrings [i++] = p + length - header->wValueLength;
                    } else {
                        infostrings [i++] = L"";
                    }

                    p += length;
                    if (length % 2) {
                        ++p;
                    }
                } while ((p < e) && (i < sizeof infostrings / sizeof infostrings [0]) && header->wLength);
            }
        }
    }

    if ((infostrings [0] == nullptr) || (infostrings [1] == nullptr) || (infostrings [6] == nullptr)) {
        ExitProcess (ERROR_FILE_CORRUPT);
    }

    // register termination message
    //  - broadcast to local applications anyway

    WM_Terminate = RegisterWindowMessage (infostrings [6]);

    bool terminate = false;
    DWORD recipients = BSM_APPLICATIONS;

    if (ends_with (GetCommandLine (), L" -terminate")) {
        if (SetPrivilege (SE_TCB_NAME, true)) {
            recipients |= BSM_ALLDESKTOPS;
        }
        terminate = true;
    }

    if (WM_Terminate) {
        if (BroadcastSystemMessage (BSF_FORCEIFHUNG | BSF_IGNORECURRENTTASK,
                                    &recipients, WM_Terminate, 0, 0) > 0) {
            if (terminate) {
                ExitProcess (ERROR_SUCCESS);
            }
        }
    }
    if (terminate) {
        ExitProcess (GetLastError ());
    }

    // single instance

    SetLastError (0u);
    if (CreateMutex (NULL, FALSE, infostrings [6])) {
        DWORD error = GetLastError ();
        if (error == ERROR_ALREADY_EXISTS || error == ERROR_ACCESS_DENIED) {
            ExitProcess (error);
        }
    } else {
        ExitProcess (ERROR_SUCCESS);
    }

    // process mode

    SetErrorMode (SEM_FAILCRITICALERRORS);
    SetProcessDEPPolicy (PROCESS_DEP_ENABLE | PROCESS_DEP_DISABLE_ATL_THUNK_EMULATION);

    // registry
    //  - we need infostrings only here

    HKEY hKeySoftware = NULL;
    if (RegCreateKeyEx (HKEY_CURRENT_USER, L"SOFTWARE", 0, NULL, 0,
                        KEY_CREATE_SUB_KEY, NULL, &hKeySoftware, NULL) == ERROR_SUCCESS) {

        HKEY hKeyTRIMCORE = NULL;
        if (RegCreateKeyEx (hKeySoftware, infostrings [0], 0, NULL, 0, // "CompanyName" TRIM CORE SOFTWARE s.r.o.
                            KEY_ALL_ACCESS, NULL, &hKeyTRIMCORE, NULL) == ERROR_SUCCESS) {
            if (RegCreateKeyEx (hKeyTRIMCORE, infostrings [1], 0, NULL, 0, // "ProductName"
                                KEY_ALL_ACCESS, NULL, &data, NULL) == ERROR_SUCCESS) {

                DWORD disp = 0;
                if (RegCreateKeyEx (data, L"settings", 0, NULL, 0,
                                    KEY_ALL_ACCESS, NULL, &settings, &disp) == ERROR_SUCCESS) {
                    if (disp == REG_CREATED_NEW_KEY) {
                        // defaults
                        RegSetSettingsValue (L"color", 1); // white
                    }
                }
            }
            RegCloseKey (hKeyTRIMCORE);
        }
        RegCloseKey (hKeySoftware);
    }

    if (!data || !settings) {
        ExitProcess (ERROR_ACCESS_DENIED);
    }

    // menu

    if (auto hMenu = LoadMenu (reinterpret_cast <HINSTANCE> (&__ImageBase), MAKEINTRESOURCE (1))) {
        menu = GetSubMenu (hMenu, 0);
    }
    if (menu) {
        SetMenuDefaultItem (menu, IDOK, FALSE);
        if (auto about = GetSubMenu (menu, 2)) {
            DeleteMenu (about, -1, 0);

            wchar_t title [128];
            _snwprintf (title, 128, L"%s %s", infostrings [1], infostrings [2]);

            AppendMenu (about, 0, 0x11, title);
            AppendMenu (about, 0, IDHELP, infostrings [8]);
        }
    } else
        ExitProcess (ERROR_FILE_CORRUPT);

    // messages

    WM_TaskbarCreated = RegisterWindowMessage (TEXT ("TaskbarCreated"));

    if (WM_TaskbarCreated || WM_Terminate) {
        BOOL (WINAPI * ChangeWindowMessageFilter) (UINT, DWORD) = NULL;
        if (Symbol (L"USER32", ChangeWindowMessageFilter, "ChangeWindowMessageFilter")) {
            ChangeWindowMessageFilter (WM_TaskbarCreated, MSGFLT_ADD);
            ChangeWindowMessageFilter (WM_Terminate, MSGFLT_ADD);
        }
    }

    // window

    if (Initialize (ctrl, lamp)) {
        InitCommonControls ();

        if (auto hWnd = CreateWindow ((LPCTSTR) (std::intptr_t) ctrl, L"", WS_POPUP, 0, 0, 0, 0, HWND_DESKTOP, NULL, NULL, NULL)) {
            Optimize ();

            MSG message {};
            while (GetMessage (&message, NULL, 0u, 0u)) {
                DispatchMessage (&message);
            }
            ExitProcess ((UINT) message.wParam);
        }
    }
    ExitProcess (GetLastError ());
}

bool Initialize (ATOM & main, ATOM & lamp) {
    WNDCLASSEX wndclass = {
        sizeof (WNDCLASSEX), 0,
        MainProcedure, 0, 0, reinterpret_cast <HINSTANCE> (&__ImageBase),
        NULL, NULL, NULL, NULL, infostrings [7], NULL
    };
    main = RegisterClassEx (&wndclass);

    wndclass.lpszClassName = infostrings [6];
    wndclass.lpfnWndProc = LampProcedure;
    wndclass.hCursor = LoadCursor (NULL, IDC_ARROW);

    lamp = RegisterClassEx (&wndclass);

    return main && lamp;
}

BOOL SetPrivilege (LPCTSTR lpszPrivilege, bool enable) {
    HANDLE hToken;
    if (OpenProcessToken (GetCurrentProcess (), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {

        LUID luid;
        if (LookupPrivilegeValue (NULL, lpszPrivilege, &luid)) {

            TOKEN_PRIVILEGES tp {};
            tp.PrivilegeCount = 1;
            tp.Privileges [0].Luid = luid;
            tp.Privileges [0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;

            if (AdjustTokenPrivileges (hToken, FALSE, &tp, sizeof tp, NULL, NULL)) {
                CloseHandle (hToken);
                return GetLastError () != ERROR_NOT_ALL_ASSIGNED;
            }
        }
        CloseHandle (hToken);
    }
    return FALSE;
}

BOOL CALLBACK CloseLampWindowsProcedure (HWND hWnd, LPARAM lParam) {
    if (GetClassLong (hWnd, GCW_ATOM) == lamp) {
        if (DestroyWindow (hWnd)) {
            *reinterpret_cast <std::size_t *> (lParam) += 1;
        }
    }
    return TRUE;
}

BOOL CALLBACK ShowLampWindowsProcedure (HWND hWnd, LPARAM lParam) {
    if (GetClassLong (hWnd, GCW_ATOM) == lamp) {
        ShowWindow (hWnd, SW_SHOW);
        *reinterpret_cast <std::size_t *> (lParam) += 1;
    }
    return TRUE;
}

BOOL CALLBACK EnumUsableMonitorsProcedure (HMONITOR monitor, HDC, LPRECT r, LPARAM lParam) {
    MONITORINFO info {};
    info.cbSize = sizeof info;

    if (GetMonitorInfo (monitor, &info)) {
        if (!(info.dwFlags & MONITORINFOF_PRIMARY)) {
            *reinterpret_cast <std::size_t *> (lParam) += 1;
        }
    }
    return TRUE;
}

BOOL CALLBACK CreateLampsProcedure (HMONITOR monitor, HDC, LPRECT r, LPARAM color) {
    MONITORINFO info {};
    info.cbSize = sizeof info;

    if (GetMonitorInfo (monitor, &info)) {
        if (!(info.dwFlags & MONITORINFOF_PRIMARY)) {
            CreateWindowEx (WS_EX_TOOLWINDOW,
                            (LPCTSTR) (std::intptr_t) lamp, L"", WS_POPUP | (WORD) color,
                            r->left, r->top, r->right - r->left, r->bottom - r->top,
                            HWND_DESKTOP, NULL, NULL, NULL);
        }
    }
    return TRUE;
}

bool IsColorDark (COLORREF color) {
    return 2 * GetRValue (color) + 5 * GetGValue (color) + GetBValue (color) <= 1024; // MS default
    // return 299 * GetRValue (color) + 587 * GetGValue (color) + 114 * GetBValue (color) <= 128000; // YIQ?
}

COLORREF GetBackgroundColor (HWND hWnd) {
    switch (GetWindowLong (hWnd, GWL_STYLE) & 0xFFFF) {
        case 0: return 0x000000;
        case 1: return 0xFFFFFF;
        default:
            // TODO: get from registry
            return 0xFF00FF;
    }
}

void Action (WORD message) {
    std::size_t n = 0;
    if (EnumThreadWindows (GetCurrentThreadId (), CloseLampWindowsProcedure, (LPARAM) &n)) {
        if (n) {
            // closed some windows, good, free memory
            Optimize ();
        } else {
            auto color = RegGetSettingsValue (L"color");
            if (message == WM_MBUTTONUP) {
                color = !color; // opposite to black/white, or black (0) if any other color is selected
            }

            // no windows open, enum monitors and create lamps
            EnumDisplayMonitors (NULL, NULL, CreateLampsProcedure, color);

            n = 0;
            EnumThreadWindows (GetCurrentThreadId (), ShowLampWindowsProcedure, (LPARAM) &n);

            if (!n) {
                MessageBeep (MB_ICONERROR);
            }
        }
    }
}

void Optimize () {
    if (IsWindows8Point1OrGreater ()) {
        HeapSetInformation (NULL, HeapOptimizeResources, NULL, 0);
    }
    SetProcessWorkingSetSize (GetCurrentProcess (), (SIZE_T) -1, (SIZE_T) -1);
}

LRESULT CALLBACK MainProcedure (HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
        case WM_CREATE:
            tray.hWnd = hWnd;
            tray.hIcon = (HICON) LoadImage (GetModuleHandle (NULL), MAKEINTRESOURCE (1), IMAGE_ICON,
                                            GetSystemMetrics (SM_CXSMICON), GetSystemMetrics (SM_CYSMICON), 0);

            _snwprintf (tray.szTip, sizeof tray.szTip / sizeof tray.szTip [0], infostrings [1]);
            PostMessage (hWnd, WM_TaskbarCreated, 0, 0);
            break;

        case WM_DPICHANGED:
            tray.hIcon = (HICON) LoadImage (GetModuleHandle (NULL), MAKEINTRESOURCE (1), IMAGE_ICON,
                                            LOWORD (wParam) * GetSystemMetrics (SM_CXSMICON) / 96,
                                            HIWORD (wParam) * GetSystemMetrics (SM_CYSMICON) / 96, 0);

            Shell_NotifyIcon (NIM_MODIFY, &tray);
            break;

        case WM_CLOSE:
            Shell_NotifyIcon (NIM_DELETE, &tray);
            PostQuitMessage ((int) wParam);
            break;

        case WM_USER:
            switch (HIWORD (lParam)) {
                case 1:
                    switch (LOWORD (lParam)) {
                        case WM_CONTEXTMENU:
                            TrackMenu (hWnd, wParam);
                            break;
                        case NIN_KEYSELECT:
                        case WM_LBUTTONDBLCLK:
                        case WM_MBUTTONUP:
                            PostMessage (hWnd, WM_COMMAND,
                                         MAKEWPARAM (GetMenuDefaultItem (menu, FALSE, 0), LOWORD (lParam)),
                                         0);
                            break;
                    }
                    break;
            }
            break;

        case WM_COMMAND:
            switch (LOWORD (wParam)) {

                case IDOK:
                    Action (HIWORD (wParam));
                    break;
                case IDHELP:
                    ShellExecute (hWnd, NULL, infostrings [9], NULL, NULL, SW_SHOWDEFAULT);
                    break;
                case IDCLOSE:
                    PostMessage (hWnd, WM_CLOSE, 0, 0);
                    break;

                default:
                    if (LOWORD (wParam) >= 0x10 && LOWORD (wParam) <= 0x11) {
                        RegSetSettingsValue (L"color", LOWORD (wParam) - 0x10);
                    }
                    if (LOWORD (wParam) >= 0x1000 && LOWORD (wParam) < 0x1000 + MAX_ENTRIES) {
                        // choose active color
                    }
            }
            break;

        case WM_ENDSESSION:
            if (wParam) {
                PostMessage (hWnd, WM_CLOSE, ERROR_SHUTDOWN_IN_PROGRESS, 0);
            }
            break;

        default:
            if (message == WM_Terminate) {
                PostMessage (hWnd, WM_CLOSE, 0, 0);
            }
            if (message == WM_TaskbarCreated) {
                Shell_NotifyIcon (NIM_ADD, &tray);
                Shell_NotifyIcon (NIM_SETVERSION, &tray);
            }
    }
    return DefWindowProc (hWnd, message, wParam, lParam);
}

LRESULT CALLBACK LampProcedure (HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
        case WM_CREATE:
            if (auto cs = reinterpret_cast <const CREATESTRUCT *> (lParam)) {
                auto hCtrl = CreateWindowEx (WS_EX_TRANSPARENT,
                                             L"STATIC", L"LAMP", WS_CHILD | SS_CENTER,
                                             cs->cx / 3, cs->cy / 2, cs->cx / 3, cs->cy / 20,
                                             hWnd, (HMENU) 101, cs->hInstance, NULL);
                SendMessage (hCtrl, WM_SETFONT, (WPARAM) GetStockObject (DEFAULT_GUI_FONT), TRUE);
            }
            break;

        case WM_LBUTTONUP:
            Action (0);
            break;

        case WM_MOUSEMOVE:
            ShowWindow (GetDlgItem (hWnd, 101), SW_SHOW);
            {
                TRACKMOUSEEVENT track = {
                    sizeof track,
                    TME_LEAVE,
                    hWnd,
                    HOVER_DEFAULT
                };
                TrackMouseEvent (&track);
            }
            break;
        case WM_MOUSELEAVE:
            ShowWindow (GetDlgItem (hWnd, 101), SW_HIDE);
            break;

        case WM_CTLCOLORSTATIC:
            if (auto hDC = (HDC) wParam) {
                auto color = GetBackgroundColor (hWnd);
                SetBkColor (hDC, color);
                SetTextColor (hDC, IsColorDark (color) ? 0xDDDDDD : 0x000000);
                SetDCBrushColor (hDC, color);
                return (LRESULT) GetStockObject (DC_BRUSH);
            } else
                return (LRESULT) GetStockObject (BLACK_BRUSH);

        case WM_ERASEBKGND: {
            RECT r;
            if (GetClientRect (hWnd, &r)) {
                SetDCBrushColor ((HDC) wParam, GetBackgroundColor (hWnd));
                FillRect ((HDC) wParam, &r, (HBRUSH) GetStockObject (DC_BRUSH));
                return TRUE;
            }
        } break;// */
    }
    return DefWindowProc (hWnd, message, wParam, lParam);
}

void TrackMenu (HWND hWnd, WPARAM wParam) {
    auto color = RegGetSettingsValue (L"color");
    
    /*if (auto list = GetSubMenu (menu, 3)) {

        // delete old items
        if (auto n = GetMenuItemCount (list)) {
            if (n > 5) {
                n -= 5;
                while (n-- && DeleteMenu (list, 3, MF_BYPOSITION))
                    ;
            }
        }

        // enum, format, and construct menu
        wchar_t path [MAX_NAME_LENGTH];

        DWORD index = 0u;
        DWORD size = sizeof path / sizeof path [0];

        while ((RegEnumValue (data, index, path, &size, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) && (index < MAX_ENTRIES)) {

            // AppendMenu (list, MF_STRING, 0x1000 + index, label);
            // next
            ++index;
            size = sizeof path / sizeof path [0];
        }
    }*/

    std::size_t n = 0;
    EnumDisplayMonitors (NULL, NULL, EnumUsableMonitorsProcedure, (LPARAM) &n);
    EnableMenuItem (menu, IDOK, n ? MF_ENABLED : MF_GRAYED);

    CheckMenuRadioItem (menu, 0x10, 0x11, 0x10 + color, MF_BYCOMMAND);
    SetForegroundWindow (hWnd);

    UINT style = TPM_RIGHTBUTTON;
    if (GetSystemMetrics (SM_MENUDROPALIGNMENT)) {
        style |= TPM_RIGHTALIGN;
    }

    if (!TrackPopupMenu (menu, style, GET_X_LPARAM (wParam), GET_Y_LPARAM (wParam), 0, hWnd, NULL)) {
        Shell_NotifyIcon (NIM_SETFOCUS, &tray);
    }
    PostMessage (hWnd, WM_NULL, 0, 0);
}
