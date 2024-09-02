#include <windows.h>
#include <TlHelp32.h>
#include <atlbase.h>

#include <iostream>
#include <format>
#include <unordered_map>

#ifdef _WIN64
#define MUTEX_NAME                  L"Global\\LowLevelKeyboardHookFix64"
#else
#define MUTEX_NAME                  L"Global\\LowLevelKeyboardHookFix32"
#endif

#define POLL_INTERVAL_MS            (2500)

static const wchar_t* g_pwszProcsToMonitor[] = { 
#ifndef _WIN64
    L"vmware-remotemks.exe",
#else
    L"vmware-vmx.exe"
#endif
};

static HMODULE g_hSelf = nullptr;
static HOOKPROC g_pVMwareHookFunc = nullptr;
static HKL g_hklCurrentKeyboard = nullptr;

static void ExitPrompt(const std::wstring& wstrMsg=L"")
{
    std::wcout << std::format(L"{}\nPress ENTER to exit\n", wstrMsg);
    std::cin.get();
}

static bool SetPrivilege(HANDLE hToken,
                         LPCWSTR lpszPrivilege,
                         bool bEnablePrivilege)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValueW(nullptr, lpszPrivilege, &luid))
    {
        std::wcout << std::format(L"LookupPrivilegeValueW failed with {}\n", GetLastError());
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = bEnablePrivilege ? SE_PRIVILEGE_ENABLED : 0;

    if (!AdjustTokenPrivileges(hToken,
                               FALSE,
                               &tp,
                               sizeof(TOKEN_PRIVILEGES),
                               nullptr,
                               nullptr)
        || GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        std::wcout << std::format(L"AdjustTokenPrivileges failed with {}\n", GetLastError());
        return false;
    }

    return true;
}

static LRESULT __stdcall HookFunc(int nCode, WPARAM wParam, LPARAM lParam)
{
    if (nCode >= 0 && (wParam == WM_KEYDOWN || wParam == WM_KEYUP))
    {
        PKBDLLHOOKSTRUCT pkbdStruct = reinterpret_cast<PKBDLLHOOKSTRUCT>(lParam);

        if (pkbdStruct->vkCode == VK_PACKET)
        {
            KBDLLHOOKSTRUCT kbdStructNew = *pkbdStruct;
            kbdStructNew.vkCode = VkKeyScanExA(static_cast<CHAR>(kbdStructNew.scanCode), g_hklCurrentKeyboard) & 0xff;
            kbdStructNew.scanCode = MapVirtualKeyA(kbdStructNew.vkCode, MAPVK_VK_TO_VSC);
            return g_pVMwareHookFunc(nCode, wParam, reinterpret_cast<LPARAM>(&kbdStructNew));
        }
    }

    return g_pVMwareHookFunc(nCode, wParam, lParam);
}

static LRESULT __stdcall HookFuncGlobal(int nCode, WPARAM wParam, LPARAM lParam)
{
    if (nCode >= 0 && (wParam == WM_KEYDOWN || wParam == WM_KEYUP))
    {
        PKBDLLHOOKSTRUCT pkbdStruct = reinterpret_cast<PKBDLLHOOKSTRUCT>(lParam);

        if (pkbdStruct->vkCode == VK_PACKET)
        {
            KBDLLHOOKSTRUCT kbdStructNew = *pkbdStruct;
            kbdStructNew.vkCode = VkKeyScanExA(static_cast<CHAR>(kbdStructNew.scanCode), g_hklCurrentKeyboard) & 0xff;
            kbdStructNew.scanCode = MapVirtualKeyA(kbdStructNew.vkCode, MAPVK_VK_TO_VSC);

            INPUT input[1] = { 0 };
            input[0].type = INPUT_KEYBOARD;
            input[0].ki.wScan = static_cast<WORD>(kbdStructNew.scanCode);
            input[0].ki.dwFlags = KEYEVENTF_SCANCODE;

            if (wParam == WM_KEYUP)
            {
                input[0].ki.dwFlags |= KEYEVENTF_KEYUP;
            }

            SendInput(ARRAYSIZE(input), input, sizeof(INPUT));
            return 0;
        }
    }

    return CallNextHookEx(nullptr, nCode, wParam, lParam);
}

static HHOOK WINAPI _SetWindowsHookExA(int idHook, HOOKPROC lpfn, HINSTANCE hmod, DWORD dwThreadId)
{
    if (idHook != WH_KEYBOARD_LL)
    {
        return SetWindowsHookExA(idHook, lpfn, hmod, dwThreadId);
    }

    g_pVMwareHookFunc = lpfn;
    return SetWindowsHookExW(WH_KEYBOARD_LL, HookFunc, g_hSelf, 0);
}

static void PerformFix()
{
    UINT_PTR pTargetDll = reinterpret_cast<UINT_PTR>(GetModuleHandleW(nullptr));
    if (!pTargetDll)
    {
        OutputDebugStringW(L"Unable to get module\n");
        return;
    }

    PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pTargetDll);
    PIMAGE_NT_HEADERS pNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(pTargetDll + pDosHeader->e_lfanew);
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(pTargetDll + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    while (pImportDescriptor->Name)
    {
        LPCSTR pszCurrentLibName = reinterpret_cast<LPCSTR>(pTargetDll + pImportDescriptor->Name);

        if (_stricmp(pszCurrentLibName, "user32.dll") == 0)
        {
            PIMAGE_THUNK_DATA pOrigFirstThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(pTargetDll + pImportDescriptor->OriginalFirstThunk);
            PIMAGE_THUNK_DATA pFirstThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(pTargetDll + pImportDescriptor->FirstThunk);

            while (pOrigFirstThunk->u1.AddressOfData)
            {
                PIMAGE_IMPORT_BY_NAME pFuncName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(pTargetDll + pOrigFirstThunk->u1.AddressOfData);
                
                if (strcmp(pFuncName->Name, "SetWindowsHookExA") == 0)
                {
                    DWORD dwOldProtect = 0;
                    if (!VirtualProtect(&pFirstThunk->u1.Function, sizeof(PVOID), PAGE_READWRITE, &dwOldProtect))
                    {
                        OutputDebugStringW(L"VirtualProtect failure\n");
                        return;
                    }

                    pFirstThunk->u1.Function = (UINT_PTR)_SetWindowsHookExA;

                    if (!VirtualProtect(&pFirstThunk->u1.Function, sizeof(PVOID), dwOldProtect, &dwOldProtect))
                    {
                        OutputDebugStringW(L"VirtualProtect failure\n");
                        return;
                    }
                    
                    return;
                }

                ++pOrigFirstThunk;
                ++pFirstThunk;
            }

            break;
        }

        ++pImportDescriptor;
    }

    OutputDebugStringW(L"Unable to find IAT hook target\n");
    return;
}

static bool IsAlreadyInjected(DWORD dwPid, PWCHAR pwszModFileName)
{
    try
    {
        MODULEENTRY32W mod32 = { 0 };
        CHandle hMods = CHandle(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, dwPid));

        mod32.dwSize = sizeof(mod32);

        if (!Module32FirstW(hMods, &mod32))
        {
            std::wcout << std::format(L"Module32FirstW failed with {}\n", GetLastError());
            return false;
        }

        do
        {
            if (_wcsicmp(mod32.szExePath, pwszModFileName) == 0)
            {
                return true;
            }
        } while (Module32NextW(hMods, &mod32));

    }
    catch (...)
    {
        std::wcout << L"Exception in IsAlreadyInjected() function\n";
    }

    return false;
}

static HRESULT Inject(HANDLE hTargetProc, PWCHAR pwszModFileName)
{
    HRESULT hRes = S_OK;
    size_t szPathByteCount = 0;
    PVOID pRemoteMem = nullptr;
    HANDLE hRemoteThread = nullptr;
    DWORD dwPid = GetProcessId(hTargetProc);

    szPathByteCount = (wcslen(pwszModFileName) + 1) * sizeof(WCHAR);
    
    pRemoteMem = VirtualAllocEx(hTargetProc, nullptr, szPathByteCount, MEM_COMMIT, PAGE_READWRITE);
    if (!pRemoteMem)
    {
        std::wcout << std::format(L"VirtualAllocEx failed with {}\n", GetLastError());
        return E_FAIL;
    }

    do
    {
        if (!WriteProcessMemory(hTargetProc, pRemoteMem, pwszModFileName, szPathByteCount, nullptr))
        {
            std::wcout << std::format(L"WriteProcessMemory failed with {}\n", GetLastError());
            hRes = E_FAIL;
            break;
        }

        PTHREAD_START_ROUTINE pLoadLibraryW = reinterpret_cast<PTHREAD_START_ROUTINE>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW"));
        if (!pLoadLibraryW)
        {
            std::wcout << std::format(L"GetProcAddress failed with {}\n", GetLastError());
            hRes = E_FAIL;
            break;
        }

        hRemoteThread = CreateRemoteThread(hTargetProc, nullptr, 0, pLoadLibraryW, pRemoteMem, 0, nullptr);
        if (!hRemoteThread)
        {
            std::wcout << std::format(L"CreateRemoteThread failed with {}\n", GetLastError());
            hRes = E_FAIL;
            break;
        }
    } while (0);
    
    if (hRemoteThread)
    {
        WaitForSingleObject(hRemoteThread, INFINITE);
        CloseHandle(hRemoteThread);
    }

    if (pRemoteMem)
    {
        VirtualFreeEx(hTargetProc, pRemoteMem, 0, MEM_RELEASE);
    }

    if (SUCCEEDED(hRes))
    {
        return IsAlreadyInjected(dwPid, pwszModFileName) ? S_OK : E_FAIL;
    }
    else
    {
        return hRes;
    }
}

DWORD WINAPI GlobalHookThread(LPVOID lpParam)
{
    HHOOK hhkHook = SetWindowsHookExW(WH_KEYBOARD_LL, HookFuncGlobal, nullptr, 0);

    MSG msg = { 0 };
    while (GetMessageW(&msg, nullptr, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    UnhookWindowsHookEx(hhkHook);

    return 0;
}

static void Entry(bool bWithGlobalHook)
{
    try
    {
        CHandle hGlobalThread;
        WCHAR wszModFileName[MAX_PATH] = { 0 };
        PROCESSENTRY32W proc32 = { 0 };
        std::unordered_map<DWORD, CHandle> umapProcsMonitored;
        FILE* fileTmp = nullptr;

        proc32.dwSize = sizeof(proc32);

        AllocConsole();
        freopen_s(&fileTmp, "CONIN$", "r", stdin);
        freopen_s(&fileTmp, "CONOUT$", "w", stdout);
        freopen_s(&fileTmp, "CONOUT$", "w", stderr);

        CHandle hMutex = CHandle(CreateMutexW(nullptr, TRUE, MUTEX_NAME));
        if (!hMutex || GetLastError() == ERROR_ALREADY_EXISTS)
        {
            ExitPrompt(L"LowLevelkeyboardHookFix already running. Aborting.\n");
            return;
        }

        HANDLE hThisProcToken;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hThisProcToken))
        {
            ExitPrompt(std::format(L"OpenProcessToken failed with {}\n", GetLastError()));
            return;
        }

        if (!SetPrivilege(hThisProcToken, SE_DEBUG_NAME, true))
        {
            ExitPrompt(L"Hint: Run as Admin / Check Permissions\n");
            CloseHandle(hThisProcToken);
            return;
        }
        CloseHandle(hThisProcToken);

        if (!GetModuleFileNameW(g_hSelf, wszModFileName, _countof(wszModFileName)))
        {
            ExitPrompt(std::format(L"GetModuleFileNameW failed with {}\n", GetLastError()));
            return;
        }

        if (bWithGlobalHook)
        {
            hGlobalThread.Attach(CreateThread(nullptr, 0, GlobalHookThread, nullptr, 0, nullptr));
            std::wcout << L"Global hook mode ENABLED\n\n";
        }

        std::wcout << L"Monitoring to fix the following "
#ifdef _WIN64
            L"64-bit"
#else
            L"32-bit"
#endif
            " processes:\n";
        for (const wchar_t* pwszCurrentProc : g_pwszProcsToMonitor)
        {
            std::wcout << std::format(L"- `{}`\n", pwszCurrentProc);
        }

        for (;; Sleep(POLL_INTERVAL_MS))
        {
            try
            {
                CHandle hProcs = CHandle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
            
                if (!Process32FirstW(hProcs, &proc32))
                {
                    std::wcout << std::format(L"Process32FirstW failed with {}\n", GetLastError());
                    continue;
                }

                do
                {
                    for (const wchar_t* pwszCurrentProc : g_pwszProcsToMonitor)
                    {
                        if (_wcsicmp(proc32.szExeFile, pwszCurrentProc) == 0)
                        {
                            if (umapProcsMonitored.find(proc32.th32ProcessID) == umapProcsMonitored.end())
                            {
                                HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION |
                                                           PROCESS_CREATE_THREAD     |
                                                           PROCESS_VM_OPERATION      |
                                                           PROCESS_VM_WRITE,
                                                           FALSE, proc32.th32ProcessID);
                                if (!hProc)
                                {
                                    std::wcout << std::format(L"OpenProcess failed on {} / {} with {}\n", pwszCurrentProc, proc32.th32ProcessID, GetLastError());
                                    continue;
                                }
                            
                                if (!IsAlreadyInjected(proc32.th32ProcessID, wszModFileName))
                                {
                                    bool bInject = false;
                                    BOOL bIsWow64 = FALSE;
                                    if (IsWow64Process(hProc, &bIsWow64) && bIsWow64)
                                    {
#ifndef _WIN64
                                        bInject = true;
#endif
                                    }
                                    else
                                    {
#ifdef _WIN64
                                        bInject = true;
#endif
                                    }

                                    if (bInject)
                                    {
                                        if (SUCCEEDED(Inject(hProc, wszModFileName)))
                                        {
                                            std::wcout << std::format(L"Injection succeeded for {} / {}\n", pwszCurrentProc, proc32.th32ProcessID);
                                        }
                                        else
                                        {
                                            std::wcout << std::format(L"Injection failed for {} / {}\n", pwszCurrentProc, proc32.th32ProcessID);
                                        }
                                    }
                                    else
                                    {
                                        std::wcout << std::format(L"Skipping injection on {} / {}. Target arch mismatch\n", pwszCurrentProc, proc32.th32ProcessID);
                                    }
                                }
                                else
                                {
                                    std::wcout << std::format(L"Skipping injection on {} / {}. Already injected\n", pwszCurrentProc, proc32.th32ProcessID);
                                }

                                umapProcsMonitored.insert(std::make_pair(proc32.th32ProcessID, hProc));
                            }
                        }
                    }

                } while (Process32NextW(hProcs, &proc32));

                for (auto iter = umapProcsMonitored.begin(); iter != umapProcsMonitored.end();)
                {
                    DWORD dwExitCode = 0;

                    if (!GetExitCodeProcess(iter->second, &dwExitCode))
                    {
                        std::wcout << std::format(L"GetExitCodeProcess failed on PID {} with {}\n", iter->first, GetLastError());
                    }

                    if (dwExitCode != STILL_ACTIVE)
                    {
                        iter = umapProcsMonitored.erase(iter);
                    }
                    else
                    {
                        ++iter;
                    }
                }
            }
            catch (...)
            {
                ExitPrompt(L"Exception while monitoring for processes\n");
            }
        }
    }
    catch (...)
    {
        ExitPrompt(L"Exception in Run() function\n");
    }
}

extern "C"
{
    __declspec(dllexport) void __cdecl Run()
    {
        Entry(false);
    }
    
    __declspec(dllexport) void __cdecl Run2()
    {
        Entry(true);
    }
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,
                    DWORD fdwReason,
                    LPVOID lpvReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
    {
        try
        {
            WCHAR wszModFileName[MAX_PATH] = { 0 };
            PWCHAR pwszExeName = nullptr;

            g_hSelf = hinstDLL;
            g_hklCurrentKeyboard = GetKeyboardLayout(0);

            if (GetModuleFileNameW(nullptr, wszModFileName, _countof(wszModFileName)))
            {
                pwszExeName = wcsrchr(wszModFileName, L'\\');
                pwszExeName = pwszExeName ? pwszExeName + 1 : wszModFileName;

                if (wcscmp(pwszExeName, L"rundll32.exe"))
                {
                    PerformFix();
                }
            }
        }
        catch (...)
        {
            OutputDebugStringW(L"Exception in DLL_PROCESS_ATTACH\n");
            return FALSE;
        }

        break;
    }
    default:
        break;
    }

    return TRUE;
}
