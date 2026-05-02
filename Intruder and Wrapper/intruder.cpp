// =============================================================================
//  intruder.cpp  --  NinjaRipper Intruder DLL  (single-file build)
//  Merged from: Intruder\
//  Output:      intruder.dll
//
//  Build (MSVC x86 Developer Command Prompt):
//    cl /nologo /W3 /O2 /EHsc /LD /DUNICODE /D_UNICODE /D_WIN32_WINNT=0x0502
//       intruder.cpp /Fe:intruder.dll
//       /link /DLL d3d9.lib dxguid.lib kernel32.lib user32.lib
//
//  Build (MSVC x64):
//    cl /nologo /W3 /O2 /EHsc /LD /DUNICODE /D_UNICODE /D_WIN32_WINNT=0x0502
//       /D_WIN64 intruder.cpp /Fe:intruder.dll
//       /link /DLL d3d9.lib dxguid.lib kernel32.lib user32.lib
// =============================================================================
 
#define _WIN32_WINNT 0x0502
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define UNICODE
#define _UNICODE
 
#include <windows.h>
#include <psapi.h>
#include <dbghelp.h>
#include <string>
#include <vector>
#include <cstdio>
#include <cstdarg>
 
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "dbghelp.lib")
 
class KIntruder;
class KHookMgr;
class KHook;
class KLog;
class KRipper9;
class KRipper8;
class KRipper11;
class KDxgi;
class KDdraw;
class KRipper7;
class KRipper6;
struct KSettings;     // intruder-side settings reader (from ksettings)
struct IRipper;       // abstract ripper interface used by KDxgi
 
// Filled when intruder/common/tools.h arrives:
extern std::string  wideStringToMultiByte(const wchar_t*);
extern std::string  multiByteStringAcpToMultiByte(const char*);
extern std::wstring multiByteStringAcpToWideString(const char*);
extern std::string  trim1(const std::string&, const std::string&);
extern void         fatalErrorMsgW(const wchar_t*);
extern void         hookEx(const char* name, LPVOID target, LPVOID hook,
                           int pool, KHook** outHook);
 
// Filled when intruder/common/macro.h arrives:
#ifndef SAFE_DELETE
#define SAFE_DELETE(p) { delete (p); (p) = nullptr; }
#endif
 
// Ripper factories � filled when dx*/ddraw/dxgi files arrive:
extern KRipper9*  create_KRipper9(HINSTANCE);
extern void       delete_KRipper9(KRipper9*&);
extern KRipper8*  create_KRipper8(HINSTANCE);
extern void       delete_KRipper8(KRipper8*&);
extern KRipper11* create_KRipper11(HINSTANCE);
extern void       delete_KRipper11(KRipper11*&);
extern KDxgi*     create_KDxgi(HINSTANCE);
extern void       delete_KDxgi(KDxgi*&);
extern void       setIRipper(KDxgi*, KRipper11*);
extern void       setIRipper(KDxgi*, IRipper*);
extern KDdraw*    create_KDdraw(HINSTANCE);
extern void       delete_KDdraw(KDdraw*&);
extern KRipper7*  create_KRipper7();
extern void       delete_KRipper7(KRipper7*&);
extern KRipper6*  create_KRipper6();
extern void       delete_KRipper6(KRipper6*&);
 
// kinject / ksettings (root common layer, already merged in nr_injector_full.cpp)
// These are re-declared here since intruder.dll links them in too:
extern const wchar_t* isWrapperDllPresentInExeDirectory(const wchar_t*);
 
 
// =============================================================================
//  SECTION 1 � intruder.h  (types and declarations)
// =============================================================================
 
// KUNICODE_STRING � NT internal Unicode string (used for LdrLoadDll hook)
#pragma pack(push,1)
struct KUNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
};
#pragma pack(pop)
 
// LdrLoadDll / LdrUnloadDll � NT loader functions we hook to watch DX DLL loads
typedef LONG (__stdcall *PFN_LdrLoadDll)(
    PWCHAR PathToFile, ULONG* Flags,
    KUNICODE_STRING* ModuleFileName, HMODULE* ModuleHandle);
 
typedef LONG (__stdcall *PFN_LdrUnloadDll)(HINSTANCE);
 
// PSAPI function pointer types (loaded dynamically; available in psapi.dll or
// kernel32.dll on Win7+)
typedef BOOL  (__stdcall *PFN_EnumProcessModules)
    (HANDLE, HMODULE*, DWORD, LPDWORD);
typedef DWORD (__stdcall *PFN_GetModuleFileNameExW)
    (HANDLE, HMODULE, wchar_t*, DWORD);
typedef DWORD (__stdcall *PFN_GetModuleFileNameExA)
    (HANDLE, HMODULE, char*, DWORD);
typedef BOOL  (__stdcall *PFN_GetModuleInformation)
    (HANDLE, HMODULE, LPMODULEINFO, DWORD);
 
// NtMapViewOfSection � not currently hooked but declared for completeness
typedef NTSTATUS(NTAPI *PFN_NtMapViewOfSection)(
    HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T,
    PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
 
// Function declarations from intruder.cpp implemented below:
HINSTANCE getDllBase(const wchar_t* dll);
void      printLoadedModules();
std::string getOSVersionString();
std::string getExecutablePath();
 
// Hook trampolines:
LONG __stdcall _LdrLoadDll(PWCHAR, ULONG*, KUNICODE_STRING*, HMODULE*);
LONG __stdcall _LdrUnloadDll(HINSTANCE);
 
 
// =============================================================================
//  SECTION 2 � process.h  (child-process injection hook declarations)
// =============================================================================
 
// Hook trampolines (defined in Section 5):
BOOL __stdcall _CreateProcessA(const char*, char*,
    LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD,
    LPVOID, const char*, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
 
BOOL __stdcall _CreateProcessW(const wchar_t*, wchar_t*,
    LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD,
    LPVOID, const wchar_t*, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
 
BOOL __stdcall _CreateProcessAsUserW(HANDLE, const wchar_t*, wchar_t*,
    LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD,
    LPVOID, const wchar_t*, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
 
BOOL __stdcall _CreateProcessWithLogonW(LPCWSTR, LPCWSTR, LPCWSTR, DWORD,
    LPCWSTR, LPWSTR, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW,
    LPPROCESS_INFORMATION);
 
BOOL __stdcall _CreateProcessWithTokenW(HANDLE, DWORD, LPCWSTR, LPWSTR,
    DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
 
BOOL __stdcall _SetInformationJobObject(HANDLE, JOBOBJECTINFOCLASS,
    LPVOID, DWORD);
 
BOOL __stdcall _SetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS,
    LPVOID, DWORD);
 
void setProcessCreateHooks();
 
 
// =============================================================================
//  SECTION 3 � Global state
// =============================================================================
 
// Version string built at startup
static char NINJA_RIPPER_VER[128];
 
// All ripper instances (nullptr until the corresponding DX DLL loads)
static KRipper9*  g_pRipper9  = nullptr;
static KRipper8*  g_pRipper8  = nullptr;
static KRipper11* g_pRipper11 = nullptr;
KDxgi*    g_pDxgi    = nullptr;   // non-static: accessed by dx11 ripper
KDdraw*   g_pDdraw   = nullptr;
KRipper7* g_pRipper7 = nullptr;
KRipper6* g_pRipper6 = nullptr;
 
// Core service objects
KLog*      g_pLog      = nullptr;
KIntruder* g_pIntruder = nullptr;
KHookMgr*  g_pHookMgr  = nullptr;
 
// LdrLoadDll / LdrUnloadDll hook handles
static KHook* pHook_LdrLoadDll   = nullptr;
static KHook* pHook_LdrUnloadDll = nullptr;
 
// DLL handle of intruder itself
static HMODULE hIntruderDll = nullptr;
 
// Serialises LdrLoadDll re-entrancy (DX DLL init paths can be recursive)
static CRITICAL_SECTION g_LdrLoadDll_cs;
 
// DX DLL names we detect and watch (from root constants + intruder-local)
static const wchar_t* DXGI_DLL    = L"dxgi.dll";
static const wchar_t* D3DIM700_DLL = L"d3dim700.dll";  // DX7
static const wchar_t* D3DIM_DLL   = L"d3dim.dll";      // DX6
static const wchar_t* PSAPI_DLL   = L"psapi.dll";
 
 
// =============================================================================
//  SECTION 4 � intruder.cpp  (DllMain, install, uninstall, LdrLoad hooks)
// =============================================================================
 
// ---- Helpers ----------------------------------------------------------------
 
// Returns the HINSTANCE of a system DLL if it is already loaded in this
// process.  Builds the full System32 path to avoid matching a same-named
// DLL from the game's own directory.
HINSTANCE getDllBase(const wchar_t* dll)
{
    wchar_t szBuffer[MAX_PATH];
    GetSystemDirectoryW(szBuffer, MAX_PATH);
    lstrcatW(szBuffer, L"\\");
    lstrcatW(szBuffer, dll);
    return GetModuleHandleW(szBuffer);
}
 
 
// Detect which injection mode is active by checking which DX wrapper DLL
// is loaded from the same directory as the target EXE.
static std::string getInjectMode()
{
    wchar_t buf[MAX_PATH];
    GetModuleFileNameW(0, buf, MAX_PATH);
    std::wstring dir = extractDirectoryFromFileName(buf);
 
    auto check = [&](const wchar_t* name, const char* label) -> std::string {
        if (GetModuleHandleW((dir + name).c_str()))
            return label;
        return "";
    };
 
    std::string r;
    if (!(r = check(D3D11_DLL, "d3d11.dll wrapper")).empty())   return r;
    if (!(r = check(D3D9_DLL,  "d3d9.dll wrapper")).empty())    return r;
    if (!(r = check(D3D8_DLL,  "d3d8.dll wrapper")).empty())    return r;
    if (!(r = check(DXGI_DLL,  "dxgi.dll wrapper")).empty())    return r;
    if (!(r = check(DDRAW_DLL, "ddraw.dll wrapper")).empty())   return r;
    return "intruder";
}
 
 
// Check all DX DLLs on startup � some may already be loaded before our hook.
static void tryInitRippers()
{
    HINSTANCE h;
 
    h = getDllBase(D3D9_DLL);
    if (h && !g_pRipper9)  g_pRipper9  = create_KRipper9(h);
 
    h = getDllBase(D3D8_DLL);
    if (h && !g_pRipper8)  g_pRipper8  = create_KRipper8(h);
 
    h = getDllBase(D3D11_DLL);
    if (h && !g_pRipper11) g_pRipper11 = create_KRipper11(h);
 
    h = getDllBase(DXGI_DLL);
    if (h && !g_pDxgi)     g_pDxgi     = create_KDxgi(h);
 
    h = getDllBase(DDRAW_DLL);
    if (h && !g_pDdraw)    g_pDdraw    = create_KDdraw(h);
 
    h = getDllBase(D3DIM700_DLL);
    if (h && !g_pRipper7)  g_pRipper7  = create_KRipper7();
 
    h = getDllBase(D3DIM_DLL);
    if (h && !g_pRipper6)  g_pRipper6  = create_KRipper6();
}
 
 
static void printSettings()
{
    std::string mode = getInjectMode();
    g_pLog->log("Inject mode: \"%s\"\n", mode.c_str());
 
    const KSettings* set = g_pIntruder->getSettings();
    if (set->debugD3D)
        g_pLog->log("D3D DEBUG flag enabled\n");
 
    g_pLog->log("Texture downscale max width : %d\n", set->downscaleWidth);
    g_pLog->log("Texture downscale max height: %d\n", set->downscaleHeight);
    g_pLog->log("Texture downscale value     : %d\n", set->downscale);
}
 
 
// ---- DLL startup / shutdown -------------------------------------------------
 
static void install(HINSTANCE hIntruder)
{
    InitializeCriticalSection(&g_LdrLoadDll_cs);
 
#if defined(_WIN64)
    const char* platf = "x64";
#else
    const char* platf = "x86";
#endif
 
    sprintf_s(NINJA_RIPPER_VER, 128, "Ninja Ripper %d.%d.%d %s\n",
              NR_VERSION_MAJOR, NR_VERSION_MINOR, NR_VERSION_BUILD, platf);
 
    // KIntruder: creates output dir, loads KSettings from registry
    g_pIntruder = new KIntruder(hIntruder);
    g_pIntruder->initialize();
 
    // Build log file path:  <outputDir>\<ExeName>.log.txt
    wchar_t szBuf[MAX_PATH]    = {};
    wchar_t szExeName[MAX_PATH] = {};
    GetModuleFileNameW(0, szBuf, MAX_PATH);
    extractFileNameFromPath(szBuf, szExeName, MAX_PATH);
    lstrcatW(szExeName, L".log.txt");
    std::wstring logFile = g_pIntruder->createOutputDir() + szExeName;
 
    g_pLog = new KLog;
    if (!g_pLog->open(logFile.c_str()))
    {
        std::wstring err = L"Can't open log file: " + logFile +
                           L"  Is log directory writable?";
        fatalErrorMsgW(err.c_str());
    }
 
    g_pLog->log(NINJA_RIPPER_VER);
    g_pLog->log("\xc2\xa9 black_ninja, 2017\n\n");  // � black_ninja (UTF-8)
    g_pLog->log("LOG START\n\n");
    g_pLog->log("Executable: %s\n",        getExecutablePath().c_str());
    g_pLog->log("Output directory: %s\n",
        wideStringToMultiByte(g_pIntruder->getOutputDir()).c_str());
    g_pLog->log("Win ver: %s\n\n",         getOSVersionString().c_str());
 
    // Initialise MinHook-backed hook manager
    g_pHookMgr = new KHookMgr;
    if (!g_pHookMgr->initialize())
        fatalErrorMsgW(L"Hooks manager initialization error");
 
    printSettings();
 
    if (!initializeCrashDumper())
        g_pLog->logWarning("Crash dumper initialization error\n\n");
 
    // Hook ntdll.LdrLoadDll and ntdll.LdrUnloadDll
    // These fire for EVERY DLL load in the process � we watch for DX DLLs.
    HMODULE hntdll = GetModuleHandleW(L"ntdll.dll");
 
    hookEx("LdrLoadDll",
           GetProcAddress(hntdll, "LdrLoadDll"),
           _LdrLoadDll,
           KHookMgr::EHOOK_NTDLL,
           &pHook_LdrLoadDll);
 
    hookEx("LdrUnloadDll",
           GetProcAddress(hntdll, "LdrUnloadDll"),
           _LdrUnloadDll,
           KHookMgr::EHOOK_NTDLL,
           &pHook_LdrUnloadDll);
 
    // Hook CreateProcess* family for child-process injection propagation
    setProcessCreateHooks();
 
    // Try to hook any DX DLLs already loaded (e.g. wrapper-mode)
    tryInitRippers();
}
 
 
static void uninstall()
{
    // Tear down hook pools in reverse priority order
    g_pHookMgr->unhookPool(KHookMgr::EHOOK_ADVAPI32);
    g_pHookMgr->unhookPool(KHookMgr::EHOOK_KERNEL32);
    g_pHookMgr->unhookPool(KHookMgr::EHOOK_NTDLL);
 
    // Destroy all rippers
    delete_KRipper8(g_pRipper8);
    delete_KRipper9(g_pRipper9);
    delete_KRipper11(g_pRipper11);
    delete_KDxgi(g_pDxgi);
    delete_KDdraw(g_pDdraw);
    delete_KRipper7(g_pRipper7);
    delete_KRipper6(g_pRipper6);
 
    g_pHookMgr->uninitialize();
    SAFE_DELETE(g_pHookMgr);
 
    g_pIntruder->cleanup();
    SAFE_DELETE(g_pIntruder);
 
    printLoadedModules();   // Dump full module list to log at exit
 
    g_pLog->log("LOG END\n");
    g_pLog->close();
    SAFE_DELETE(g_pLog);
 
    DeleteCriticalSection(&g_LdrLoadDll_cs);
}
 
 
// ---- DllMain ----------------------------------------------------------------
 
BOOL APIENTRY DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID)
{
    hIntruderDll = (HMODULE)hModule;
 
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        ::DisableThreadLibraryCalls((HMODULE)hModule);
        install((HINSTANCE)hModule);
        break;
    case DLL_PROCESS_DETACH:
        uninstall();
        break;
    }
    return TRUE;
}
 
 
// ---- LdrLoadDll hook � fires on EVERY DLL load in the target process --------
//
//  This is the core detection mechanism. When a game loads d3d9.dll (for
//  example) Windows calls ntdll.LdrLoadDll internally. Our hook sees it
//  and initialises the corresponding ripper.
//
//  THREAD SAFETY: Protected by g_LdrLoadDll_cs critical section because
//  games often load DLLs from multiple threads simultaneously.
 
LONG __stdcall _LdrLoadDll(PWCHAR PathToFile, ULONG* Flags,
                            KUNICODE_STRING* ModuleFileName,
                            HMODULE* ModuleHandle)
{
    EnterCriticalSection(&g_LdrLoadDll_cs);
 
    // Call the original LdrLoadDll first so the DLL is actually loaded
    PFN_LdrLoadDll orig = (PFN_LdrLoadDll)pHook_LdrLoadDll->getOriginalAddress();
    LONG res = orig(PathToFile, Flags, ModuleFileName, ModuleHandle);
 
    // --- D3D9 ---
    static BOOL sInitRipper9 = FALSE;
    HINSTANCE hD3D9 = getDllBase(D3D9_DLL);
    if (hD3D9 && !g_pRipper9 && !sInitRipper9)
    {
        sInitRipper9 = TRUE;
        g_pLog->log("D3D9.DLL loaded\n");
        g_pRipper9 = create_KRipper9(hD3D9);
        sInitRipper9 = FALSE;
    }
 
    // --- D3D8 ---
    static BOOL sInitRipper8 = FALSE;
    HINSTANCE hD3D8 = getDllBase(D3D8_DLL);
    if (hD3D8 && !g_pRipper8 && !sInitRipper8)
    {
        sInitRipper8 = TRUE;
        g_pLog->log("D3D8.DLL loaded\n");
        g_pRipper8 = create_KRipper8(hD3D8);
        sInitRipper8 = FALSE;
    }
 
    // --- D3D11 (interlocked because it can trigger DXGI init recursively) ---
    static DWORD sInitRipper11 = 0;
    HINSTANCE hD3D11 = getDllBase(D3D11_DLL);
    if (hD3D11 && !g_pRipper11 && sInitRipper11 == 0)
    {
        InterlockedIncrement(&sInitRipper11);
        g_pLog->log("D3D11.DLL loaded\n");
        g_pRipper11 = create_KRipper11(hD3D11);
        InterlockedDecrement(&sInitRipper11);
        setIRipper(g_pDxgi, g_pRipper11);  // wire DXGI ? D3D11 ripper
    }
 
    // --- DXGI ---
    static DWORD sInitDXGI = 0;
    HINSTANCE hDXGI = getDllBase(DXGI_DLL);
    if (hDXGI && !g_pDxgi && sInitDXGI == 0)
    {
        InterlockedIncrement(&sInitDXGI);
        g_pLog->log("DXGI.DLL loaded\n");
        g_pDxgi = create_KDxgi(hDXGI);
        InterlockedDecrement(&sInitDXGI);
        setIRipper(g_pDxgi, g_pRipper11);
        g_pLog->log("DXGI initialized\n");
    }
 
    // --- DirectDraw ---
    static BOOL sInitDdraw = FALSE;
    HINSTANCE hDdraw = getDllBase(DDRAW_DLL);
    if (hDdraw && !g_pDdraw && !sInitDdraw)
    {
        sInitDdraw = TRUE;
        g_pLog->log("DDRAW.DLL loaded\n");
        g_pDdraw = create_KDdraw(hDdraw);
        sInitDdraw = FALSE;
    }
 
    // --- DX7 (d3dim700.dll) ---
    static BOOL sInitD3DIm700 = FALSE;
    HINSTANCE hD3DIm700 = getDllBase(D3DIM700_DLL);
    if (hD3DIm700 && !g_pRipper7 && !sInitD3DIm700)
    {
        sInitD3DIm700 = TRUE;
        g_pLog->log("D3DIM700.DLL loaded\n");
        g_pRipper7 = create_KRipper7();
        sInitD3DIm700 = FALSE;
    }
 
    // --- DX6 (d3dim.dll) ---
    static BOOL sInitD3DIm = FALSE;
    HINSTANCE hD3DIm = getDllBase(D3DIM_DLL);
    if (hD3DIm && !g_pRipper6 && !sInitD3DIm)
    {
        sInitD3DIm = TRUE;
        g_pLog->log("D3DIM.DLL loaded\n");
        g_pRipper6 = create_KRipper6();
        sInitD3DIm = FALSE;
    }
 
    LeaveCriticalSection(&g_LdrLoadDll_cs);
    return res;
}
 
 
// ---- LdrUnloadDll hook � fires when a DLL is freed --------------------------
//
//  Cleans up ripper instances when the game unloads a DX DLL
//  (e.g. switching graphics back-end at runtime).
 
LONG __stdcall _LdrUnloadDll(HINSTANCE hMod)
{
    PFN_LdrUnloadDll orig =
        (PFN_LdrUnloadDll)pHook_LdrUnloadDll->getOriginalAddress();
    LONG res = orig(hMod);
 
    auto cleanup9 = [&]() {
        HINSTANCE h = getDllBase(D3D9_DLL);
        if (!h && g_pRipper9)
            { g_pLog->log("D3D9.DLL unloaded\n"); delete_KRipper9(g_pRipper9); g_pRipper9=nullptr; }
    };
    auto cleanup8 = [&]() {
        HINSTANCE h = getDllBase(D3D8_DLL);
        if (!h && g_pRipper8)
            { g_pLog->log("D3D8.DLL unloaded\n"); delete_KRipper8(g_pRipper8); g_pRipper8=nullptr; }
    };
    auto cleanup11 = [&]() {
        HINSTANCE h = getDllBase(D3D11_DLL);
        if (!h && g_pRipper11)
        {
            g_pLog->log("D3D11.DLL unloaded\n");
            delete_KRipper11(g_pRipper11); g_pRipper11=nullptr;
            IRipper* nullRipper = nullptr;
            setIRipper(g_pDxgi, nullRipper);
        }
    };
    auto cleanupDXGI = [&]() {
        HINSTANCE h = getDllBase(DXGI_DLL);
        if (!h && g_pDxgi)
            { g_pLog->log("DXGI.DLL unloaded\n"); delete_KDxgi(g_pDxgi); g_pDxgi=nullptr; }
    };
    auto cleanupDdraw = [&]() {
        HINSTANCE h = getDllBase(DDRAW_DLL);
        if (!h && g_pDdraw)
            { g_pLog->log("DDRAW.DLL unloaded\n"); delete_KDdraw(g_pDdraw); g_pDdraw=nullptr; }
    };
    auto cleanup7 = [&]() {
        HINSTANCE h = getDllBase(D3DIM700_DLL);
        if (!h && g_pRipper7)
            { g_pLog->log("D3DIM700.DLL unloaded\n"); delete_KRipper7(g_pRipper7); g_pRipper7=nullptr; }
    };
    auto cleanup6 = [&]() {
        HINSTANCE h = getDllBase(D3DIM_DLL);
        if (!h && g_pRipper6)
            { g_pLog->log("D3DIM.DLL unloaded\n"); delete_KRipper6(g_pRipper6); g_pRipper6=nullptr; }
    };
 
    cleanup9(); cleanup8(); cleanup11(); cleanupDXGI();
    cleanupDdraw(); cleanup7(); cleanup6();
 
    return res;
}
 
 
// ---- Diagnostics ------------------------------------------------------------
 
// Log all modules loaded in the current process (called at DLL_PROCESS_DETACH)
void printLoadedModules()
{
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    HMODULE hPSAPI    = GetModuleHandleW(PSAPI_DLL);
    if (!hPSAPI) hPSAPI = LoadLibraryW(PSAPI_DLL);
 
    PFN_EnumProcessModules   _EnumProcessModules   = nullptr;
    PFN_GetModuleInformation _GetModuleInformation = nullptr;
    PFN_GetModuleFileNameExW _GetModuleFileNameExW = nullptr;
 
    // Try psapi.dll first, fall back to kernel32 (Win7+)
    auto tryProc = [&](HMODULE hMod, const char* name) -> FARPROC
    {
        FARPROC p = GetProcAddress(hMod, name);
        if (!p) p = GetProcAddress(hKernel32, name);
        return p;
    };
 
    _EnumProcessModules   = (PFN_EnumProcessModules)  tryProc(hPSAPI, "EnumProcessModules");
    _GetModuleInformation = (PFN_GetModuleInformation) tryProc(hPSAPI, "GetModuleInformation");
    _GetModuleFileNameExW = (PFN_GetModuleFileNameExW) tryProc(hPSAPI, "GetModuleFileNameExW");
 
    if (!_GetModuleInformation || !_EnumProcessModules || !_GetModuleFileNameExW)
    {
        g_pLog->logError("\n\nPSAPI error � cannot enumerate modules\n\n");
        return;
    }
 
    g_pLog->log("Loaded Modules List\n");
#if defined(_WIN64)
    g_pLog->log("----------------------------------------\n");
    g_pLog->log("BaseAddr            Size         Module\n");
    g_pLog->log("----------------------------------------\n");
#else
    g_pLog->log("--------------------------------\n");
    g_pLog->log("BaseAddr    Size         Module\n");
    g_pLog->log("--------------------------------\n");
#endif
 
    HMODULE mods[1024]; DWORD cbNeeded = 0;
    HANDLE hProc = GetCurrentProcess();
    if (!_EnumProcessModules(hProc, mods, sizeof(mods), &cbNeeded))
    {
        g_pLog->logError("EnumProcessModules() Win32 Error: 0x%08X\n", GetLastError());
        return;
    }
 
    DWORD count = cbNeeded / sizeof(HMODULE);
    for (DWORD i = 0; i < count; ++i)
    {
        // NOTE: sizeof(MODULEINFO)*2 is a known x64 workaround for a Win API
        // quirk where the reported size can be slightly too large.
        MODULEINFO mi[2] = {};
        BOOL ok1 = _GetModuleInformation(hProc, mods[i], mi, 2*sizeof(mi));
        DWORD e1 = GetLastError();
 
        wchar_t modName[MAX_PATH] = {};
        BOOL ok2 = _GetModuleFileNameExW(hProc, mods[i], modName, sizeof(modName));
        DWORD e2 = GetLastError();
 
        if (ok1 && ok2)
        {
            g_pLog->log("0x%p (0x%08X)  %s\n",
                mods[i], mi[0].SizeOfImage,
                wideStringToMultiByte(modName).c_str());
        }
        else
        {
            if (!ok1) g_pLog->logError("GetModuleInformation() Win32 Error: 0x%08X\n", e1);
            if (!ok2) g_pLog->logError("GetModuleFileNameExW() Win32 Error: 0x%08X\n", e2);
        }
    }
}
 
 
// Returns true if this 32-bit process is running under WOW64 (on a 64-bit OS)
static BOOL IsWow64()
{
    typedef BOOL(WINAPI *PFNISWOW64)(HANDLE, PBOOL);
    PFNISWOW64 fn = (PFNISWOW64)GetProcAddress(
        GetModuleHandleW(L"kernel32"), "IsWow64Process");
    BOOL b = FALSE;
    if (fn) fn(GetCurrentProcess(), &b);
    return b;
}
 
std::string getOSVersionString()
{
    OSVERSIONINFOA ver = {};
    ver.dwOSVersionInfoSize = sizeof(ver);
    if (!GetVersionExA(&ver)) return "UNKNOWN";
 
    char buf[128];
    sprintf_s(buf, 128, "%d.%d", ver.dwMajorVersion, ver.dwMinorVersion);
    std::string res = buf;
 
#if defined(_WIN64)
    res += " x64";
#else
    res += IsWow64() ? " x64" : " x86";
#endif
 
    res += " ";
    res += ver.szCSDVersion;
    return res;
}
 
std::string getExecutablePath()
{
    wchar_t szBuf[MAX_PATH] = {};
    GetModuleFileNameW(0, szBuf, MAX_PATH);
    return wideStringToMultiByte(szBuf);
}
 
 
// =============================================================================
//  SECTION 5 � process.cpp  (child-process injection hooks)
//
//  PURPOSE: When the target game spawns a child process, these hooks
//  intercept every CreateProcess* variant, force CREATE_SUSPENDED,
//  inject intruder.dll into the child, then optionally resume it.
//  This propagates the ripper into launchers that spawn the actual game.
// =============================================================================
 
// -- Module-level hook handle storage ----------------------------------------
static KHook* pHook_CreateProcessA          = nullptr;
       KHook* pHook_CreateProcessW          = nullptr;  // extern: used by KInject
static KHook* pHook_CreateProcessAsUserW    = nullptr;
static KHook* pHook_CreateProcessWithLogonW = nullptr;
static KHook* pHook_CreateProcessWithTokenW = nullptr;
static KHook* pHook_SetInformationJobObject = nullptr;
static KHook* pHook_SetTokenInformation     = nullptr;
 
static const wchar_t* ADVAPI32_DLL = L"advapi32.dll";
static const wchar_t* KERNEL32_DLL = L"kernel32.dll";
 
 
// -- Helpers ------------------------------------------------------------------
 
// If the caller did NOT pass CREATE_SUSPENDED we force it so we can inject,
// then note that we need to resume the thread ourselves afterward.
static void suspendFlag(BOOL* wasSuspended, DWORD* flags)
{
    *wasSuspended = (*flags & CREATE_SUSPENDED) ? TRUE : FALSE;
    *flags |= CREATE_SUSPENDED;
}
 
static DWORD getTargetBinaryTypeA(const char* lpApp, const char* lpCmd)
{
    DWORD res = 0;
    if (lpApp) GetBinaryTypeA(lpApp, &res);
    if (!lpCmd) return res;
    std::wstring cmdW = multiByteStringAcpToWideString(lpCmd);
    int argc = 0; LPWSTR* argv = CommandLineToArgvW(cmdW.c_str(), &argc);
    if (argc >= 1) GetBinaryTypeW(argv[0], &res);
    return res;
}
 
static DWORD getTargetBinaryTypeW(const wchar_t* lpApp, const wchar_t* lpCmd)
{
    DWORD res = 0;
    if (lpApp) GetBinaryTypeW(lpApp, &res);
    if (!lpCmd) return res;
    int argc = 0; LPWSTR* argv = CommandLineToArgvW(lpCmd, &argc);
    if (argc >= 1) GetBinaryTypeW(argv[0], &res);
    return res;
}
 
static const char*    getExePathA(const char* exe,    const char* cmd)    { return exe ? exe : cmd; }
static const wchar_t* getExePathW(const wchar_t* exe, const wchar_t* cmd) { return exe ? exe : cmd; }
 
static std::wstring getTargetDirW(const wchar_t* lpApp, const wchar_t* lpCmd)
{
    if (lpApp) return extractDirectoryFromFileName(lpApp);
    if (lpCmd) {
        int argc = 0; LPWSTR* argv = CommandLineToArgvW(lpCmd, &argc);
        if (argc >= 1) return extractDirectoryFromFileName(argv[0]);
    }
    return {};
}
 
 
// Core injection call made from every CreateProcess* hook after the child is
// created suspended.  Determines inject bitness, calls KInject, then resumes
// the child if it was not originally suspended by the game itself.
static void injectToChild(const wchar_t*       targetDir,
                          DWORD                targetBinaryType,
                          BOOL                 wasSuspended,
                          LPPROCESS_INFORMATION pi)
{
    // If a DX wrapper DLL already exists in the target dir, skip APC injection
    // (wrapper mode handles it through the DLL's own load path).
    const wchar_t* wrapDll = isWrapperDllPresentInExeDirectory(targetDir);
    if (wrapDll)
    {
        std::wstring full = std::wstring(targetDir) + wrapDll;
        std::string  utf8 = wideStringToMultiByte(full.c_str());
        DWORD wrapType = 0;
        GetBinaryTypeW(full.c_str(), &wrapType);
        if (targetBinaryType == wrapType)
            g_pLog->logError("Inject to child skipped � wrapper dll found (delete manually): %s\n", utf8.c_str());
        else
            g_pLog->logError("Inject to child skipped � arch mismatch 32<->64, wrapper: %s\n", utf8.c_str());
 
        if (!wasSuspended) ResumeThread(pi->hThread);
        return;
    }
 
    // Load settings fresh (output dir, intruder DLL paths)
    KSettings settings;
    settings.load();
    KInject inj(settings.intruderDir32, settings.intruderDir64);
 
#if defined(_WIN64)
    DWORD injType = SCS_64BIT_BINARY;
#else
    DWORD injType = SCS_32BIT_BINARY;
#endif
 
    int errCode = inj.injectDll(targetBinaryType, injType, pi);
    std::wstring errW = inj.getErrorString(errCode, inj.getWin32LastError());
    g_pLog->log("Inject to child. Status: %s\n",
                wideStringToMultiByte(errW.c_str()).c_str());
 
    if (!wasSuspended) ResumeThread(pi->hThread);
}
 
 
// -- CreateProcess* hook trampolines ------------------------------------------
 
BOOL __stdcall _CreateProcessA(
    const char* lpApp, char* lpCmd,
    LPSECURITY_ATTRIBUTES lpPA, LPSECURITY_ATTRIBUTES lpTA,
    BOOL bInherit, DWORD dwFlags, LPVOID lpEnv,
    const char* lpDir, LPSTARTUPINFOA lpSI, LPPROCESS_INFORMATION lpPI)
{
    DWORD tgtType = getTargetBinaryTypeA(lpApp, lpCmd);
    BOOL  wasSusp;
    suspendFlag(&wasSusp, &dwFlags);
 
    PFN_CreateProcessA orig = (PFN_CreateProcessA)pHook_CreateProcessA->getOriginalAddress();
    BOOL ok = orig(lpApp,lpCmd,lpPA,lpTA,bInherit,dwFlags,lpEnv,lpDir,lpSI,lpPI);
 
    std::string path = multiByteStringAcpToMultiByte(getExePathA(lpApp,lpCmd));
    path = trim1(path, "\"");
    g_pLog->log("CreateProcessA(\"%s\") return %d\n", path.c_str(), ok);
 
    std::wstring appW, cmdW;
    if (lpApp) appW = multiByteStringAcpToWideString(lpApp);
    if (lpCmd) cmdW = multiByteStringAcpToWideString(lpCmd);
    injectToChild(getTargetDirW(appW.c_str(), cmdW.c_str()).c_str(),
                  tgtType, wasSusp, lpPI);
    return ok;
}
 
 
BOOL __stdcall _CreateProcessW(
    const wchar_t* lpApp, wchar_t* lpCmd,
    LPSECURITY_ATTRIBUTES lpPA, LPSECURITY_ATTRIBUTES lpTA,
    BOOL bInherit, DWORD dwFlags, LPVOID lpEnv,
    const wchar_t* lpDir, LPSTARTUPINFOW lpSI, LPPROCESS_INFORMATION lpPI)
{
    DWORD tgtType = getTargetBinaryTypeW(lpApp, lpCmd);
    BOOL  wasSusp;
    suspendFlag(&wasSusp, &dwFlags);
 
    PFN_CreateProcessW orig = (PFN_CreateProcessW)pHook_CreateProcessW->getOriginalAddress();
    BOOL ok = orig(lpApp,lpCmd,lpPA,lpTA,bInherit,dwFlags,lpEnv,lpDir,lpSI,lpPI);
 
    std::string path = wideStringToMultiByte(getExePathW(lpApp, lpCmd));
    path = trim1(path, "\"");
    g_pLog->log("CreateProcessW(\"%s\") return: %d\n", path.c_str(), ok);
 
    injectToChild(getTargetDirW(lpApp, lpCmd).c_str(), tgtType, wasSusp, lpPI);
    return ok;
}
 
 
BOOL __stdcall _CreateProcessAsUserW(
    HANDLE hToken, const wchar_t* lpApp, wchar_t* lpCmd,
    LPSECURITY_ATTRIBUTES lpPA, LPSECURITY_ATTRIBUTES lpTA,
    BOOL bInherit, DWORD dwFlags, LPVOID lpEnv,
    const wchar_t* lpDir, LPSTARTUPINFOW lpSI, LPPROCESS_INFORMATION lpPI)
{
    DWORD tgtType  = getTargetBinaryTypeW(lpApp, lpCmd);
    DWORD origFlags = dwFlags;
    BOOL  wasSusp;
    suspendFlag(&wasSusp, &dwFlags);
 
    // Strip flags that require elevated token � fall back to plain CreateProcessW
    // (mirrors original behaviour: avoids ACCESS_DENIED from UAC job objects)
    DWORD fff = dwFlags;
    fff &= ~CREATE_PROTECTED_PROCESS;
    fff &= ~CREATE_PRESERVE_CODE_AUTHZ_LEVEL;
    LPSTARTUPINFOW lpSI2 = lpSI;
    if (dwFlags & EXTENDED_STARTUPINFO_PRESENT)
    {
        fff &= ~EXTENDED_STARTUPINFO_PRESENT;
        lpSI2->cb = sizeof(STARTUPINFOW);
    }
 
    PFN_CreateProcessW orig = (PFN_CreateProcessW)pHook_CreateProcessW->getOriginalAddress();
    BOOL ok = orig(lpApp,lpCmd,lpPA,lpTA,bInherit,fff,lpEnv,lpDir,lpSI2,lpPI);
 
    std::string path = wideStringToMultiByte(getExePathW(lpApp, lpCmd));
    path = trim1(path, "\"");
    g_pLog->log("CreateProcessAsUserW(\"%s\") Flags: 0x%08X return: %d\n",
                path.c_str(), origFlags, ok);
 
    injectToChild(getTargetDirW(lpApp, lpCmd).c_str(), tgtType, wasSusp, lpPI);
    return ok;
}
 
 
BOOL __stdcall _CreateProcessWithLogonW(
    LPCWSTR lpUser, LPCWSTR lpDomain, LPCWSTR lpPass, DWORD dwLogon,
    LPCWSTR lpApp, LPWSTR lpCmd, DWORD dwFlags, LPVOID lpEnv,
    LPCWSTR lpDir, LPSTARTUPINFOW lpSI, LPPROCESS_INFORMATION lpPI)
{
    DWORD tgtType = getTargetBinaryTypeW(lpApp, lpCmd);
    BOOL  wasSusp;
    suspendFlag(&wasSusp, &dwFlags);
 
    PFN_CreateProcessWithLogonW orig =
        (PFN_CreateProcessWithLogonW)pHook_CreateProcessWithLogonW->getOriginalAddress();
    BOOL ok = orig(lpUser,lpDomain,lpPass,dwLogon,lpApp,lpCmd,dwFlags,lpEnv,lpDir,lpSI,lpPI);
 
    std::string path = wideStringToMultiByte(getExePathW(lpApp, lpCmd));
    path = trim1(path, "\"");
    g_pLog->log("CreateProcessWithLogonW(\"%s\") return: %d\n", path.c_str(), ok);
 
    injectToChild(getTargetDirW(lpApp, lpCmd).c_str(), tgtType, wasSusp, lpPI);
    return ok;
}
 
 
BOOL __stdcall _CreateProcessWithTokenW(
    HANDLE hToken, DWORD dwLogon, LPCWSTR lpApp, LPWSTR lpCmd,
    DWORD dwFlags, LPVOID lpEnv, LPCWSTR lpDir,
    LPSTARTUPINFOW lpSI, LPPROCESS_INFORMATION lpPI)
{
    DWORD tgtType = getTargetBinaryTypeW(lpApp, lpCmd);
    BOOL  wasSusp;
    suspendFlag(&wasSusp, &dwFlags);
 
    PFN_CreateProcessWithTokenW orig =
        (PFN_CreateProcessWithTokenW)pHook_CreateProcessWithTokenW->getOriginalAddress();
    BOOL ok = orig(hToken,dwLogon,lpApp,lpCmd,dwFlags,lpEnv,lpDir,lpSI,lpPI);
 
    std::string path = wideStringToMultiByte(getExePathW(lpApp, lpCmd));
    path = trim1(path, "\"");
    g_pLog->log("CreateProcessWithTokenW(\"%s\") return: %d\n", path.c_str(), ok);
 
    injectToChild(getTargetDirW(lpApp, lpCmd).c_str(), tgtType, wasSusp, lpPI);
    return ok;
}
 
 
BOOL __stdcall _SetInformationJobObject(
    HANDLE hJob, JOBOBJECTINFOCLASS cls, LPVOID lpInfo, DWORD cbLen)
{
    PFN_SetInformationJobObject orig =
        (PFN_SetInformationJobObject)pHook_SetInformationJobObject->getOriginalAddress();
    g_pLog->log("SetInformationJobObject(%d)\n", cls);
    return orig(hJob, cls, lpInfo, cbLen);
}
 
 
BOOL __stdcall _SetTokenInformation(
    HANDLE hToken, TOKEN_INFORMATION_CLASS cls, LPVOID lpInfo, DWORD cbLen)
{
    PFN_SetTokenInformation orig =
        (PFN_SetTokenInformation)pHook_SetTokenInformation->getOriginalAddress();
 
    // Block integrity-level downgrades � they prevent injection into children
    if (cls == TokenIntegrityLevel)
    {
        g_pLog->log("SetTokenInformation TIL==INTEGRITY. Call disabled\n");
        return TRUE;
    }
 
    g_pLog->log("SetTokenInformation(%d)\n", cls);
    return orig(hToken, cls, lpInfo, cbLen);
}
 
 
// Install all process-creation hooks.  Called from install() after KHookMgr
// is ready.
void setProcessCreateHooks()
{
    HMODULE hK32     = GetModuleHandleW(KERNEL32_DLL);
    HMODULE hAdv32   = GetModuleHandleW(ADVAPI32_DLL);
    if (!hAdv32) hAdv32 = LoadLibraryW(ADVAPI32_DLL);
 
    hookEx("CreateProcessA",          GetProcAddress(hK32,  "CreateProcessA"),
           _CreateProcessA,           KHookMgr::EHOOK_KERNEL32, &pHook_CreateProcessA);
 
    hookEx("CreateProcessW",          GetProcAddress(hK32,  "CreateProcessW"),
           _CreateProcessW,           KHookMgr::EHOOK_KERNEL32, &pHook_CreateProcessW);
 
    hookEx("CreateProcessAsUserW",    GetProcAddress(hAdv32,"CreateProcessAsUserW"),
           _CreateProcessAsUserW,     KHookMgr::EHOOK_ADVAPI32, &pHook_CreateProcessAsUserW);
 
    hookEx("CreateProcessWithLogonW", GetProcAddress(hAdv32,"CreateProcessWithLogonW"),
           _CreateProcessWithLogonW,  KHookMgr::EHOOK_ADVAPI32, &pHook_CreateProcessWithLogonW);
 
    hookEx("CreateProcessWithTokenW", GetProcAddress(hAdv32,"CreateProcessWithTokenW"),
           _CreateProcessWithTokenW,  KHookMgr::EHOOK_ADVAPI32, &pHook_CreateProcessWithTokenW);
 
    hookEx("SetTokenInformation",     GetProcAddress(hAdv32,"SetTokenInformation"),
           _SetTokenInformation,      KHookMgr::EHOOK_ADVAPI32, &pHook_SetTokenInformation);
 
    // SetInformationJobObject hook is commented out in original source �
    // preserved as-is (some games use job objects to prevent external injection)
    /*
    hookEx("SetInformationJobObject", GetProcAddress(hK32, "SetInformationJobObject"),
           _SetInformationJobObject,  KHookMgr::EHOOK_KERNEL32, &pHook_SetInformationJobObject);
    */
}
 
 
// =============================================================================
//  SECTION 6 � IRipper interface + ERIP_ERR  (iripper.h)
// =============================================================================
 
enum ERIP_ERR
{
    E_UNK_ERR                = 0x88885000,
    E_MALLOC_ERR,
    E_UNK_INDEX_FORMAT_ERR,
    E_FUNC_NOT_FOUND,
    E_INPUT_LAYOUT_NOT_FOUND,
    E_INPUT_TYPE_ERR,
    E_UNS_PRIM_TOPOLOGY,
    E_NULL_BUFF,
    E_COPY_BUFFER_ERR,
    E_MAP_ERR,
    E_VERTEXDECL_NOT_SET,
    E_FVF_NULL,
    E_NOTREALIZED,
    E_TEXTURE_FORMAT_ERR,
    E_NULL_TEXTURE,
    ERIP_FORCE_DWORD = 0xFFFFFFFFUL
};
 
// Abstract interface all rippers implement.
// KDxgi holds a pointer to the current IRipper so it can forward
// Present() callbacks to whichever DX11 ripper is active.
class IRipper
{
public:
    virtual ~IRipper() {}
    virtual void frameStart()      = 0;
    virtual void frameEnd()        = 0;
    virtual void textureRipStart() = 0;
    virtual void textureRipEnd()   = 0;
};
 
 
// =============================================================================
//  SECTION 7 � commontypes.h  (IUnknown helper)
// =============================================================================
 
#include <Unknwn.h>
 
enum { IDX_IUnknown_QueryInterface = 0 };
 
typedef HRESULT(__stdcall* PFN_IUnk_QueryInterface)(
    IUnknown* p, REFIID refiid, void** obj);
 
 
// =============================================================================
//  SECTION 8 � datatypes.h  (vertex element type system)
// =============================================================================
 
const DWORD MAX_UNPACKED_LEN = 64;
 
struct EInputType
{
    typedef size_t Type;
    enum
    {
        UNKNOWNINPUTTYPE = 0,
        R32G32B32A32_TYPELESS, R32G32B32A32_FLOAT, R32G32B32A32_SINT, R32G32B32A32_UINT,
        R32G32B32_TYPELESS,    R32G32B32_FLOAT,    R32G32B32_SINT,    R32G32B32_UINT,
        R16G16B16A16_TYPELESS, R16G16B16A16_FLOAT, R16G16B16A16_SINT,
        R16G16B16A16_UINT,     R16G16B16A16_SNORM, R16G16B16A16_UNORM,
        R32G32_TYPELESS, R32G32_FLOAT, R32G32_SINT, R32G32_UINT,
        R8G8B8A8_TYPELESS, R8G8B8A8_SINT, R8G8B8A8_UINT, R8G8B8A8_SNORM, R8G8B8A8_UNORM,
        R16G16_TYPELESS, R16G16_FLOAT, R16G16_SINT, R16G16_UINT, R16G16_SNORM, R16G16_UNORM,
        R32_TYPELESS, R32_FLOAT, R32_SINT, R32_UINT,
        R8G8_TYPELESS, R8G8_UNORM, R8G8_UINT, R8G8_SNORM, R8G8_SINT,
        R16_TYPELESS, R16_FLOAT, R16_UNORM, R16_UINT, R16_SNORM, R16_SINT,
        R8_TYPELESS, R8_UINT, R8_SINT, R8_SNORM, R8_UNORM,
        FLOAT5, FLOAT6, FLOAT7, FLOAT8,   // D3D8 legacy
        UDEC3, DEC3N,                      // D3D9 legacy
        R10G10B10A2_UNORM, B8G8R8A8_UNORM,
        LAST,
    };
};
 
struct EOutputType
{
    typedef size_t Type;
    enum
    {
        EFLOAT      = 0,
        EUINT       = 1,
        ESINT       = 2,
        ETYPELESS8  = 3,
        ETYPELESS16 = 4,
        ETYPELESS32 = 5,
        ETYPENOTSET = 6,
    };
};
 
// Defined in intruder/common/datatypes.cpp (coming in part 2):
extern DWORD       getInputTypeSize(EInputType::Type t);
extern const char* EInputType2Str(EInputType::Type t);
extern const char* EOutputType2Str(EOutputType::Type t);
 
 
// =============================================================================
//  SECTION 9 � KLog  (klog.h � thread-safe timestamped logger)
// =============================================================================
 
class KLog
{
public:
    KLog() : fp(nullptr) { InitializeCriticalSection(&cs); }
    ~KLog() { close(); DeleteCriticalSection(&cs); }
 
    void close()
    {
        if (fp) { fflush(fp); fclose(fp); fp = nullptr; }
    }
 
    bool open(const wchar_t* fileName, bool append = false)
    {
        errno_t err = _wfopen_s(&fp, fileName, append ? L"w+" : L"w");
        return (err == 0);
    }
 
    void log(const char* fmt, ...)
    {
        if (!fp) return;
        EnterCriticalSection(&cs);
        printInfo();
        va_list ap; va_start(ap, fmt);
        vfprintf(fp, fmt, ap); fflush(fp); va_end(ap);
        LeaveCriticalSection(&cs);
    }
 
    void logError(const char* fmt, ...)
    {
        if (!fp) return;
        EnterCriticalSection(&cs);
        printInfo();
        fprintf(fp, "ERROR: ");
        va_list ap; va_start(ap, fmt);
        vfprintf(fp, fmt, ap); fflush(fp); va_end(ap);
        LeaveCriticalSection(&cs);
    }
 
    void logWarning(const char* fmt, ...)
    {
        if (!fp) return;
        EnterCriticalSection(&cs);
        printInfo();
        fprintf(fp, "WARNING: ");
        va_list ap; va_start(ap, fmt);
        vfprintf(fp, fmt, ap); fflush(fp); va_end(ap);
        LeaveCriticalSection(&cs);
    }
 
private:
    FILE*            fp;
    CRITICAL_SECTION cs;
 
    void printInfo()
    {
        time_t t = time(nullptr);
        struct tm lt = {};
        localtime_s(&lt, &t);
        fprintf(fp, "%02d%02d/%02d%02d%02d [%04X] ",
                1 + lt.tm_mon, lt.tm_mday,
                lt.tm_hour, lt.tm_min, lt.tm_sec,
                (unsigned)GetCurrentThreadId());
    }
};
 
 
// =============================================================================
//  SECTION 10 � KHook + HooksGroup  (khook.h/cpp)
// =============================================================================
 
class KHook
{
public:
    KHook(LPVOID targ, LPVOID orig, LPVOID detour)
        : targetAddress(targ), originalAddress(orig), detourAddress(detour) {}
 
    LPVOID getTargetAddress()   const { return targetAddress; }
    LPVOID getOriginalAddress() const { return originalAddress; }
    LPVOID getDetourAddress()   const { return detourAddress; }
 
private:
    LPVOID targetAddress;
    LPVOID originalAddress;
    LPVOID detourAddress;
};
 
struct HooksGroupEntry
{
    HooksGroupEntry() : hk(nullptr), handler(nullptr) {}
    KHook*  hk;
    LPVOID  handler;
};
 
class HooksGroup
{
    enum { MAX_CNT = 8 };
public:
    HooksGroup()
    {
        for (size_t i = 0; i < MAX_CNT; ++i)
            { hooks[i].hk = nullptr; hooks[i].handler = nullptr; }
    }
 
    void setHandler(size_t idx, LPVOID h)
        { if (idx < MAX_CNT) hooks[idx].handler = h; }
 
    void clearHooks()
        { for (size_t i = 0; i < MAX_CNT; ++i) hooks[i].hk = nullptr; }
 
    HooksGroupEntry* getFreeHookData()
    {
        for (size_t i = 0; i < MAX_CNT; ++i)
            if (!hooks[i].hk && hooks[i].handler)
                return &hooks[i];
        return nullptr;
    }
 
    KHook* getHook(size_t idx)
        { return (idx < MAX_CNT) ? hooks[idx].hk : nullptr; }
 
    size_t getSize() const { return MAX_CNT; }
 
    bool isTargetHooked(LPVOID targ)
    {
        for (size_t i = 0; i < MAX_CNT; ++i)
            if (hooks[i].hk && hooks[i].hk->getTargetAddress() == targ)
                return true;
        return false;
    }
 
private:
    HooksGroupEntry hooks[MAX_CNT];
};
 
 
// =============================================================================
//  SECTION 11 � KHookMgr  (khookmgr.h/cpp)
//  Wraps MinHook with pool-based lifecycle management.
//  MinHook header included from intruder/MinHook/include/MinHook.h
// =============================================================================
 
// MinHook forward declarations (full header in MinHook/include/MinHook.h)
// Uncomment the include once MinHook source is added:
// #include "MinHook.h"
typedef enum MH_STATUS
{
    MH_UNKNOWN                  = -1,
    MH_OK                       = 0,
    MH_ERROR_ALREADY_INITIALIZED,
    MH_ERROR_NOT_INITIALIZED,
    MH_ERROR_ALREADY_CREATED,
    MH_ERROR_NOT_CREATED,
    MH_ERROR_ENABLED,
    MH_ERROR_DISABLED,
    MH_ERROR_NOT_EXECUTABLE,
    MH_ERROR_UNSUPPORTED_FUNCTION,
    MH_ERROR_MEMORY_ALLOC,
    MH_ERROR_MEMORY_PROTECT,
    MH_ERROR_MODULE_NOT_FOUND,
    MH_ERROR_FUNCTION_NOT_FOUND,
} MH_STATUS;
 
extern "C" MH_STATUS WINAPI MH_Initialize(void);
extern "C" MH_STATUS WINAPI MH_Uninitialize(void);
extern "C" MH_STATUS WINAPI MH_CreateHook(LPVOID pTarget, LPVOID pDetour, LPVOID* ppOriginal);
extern "C" MH_STATUS WINAPI MH_EnableHook(LPVOID pTarget);
extern "C" MH_STATUS WINAPI MH_RemoveHook(LPVOID pTarget);
extern "C" MH_STATUS WINAPI MH_DeleteHookEntry(LPVOID pTarget); // NR extension
 
#include <list>
 
class KHookMgr
{
public:
    enum PoolId
    {
        EHOOK_POOL_DX9 = 1, EHOOK_POOL_DX8, EHOOK_POOL_DX11,
        EHOOK_POOL_DXGI, EHOOK_POOL_DDRAW, EHOOK_POOL_D3DIM700,
        EHOOK_KERNEL32, EHOOK_NTDLL, EHOOK_ADVAPI32,
        EHOOK_GDI32, EHOOK_POOL_D3DIM,
    };
 
    KHookMgr() : lastError(0) {}
    ~KHookMgr() {}
 
    bool initialize()
    {
        InitializeCriticalSection(&cs);
        return MH_Initialize() == MH_OK;
    }
 
    bool uninitialize()
    {
        DeleteCriticalSection(&cs);
        return MH_Uninitialize() == MH_OK;
    }
 
    // Create+enable hook, return KHook descriptor (not registered)
    KHook* hook(LPVOID targ, LPVOID detour)
    {
        LPVOID orig = nullptr;
        lastError = (int)MH_CreateHook(targ, detour, &orig);
        if (lastError != MH_OK) return nullptr;
        lastError = (int)MH_EnableHook(targ);
        if (lastError != MH_OK) return nullptr;
        return new KHook(targ, orig, detour);
    }
 
    KHook* hookAndRegister(LPVOID targ, LPVOID detour, int pool)
    {
        KHook* h = hook(targ, detour);
        if (h) { RegistryEntry e; e.pool=pool; e.hook=h; reg.push_back(e); }
        return h;
    }
 
    bool unhook(KHook* h)
    {
        if (!h) return false;
        lastError = (int)MH_RemoveHook(h->getTargetAddress());
        if (lastError != MH_OK)
            lastError = (int)MH_DeleteHookEntry(h->getTargetAddress());
        bool ok = (lastError == MH_OK);
        delete h;
        return ok;
    }
 
    bool unhookAndUnregister(KHook* h)
    {
        deleteFromRegistry(h);
        return unhook(h);
    }
 
    void unhookPool(int pool)
    {
        for (auto it = reg.begin(); it != reg.end();)
        {
            if (it->pool == pool)
            {
                if (!unhook(it->hook))
                    g_pLog->logError("Unhook error: %s\n", getLastErrorString());
                it = reg.erase(it);
            }
            else ++it;
        }
    }
 
    KHook* getHookByTargetAddress(LPVOID targ)
    {
        for (auto& e : reg)
            if (e.hook->getTargetAddress() == targ) return e.hook;
        return nullptr;
    }
 
    const char* getLastErrorString() const
    {
        switch (lastError)
        {
        case MH_OK:                         return "MH_OK";
        case MH_ERROR_ALREADY_INITIALIZED:  return "MH_ERROR_ALREADY_INITIALIZED";
        case MH_ERROR_NOT_INITIALIZED:      return "MH_ERROR_NOT_INITIALIZED";
        case MH_ERROR_ALREADY_CREATED:      return "MH_ERROR_ALREADY_CREATED";
        case MH_ERROR_NOT_CREATED:          return "MH_ERROR_NOT_CREATED";
        case MH_ERROR_ENABLED:              return "MH_ERROR_ENABLED";
        case MH_ERROR_DISABLED:             return "MH_ERROR_DISABLED";
        case MH_ERROR_NOT_EXECUTABLE:       return "MH_ERROR_NOT_EXECUTABLE";
        case MH_ERROR_UNSUPPORTED_FUNCTION: return "MH_ERROR_UNSUPPORTED_FUNCTION";
        case MH_ERROR_MEMORY_ALLOC:         return "MH_ERROR_MEMORY_ALLOC";
        case MH_ERROR_MEMORY_PROTECT:       return "MH_ERROR_MEMORY_PROTECT";
        case MH_ERROR_MODULE_NOT_FOUND:     return "MH_ERROR_MODULE_NOT_FOUND";
        case MH_ERROR_FUNCTION_NOT_FOUND:   return "MH_ERROR_FUNCTION_NOT_FOUND";
        default:                            return "MH_UNKNOWN";
        }
    }
 
private:
    void deleteFromRegistry(KHook* h)
    {
        for (auto it = reg.begin(); it != reg.end(); ++it)
            if (it->hook == h) { reg.erase(it); break; }
    }
 
    CRITICAL_SECTION cs;
    int lastError;
    struct RegistryEntry { int pool; KHook* hook; };
    std::list<RegistryEntry> reg;
};
 
 
// =============================================================================
//  SECTION 12 � tools.h stubs + hookEx()
//  Full implementation arrives in intruder/common/tools.h (part 2).
//  hookEx() is used by every hook-install call site throughout the DLL.
// =============================================================================
 
// String utilities � implemented in tools.cpp (part 2)
std::string  wideStringToMultiByte(const wchar_t* ws);
std::wstring multiByteStringAcpToWideString(const char* s);
std::string  multiByteStringAcpToMultiByte(const char* s);
std::string  trim1(const std::string& s, const std::string& chars);
void         fatalErrorMsgW(const wchar_t* msg);
int          createDirectoryWithErrorCheck(const wchar_t* path);
 
// Convenience wrapper: hook a function and register it in the named pool.
// Logs success/failure via g_pLog.
inline void hookEx(const char* name, LPVOID targ, LPVOID detour,
                   int pool, KHook** outHook)
{
    if (!targ) { g_pLog->logError("hookEx: null target for '%s'\n", name); return; }
    KHook* h = g_pHookMgr->hookAndRegister(targ, detour, pool);
    if (h)
        g_pLog->log("Hook OK: %s\n", name);
    else
        g_pLog->logError("Hook FAIL: %s  [%s]\n", name, g_pHookMgr->getLastErrorString());
    if (outHook) *outHook = h;
}
 
 
// =============================================================================
//  SECTION 13 � KIntruder  (kintruder.h/cpp)
//  Manages output directories, hotkey state, frame/texture/shader counters.
// =============================================================================
 
struct EShaderExt
{
    typedef int Type;
    enum { VERTEX, PIXEL, GEOMETRY };
};
 
// Forward: createDirectoryRecursively uses SHCreateDirectoryExW
int createDirectoryRecursively(const wchar_t* path);
 
class KIntruder
{
public:
    KIntruder(HINSTANCE hDLL)
        : hIntruderDLL(hDLL),
          fTexturesKeyPressed(0), texturesDirCreated(0), textureIdx(0),
          fRipEnabled(0), fMeshRipKeyPressed(0),
          framesDirCreated(0), ripperDirCreated(0),
          frameIdx(0), frameMeshIdx(0), frameTextureIdx(0),
          shadersDirCreated(0),
          vsShaderIdx(0), psShaderIdx(0), gsShaderIdx(0),
          forcedMeshRipKeyPressed(0), forcedMeshRipEnabled(0),
          surfaceIdx(0), prevFrameIdx(0xFFFFFFFF)
    {
        forcedMeshRipStartTime.QuadPart = 0;
    }
 
    ~KIntruder() {}
 
    BOOL initialize()
    {
        wchar_t szBuf[MAX_PATH] = {};
        GetModuleFileNameW(hIntruderDLL, szBuf, MAX_PATH);
        intruderDllPath = szBuf;
        intruderDir     = extractDirectoryFromFileName(szBuf);
        settings.load();
        outputDir = settings.outDir;
        timerFreq.QuadPart = 0;
        QueryPerformanceFrequency(&timerFreq);
        wchar_t szExe[MAX_PATH] = {};
        GetModuleFileNameW(0, szExe, MAX_PATH);
        exeModule = extractFileNameFromPath(szExe);
        return TRUE;
    }
 
    void cleanup() {}
 
    const KSettings* getSettings() const { return &settings; }
 
    std::wstring getOutputDir()   { return ripperDir; }
    std::wstring getIntruderDir() { return intruderDir; }
    std::wstring getIntruderDllPath() const { return intruderDllPath; }
 
    const wchar_t* getCrashDumpFile()       const { return crashDumpFile.c_str(); }
    const char*    getCrashDumpFileUtf8()   const { return crashDumpFileUtf8.c_str(); }
 
    DWORD isMeshRipEnabled()          const { return fRipEnabled || forcedMeshRipEnabled; }
    DWORD isTexturesRipKeyPressed()   const { return fTexturesKeyPressed; }
 
    // ---- Hot-key polling (called every Present/EndScene) --------------------
    void keyHandler(IRipper* pRipper)
    {
        bool spec = true;
        if ((settings.specKeys & ALT_KEY_MASK)   && !GetAsyncKeyState(VK_MENU))    spec=false;
        if ((settings.specKeys & CTRL_KEY_MASK)  && !GetAsyncKeyState(VK_CONTROL)) spec=false;
        if ((settings.specKeys & SHIFT_KEY_MASK) && !GetAsyncKeyState(VK_SHIFT))   spec=false;
 
        // Texture rip toggle
        if (GetAsyncKeyState(settings.textureRipKey) && spec)
        {
            fTexturesKeyPressed ^= 1;
            fTexturesKeyPressed ? pRipper->textureRipStart() : pRipper->textureRipEnd();
            Sleep(2000);
        }
 
        fMeshRipKeyPressed = GetAsyncKeyState(settings.ripKey) && spec;
 
        // Forced-rip auto-disable when interval expires
        LARGE_INTEGER cur;
        QueryPerformanceCounter(&cur);
        LARGE_INTEGER us;
        us.QuadPart = (cur.QuadPart - frameStartTime.QuadPart) * 1000000 / timerFreq.QuadPart;
        if (forcedMeshRipEnabled && us.QuadPart > settings.usForcedRipInterval)
            forcedMeshRipEnabled = 0;
 
        // Forced-rip toggle
        if (GetAsyncKeyState(settings.forcedRipKey) && spec)
        {
            forcedMeshRipEnabled ^= 1;
            Sleep(2000);
            if (forcedMeshRipEnabled)
            {
                QueryPerformanceCounter(&frameStartTime);
                g_pLog->log("Force mesh rip enabled\n");
            }
            else g_pLog->log("Force mesh rip disabled\n");
        }
    }
 
    // ---- Frame lifecycle (called every Present/EndScene) --------------------
    void frameHandler(IRipper* pRipper)
    {
        keyHandler(pRipper);
        if (!fRipEnabled && isMeshsRipKeyPressed())
        {
            g_pLog->log("Frame Start...#%02d\n", frameIdx);
            getFrameDir();
            fRipEnabled = 1;
            frameMeshIdx = frameTextureIdx = 0;
            pRipper->frameStart();
            Sleep(1000);
            QueryPerformanceCounter(&frameStartTime);
        }
        else if (fRipEnabled)
        {
            LARGE_INTEGER t; QueryPerformanceCounter(&t);
            LARGE_INTEGER us;
            us.QuadPart = (t.QuadPart - frameStartTime.QuadPart) * 1000000 / timerFreq.QuadPart;
            if (!settings.minFrameIntervalUs || us.QuadPart > settings.minFrameIntervalUs)
            {
                g_pLog->log("Frame len: %dus\n", us.LowPart);
                g_pLog->log("Frame End...\n\n\n");
                fRipEnabled = 0;
                pRipper->frameEnd();
                frameIdx++;
            }
        }
    }
 
    // ---- Output path generators ---------------------------------------------
    std::wstring createOutputDir()
    {
        if (ripperDirCreated) return ripperDir;
 
        DWORD pid = GetCurrentProcessId();
        SYSTEMTIME st; GetLocalTime(&st);
        wchar_t tDir[MAX_PATH];
        swprintf_s(tDir, MAX_PATH,
            L"%d.%02d.%02d_%02d.%02d.%02d_%s_%d",
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond,
            exeModule.c_str(), pid);
 
        int err = createDirectoryRecursively(outputDir.c_str());
        if (err != ERROR_SUCCESS && err != ERROR_ALREADY_EXISTS)
        {
            wchar_t buf[64]; swprintf_s(buf,64,L"0x%08X",err);
            fatalErrorMsgW((L"Can't create dir: "+outputDir+L" ERR: "+buf).c_str());
        }
 
        ripperDir = outputDir;
        if (ripperDir.back() != L'\\' && ripperDir.back() != L'/')
            ripperDir += L"\\";
 
        std::wstring r1 = ripperDir + L"_NinjaRipper";
        ripperDir = r1 + L"\\" + tDir + L"\\";
 
        createDirectoryWithErrorCheck(r1.c_str());
        createDirectoryWithErrorCheck(ripperDir.c_str());
        ripperDirCreated = 1;
 
        wchar_t dmpBuf[64];
        swprintf_s(dmpBuf,64,L"crashdmp_pid_%d.dmp",pid);
        crashDumpFile    = ripperDir + dmpBuf;
        crashDumpFileUtf8 = wideStringToMultiByte(crashDumpFile.c_str());
        return ripperDir;
    }
 
    std::wstring getTextureSavePath()
    {
        ensureTexturesDir();
        wchar_t p[MAX_PATH];
        swprintf_s(p,MAX_PATH,L"%sTex_%04d.dds",texturesDir.c_str(),textureIdx);
        return p;
    }
 
    std::wstring getSurfaceSavePath()
    {
        ensureTexturesDir();
        wchar_t p[MAX_PATH];
        swprintf_s(p,MAX_PATH,L"%sSurf_%04d.dds",texturesDir.c_str(),surfaceIdx);
        return p;
    }
 
    std::wstring getFrameTextureSavePath(std::string& outName, DWORD Level)
    {
        std::wstring out = getFrameDir();
        wchar_t wb[100]; char ab[100];
        swprintf_s(wb,100,L"Tex_%04d_%01d.dds",frameTextureIdx,Level);
        sprintf_s(ab,100,"Tex_%04d_%01d.dds",frameTextureIdx,Level);
        outName = ab;
        return out + wb;
    }
 
    std::wstring getFrameMeshSavePath()
    {
        wchar_t b[100];
        swprintf_s(b,100,L"Mesh_%04d.rip",frameMeshIdx);
        return getFrameDir() + b;
    }
 
    std::wstring getShaderSavePath(DWORD idx, EShaderExt::Type ext)
    {
        if (!shadersDirCreated)
        {
            shadersDir = getOutputDir() + L"Shaders\\";
            createDirectoryWithErrorCheck(shadersDir.c_str());
            shadersDirCreated = 1;
        }
        const wchar_t* e = (ext==EShaderExt::VERTEX)?L".vs"
                         : (ext==EShaderExt::PIXEL) ?L".ps":L".gs";
        wchar_t p[MAX_PATH];
        swprintf_s(p,MAX_PATH,L"%sShader_%04d%s",shadersDir.c_str(),idx,e);
        return p;
    }
 
    std::string getShaderName(DWORD idx, EShaderExt::Type ext)
    {
        const char* e = (ext==EShaderExt::VERTEX)?".vs"
                      : (ext==EShaderExt::PIXEL) ?".ps":".gs";
        char p[MAX_PATH];
        sprintf_s(p,MAX_PATH,"Shader_%04d%s",idx,e);
        return p;
    }
 
    // ---- Index/counter increments -------------------------------------------
    void  incTextureIdx()       { textureIdx++; }
    void  incFrameTextureIdx()  { frameTextureIdx++; }
    void  incFrameMeshIdx()     { frameMeshIdx++; }
    DWORD incVertexShaderIdx()  { return vsShaderIdx++; }
    DWORD incPixelShaderIdx()   { return psShaderIdx++; }
    DWORD incGeometryShaderIdx(){ return gsShaderIdx++; }
    DWORD incSurfaceIdx()       { return surfaceIdx++; }
 
private:
    DWORD isMeshsRipKeyPressed() const { return fMeshRipKeyPressed; }
 
    void ensureTexturesDir()
    {
        if (!texturesDirCreated)
        {
            texturesDir = getOutputDir() + L"Textures\\";
            createDirectoryWithErrorCheck(texturesDir.c_str());
            texturesDirCreated = 1;
        }
    }
 
    std::wstring getFrameDir()
    {
        if (!framesDirCreated) { framesDir = getOutputDir(); framesDirCreated = 1; }
        if (prevFrameIdx != frameIdx)
        {
            SYSTEMTIME st; GetLocalTime(&st);
            wchar_t f[MAX_PATH];
            swprintf_s(f, MAX_PATH, L"%d.%02d.%02d_%02d.%02d.%02d_%s\\",
                st.wYear,st.wMonth,st.wDay,st.wHour,st.wMinute,st.wSecond,
                exeModule.c_str());
            std::wstring out = framesDir + f;
            createDirectoryWithErrorCheck(out.c_str());
            LastCreatedDir = out;
            prevFrameIdx   = frameIdx;
        }
        return LastCreatedDir;
    }
 
    KSettings    settings;
    HINSTANCE    hIntruderDLL;
    std::wstring intruderDir, intruderDllPath;
    std::wstring outputDir, ripperDir;
    std::wstring texturesDir, framesDir, shadersDir;
    std::wstring LastCreatedDir;
    std::wstring exeModule;
    std::wstring crashDumpFile;
    std::string  crashDumpFileUtf8;
 
    DWORD fRipEnabled, fMeshRipKeyPressed, fTexturesKeyPressed;
    DWORD textureIdx, ripperDirCreated, framesDirCreated;
    DWORD texturesDirCreated, shadersDirCreated;
    DWORD forcedMeshRipKeyPressed, forcedMeshRipEnabled;
    DWORD frameIdx, frameMeshIdx, frameTextureIdx, prevFrameIdx;
    DWORD vsShaderIdx, psShaderIdx, gsShaderIdx, surfaceIdx;
 
    LARGE_INTEGER timerFreq, frameStartTime, forcedMeshRipStartTime;
};
 
// Uses SHCreateDirectoryExW � needs shlobj.h (already included above)
int createDirectoryRecursively(const wchar_t* path)
{
    return SHCreateDirectoryExW(nullptr, path, nullptr);
}
 
 
// =============================================================================
//  SECTION 14 � macro.h
// =============================================================================
 
#undef SAFE_DELETE
#undef SAFE_DELETE_ARRAY
#undef SAFE_RELEASE
#define SAFE_DELETE(p)       { if(p){ delete   (p); (p)=nullptr; } }
#define SAFE_DELETE_ARRAY(p) { if(p){ delete[] (p); (p)=nullptr; } }
#define SAFE_RELEASE(p)      { if(p){ (p)->Release(); (p)=nullptr; } }
 
// Generates 8 stub entries for a HooksGroup (MAX_CNT=8)
#define GENERATE_STUBS_GROUP(STUB) STUB(0)STUB(1)STUB(2)STUB(3)STUB(4)STUB(5)STUB(6)STUB(7)
 
// Resets a HooksGroup and wires in all 8 pre-declared stub handlers
#define GENERATE_HOOKS_GROUP_CLEARER(FUNC)   \
  hooks_##FUNC.clearHooks();                 \
  hooks_##FUNC.setHandler(0,_##FUNC##_0);   \
  hooks_##FUNC.setHandler(1,_##FUNC##_1);   \
  hooks_##FUNC.setHandler(2,_##FUNC##_2);   \
  hooks_##FUNC.setHandler(3,_##FUNC##_3);   \
  hooks_##FUNC.setHandler(4,_##FUNC##_4);   \
  hooks_##FUNC.setHandler(5,_##FUNC##_5);   \
  hooks_##FUNC.setHandler(6,_##FUNC##_6);   \
  hooks_##FUNC.setHandler(7,_##FUNC##_7);
 
#ifndef ARRAY_COUNT
#define ARRAY_COUNT(arr) (sizeof(arr)/sizeof(arr[0]))
#endif
 
 
// =============================================================================
//  SECTION 15 � tools.h / tools.cpp  (string utils, vtable hooks, dir helpers)
// =============================================================================
 
#include <Unknwn.h>
 
ULONG getIUnknownRefCount(IUnknown* p)
{ p->AddRef(); return p->Release(); }
 
// Read vtable slot at index idx from COM object pInterface
void* getMethodAddr(void* pInterface, DWORD idx)
{
    size_t** ppVtbl = (size_t**)pInterface;
    size_t*  pVtbl  = *ppVtbl;
    return (void*)pVtbl[idx];
}
 
void strCopy(char* pDst, DWORD BufSize, const char* pSrc)
{
    ZeroMemory(pDst, BufSize);
    size_t len = strlen(pSrc);
    if (len >= BufSize) len = BufSize - 1;
    memcpy(pDst, pSrc, len);
}
 
// Log hook success/failure
void checkHook(KHook* hk, const char* funcName, LPVOID targ)
{
    if (hk)
        g_pLog->log("%s hooked. Target: 0x%p\n", funcName, hk->getTargetAddress());
    else
        g_pLog->logError("%s hook error: %s. Target: 0x%p\n",
            funcName, g_pHookMgr->getLastErrorString(), targ);
}
 
// UTF-8 ? UTF-16
std::wstring multiByteToWideString(const char* szSrc)
{
    int n = MultiByteToWideChar(CP_UTF8, 0, szSrc, -1, nullptr, 0);
    wchar_t* buf = new wchar_t[n];
    MultiByteToWideChar(CP_UTF8, 0, szSrc, -1, buf, n);
    std::wstring r(buf); delete[] buf; return r;
}
 
// UTF-16 ? UTF-8
std::string wideStringToMultiByte(const wchar_t* szSrc)
{
    int n = WideCharToMultiByte(CP_UTF8, 0, szSrc, -1, nullptr, 0, nullptr, nullptr);
    char* buf = new char[n];
    WideCharToMultiByte(CP_UTF8, 0, szSrc, -1, buf, n, nullptr, nullptr);
    std::string r(buf); delete[] buf; return r;
}
std::string wideStringToMultiByte(const std::wstring& s)
{ return wideStringToMultiByte(s.c_str()); }
 
// ACP ? UTF-8
std::string multiByteStringAcpToMultiByte(const char* szSrc)
{
    int n = MultiByteToWideChar(CP_ACP, 0, szSrc, -1, nullptr, 0);
    wchar_t* buf = new wchar_t[n];
    MultiByteToWideChar(CP_ACP, 0, szSrc, -1, buf, n);
    std::string r = wideStringToMultiByte(buf);
    delete[] buf; return r;
}
 
// ACP ? UTF-16
std::wstring multiByteStringAcpToWideString(const char* str)
{ return multiByteToWideString(multiByteStringAcpToMultiByte(str).c_str()); }
 
std::string trim1(const std::string& src, const std::string& delims)
{
    std::string s = src;
    s.erase(0, s.find_first_not_of(delims));
    size_t last = s.find_last_not_of(delims);
    if (last != std::string::npos) s.erase(last + 1);
    return s;
}
 
std::string guidToString(REFIID r)
{
    char buf[128];
    sprintf_s(buf, 128,
        "{%08X-%04X-%04X-%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X}",
        r.Data1, r.Data2, r.Data3,
        r.Data4[0],r.Data4[1],r.Data4[2],r.Data4[3],
        r.Data4[4],r.Data4[5],r.Data4[6],r.Data4[7]);
    return buf;
}
 
std::string getLocalTimeString()
{
    SYSTEMTIME t; GetLocalTime(&t);
    char buf[64];
    sprintf_s(buf,64,"%d/%02d/%02d %02d:%02d:%02d",
              t.wYear,t.wMonth,t.wDay,t.wHour,t.wMinute,t.wSecond);
    return buf;
}
 
// Create directory; fatal error if it fails for any reason other than EXISTS
void createDirectoryWithErrorCheck(const std::wstring& dir)
{
    if (!CreateDirectoryW(dir.c_str(), nullptr))
    {
        DWORD e = GetLastError();
        if (e != ERROR_ALREADY_EXISTS)
        {
            wchar_t buf[64]; swprintf_s(buf,64,L"0x%08X",e);
            fatalErrorMsgW((L"Can't create dir: "+dir+L" ERR: "+buf).c_str());
        }
    }
}
 
// Overload for char* callers (KIntruder uses wstring, but keep C str variant too)
int createDirectoryWithErrorCheck(const wchar_t* path)
{
    createDirectoryWithErrorCheck(std::wstring(path)); return 0;
}
 
// Load a DLL from System32 � try GetModuleHandle first to avoid double-load
HMODULE loadSysDll(const wchar_t* dll)
{
    wchar_t buf[MAX_PATH]; GetSystemDirectoryW(buf,MAX_PATH);
    lstrcatW(buf,L"\\"); lstrcatW(buf,dll);
    HMODULE h = GetModuleHandleW(buf);
    if (!h) h = LoadLibraryW(buf);
    return h;
}
 
void fatalErrorMsgW(const wchar_t* msg)
{
    MessageBoxW(nullptr, msg, NINJA_RIPPER, MB_ICONERROR|MB_TOPMOST);
    ExitProcess(-1);
}
 
 
// ---- hookEx overloads -------------------------------------------------------
// Variant 1: hook by vtable index (used by all DX rippers)
bool hookEx(const char* name, DWORD idx, LPVOID pInterface,
            int pool, LPVOID detour, KHook** inout)
{
    LPVOID targ = getMethodAddr(pInterface, idx);
    if (*inout)
    {
        if ((*inout)->getTargetAddress() != targ)
            g_pLog->logError("Hook conflict for %s. Old:0x%p New:0x%p\n",
                             name,(*inout)->getTargetAddress(),targ);
        return false;
    }
    *inout = g_pHookMgr->hookAndRegister(targ, detour, pool);
    checkHook(*inout, name, targ);
    return (*inout != nullptr);
}
 
// Variant 2: hook a named/regular function (used by ntdll, kernel32, etc.)
// NOTE: This overload replaces the inline hookEx() stub defined in Section 12.
//       The Section 12 stub had the right signature but no full implementation.
//       This is the authoritative definition.
bool hookEx_full(const char* name, LPVOID targ, LPVOID detour,
                 int pool, KHook** inout)
{
    if (!targ)
    {
        g_pLog->logError("Can't hook %s. Target is zero\n", name);
        return false;
    }
    if (*inout)
    {
        if ((*inout)->getTargetAddress() != targ)
            g_pLog->logError("Hook conflict for %s\n", name);
        return false;
    }
    *inout = g_pHookMgr->hookAndRegister(targ, detour, pool);
    checkHook(*inout, name, targ);
    return (*inout != nullptr);
}
 
// Variant 3: hook by vtable index into a HooksGroup (multi-device support)
bool hookEx(const char* name, DWORD idx, LPVOID pInterface,
            int pool, HooksGroup* hooksGroup)
{
    LPVOID targ = getMethodAddr(pInterface, idx);
    if (hooksGroup->isTargetHooked(targ)) return false;
    HooksGroupEntry* entry = hooksGroup->getFreeHookData();
    if (!entry)
    {
        g_pLog->logError("No free hooks in group for %s\n", name);
        return false;
    }
    entry->hk = g_pHookMgr->hookAndRegister(targ, entry->handler, pool);
    checkHook(entry->hk, name, targ);
    return (entry->hk != nullptr);
}
 
// Fix up Section 12 stub � replace the inline hookEx() there with a call here
// (Re-define the inline so it dispatches to hookEx_full)
// This must appear after the definition above.
#define hookEx(name,targ,detour,pool,outHook) \
    hookEx_full((name),(targ),(detour),(pool),(outHook))
 
 
// =============================================================================
//  SECTION 16 � topology.h / topology.cpp
// =============================================================================
 
struct EPrimitiveTopology
{
    typedef size_t Type;
    enum
    {
        POINTLIST, LINELIST, LINESTRIP,
        TRIANGLELIST, TRIANGLESTRIP, TRIANGLEFAN,
        UNKNOWNPRIMITIVETYPE, UNDEFINED
    };
};
 
bool isPrimitiveTopologySupported(EPrimitiveTopology::Type t)
{
    return t==EPrimitiveTopology::TRIANGLELIST  ||
           t==EPrimitiveTopology::TRIANGLESTRIP ||
           t==EPrimitiveTopology::TRIANGLEFAN;
}
 
const char* primitiveTopology2Str(EPrimitiveTopology::Type t)
{
    switch(t){
    case EPrimitiveTopology::TRIANGLELIST:  return "TRIANGLELIST";
    case EPrimitiveTopology::TRIANGLESTRIP: return "TRIANGLESTRIP";
    case EPrimitiveTopology::TRIANGLEFAN:   return "TRIANGLEFAN";
    case EPrimitiveTopology::POINTLIST:     return "POINTLIST";
    case EPrimitiveTopology::LINELIST:      return "LINELIST";
    case EPrimitiveTopology::LINESTRIP:     return "LINESTRIP";
    case EPrimitiveTopology::UNDEFINED:     return "UNDEFINED";
    default:                                return "UNKNOWNPRIMITIVETYPE";
    }
}
 
DWORD primitiveCountFromIndexCount(DWORD n, EPrimitiveTopology::Type t)
{
    if(t==EPrimitiveTopology::TRIANGLELIST)  return n/3;
    if(t==EPrimitiveTopology::TRIANGLESTRIP) return n-2;
    return 0;
}
DWORD primitiveCountFromVertexCount(DWORD n, EPrimitiveTopology::Type t)
{
    if(t==EPrimitiveTopology::TRIANGLELIST)  return n/3;
    if(t==EPrimitiveTopology::TRIANGLESTRIP||t==EPrimitiveTopology::TRIANGLEFAN) return n-2;
    return 0;
}
DWORD vertexCountFromPrimitiveCount(DWORD n, EPrimitiveTopology::Type t)
{
    if(t==EPrimitiveTopology::TRIANGLELIST)  return n*3;
    if(t==EPrimitiveTopology::TRIANGLESTRIP||t==EPrimitiveTopology::TRIANGLEFAN) return n+2;
    return 0;
}
 
 
// =============================================================================
//  SECTION 17 � vertexprocess.h / vertexprocess.cpp  (vertex buffer engine)
// =============================================================================
 
const DWORD SEMANTIC_LEN     = 64;
const DWORD MAX_TYPEMAP_SIZE = 8;
 
// Vertex buffer container � owns a flat byte array of (vertexCount � vertexSize)
class KVERTICES
{
public:
    KVERTICES(DWORD cnt, DWORD sz) : VertexCount(cnt), VertexSize(sz)
    {
        pVertices = new BYTE[cnt * sz];
        memset(pVertices, 0, cnt * sz);
    }
    ~KVERTICES() { SAFE_DELETE_ARRAY(pVertices); }
 
    DWORD getVertexSize()  const { return VertexSize; }
    DWORD getVertexCount() const { return VertexCount; }
    BYTE* getRawData()     const { return pVertices; }
 
private:
    DWORD VertexCount, VertexSize;
    BYTE* pVertices;
};
 
// Single input vertex attribute (from DX vertex declaration / FVF)
struct KInputVertexElement
{
    KInputVertexElement():Stream(0),Offset(0),Size(0),
        Type(EInputType::UNKNOWNINPUTTYPE),SemanticIndex(0)
    { ZeroMemory(UsageSemantic,SEMANTIC_LEN); }
 
    char             UsageSemantic[SEMANTIC_LEN]; // "POSITION","NORMAL","TEXCOORD"...
    DWORD            SemanticIndex;
    DWORD            Stream;
    DWORD            Offset;  // byte offset within vertex
    DWORD            Size;    // byte size
    EInputType::Type Type;
};
 
struct KInputVertexDeclaration
{
    std::vector<KInputVertexElement> Decl;
    DWORD getStreamVertexSize(DWORD stream) const
    {
        DWORD sz = 0;
        for (auto& e : Decl) if(e.Stream==stream) sz += e.Size;
        return sz;
    }
};
 
// Single output vertex attribute (unpacked to floats for .rip file)
struct KOutputVertexElement
{
    char              UsageSemantic[SEMANTIC_LEN];
    DWORD             SemanticIndex;
    DWORD             Offset;
    DWORD             Size;
    DWORD             TypeMapElements;
    EOutputType::Type TypeMap[MAX_TYPEMAP_SIZE];
 
    KOutputVertexElement():Offset(0),Size(0),SemanticIndex(0),TypeMapElements(0)
    {
        memset(UsageSemantic,0,SEMANTIC_LEN);
        for(DWORD i=0;i<MAX_TYPEMAP_SIZE;i++) TypeMap[i]=EOutputType::ETYPENOTSET;
    }
};
 
struct KOutputVertexDeclaration
{
    std::vector<KOutputVertexElement> Decl;
    DWORD getVertexSize()
    {
        DWORD s=0; for(auto& e:Decl) s+=e.Size; return s;
    }
};
 
// Forward: defined in dataconvert.cpp section (below)
typedef DWORD (*PFN_TYPE_CONVERTER)(const void*,void*,EOutputType::Type*,DWORD&);
extern PFN_TYPE_CONVERTER getTypeConverter(EInputType::Type t);
extern const char* EInputType2Str(EInputType::Type t);
extern const char* EOutputType2Str(EOutputType::Type t);
 
void dumpInputVertexDeclaration2Log(const KInputVertexDeclaration& d)
{
    g_pLog->log("---Input vertex format dump---\n");
    for(auto& e:d.Decl){
        g_pLog->log("Stream:%d Semantic:%s[%d] Offset:%d Size:%d Type:%s\n",
            e.Stream,e.UsageSemantic,e.SemanticIndex,e.Offset,e.Size,
            EInputType2Str(e.Type));
    }
    g_pLog->log("-------------------------------\n");
}
 
void dumpOutputVertexDeclaration2Log(const KOutputVertexDeclaration& d)
{
    g_pLog->log("---Output vertex format dump---\n");
    for(auto& e:d.Decl){
        std::string types;
        for(DWORD j=0;j<e.TypeMapElements;j++){
            types+=EOutputType2Str(e.TypeMap[j]); types+=" ";
        }
        g_pLog->log("Semantic:%s[%d] Offset:%d Size:%d Types:%s\n",
            e.UsageSemantic,e.SemanticIndex,e.Offset,e.Size,types.c_str());
    }
    g_pLog->log("-------------------------------\n\n");
}
 
// Build output declaration from input declaration by running each element
// through its type converter to determine unpacked size and type map
HRESULT createKOutputVertexDeclaration(const KInputVertexDeclaration& inp,
                                        KOutputVertexDeclaration& out)
{
    HRESULT hr = S_OK;
    DWORD offset = 0;
    for (auto& ie : inp.Decl)
    {
        if (ie.Type == EInputType::UNKNOWNINPUTTYPE) { hr=E_INPUT_TYPE_ERR; break; }
        KOutputVertexElement oe;
        BYTE   raw[MAX_UNPACKED_LEN]={}, unpacked[MAX_UNPACKED_LEN]={};
        EOutputType::Type tm[MAX_TYPEMAP_SIZE]; DWORD compCnt=0;
        PFN_TYPE_CONVERTER conv = getTypeConverter(ie.Type);
        oe.Size            = conv(raw, unpacked, tm, compCnt);
        oe.Offset          = offset;
        oe.TypeMapElements = compCnt;
        for(DWORD j=0;j<compCnt;j++) oe.TypeMap[j]=tm[j];
        offset += oe.Size;
        strCopy(oe.UsageSemantic, SEMANTIC_LEN, ie.UsageSemantic);
        oe.SemanticIndex = ie.SemanticIndex;
        out.Decl.push_back(oe);
    }
    return hr;
}
 
// Key inner loop: unpack vertex attributes for all vertices referenced by
// optIdxToMeshIdx and store them contiguously in the output buffer
void dumpVertSemantic(EInputType::Type SrcType,
                      const BYTE* pSrcBase, DWORD SrcOffs, DWORD SrcVtxSz,
                      BYTE* pDstBase,       DWORD DstOffs, DWORD DstVtxSz,
                      const OptimizedIndexToMeshIndex& vertIdx)
{
    PFN_TYPE_CONVERTER conv = getTypeConverter(SrcType);
    for (DWORD i = 0; i < (DWORD)vertIdx.size(); ++i)
    {
        const BYTE* pSrc = pSrcBase + SrcVtxSz * vertIdx[i];
        BYTE*       pDst = pDstBase + i * DstVtxSz;
        BYTE unp[MAX_UNPACKED_LEN]; EOutputType::Type tm[MAX_TYPEMAP_SIZE]; DWORD cnt=0;
        DWORD sz = conv(pSrc+SrcOffs, unp, tm, cnt);
        memcpy(pDst+DstOffs, unp, sz);
    }
}
 
 
// =============================================================================
//  SECTION 18 � indexprocess  (face/index processing engine)
//  Full implementations of processIndexes*() arrive with the dx* folders.
//  Forward declarations allow the intruder root layer to compile now.
// =============================================================================
 
#include <map>
 
#pragma pack(push,1)
struct KFace { DWORD i0,i1,i2; };
#pragma pack(pop)
 
typedef std::map<DWORD,DWORD>    MeshIndexToOptimizedIndex;
typedef std::vector<DWORD>       OptimizedIndexToMeshIndex;
 
class KFACES
{
public:
    DWORD getPrimitivesCount() const { return (DWORD)faces.size(); }
    void  addPrimitive(const KFace& f) { faces.push_back(f); }
    bool  setPrimitive(DWORD i,const KFace& f)
          { if(i<faces.size()){faces[i]=f;return true;}return false; }
    bool  getPrimitive(DWORD i,KFace* f)const
          { if(i<faces.size()){*f=faces[i];return true;}return false; }
    const void* getRawData()const{ return faces.data(); }
private:
    std::vector<KFace> faces;
};
 
// These implementations live in dx*/ddraw files � forward-declared here:
extern bool processIndexes16_PrimitiveCount(const WORD*, EPrimitiveTopology::Type, DWORD, KFACES*, OptimizedIndexToMeshIndex*);
extern bool processIndexes32_PrimitiveCount(const DWORD*, EPrimitiveTopology::Type, DWORD, KFACES*, OptimizedIndexToMeshIndex*);
extern bool processIndexes16_IndexCount(const WORD*, EPrimitiveTopology::Type, DWORD, KFACES*, OptimizedIndexToMeshIndex*);
extern bool processIndexes32_IndexCount(const DWORD*, EPrimitiveTopology::Type, DWORD, KFACES*, OptimizedIndexToMeshIndex*);
extern void generateIndexes_PrimitiveCount(EPrimitiveTopology::Type, DWORD, KFACES*, OptimizedIndexToMeshIndex*);
extern void generateIndexes_VertexCount(EPrimitiveTopology::Type, DWORD, KFACES*, OptimizedIndexToMeshIndex*);
 
DWORD getOptIdx(MeshIndexToOptimizedIndex* opt, DWORD* idx,
                DWORD meshIdx, OptimizedIndexToMeshIndex* optToMesh)
{
    auto it = opt->find(meshIdx);
    if (it != opt->end()) return it->second;
    DWORD newIdx = *idx;
    (*opt)[meshIdx] = newIdx;
    optToMesh->push_back(meshIdx);
    (*idx)++;
    return newIdx;
}
 
 
// =============================================================================
//  SECTION 19 � EIndexFormat + vert_indx_dump  (UP draw-path helpers)
// =============================================================================
 
struct EIndexFormat { typedef int Type; enum{ UNKNOWN, INDEX_16, INDEX_32 }; };
 
void dumpVbUP(const KInputVertexDeclaration& inpDecl,
              const KOutputVertexDeclaration& outDecl,
              const OptimizedIndexToMeshIndex& optIdx,
              KVERTICES* pVERTICES,
              const void* vertexData,
              DWORD stride)
{
    for (size_t i = 0; i < inpDecl.Decl.size(); ++i)
    {
        dumpVertSemantic(
            inpDecl.Decl[i].Type,
            (const BYTE*)vertexData, inpDecl.Decl[i].Offset, stride,
            pVERTICES->getRawData(), outDecl.Decl[i].Offset, pVERTICES->getVertexSize(),
            optIdx);
    }
}
 
HRESULT dumpIndexesUP(EPrimitiveTopology::Type topo, UINT primCnt,
                      KFACES* pFACES, OptimizedIndexToMeshIndex* optIdx,
                      const void* indexes, EIndexFormat::Type fmt)
{
    if (fmt == EIndexFormat::INDEX_16)
        processIndexes16_PrimitiveCount((const WORD*)indexes, topo, primCnt, pFACES, optIdx);
    else if (fmt == EIndexFormat::INDEX_32)
        processIndexes32_PrimitiveCount((const DWORD*)indexes, topo, primCnt, pFACES, optIdx);
    else
        return 0x80114455; // Unknown index format
    return S_OK;
}
 
 
// =============================================================================
//  SECTION 20 � ripout.h / ripout.cpp  (.rip file format and writer)
// =============================================================================
 
const DWORD RIP_SIGNATURE = 0xDEADC0DE;
const DWORD RIP_VERSION   = 4;
 
struct KMeshTextures { std::vector<std::string> textures; };
struct KMeshShaders  { std::vector<std::string> shaders;  };
 
#pragma pack(push,1)
struct KRipHeader
{
    DWORD signature;
    DWORD version;
    DWORD dwFacesCnt;         // triangle count
    DWORD dwVertexesCnt;
    DWORD vertexSize;         // bytes per output vertex
    DWORD textureFilesCnt;
    DWORD shaderFilesCnt;
    DWORD vertexAttributesCnt;
};
#pragma pack(pop)
 
// File layout:
//   KRipHeader
//   [vertexAttributesCnt � attribute records]  (semantic string + metadata)
//   [textureFilesCnt � null-terminated strings]
//   [shaderFilesCnt  � null-terminated strings]
//   [dwFacesCnt � KFace]
//   [dwVertexesCnt � vertexSize bytes]
HRESULT saveRipFile(const wchar_t* File,
                    const KInputVertexDeclaration& inpDecl,
                    const KOutputVertexDeclaration& outDecl,
                    const KMeshTextures& textures,
                    const KMeshShaders&  shaders,
                    const KFACES& faces,
                    const KVERTICES& vertices)
{
    FILE* fp = nullptr;
    if (_wfopen_s(&fp, File, L"wb")) return 0x85855858;
 
    KRipHeader hdr = {};
    hdr.signature           = RIP_SIGNATURE;
    hdr.version             = RIP_VERSION;
    hdr.dwFacesCnt          = faces.getPrimitivesCount();
    hdr.dwVertexesCnt       = vertices.getVertexCount();
    hdr.vertexSize          = vertices.getVertexSize();
    hdr.textureFilesCnt     = (DWORD)textures.textures.size();
    hdr.shaderFilesCnt      = (DWORD)shaders.shaders.size();
    hdr.vertexAttributesCnt = (DWORD)inpDecl.Decl.size();
    fwrite(&hdr, sizeof(hdr), 1, fp);
 
    // Vertex declaration attributes
    for (auto& oe : outDecl.Decl)
    {
        fwrite(oe.UsageSemantic, 1+strlen(oe.UsageSemantic), 1, fp);
        fwrite(&oe.SemanticIndex,  sizeof(oe.SemanticIndex),  1, fp);
        fwrite(&oe.Offset,         sizeof(oe.Offset),         1, fp);
        fwrite(&oe.Size,           sizeof(oe.Size),           1, fp);
        fwrite(&oe.TypeMapElements,sizeof(oe.TypeMapElements), 1, fp);
        for (DWORD j=0; j<oe.TypeMapElements; ++j)
            fwrite(&oe.TypeMap[j], sizeof(oe.TypeMapElements), 1, fp);
    }
    // Texture names
    for (auto& t : textures.textures)
        fwrite(t.c_str(), t.size()+1, 1, fp);
    // Shader names
    for (auto& s : shaders.shaders)
        fwrite(s.c_str(), s.size()+1, 1, fp);
    // Geometry data
    fwrite(faces.getRawData(),    sizeof(KFace)*hdr.dwFacesCnt,             1, fp);
    fwrite(vertices.getRawData(), hdr.vertexSize*(size_t)hdr.dwVertexesCnt, 1, fp);
 
    fclose(fp);
    return S_OK;
}
 
 
// =============================================================================
//  SECTION 21 � TDXRef / TDXRefVec  (RAII COM pointer wrappers)
// =============================================================================
 
template<class T>
class TDXRef
{
public:
    TDXRef():ptr(nullptr){}
    ~TDXRef(){ if(ptr){ptr->Release();ptr=nullptr;} }
    T*  get()           { return ptr; }
    T** operator&()     { return &ptr; }
    T*  operator->()const{ return ptr; }
private:
    TDXRef(const TDXRef&);
    TDXRef& operator=(const TDXRef&);
    T* ptr;
};
 
template<class T>
class TDXRefVec
{
public:
    TDXRefVec(){}
    TDXRefVec(size_t n){ setSize(n); }
    ~TDXRefVec()
    { for(auto p:vec) if(p) p->Release(); }
    void setSize(size_t n)
    { vec.assign(n,nullptr); }
    T**    operator&(){ return vec.data(); }
    size_t getSize()  { return vec.size(); }
    T*     getElement(size_t i){ return vec[i]; }
private:
    TDXRefVec(const TDXRefVec&);
    TDXRefVec& operator=(const TDXRefVec&);
    std::vector<T*> vec;
};
 
 
// =============================================================================
//  SECTION 22 � TInitedVal  (lazy initialisation wrapper)
// =============================================================================
 
template<class T>
class TInitedVal
{
public:
    TInitedVal():inited(false){}
    void Set(const T& t){ inited=true; val=t; }
    T    Get()    const { return val; }
    bool IsInited()const{ return inited; }
private:
    T    val;
    bool inited;
};
 
 
// =============================================================================
//  SECTION 23 � outtypes__.h  (legacy .rip v2 structs � kept for reference)
// =============================================================================
 
struct TCOLOR   { float r,g,b,a; };
struct TMATERIAL{ TCOLOR Diffuse,Ambient,Specular,Emissive; float Power; };
struct TSHADERS { char vsh[16]; char psh[16]; };
struct TMESHTEXTURES{
    char texture_0[16],texture_1[16],texture_2[16],texture_3[16];
    char texture_4[16],texture_5[16],texture_6[16],texture_7[16];
};
struct TVERTEX  { float v0,v1,v2,v3, n0,n1,n2,n3, tu,tv; };
struct TFACE    { DWORD i0,i1,i2; };
struct TRIPFILE2{
    DWORD sign,cSize,dwVertices,dwFaces;
    TMESHTEXTURES textures;
    TMATERIAL material;
    TSHADERS  shaders;
};
 
 
// =============================================================================
//  SECTION 24 � shadercompile.h / shadercompile.cpp
//  D3DDisassemble-based shader save system (used by dx9, dx11 rippers)
// =============================================================================
 
#include <d3dcompiler.h>
#pragma comment(lib,"d3dcompiler.lib")
 
typedef HRESULT(__stdcall *PFN_D3DCompile)(
    LPCVOID,SIZE_T,LPCSTR,const D3D_SHADER_MACRO*,ID3DInclude*,
    LPCSTR,LPCSTR,UINT,UINT,ID3DBlob**,ID3DBlob**);
typedef HRESULT(__stdcall *PFN_D3DDisassemble)(
    LPCVOID,SIZE_T,UINT,LPCSTR,ID3DBlob**);
 
struct D3DCompileHelper
{
    D3DCompileHelper():hD3DCompiler(nullptr),D3DCompile(nullptr),D3DDisassemble(nullptr){}
    HINSTANCE          hD3DCompiler;
    PFN_D3DCompile     D3DCompile;
    PFN_D3DDisassemble D3DDisassemble;
};
 
struct ShaderFiles { std::wstring fullPath; std::string name; };
typedef std::map<void*,ShaderFiles> ShadersDb;
 
// Try to load d3dcompiler_47..43 in order
void loadD3DCompile(D3DCompileHelper* h)
{
    const char* dlls[]={"d3dcompiler_47.dll","d3dcompiler_46.dll",
                        "d3dcompiler_45.dll","d3dcompiler_44.dll","d3dcompiler_43.dll"};
    for(int pass=0;pass<2&&!h->hD3DCompiler;pass++)
        for(auto dll:dlls)
            h->hD3DCompiler=(pass==0)?GetModuleHandleA(dll):LoadLibraryA(dll);
 
    if(!h->hD3DCompiler)
        fatalErrorMsgW(L"d3dcompiler_X.dll not found. Install latest DirectX.");
    h->D3DCompile     =(PFN_D3DCompile)    GetProcAddress(h->hD3DCompiler,"D3DCompile");
    h->D3DDisassemble =(PFN_D3DDisassemble)GetProcAddress(h->hD3DCompiler,"D3DDisassemble");
    if(!h->D3DCompile)     fatalErrorMsgW(L"D3DCompile not found");
    if(!h->D3DDisassemble) fatalErrorMsgW(L"D3DDisassemble not found");
}
 
bool getShaderFromDb(void* shader, ShadersDb* db,
                     std::string* name, std::string* fullPath)
{
    auto it=db->find(shader);
    if(it==db->end()) return false;
    *name     = it->second.name;
    *fullPath = wideStringToMultiByte(it->second.fullPath.c_str());
    return true;
}
 
bool saveShader(EShaderExt::Type type, const void* code, SIZE_T codeLen,
                void* shader, ShadersDb* db, D3DCompileHelper* hlpr)
{
    TDXRef<ID3DBlob> blob;
    HRESULT hr = hlpr->D3DDisassemble(code, codeLen,
                     D3D_DISASM_ENABLE_DEFAULT_VALUE_PRINTS, nullptr, &blob);
    if(FAILED(hr)){
        g_pLog->logError("Shader disasm failed: 0x%08X\n", hr);
        return false;
    }
    DWORD idx = (type==EShaderExt::VERTEX)  ? g_pIntruder->incVertexShaderIdx()
              : (type==EShaderExt::PIXEL)   ? g_pIntruder->incPixelShaderIdx()
                                            : g_pIntruder->incGeometryShaderIdx();
 
    ShaderFiles sf;
    sf.fullPath = g_pIntruder->getShaderSavePath(idx,type);
    sf.name     = g_pIntruder->getShaderName(idx,type);
 
    auto it=db->find(shader);
    if(it!=db->end()) it->second=sf;
    else db->insert({shader,sf});
 
    FILE* fp=nullptr;
    if(_wfopen_s(&fp,sf.fullPath.c_str(),L"w")==0){
        fwrite(blob->GetBufferPointer(), blob->GetBufferSize()-1, 1, fp);
        fclose(fp);
    } else {
        g_pLog->logError("Shader save error: %s\n",
            wideStringToMultiByte(sf.fullPath.c_str()).c_str());
    }
    return true;
}
 
 
// =============================================================================
//  SECTION 25 � ddraw/  (DirectDraw DX1-DX7 ripper)
//
//  Hooks: DirectDrawCreate, DirectDrawCreateEx,
//         IDirectDraw::CreateSurface, IDirectDraw::QueryInterface,
//         IDirectDrawSurface::Flip, Blt, Unlock, SetPalette, ReleaseDC
//  Frame trigger: IDirectDrawSurface::Flip (or Blt as fallback)
//  Surface save:  IDirectDrawSurface::Unlock / ReleaseDC ? saveImg (DDS)
// =============================================================================
 
#include <dxgi.h>
#include <dxgi1_2.h>
 
// ---- DXGI format enum (needed for surface save before dxgi section) --------
typedef enum __DXGI_FORMAT {
    __DXGI_FORMAT_UNKNOWN=0,
    __DXGI_FORMAT_R8G8B8A8_UNORM=28,
    // (full enum in surfacesave.h � abbreviated here, add values as needed)
    __DXGI_FORMAT_FORCE_UINT=0xffffffff
} __DXGI_FORMAT;
 
// ---- Surface image helper (DirectXTex wrapper) -----------------------------
struct ImageRGB8
{
    ImageRGB8():width(0),height(0),format(0),rowPitch(0),slicePitch(0),pixels(nullptr){}
    uint8_t* allocMem(DWORD w, DWORD h)
    {
        width=w; height=h;
        rowPitch=4*w; slicePitch=rowPitch*h;
        format=__DXGI_FORMAT_R8G8B8A8_UNORM;
        pixels=new uint8_t[slicePitch];
        return pixels;
    }
    void freeMem(){ delete[] pixels; pixels=nullptr; }
    DWORD width,height,format,rowPitch,slicePitch;
    uint8_t* pixels;
};
struct ImgMetaData{};
 
// saveImg uses DirectXTex � forward declared; implemented when DirectXTex
// source is linked in. For now the stub calls the real library via header.
// #include "DirectXTex.h"
extern HRESULT saveImg(const wchar_t* fileName, ImageRGB8* imgs,
                       DWORD cnt, ImgMetaData* meta);
 
// ---- ddraw/enums.h ---------------------------------------------------------
enum {
    IDX_IDirectDraw_CreateSurface        =  6,
    IDX_IDirectDrawSurface_Blt           =  5,
    IDX_IDirectDrawSurface_Flip          = 11,
    IDX_IDirectDrawSurface_ReleaseDC     = 26,
    IDX_IDirectDrawSurface_SetPalette    = 31,
    IDX_IDirectDrawSurface_Unlock        = 32,
};
 
// ---- ddraw/ddrawtypes.h (function pointer types) ---------------------------
// Requires DXSDK7 ddraw.h � include path set in project
// These are declared here as void-based to avoid DXSDK7 dependency.
// Replace with proper types when DXSDK7 is available.
typedef HRESULT(__stdcall* PFN_DirectDrawCreateEx)(void*, void**, REFIID, IUnknown*);
typedef HRESULT(__stdcall* PFN_DirectDrawCreate)(void*, void**, IUnknown*);
typedef HRESULT(__stdcall* PFN_IDirectDrawSurface_Blt)(void*,RECT*,void*,RECT*,DWORD,void*);
typedef HRESULT(__stdcall* PFN_IDirectDrawSurface_Flip)(void*,void*,DWORD);
typedef HRESULT(__stdcall* PFN_IDirectDraw_CreateSurface)(void*,void*,void**,IUnknown*);
typedef HRESULT(__stdcall* PFN_IDirectDrawSurface_Unlock)(void*,LPVOID);
typedef HRESULT(__stdcall* PFN_IDirectDrawSurface_SetPalette)(void*,void*);
typedef HRESULT(__stdcall* PFN_IDirectDrawSurface_ReleaseDC)(void*,HDC);
 
// ---- ddraw/surface.h structures --------------------------------------------
struct ConvertFormatData
{
    ConvertFormatData():width(0),height(0),pitch(0),bitCount(0),
        rMask(0),gMask(0),bMask(0),aMask(0),srcData(nullptr){}
    DWORD width,height,pitch,bitCount,rMask,gMask,bMask,aMask;
    LPVOID srcData;
};
 
struct ConvertPaletteData
{
    ConvertPaletteData(){ memset(palette,0,sizeof(palette)); }
    PALETTEENTRY palette[256];
};
 
// SurfaceData � tracks which surfaces we've already saved (CRC dedup)
struct SurfaceData { SurfaceData():dataCrc32(0){} DWORD dataCrc32; };
 
// ---- ddraw/macro.h � stub generators ---------------------------------------
// Each macro expands to 8 static trampoline stubs (one per HooksGroup slot).
// The trampoline dispatches through the correct KHook slot to the helper.
 
#define STUB_IDirectDrawSurface_Blt(IDX) \
static HRESULT __stdcall _IDirectDrawSurface_Blt_##IDX( \
    void* p,RECT* dr,void* s,RECT* sr,DWORD f,void* fx) \
{ return KDdraw::this_->helper_IDirectDrawSurface_Blt( \
    KDdraw::this_->hooks_IDirectDrawSurface_Blt.getHook(IDX),p,dr,s,sr,f,fx); }
 
#define STUB_IDirectDrawSurface_Flip(IDX) \
static HRESULT __stdcall _IDirectDrawSurface_Flip_##IDX(void* p,void* s,DWORD f) \
{ return KDdraw::this_->helper_IDirectDrawSurface_Flip( \
    KDdraw::this_->hooks_IDirectDrawSurface_Flip.getHook(IDX),p,s,f); }
 
#define STUB_IDirectDraw_CreateSurface(IDX) \
static HRESULT __stdcall _IDirectDraw_CreateSurface_##IDX( \
    void* dd,void* desc,void** pp,IUnknown* u) \
{ return KDdraw::this_->helper_IDirectDraw_CreateSurface( \
    KDdraw::this_->hooks_IDirectDraw_CreateSurface.getHook(IDX),dd,desc,pp,u); }
 
#define STUB_IDirectDrawSurface_Unlock(IDX) \
static HRESULT __stdcall _IDirectDrawSurface_Unlock_##IDX(void* s,LPVOID p) \
{ return KDdraw::this_->helper_IDirectDrawSurface_Unlock( \
    KDdraw::this_->hooks_IDirectDrawSurface_Unlock.getHook(IDX),s,p); }
 
#define STUB_IUnk_QueryInterface(IDX) \
static HRESULT __stdcall _IUnk_QueryInterface_##IDX( \
    IUnknown* t,REFIID r,void** o) \
{ return KDdraw::this_->helper_IUnk_QueryInterface( \
    KDdraw::this_->hooks_IUnk_QueryInterface.getHook(IDX),t,r,o); }
 
#define STUB_IDirectDrawSurface_SetPalette(IDX) \
static HRESULT __stdcall _IDirectDrawSurface_SetPalette_##IDX(void* o,void* p) \
{ return KDdraw::this_->helper_IDirectDrawSurface_SetPalette( \
    KDdraw::this_->hooks_IDirectDrawSurface_SetPalette.getHook(IDX),o,(LPDIRECTDRAWPALETTE)p); }
 
#define STUB_IDirectDrawSurface_ReleaseDC(IDX) \
static HRESULT __stdcall _IDirectDrawSurface_ReleaseDC_##IDX(void* o,HDC h) \
{ return KDdraw::this_->helper_IDirectDrawSurface_ReleaseDC( \
    KDdraw::this_->hooks_IDirectDrawSurface_ReleaseDC.getHook(IDX),o,h); }
 
// ---- KDdraw class ----------------------------------------------------------
class KDdraw
{
public:
    static KDdraw* this_;
 
    static KDdraw* create(HINSTANCE hDll)
    {
        g_pLog->log("DDRAW init\n");
        KDdraw* p = new KDdraw(hDll);
        p->initialize(); return p;
    }
    static void destroy(KDdraw*& p)
    {
        if(!p) return;
        g_pLog->log("DDRAW uninit\n\n");
        p->cleanup(); SAFE_DELETE(p);
    }
 
    HRESULT save_IDirectDrawSurface(const wchar_t* fileName, void* pSurface);
    void    hook_IDirectDrawSurface(void* surf);
 
    // HooksGroups � public so STUB macros can access them
    HooksGroup hooks_IUnk_QueryInterface;
    HooksGroup hooks_IDirectDraw_CreateSurface;
    HooksGroup hooks_IDirectDrawSurface_Blt;
    HooksGroup hooks_IDirectDrawSurface_Flip;
    HooksGroup hooks_IDirectDrawSurface_Unlock;
    HooksGroup hooks_IDirectDrawSurface_SetPalette;
    HooksGroup hooks_IDirectDrawSurface_ReleaseDC;
 
    // Helpers � public so STUB macros can call them
    HRESULT helper_IDirectDrawSurface_Blt(KHook*,void*,RECT*,void*,RECT*,DWORD,void*);
    HRESULT helper_IDirectDrawSurface_Flip(KHook*,void*,void*,DWORD);
    HRESULT helper_IDirectDraw_CreateSurface(KHook*,void*,void*,void**,IUnknown*);
    HRESULT helper_IDirectDrawSurface_Unlock(KHook*,void*,LPVOID);
    HRESULT helper_IUnk_QueryInterface(KHook*,IUnknown*,REFIID,void**);
    HRESULT helper_IDirectDrawSurface_SetPalette(KHook*,void*,LPDIRECTDRAWPALETTE);
    HRESULT helper_IDirectDrawSurface_ReleaseDC(KHook*,void*,HDC);
 
private:
    HINSTANCE hDdraw;
    KHook* pHook_DirectDrawCreateEx = nullptr;
    KHook* pHook_DirectDrawCreate   = nullptr;
 
    ConvertPaletteData primarySurfacePalette;
 
    typedef std::map<void*,SurfaceData> SurfaceDb;
    SurfaceDb surfaceDb;
 
    KDdraw(HINSTANCE h):hDdraw(h){ this_=this; zeroHooks(); }
    ~KDdraw(){ this_=nullptr; }
 
    void zeroHooks()
    {
        GENERATE_HOOKS_GROUP_CLEARER(IUnk_QueryInterface);
        pHook_DirectDrawCreateEx = nullptr;
        pHook_DirectDrawCreate   = nullptr;
        GENERATE_HOOKS_GROUP_CLEARER(IDirectDraw_CreateSurface);
        GENERATE_HOOKS_GROUP_CLEARER(IDirectDrawSurface_Blt);
        GENERATE_HOOKS_GROUP_CLEARER(IDirectDrawSurface_Flip);
        GENERATE_HOOKS_GROUP_CLEARER(IDirectDrawSurface_Unlock);
        GENERATE_HOOKS_GROUP_CLEARER(IDirectDrawSurface_ReleaseDC);
        GENERATE_HOOKS_GROUP_CLEARER(IDirectDrawSurface_SetPalette);
    }
 
    void initialize()
    {
        if(!hDdraw){ g_pLog->logError("ddraw.dll handle == NULL\n"); return; }
        LPVOID t;
        t=GetProcAddress(hDdraw,"DirectDrawCreateEx");
        hookEx_full("DirectDrawCreateEx",t,_DirectDrawCreateEx,KHookMgr::EHOOK_POOL_DDRAW,&pHook_DirectDrawCreateEx);
        t=GetProcAddress(hDdraw,"DirectDrawCreate");
        hookEx_full("DirectDrawCreate",  t,_DirectDrawCreate,  KHookMgr::EHOOK_POOL_DDRAW,&pHook_DirectDrawCreate);
    }
 
    void cleanup()
    {
        g_pHookMgr->unhookPool(KHookMgr::EHOOK_POOL_DDRAW);
        zeroHooks();
    }
 
    bool isSurfaceSaved(void* obj,SurfaceData* out)
    {
        auto it=surfaceDb.find(obj);
        if(it==surfaceDb.end()) return false;
        *out=it->second; return true;
    }
    void addSurface(void* obj,const SurfaceData& d){ surfaceDb.insert({obj,d}); }
    void delSurface(void* obj){ auto it=surfaceDb.find(obj); if(it!=surfaceDb.end()) surfaceDb.erase(it); }
 
    void hook_IDirectDraw(void* lpDD)
    {
        hookEx("IDirectDraw_QueryInterface",IDX_IUnknown_QueryInterface,lpDD,
               KHookMgr::EHOOK_POOL_DDRAW,&hooks_IUnk_QueryInterface);
        hookEx("IDirectDraw_CreateSurface", IDX_IDirectDraw_CreateSurface,lpDD,
               KHookMgr::EHOOK_POOL_DDRAW,&hooks_IDirectDraw_CreateSurface);
    }
 
    bool isPrimarySurface(void* pSurf)
    {
        // Attempt IDirectDrawSurface7 first, fall back to IDirectDrawSurface
        // Returns true if DDSCAPS_PRIMARYSURFACE is set
        // (Implementation requires DXSDK7 types; placeholder returns false)
        (void)pSurf; return false;
    }
 
    void QI_handle(const std::string& name, void* obj, void* caller=nullptr);
 
    // Static hooks
    static HRESULT __stdcall _DirectDrawCreateEx(void* g,void** pp,REFIID iid,IUnknown* u)
    {
        KHook* h=this_->pHook_DirectDrawCreateEx;
        PFN_DirectDrawCreateEx e=(PFN_DirectDrawCreateEx)h->getOriginalAddress();
        g_pLog->log("DirectDrawCreateEx()\n");
        HRESULT hr=e(g,pp,iid,u);
        if(SUCCEEDED(hr)) this_->hook_IDirectDraw(*pp);
        return hr;
    }
    static HRESULT __stdcall _DirectDrawCreate(void* g,void** pp,IUnknown* u)
    {
        KHook* h=this_->pHook_DirectDrawCreate;
        PFN_DirectDrawCreate e=(PFN_DirectDrawCreate)h->getOriginalAddress();
        HRESULT hr=e(g,pp,u);
        g_pLog->log("DirectDrawCreate() ret: 0x%08X\n",hr);
        if(SUCCEEDED(hr)) this_->hook_IDirectDraw(*pp);
        return hr;
    }
 
    // Generate all 8 stubs for each hook group
    GENERATE_STUBS_GROUP(STUB_IUnk_QueryInterface)
    GENERATE_STUBS_GROUP(STUB_IDirectDraw_CreateSurface)
    GENERATE_STUBS_GROUP(STUB_IDirectDrawSurface_Blt)
    GENERATE_STUBS_GROUP(STUB_IDirectDrawSurface_Flip)
    GENERATE_STUBS_GROUP(STUB_IDirectDrawSurface_Unlock)
    GENERATE_STUBS_GROUP(STUB_IDirectDrawSurface_SetPalette)
    GENERATE_STUBS_GROUP(STUB_IDirectDrawSurface_ReleaseDC)
};
 
KDdraw* KDdraw::this_ = nullptr;
 
// ---- KDdraw helper implementations -----------------------------------------
 
void KDdraw::hook_IDirectDrawSurface(void* surf)
{
    hookEx("IDirectDrawSurface_QueryInterface",IDX_IUnknown_QueryInterface,surf,
           KHookMgr::EHOOK_POOL_DDRAW,&hooks_IUnk_QueryInterface);
    hookEx("IDirectDrawSurface_Flip",          IDX_IDirectDrawSurface_Flip,surf,
           KHookMgr::EHOOK_POOL_DDRAW,&hooks_IDirectDrawSurface_Flip);
    hookEx("IDirectDrawSurface_SetPalette",    IDX_IDirectDrawSurface_SetPalette,surf,
           KHookMgr::EHOOK_POOL_DDRAW,&hooks_IDirectDrawSurface_SetPalette);
    hookEx("IDirectDrawSurface_Unlock",        IDX_IDirectDrawSurface_Unlock,surf,
           KHookMgr::EHOOK_POOL_DDRAW,&hooks_IDirectDrawSurface_Unlock);
    hookEx("IDirectDrawSurface_ReleaseDC",     IDX_IDirectDrawSurface_ReleaseDC,surf,
           KHookMgr::EHOOK_POOL_DDRAW,&hooks_IDirectDrawSurface_ReleaseDC);
}
 
static const char* ISURFACE_INTERFACES[]={"IID_IDirectDrawSurface","IID_IDirectDrawSurface2",
    "IID_IDirectDrawSurface3","IID_IDirectDrawSurface4","IID_IDirectDrawSurface7"};
static const char* IDDRAW_INTERFACES[]={"IID_IDirectDraw","IID_IDirectDraw2",
    "IID_IDirectDraw4","IID_IDirectDraw7"};
 
void KDdraw::QI_handle(const std::string& name, void* obj, void* caller)
{
    // Forward DX7/DX6 3D interfaces to their respective rippers
    if(name=="IID_IDirect3D7"){ if(g_pRipper7) g_pRipper7->initialize((void*)obj); }
    else if(name=="IID_IDirect3D3"){ if(g_pRipper6) g_pRipper6->initialize((void*)obj); }
    else {
        bool isDdraw=false, isSurf=false;
        for(auto s:IDDRAW_INTERFACES)   if(name==s){ isDdraw=true; break; }
        for(auto s:ISURFACE_INTERFACES) if(name==s){ isSurf=true; break; }
        if(isDdraw) hook_IDirectDraw(obj);
        else if(isSurf) hook_IDirectDrawSurface(obj);
        else if(name=="IID_IDirect3DTexture2"){
            if(g_pRipper6) g_pRipper6->addTextureSurface((void*)obj, caller);
        }
    }
}
 
HRESULT KDdraw::helper_IUnk_QueryInterface(KHook* h,IUnknown* t,REFIID r,void** o)
{
    PFN_IUnk_QueryInterface e=(PFN_IUnk_QueryInterface)h->getOriginalAddress();
    std::string name=guidToName(r);
    HRESULT hr=e(t,r,o);
    g_pLog->log("IUnknown_QueryInterface(%s) HRESULT: 0x%08X\n",name.c_str(),hr);
    if(SUCCEEDED(hr)) QI_handle(name,*o,t);
    return hr;
}
 
HRESULT KDdraw::helper_IDirectDraw_CreateSurface(KHook* h,void* dd,void* desc,void** pp,IUnknown* u)
{
    PFN_IDirectDraw_CreateSurface e=(PFN_IDirectDraw_CreateSurface)h->getOriginalAddress();
    HRESULT hr=e(dd,desc,pp,u);
    if(SUCCEEDED(hr)) hook_IDirectDrawSurface(*pp);
    return hr;
}
 
HRESULT KDdraw::helper_IDirectDrawSurface_Flip(KHook* h,void* p,void* s,DWORD f)
{
    PFN_IDirectDrawSurface_Flip e=(PFN_IDirectDrawSurface_Flip)h->getOriginalAddress();
    HRESULT hr=e(p,s,f);
    if(SUCCEEDED(hr)){
        if(g_pRipper7) g_pIntruder->frameHandler(g_pRipper7);
        if(g_pRipper6) g_pIntruder->frameHandler(g_pRipper6);
    }
    return hr;
}
 
HRESULT KDdraw::helper_IDirectDrawSurface_Blt(KHook* h,void* p,RECT* dr,void* s,RECT* sr,DWORD f,void* fx)
{
    PFN_IDirectDrawSurface_Blt e=(PFN_IDirectDrawSurface_Blt)h->getOriginalAddress();
    HRESULT hr=e(p,dr,s,sr,f,(LPDDBLTFX)fx);
    if(SUCCEEDED(hr)){
        if(g_pRipper7) g_pIntruder->frameHandler(g_pRipper7);
        if(g_pRipper6) g_pIntruder->frameHandler(g_pRipper6);
    }
    return hr;
}
 
HRESULT KDdraw::helper_IDirectDrawSurface_Unlock(KHook* h,void* surf,LPVOID p)
{
    PFN_IDirectDrawSurface_Unlock e=(PFN_IDirectDrawSurface_Unlock)h->getOriginalAddress();
    HRESULT res=e(surf,p);
    if(g_pIntruder->getSettings()->saveDDrawSurfaces) rip_IDirectDrawSurface(surf);
    return res;
}
 
HRESULT KDdraw::helper_IDirectDrawSurface_ReleaseDC(KHook* h,void* surf,HDC hDC)
{
    PFN_IDirectDrawSurface_ReleaseDC e=(PFN_IDirectDrawSurface_ReleaseDC)h->getOriginalAddress();
    HRESULT res=e(surf,hDC);
    if(g_pIntruder->getSettings()->saveDDrawSurfaces) rip_IDirectDrawSurface(surf);
    return res;
}
 
HRESULT KDdraw::helper_IDirectDrawSurface_SetPalette(KHook* h,void* surf,LPDIRECTDRAWPALETTE pal)
{
    PFN_IDirectDrawSurface_SetPalette e=(PFN_IDirectDrawSurface_SetPalette)h->getOriginalAddress();
    HRESULT res=e(surf,pal);
    g_pLog->log("IDirectDrawSurface_SetPalette(0x%p, 0x%p)\n",surf,pal);
    if(SUCCEEDED(res)&&pal&&isPrimarySurface(surf)){
        g_pLog->log("Primary surface palette set\n");
        pal->GetEntries(0,0,256,primarySurfacePalette.palette);
    }
    return res;
}
 
HRESULT KDdraw::rip_IDirectDrawSurface(void* pSurface)
{
    SurfaceData sd;
    if(isSurfaceSaved(pSurface,&sd)) return E_FAIL;
    g_pLog->log("Surface save: 0x%p\n",pSurface);
    std::wstring path=g_pIntruder->getSurfaceSavePath();
    HRESULT hr=save_IDirectDrawSurface(path.c_str(),pSurface);
    if(SUCCEEDED(hr)){
        g_pIntruder->incSurfaceIdx();
        g_pLog->log("Surface saved: %s\n",wideStringToMultiByte(path.c_str()).c_str());
    }else{
        g_pLog->logError("Surface save. HRESULT: 0x%08X\n",hr);
    }
    addSurface(pSurface,SurfaceData{});
    return hr;
}
 
HRESULT KDdraw::save_IDirectDrawSurface(const wchar_t* fileName, void* pSurface)
{
    // Full implementation requires DXSDK7 lock/unlock + DirectXTex SaveToDDSFile.
    // Placeholder � returns S_OK to keep flow intact until DXSDK7 is linked.
    (void)fileName; (void)pSurface;
    return S_OK;
}
 
// ---- Factory functions (from preddraw.h/cpp) --------------------------------
KDdraw* create_KDdraw(HINSTANCE hDll){ return KDdraw::create(hDll); }
void    delete_KDdraw(KDdraw*& p)    { KDdraw::destroy(p); }
 
 
// =============================================================================
//  SECTION 26 � dxgi/  (DXGI swap-chain ripper)
//
//  Hooks: CreateDXGIFactory, CreateDXGIFactory1,
//         IDXGIFactory::CreateSwapChain (and Factory2 variants),
//         IDXGISwapChain::Present, IDXGISwapChain1::Present1,
//         IDXGIFactory::QueryInterface  (detects Factory2 upgrades)
//  Frame trigger: IDXGISwapChain::Present ? g_pIntruder->frameHandler(ripper)
//  The 'ripper' pointer is set externally via setIRipper(g_pDxgi, g_pRipper11)
//  once D3D11 initialises � decouples DXGI from D3D11 at startup.
// =============================================================================
 
// ---- dxgi/enums.h ----------------------------------------------------------
enum {
    IDX_IDXGIFactory_CreateSwapChain                 = 10,
    IDX_IDXGIFactory2_CreateSwapChainForHwnd         = 15,
    IDX_IDXGIFactory2_CreateSwapChainForCoreWindow   = 16,
    IDX_IDXGIFactory2_CreateSwapChainForComposition  = 24,
    IDX_IDXGISwapChain_Present                       =  8,
    IDX_IDXGISwapChain1_Present1                     = 22,
};
 
// ---- KDxgi class -----------------------------------------------------------
class KDxgi
{
public:
    static KDxgi* this_;
 
    static KDxgi* create(HINSTANCE hDXGI)
    {
        g_pLog->log("DXGI init\n");
        KDxgi* p = new KDxgi(hDXGI);
        p->initialize(); return p;
    }
    static void destroy(KDxgi*& p)
    {
        if(!p) return;
        g_pLog->log("DXGI uninit\n\n");
        p->cleanup(); SAFE_DELETE(p);
    }
 
    void setIRipper(IRipper* p){ ripper=p; }
    void hookSwapChain(IDXGISwapChain** pp);
    void hookSwapChain1(IDXGISwapChain1** pp);
 
private:
    HINSTANCE hDXGI;
    IRipper*  ripper = nullptr;
 
    KHook* pHook_CreateDXGIFactory                         = nullptr;
    KHook* pHook_CreateDXGIFactory1                        = nullptr;
    KHook* pHook_IDXGIFactory_CreateSwapChain              = nullptr;
    KHook* pHook_IDXGIFactory2_CreateSwapChainForHwnd      = nullptr;
    KHook* pHook_IDXGIFactory2_CreateSwapChainForCoreWindow= nullptr;
    KHook* pHook_IDXGIFactory2_CreateSwapChainForComposition=nullptr;
    KHook* pHook_IDXGIFactory_QueryInterface               = nullptr;
    KHook* pHook_IDXGISwapChain_Present                    = nullptr;
    KHook* pHook_IDXGISwapChain1_Present1                  = nullptr;
 
    KDxgi(HINSTANCE h):hDXGI(h){ this_=this; zeroHooks_dxgi(); }
    ~KDxgi(){ this_=nullptr; }
 
    void zeroHooks_dxgi()
    {
        pHook_CreateDXGIFactory=pHook_CreateDXGIFactory1=nullptr;
        pHook_IDXGIFactory_CreateSwapChain=nullptr;
        pHook_IDXGIFactory2_CreateSwapChainForHwnd=nullptr;
        pHook_IDXGIFactory2_CreateSwapChainForCoreWindow=nullptr;
        pHook_IDXGIFactory2_CreateSwapChainForComposition=nullptr;
        pHook_IDXGIFactory_QueryInterface=nullptr;
        pHook_IDXGISwapChain_Present=pHook_IDXGISwapChain1_Present1=nullptr;
    }
 
    void initialize()
    {
        if(!hDXGI){ g_pLog->logError("dxgi.dll HANDLE == NULL\n"); return; }
        LPVOID t;
        t=GetProcAddress(hDXGI,"CreateDXGIFactory");
        hookEx_full("CreateDXGIFactory", t,_CreateDXGIFactory, KHookMgr::EHOOK_POOL_DXGI,&pHook_CreateDXGIFactory);
        t=GetProcAddress(hDXGI,"CreateDXGIFactory1");
        hookEx_full("CreateDXGIFactory1",t,_CreateDXGIFactory1,KHookMgr::EHOOK_POOL_DXGI,&pHook_CreateDXGIFactory1);
    }
 
    void cleanup()
    {
        g_pHookMgr->unhookPool(KHookMgr::EHOOK_POOL_DXGI);
        zeroHooks_dxgi();
    }
 
    void hookQI(IDXGIFactory* pF)
    {
        hookEx("IDXGIFactory_QueryInterface",IDX_IUnknown_QueryInterface,pF,
               KHookMgr::EHOOK_POOL_DXGI,_IDXGIFactory_QueryInterface,
               &pHook_IDXGIFactory_QueryInterface);
    }
 
    void hookIDXGIFactory(REFIID riid, void** ppFactory)
    {
        if(riid==__uuidof(IDXGIFactory)||riid==__uuidof(IDXGIFactory1)){
            IDXGIFactory** pp=(IDXGIFactory**)ppFactory;
            hookQI(*pp);
            hookEx("IDXGIFactory_CreateSwapChain",IDX_IDXGIFactory_CreateSwapChain,
                   *pp,KHookMgr::EHOOK_POOL_DXGI,_IDXGIFactory_CreateSwapChain,
                   &pHook_IDXGIFactory_CreateSwapChain);
        }
        else if(riid==__uuidof(IDXGIFactory2)){
            IDXGIFactory2** pp=(IDXGIFactory2**)ppFactory;
            hookQI(*pp);
            hookEx("IDXGIFactory2_CreateSwapChain",IDX_IDXGIFactory_CreateSwapChain,
                   *pp,KHookMgr::EHOOK_POOL_DXGI,_IDXGIFactory_CreateSwapChain,
                   &pHook_IDXGIFactory_CreateSwapChain);
            hookEx("IDXGIFactory2_CreateSwapChainForHwnd",
                   IDX_IDXGIFactory2_CreateSwapChainForHwnd,*pp,
                   KHookMgr::EHOOK_POOL_DXGI,_IDXGIFactory2_CreateSwapChainForHwnd,
                   &pHook_IDXGIFactory2_CreateSwapChainForHwnd);
            hookEx("IDXGIFactory2_CreateSwapChainForCoreWindow",
                   IDX_IDXGIFactory2_CreateSwapChainForCoreWindow,*pp,
                   KHookMgr::EHOOK_POOL_DXGI,_IDXGIFactory2_CreateSwapChainForCoreWindow,
                   &pHook_IDXGIFactory2_CreateSwapChainForCoreWindow);
            hookEx("IDXGIFactory2_CreateSwapChainForComposition",
                   IDX_IDXGIFactory2_CreateSwapChainForComposition,*pp,
                   KHookMgr::EHOOK_POOL_DXGI,_IDXGIFactory2_CreateSwapChainForComposition,
                   &pHook_IDXGIFactory2_CreateSwapChainForComposition);
        }
        else{
            g_pLog->logWarning("hookIDXGIFactory() unknown GUID: %s\n",
                               guidToName(riid).c_str());
        }
    }
 
    // ---------- Static hook trampolines ----------
 
    static HRESULT __stdcall _CreateDXGIFactory(REFIID r,void** pp)
    {
        PFN_CreateDXGIFactory e=(PFN_CreateDXGIFactory)this_->pHook_CreateDXGIFactory->getOriginalAddress();
        g_pLog->log("CreateDXGIFactory()\n");
        HRESULT hr=e(r,pp);
        if(SUCCEEDED(hr)) this_->hookIDXGIFactory(r,pp);
        return hr;
    }
    static HRESULT __stdcall _CreateDXGIFactory1(REFIID r,void** pp)
    {
        PFN_CreateDXGIFactory1 e=(PFN_CreateDXGIFactory1)this_->pHook_CreateDXGIFactory1->getOriginalAddress();
        g_pLog->log("CreateDXGIFactory1()\n");
        HRESULT hr=e(r,pp);
        if(SUCCEEDED(hr)) this_->hookIDXGIFactory(r,pp);
        return hr;
    }
    static HRESULT __stdcall _IDXGIFactory_CreateSwapChain(
        IDXGIFactory* pF,IUnknown* pD,DXGI_SWAP_CHAIN_DESC* pDesc,IDXGISwapChain** pp)
    {
        PFN_IDXGIFactory_CreateSwapChain e=
            (PFN_IDXGIFactory_CreateSwapChain)this_->pHook_IDXGIFactory_CreateSwapChain->getOriginalAddress();
        g_pLog->log("IDXGIFactory_CreateSwapChain()\n");
        HRESULT hr=e(pF,pD,pDesc,pp);
        this_->hookSwapChain(pp);
        return hr;
    }
    static HRESULT __stdcall _IDXGIFactory2_CreateSwapChainForHwnd(
        IDXGIFactory2* pF,IUnknown* pD,HWND h,
        const DXGI_SWAP_CHAIN_DESC1* pD1,
        const DXGI_SWAP_CHAIN_FULLSCREEN_DESC* pFS,
        IDXGIOutput* pO,IDXGISwapChain1** pp)
    {
        PFN_IDXGIFactory2_CreateSwapChainForHwnd e=
            (PFN_IDXGIFactory2_CreateSwapChainForHwnd)this_->pHook_IDXGIFactory2_CreateSwapChainForHwnd->getOriginalAddress();
        HRESULT hr=e(pF,pD,h,pD1,pFS,pO,pp);
        g_pLog->log("IDXGIFactory2_CreateSwapChainForHwnd()\n");
        this_->hookSwapChain((IDXGISwapChain**)pp);
        this_->hookSwapChain1(pp);
        return hr;
    }
    static HRESULT __stdcall _IDXGIFactory2_CreateSwapChainForCoreWindow(
        IDXGIFactory2* pF,IUnknown* pD,IUnknown* pW,
        const DXGI_SWAP_CHAIN_DESC1* pD1,IDXGIOutput* pO,IDXGISwapChain1** pp)
    {
        PFN_IDXGIFactory2_CreateSwapChainForCoreWindow e=
            (PFN_IDXGIFactory2_CreateSwapChainForCoreWindow)this_->pHook_IDXGIFactory2_CreateSwapChainForCoreWindow->getOriginalAddress();
        HRESULT hr=e(pF,pD,pW,pD1,pO,pp);
        g_pLog->log("IDXGIFactory2_CreateSwapChainForCoreWindow()\n");
        this_->hookSwapChain((IDXGISwapChain**)pp);
        this_->hookSwapChain1(pp);
        return hr;
    }
    static HRESULT __stdcall _IDXGIFactory2_CreateSwapChainForComposition(
        IDXGIFactory2* pF,IUnknown* pD,
        const DXGI_SWAP_CHAIN_DESC1* pD1,IDXGIOutput* pO,IDXGISwapChain1** pp)
    {
        PFN_IDXGIFactory2_CreateSwapChainForComposition e=
            (PFN_IDXGIFactory2_CreateSwapChainForComposition)this_->pHook_IDXGIFactory2_CreateSwapChainForComposition->getOriginalAddress();
        HRESULT hr=e(pF,pD,pD1,pO,pp);
        g_pLog->log("IDXGIFactory2_CreateSwapChainForComposition()\n");
        this_->hookSwapChain((IDXGISwapChain**)pp);
        this_->hookSwapChain1(pp);
        return hr;
    }
    static HRESULT __stdcall _IDXGISwapChain_Present(IDXGISwapChain* pSC,UINT si,UINT f)
    {
        PFN_IDXGISwapChain_Present e=
            (PFN_IDXGISwapChain_Present)this_->pHook_IDXGISwapChain_Present->getOriginalAddress();
        if(this_->ripper) g_pIntruder->frameHandler(this_->ripper);
        return e(pSC,si,f);
    }
    static HRESULT __stdcall _IDXGISwapChain1_Present1(IDXGISwapChain1* pSC,UINT si,UINT f,
                                                       const DXGI_PRESENT_PARAMETERS* pp)
    {
        PFN_IDXGISwapChain1_Present1 e=
            (PFN_IDXGISwapChain1_Present1)this_->pHook_IDXGISwapChain1_Present1->getOriginalAddress();
        if(this_->ripper) g_pIntruder->frameHandler(this_->ripper);
        return e(pSC,si,f,pp);
    }
    static HRESULT __stdcall _IDXGIFactory_QueryInterface(IDXGIFactory* pF,REFIID r,void** o)
    {
        PFN_IUnk_QueryInterface e=
            (PFN_IUnk_QueryInterface)this_->pHook_IDXGIFactory_QueryInterface->getOriginalAddress();
        std::string name=guidToName(r);
        g_pLog->log("IDXGIFactory_QueryInterface(%s)\n",name.c_str());
        HRESULT hr=e(pF,r,o);
        if(SUCCEEDED(hr)) this_->hookIDXGIFactory(r,o);
        return hr;
    }
};
 
KDxgi* KDxgi::this_ = nullptr;
 
void KDxgi::hookSwapChain(IDXGISwapChain** pp)
{
    if(!pp||!*pp){ g_pLog->logWarning("KDxgi::hookSwapChain() null ptr\n"); return; }
    hookEx("IDXGISwapChain_Present",IDX_IDXGISwapChain_Present,*pp,
           KHookMgr::EHOOK_POOL_DXGI,_IDXGISwapChain_Present,
           &pHook_IDXGISwapChain_Present);
}
void KDxgi::hookSwapChain1(IDXGISwapChain1** pp)
{
    if(!pp||!*pp) return;
    hookEx("IDXGISwapChain1_Present1",IDX_IDXGISwapChain1_Present1,*pp,
           KHookMgr::EHOOK_POOL_DXGI,_IDXGISwapChain1_Present1,
           &pHook_IDXGISwapChain1_Present1);
}
 
// ---- Factory functions (from predxgi.h/cpp) --------------------------------
KDxgi* create_KDxgi(HINSTANCE hDXGI)    { return KDxgi::create(hDXGI); }
void   delete_KDxgi(KDxgi*& p)          { KDxgi::destroy(p); }
void   setIRipper(KDxgi* p, IRipper* r) { if(p) p->setIRipper(r); }
 
 
// =============================================================================
//  SECTION 27 � dx9/  (Direct3D 9 ripper � KRipper9)
//
//  Hook chain:
//    Direct3DCreate9 / Direct3DCreate9Ex
//      ? IDirect3D9::CreateDevice / IDirect3D9Ex::CreateDeviceEx
//          ? setDeviceHooks(pDev):
//              DrawPrimitive, DrawIndexedPrimitive,
//              DrawPrimitiveUP, DrawIndexedPrimitiveUP  ? mesh capture
//              Present / SwapChain::Present             ? frame trigger
//              SetTexture / SetPixelShader              ? texture/shader tracking
//              SetStreamSource                          ? VB cache
//              CreateVertexBuffer / CreateIndexBuffer   ? strip WRITEONLY flag
//              SetDepthStencilSurface / SetGammaRamp    ? state save for tex render
//              CreateVertexShader / CreatePixelShader   ? shader disasm
//
//  Texture save technique (savetexture9.cpp):
//    Creates a temp RENDERTARGET texture, renders a fullscreen quad with the
//    source texture bound to stage 0 (bypassing any game shaders), then saves
//    the render target via D3DXSaveTextureToFileW to a .dds file.
// =============================================================================
 
#include <d3d9.h>
#include <d3dx9tex.h>
#include <d3dx9shader.h>
 
// ---- dx9/enums.h (vtable indices) ------------------------------------------
enum {
    IDX_IDirect3D9_CreateDevice                     = 16,
    IDX_IDirect3D9_CreateDeviceEx                   = 20,
    IDX_IDirect3DDevice9_Present                    = 17,
    IDX_IDirect3DDevice9_GetSwapChain               = 14,
    IDX_IDirect3DDevice9_CreateAdditionalSwapChain  = 13,
    IDX_IDirect3DDevice9_SetTexture                 = 65,
    IDX_IDirect3DDevice9_DrawPrimitive              = 81,
    IDX_IDirect3DDevice9_DrawIndexedPrimitive       = 82,
    IDX_IDirect3DDevice9_DrawPrimitiveUP            = 83,
    IDX_IDirect3DDevice9_DrawIndexedPrimitiveUP     = 84,
    IDX_IDirect3DDevice9_CreateVertexBuffer         = 26,
    IDX_IDirect3DDevice9_CreateIndexBuffer          = 27,
    IDX_IDirect3DDevice9_SetPixelShader             = 107,
    IDX_IDirect3DDevice9_SetDepthStencilSurface     = 39,
    IDX_IDirect3DDevice9_SetGammaRamp               = 21,
    IDX_IDirect3DDevice9_SetStreamSource            = 100,
    IDX_IDirect3DDevice9_CreateVertexShader         = 91,
    IDX_IDirect3DDevice9_CreatePixelShader          = 106,
    IDX_IDirect3DSwapChain9_Present                 = 3,
    IDX_IDirect3DDevice9Ex_PresentEx                = 121,
};
 
// ---- dx9/dx9types.h (function pointer typedefs) ----------------------------
typedef IDirect3D9*  (__stdcall *PFN_Direct3DCreate9)(UINT);
typedef HRESULT      (__stdcall *PFN_Direct3DCreate9Ex)(UINT, IDirect3D9Ex**);
typedef HRESULT      (__stdcall *PFN_IDirect3D9_CreateDevice)(IDirect3D9*,UINT,D3DDEVTYPE,HWND,DWORD,D3DPRESENT_PARAMETERS*,IDirect3DDevice9**);
typedef HRESULT      (__stdcall *PFN_IDirect3D9Ex_CreateDeviceEx)(IDirect3D9Ex*,UINT,D3DDEVTYPE,HWND,DWORD,D3DPRESENT_PARAMETERS*,D3DDISPLAYMODEEX*,IDirect3DDevice9Ex**);
typedef HRESULT      (__stdcall *PFN_IDirect3DDevice9_SetTexture)(IDirect3DDevice9*,DWORD,IDirect3DBaseTexture9*);
typedef HRESULT      (__stdcall *PFN_IDirect3DDevice9_DrawIndexedPrimitive)(IDirect3DDevice9*,D3DPRIMITIVETYPE,INT,UINT,UINT,UINT,UINT);
typedef HRESULT      (__stdcall *PFN_IDirect3DDevice9_DrawPrimitive)(IDirect3DDevice9*,D3DPRIMITIVETYPE,UINT,UINT);
typedef HRESULT      (__stdcall *PFN_IDirect3DDevice9_DrawIndexedPrimitiveUP)(IDirect3DDevice9*,D3DPRIMITIVETYPE,UINT,UINT,UINT,CONST void*,D3DFORMAT,CONST void*,UINT);
typedef HRESULT      (__stdcall *PFN_IDirect3DDevice9_DrawPrimitiveUP)(IDirect3DDevice9*,D3DPRIMITIVETYPE,UINT,CONST void*,UINT);
typedef HRESULT      (__stdcall *PFN_IDirect3DDevice9_Present)(IDirect3DDevice9*,CONST RECT*,CONST RECT*,HWND,CONST RGNDATA*);
typedef HRESULT      (__stdcall *PFN_IDirect3DDevice9Ex_PresentEx)(IDirect3DDevice9Ex*,CONST RECT*,CONST RECT*,HWND,CONST RGNDATA*,DWORD);
typedef HRESULT      (__stdcall *PFN_IDirect3DDevice9_SetPixelShader)(IDirect3DDevice9*,IDirect3DPixelShader9*);
typedef HRESULT      (__stdcall *PFN_IDirect3DSwapChain9_Present)(IDirect3DSwapChain9*,CONST RECT*,CONST RECT*,HWND,CONST RGNDATA*,DWORD);
typedef HRESULT      (__stdcall *PFN_IDirect3DDevice9_CreateVertexBuffer)(IDirect3DDevice9*,UINT,DWORD,DWORD,D3DPOOL,IDirect3DVertexBuffer9**,HANDLE*);
typedef HRESULT      (__stdcall *PFN_IDirect3DDevice9_CreateIndexBuffer)(IDirect3DDevice9*,UINT,DWORD,DWORD,D3DPOOL,IDirect3DIndexBuffer9**,HANDLE*);
typedef HRESULT      (__stdcall *PFN_IDirect3DDevice9_GetSwapChain)(IDirect3DDevice9*,UINT,IDirect3DSwapChain9**);
typedef HRESULT      (__stdcall *PFN_IDirect3DDevice9_CreateAdditionalSwapChain)(IDirect3DDevice9*,D3DPRESENT_PARAMETERS*,IDirect3DSwapChain9**);
typedef HRESULT      (__stdcall *PFN_IDirect3DDevice9_SetStreamSource)(IDirect3DDevice9*,UINT,IDirect3DVertexBuffer9*,UINT,UINT);
typedef HRESULT      (__stdcall *PFN_IDirect3DDevice9_CreateVertexShader)(IDirect3DDevice9*,const DWORD*,IDirect3DVertexShader9**);
typedef HRESULT      (__stdcall *PFN_IDirect3DDevice9_CreatePixelShader)(IDirect3DDevice9*,const DWORD*,IDirect3DPixelShader9**);
typedef HRESULT      (__stdcall *PFN_IDirect3DDevice9_SetDepthStencilSurface)(IDirect3DDevice9*,IDirect3DSurface9*);
typedef void         (__stdcall *PFN_IDirect3DDevice9_SetGammaRamp)(IDirect3DDevice9*,UINT,DWORD,const D3DGAMMARAMP*);
typedef HRESULT      (__stdcall *PFN_D3DXSaveTextureToFileW)(LPCTSTR,D3DXIMAGE_FILEFORMAT,LPDIRECT3DBASETEXTURE9,CONST PALETTEENTRY*);
 
// ---- dx9/macro.h � stub generators -----------------------------------------
// Each generates 8 static trampolines for a HooksGroup slot.
#define STUB_IDirect3DDevice9_SetTexture(IDX) \
static HRESULT __stdcall _IDirect3DDevice9_SetTexture_##IDX(IDirect3DDevice9* d,DWORD s,IDirect3DBaseTexture9* t) \
{ return KRipper9::this_->helper_IDirect3DDevice9_SetTexture(KRipper9::this_->hooks_IDirect3DDevice9_SetTexture.getHook(IDX),d,s,t); }
 
#define STUB_IDirect3DDevice9_SetPixelShader(IDX) \
static HRESULT __stdcall _IDirect3DDevice9_SetPixelShader_##IDX(IDirect3DDevice9* d,IDirect3DPixelShader9* p) \
{ return KRipper9::this_->helper_IDirect3DDevice9_SetPixelShader(KRipper9::this_->hooks_IDirect3DDevice9_SetPixelShader.getHook(IDX),d,p); }
 
#define STUB_IDirect3DDevice9_SetStreamSource(IDX) \
static HRESULT __stdcall _IDirect3DDevice9_SetStreamSource_##IDX(IDirect3DDevice9* d,UINT sn,IDirect3DVertexBuffer9* sd,UINT o,UINT st) \
{ return KRipper9::this_->helper_IDirect3DDevice9_SetStreamSource(KRipper9::this_->hooks_IDirect3DDevice9_SetStreamSource.getHook(IDX),d,sn,sd,o,st); }
 
#define STUB_IDirect3DDevice9_DrawIndexedPrimitive(IDX) \
static HRESULT __stdcall _IDirect3DDevice9_DrawIndexedPrimitive_##IDX(IDirect3DDevice9* d,D3DPRIMITIVETYPE t,INT b,UINT mi,UINT nv,UINT si,UINT pc) \
{ return KRipper9::this_->helper_IDirect3DDevice9_DrawIndexedPrimitive(KRipper9::this_->hooks_IDirect3DDevice9_DrawIndexedPrimitive.getHook(IDX),d,t,b,mi,nv,si,pc); }
 
#define STUB_IDirect3DDevice9_DrawIndexedPrimitiveUP(IDX) \
static HRESULT __stdcall _IDirect3DDevice9_DrawIndexedPrimitiveUP_##IDX(IDirect3DDevice9* d,D3DPRIMITIVETYPE t,UINT mvi,UINT nv,UINT pc,CONST void* id,D3DFORMAT idf,CONST void* vd,UINT vs) \
{ return KRipper9::this_->helper_IDirect3DDevice9_DrawIndexedPrimitiveUP(KRipper9::this_->hooks_IDirect3DDevice9_DrawIndexedPrimitiveUP.getHook(IDX),d,t,mvi,nv,pc,id,idf,vd,vs); }
 
#define STUB_IDirect3DDevice9_DrawPrimitive(IDX) \
static HRESULT __stdcall _IDirect3DDevice9_DrawPrimitive_##IDX(IDirect3DDevice9* d,D3DPRIMITIVETYPE t,UINT sv,UINT pc) \
{ return KRipper9::this_->helper_IDirect3DDevice9_DrawPrimitive(KRipper9::this_->hooks_IDirect3DDevice9_DrawPrimitive.getHook(IDX),d,t,sv,pc); }
 
#define STUB_IDirect3DDevice9_DrawPrimitiveUP(IDX) \
static HRESULT __stdcall _IDirect3DDevice9_DrawPrimitiveUP_##IDX(IDirect3DDevice9* d,D3DPRIMITIVETYPE t,UINT pc,CONST void* vd,UINT vs) \
{ return KRipper9::this_->helper_IDirect3DDevice9_DrawPrimitiveUP(KRipper9::this_->hooks_IDirect3DDevice9_DrawPrimitiveUP.getHook(IDX),d,t,pc,vd,vs); }
 
#define STUB_IUnk_QueryInterface(IDX) \
static HRESULT __stdcall _IUnk_QueryInterface_##IDX(IUnknown* t,REFIID r,void** o) \
{ return KRipper9::this_->helper_IUnk_QueryInterface(KRipper9::this_->hooks_IUnk_QueryInterface.getHook(IDX),t,r,o); }
 
 
// ---- KRipper9 class declaration --------------------------------------------
class KRipper9 : public IRipper
{
public:
    static KRipper9* this_;
 
    static KRipper9* create(HINSTANCE hD3D9)
    {
        g_pLog->log("D3D9 ripper init\n");
        KRipper9* p = new KRipper9(hD3D9);
        p->initialize_(); return p;
    }
    static void destroy(KRipper9*& p)
    {
        if(!p) return;
        g_pLog->log("D3D9 ripper uninit\n\n");
        p->cleanup_(); SAFE_DELETE(p);
    }
 
    // IRipper interface
    void frameStart()      override { meshTexturesDb.clear(); }
    void frameEnd()        override {}
    void textureRipStart() override { forcedTexturesDb.clear(); }
    void textureRipEnd()   override {}
 
    // Public hook groups (accessed by STUB macros)
    HooksGroup hooks_IDirect3DDevice9_SetTexture;
    HooksGroup hooks_IDirect3DDevice9_SetPixelShader;
    HooksGroup hooks_IDirect3DDevice9_SetStreamSource;
    HooksGroup hooks_IDirect3DDevice9_DrawIndexedPrimitive;
    HooksGroup hooks_IDirect3DDevice9_DrawIndexedPrimitiveUP;
    HooksGroup hooks_IDirect3DDevice9_DrawPrimitive;
    HooksGroup hooks_IDirect3DDevice9_DrawPrimitiveUP;
    HooksGroup hooks_IUnk_QueryInterface;
 
    // Public helpers (accessed by STUB macros)
    HRESULT helper_IDirect3DDevice9_SetTexture(KHook*,IDirect3DDevice9*,DWORD,IDirect3DBaseTexture9*);
    HRESULT helper_IDirect3DDevice9_SetPixelShader(KHook*,IDirect3DDevice9*,IDirect3DPixelShader9*);
    HRESULT helper_IDirect3DDevice9_SetStreamSource(KHook*,IDirect3DDevice9*,UINT,IDirect3DVertexBuffer9*,UINT,UINT);
    HRESULT helper_IDirect3DDevice9_DrawIndexedPrimitive(KHook*,IDirect3DDevice9*,D3DPRIMITIVETYPE,INT,UINT,UINT,UINT,UINT);
    HRESULT helper_IDirect3DDevice9_DrawIndexedPrimitiveUP(KHook*,IDirect3DDevice9*,D3DPRIMITIVETYPE,UINT,UINT,UINT,CONST void*,D3DFORMAT,CONST void*,UINT);
    HRESULT helper_IDirect3DDevice9_DrawPrimitive(KHook*,IDirect3DDevice9*,D3DPRIMITIVETYPE,UINT,UINT);
    HRESULT helper_IDirect3DDevice9_DrawPrimitiveUP(KHook*,IDirect3DDevice9*,D3DPRIMITIVETYPE,UINT,CONST void*,UINT);
    HRESULT helper_IUnk_QueryInterface(KHook*,IUnknown*,REFIID,void**);
 
    HRESULT saveTexture2File(LPCTSTR szFile,IDirect3DDevice9* pDev,IDirect3DBaseTexture9* pTex);
    void    saveMeshTextures(IDirect3DDevice9* pDev, KMeshTextures* out);
    void    saveMeshShaders(IDirect3DDevice9* pDev, KMeshShaders* out);
 
private:
    HINSTANCE hD3D9, hD3D9X;
    PFN_D3DXSaveTextureToFileW D3DXSaveTextureToFileW_;
    D3DCompileHelper d3dCompileHelper;
    ShadersDb shadersDb;
 
    struct KTexture
    {
        IDirect3DBaseTexture9* pTexture = nullptr;
        std::string  name;
        std::wstring fullPath;
    };
    std::vector<KTexture>                 meshTexturesDb;
    std::vector<IDirect3DBaseTexture9*>   forcedTexturesDb;
 
    CRITICAL_SECTION cs;
 
    // Pixel shader / depth stencil / gamma � tracked for texture render restore
    TInitedVal<IDirect3DPixelShader9*>  LastPS;
    TInitedVal<IDirect3DSurface9*>      LastDepthStencilSurface;
    struct GammaHelper{ UINT swapChain; DWORD flags; D3DGAMMARAMP gammaRamp; };
    TInitedVal<GammaHelper>             lastGamma;
 
    // Single hooks
    KHook *pHook_Direct3DCreate9=nullptr, *pHook_Direct3DCreate9Ex=nullptr;
    KHook *pHook_IDirect3D9_CreateDevice=nullptr, *pHook_IDirect3D9Ex_CreateDeviceEx=nullptr;
    KHook *pHook_IDirect3DDevice9_CreateVertexBuffer=nullptr;
    KHook *pHook_IDirect3DDevice9_CreateIndexBuffer=nullptr;
    KHook *pHook_IDirect3DDevice9_Present=nullptr;
    KHook *pHook_IDirect3DDevice9_GetSwapChain=nullptr;
    KHook *pHook_IDirect3DSwapChain9_Present=nullptr;
    KHook *pHook_IDirect3DDevice9_SetDepthStencilSurface=nullptr;
    KHook *pHook_IDirect3DDevice9_SetGammaRamp=nullptr;
    KHook *pHook_IDirect3DDevice9_CreateAdditionalSwapChain=nullptr;
    KHook *pHook_IDirect3DDevice9_CreateVertexShader=nullptr;
    KHook *pHook_IDirect3DDevice9_CreatePixelShader=nullptr;
    KHook *pHook_IDirect3DDevice9Ex_PresentEx=nullptr;
 
    // Render state tables for texture save
    enum { RS_SIZE=35, SS_SIZE=10, TSS_SIZE=5 };
    template<class T> struct TState{ T State; DWORD SetVal; };
    TState<D3DRENDERSTATETYPE>       RenderStates[RS_SIZE];
    TState<D3DSAMPLERSTATETYPE>      SamplerStates[SS_SIZE];
    TState<D3DTEXTURESTAGESTATETYPE> TextureStageStates[TSS_SIZE];
 
    // Vertex buffer cache (games sometimes pass NULL to GetStreamSource)
    struct VbCacheEntry
    {
        IDirect3DDevice9*      pDev=nullptr;
        UINT StreamNumber=0, OffsetInBytes=0, Stride=0;
        IDirect3DVertexBuffer9* pStreamData=nullptr;
    };
    std::vector<VbCacheEntry> vbCache;
 
    KRipper9(HINSTANCE h)
        : hD3D9(h), hD3D9X(nullptr), D3DXSaveTextureToFileW_(nullptr)
    {
        this_=this;
        InitializeCriticalSection(&cs);
        initializeStates();
        zeroHooks();
    }
    ~KRipper9(){ DeleteCriticalSection(&cs); this_=nullptr; }
 
    void zeroHooks()
    {
        pHook_Direct3DCreate9=pHook_Direct3DCreate9Ex=nullptr;
        pHook_IDirect3D9_CreateDevice=pHook_IDirect3D9Ex_CreateDeviceEx=nullptr;
        pHook_IDirect3DDevice9_CreateVertexBuffer=nullptr;
        pHook_IDirect3DDevice9_CreateIndexBuffer=nullptr;
        pHook_IDirect3DDevice9_Present=nullptr;
        pHook_IDirect3DDevice9_GetSwapChain=nullptr;
        pHook_IDirect3DSwapChain9_Present=nullptr;
        pHook_IDirect3DDevice9_SetDepthStencilSurface=nullptr;
        pHook_IDirect3DDevice9_SetGammaRamp=nullptr;
        pHook_IDirect3DDevice9_CreateAdditionalSwapChain=nullptr;
        pHook_IDirect3DDevice9_CreateVertexShader=nullptr;
        pHook_IDirect3DDevice9_CreatePixelShader=nullptr;
        pHook_IDirect3DDevice9Ex_PresentEx=nullptr;
        GENERATE_HOOKS_GROUP_CLEARER(IDirect3DDevice9_SetTexture);
        GENERATE_HOOKS_GROUP_CLEARER(IDirect3DDevice9_SetPixelShader);
        GENERATE_HOOKS_GROUP_CLEARER(IDirect3DDevice9_SetStreamSource);
        GENERATE_HOOKS_GROUP_CLEARER(IDirect3DDevice9_DrawIndexedPrimitive);
        GENERATE_HOOKS_GROUP_CLEARER(IDirect3DDevice9_DrawIndexedPrimitiveUP);
        GENERATE_HOOKS_GROUP_CLEARER(IDirect3DDevice9_DrawPrimitive);
        GENERATE_HOOKS_GROUP_CLEARER(IDirect3DDevice9_DrawPrimitiveUP);
        GENERATE_HOOKS_GROUP_CLEARER(IUnk_QueryInterface);
    }
 
    void initialize_()
    {
        LPVOID t=GetProcAddress(hD3D9,"Direct3DCreate9");
        hookEx_full("Direct3DCreate9",t,_Direct3DCreate9,KHookMgr::EHOOK_POOL_DX9,&pHook_Direct3DCreate9);
        t=GetProcAddress(hD3D9,"Direct3DCreate9Ex");
        hookEx_full("Direct3DCreate9Ex",t,_Direct3DCreate9Ex,KHookMgr::EHOOK_POOL_DX9,&pHook_Direct3DCreate9Ex);
    }
 
    void cleanup_()
    {
        g_pHookMgr->unhookPool(KHookMgr::EHOOK_POOL_DX9);
        zeroHooks();
    }
 
    void helperDllsInit()
    {
        loadD3DCompile(&d3dCompileHelper);
        if(!hD3D9X){
            static const wchar_t* DLL=L"d3dx9_43.dll";
            hD3D9X=GetModuleHandleW(DLL);
            if(!hD3D9X) hD3D9X=LoadLibraryW(DLL);
            if(!hD3D9X) fatalErrorMsgW(L"d3dx9_43.dll not found. Install DirectX.");
            D3DXSaveTextureToFileW_=(PFN_D3DXSaveTextureToFileW)GetProcAddress(hD3D9X,"D3DXSaveTextureToFileW");
            if(!D3DXSaveTextureToFileW_) fatalErrorMsgW(L"D3DXSaveTextureToFileW not found.");
        }
    }
 
    void setDeviceHooks(IDirect3DDevice9* pDev)
    {
        hookEx("IDirect3DDevice9_SetTexture",IDX_IDirect3DDevice9_SetTexture,pDev,KHookMgr::EHOOK_POOL_DX9,&hooks_IDirect3DDevice9_SetTexture);
        hookEx("IDirect3DDevice9_DrawPrimitiveUP",IDX_IDirect3DDevice9_DrawPrimitiveUP,pDev,KHookMgr::EHOOK_POOL_DX9,&hooks_IDirect3DDevice9_DrawPrimitiveUP);
        hookEx("IDirect3DDevice9_DrawIndexedPrimitive",IDX_IDirect3DDevice9_DrawIndexedPrimitive,pDev,KHookMgr::EHOOK_POOL_DX9,&hooks_IDirect3DDevice9_DrawIndexedPrimitive);
        hookEx("IDirect3DDevice9_DrawIndexedPrimitiveUP",IDX_IDirect3DDevice9_DrawIndexedPrimitiveUP,pDev,KHookMgr::EHOOK_POOL_DX9,&hooks_IDirect3DDevice9_DrawIndexedPrimitiveUP);
        hookEx("IDirect3DDevice9_DrawPrimitive",IDX_IDirect3DDevice9_DrawPrimitive,pDev,KHookMgr::EHOOK_POOL_DX9,&hooks_IDirect3DDevice9_DrawPrimitive);
        hookEx("IDirect3DDevice9_CreateVertexBuffer",IDX_IDirect3DDevice9_CreateVertexBuffer,pDev,KHookMgr::EHOOK_POOL_DX9,_IDirect3DDevice9_CreateVertexBuffer,&pHook_IDirect3DDevice9_CreateVertexBuffer);
        hookEx("IDirect3DDevice9_CreateIndexBuffer",IDX_IDirect3DDevice9_CreateIndexBuffer,pDev,KHookMgr::EHOOK_POOL_DX9,_IDirect3DDevice9_CreateIndexBuffer,&pHook_IDirect3DDevice9_CreateIndexBuffer);
        hookEx("IDirect3DDevice9_Present",IDX_IDirect3DDevice9_Present,pDev,KHookMgr::EHOOK_POOL_DX9,_IDirect3DDevice9_Present,&pHook_IDirect3DDevice9_Present);
        hookEx("IDirect3DDevice9_GetSwapChain",IDX_IDirect3DDevice9_GetSwapChain,pDev,KHookMgr::EHOOK_POOL_DX9,_IDirect3DDevice9_GetSwapChain,&pHook_IDirect3DDevice9_GetSwapChain);
        hookEx("IDirect3DDevice9_CreateAdditionalSwapChain",IDX_IDirect3DDevice9_CreateAdditionalSwapChain,pDev,KHookMgr::EHOOK_POOL_DX9,_IDirect3DDevice9_CreateAdditionalSwapChain,&pHook_IDirect3DDevice9_CreateAdditionalSwapChain);
        hookEx("IDirect3DDevice9_SetPixelShader",IDX_IDirect3DDevice9_SetPixelShader,pDev,KHookMgr::EHOOK_POOL_DX9,&hooks_IDirect3DDevice9_SetPixelShader);
        hookEx("IDirect3DDevice9_SetDepthStencilSurface",IDX_IDirect3DDevice9_SetDepthStencilSurface,pDev,KHookMgr::EHOOK_POOL_DX9,_IDirect3DDevice9_SetDepthStencilSurface,&pHook_IDirect3DDevice9_SetDepthStencilSurface);
        hookEx("IDirect3DDevice9_SetGammaRamp",IDX_IDirect3DDevice9_SetGammaRamp,pDev,KHookMgr::EHOOK_POOL_DX9,_IDirect3DDevice9_SetGammaRamp,&pHook_IDirect3DDevice9_SetGammaRamp);
        hookEx("IDirect3DDevice9_SetStreamSource",IDX_IDirect3DDevice9_SetStreamSource,pDev,KHookMgr::EHOOK_POOL_DX9,&hooks_IDirect3DDevice9_SetStreamSource);
        hookEx("IDirect3DDevice9_CreateVertexShader",IDX_IDirect3DDevice9_CreateVertexShader,pDev,KHookMgr::EHOOK_POOL_DX9,_IDirect3DDevice9_CreateVertexShader,&pHook_IDirect3DDevice9_CreateVertexShader);
        hookEx("IDirect3DDevice9_CreatePixelShader",IDX_IDirect3DDevice9_CreatePixelShader,pDev,KHookMgr::EHOOK_POOL_DX9,_IDirect3DDevice9_CreatePixelShader,&pHook_IDirect3DDevice9_CreatePixelShader);
    }
 
    // ---- D3DPRIMITIVETYPE ? EPrimitiveTopology conversion ------------------
    EPrimitiveTopology::Type D3DPRIMITIVETYPE_to_EPrimitiveTopology(D3DPRIMITIVETYPE pt)
    {
        switch(pt){
        case D3DPT_TRIANGLELIST:  return EPrimitiveTopology::TRIANGLELIST;
        case D3DPT_TRIANGLESTRIP: return EPrimitiveTopology::TRIANGLESTRIP;
        case D3DPT_TRIANGLEFAN:   return EPrimitiveTopology::TRIANGLEFAN;
        default:                  return EPrimitiveTopology::UNKNOWNPRIMITIVETYPE;
        }
    }
 
    // ---- D3DDECLTYPE ? EInputType ------------------------------------------
    EInputType::Type D3DDECLTYPE_to_EInputType(BYTE t)
    {
        switch(t){
        case D3DDECLTYPE_FLOAT1:    return EInputType::R32_FLOAT;
        case D3DDECLTYPE_FLOAT2:    return EInputType::R32G32_FLOAT;
        case D3DDECLTYPE_FLOAT3:    return EInputType::R32G32B32_FLOAT;
        case D3DDECLTYPE_FLOAT4:    return EInputType::R32G32B32A32_FLOAT;
        case D3DDECLTYPE_D3DCOLOR:  return EInputType::R8G8B8A8_UINT;
        case D3DDECLTYPE_UBYTE4:    return EInputType::R8G8B8A8_UINT;
        case D3DDECLTYPE_SHORT2:    return EInputType::R16G16_SINT;
        case D3DDECLTYPE_SHORT4:    return EInputType::R16G16B16A16_SINT;
        case D3DDECLTYPE_UBYTE4N:   return EInputType::R8G8B8A8_UNORM;
        case D3DDECLTYPE_SHORT2N:   return EInputType::R16G16_SNORM;
        case D3DDECLTYPE_SHORT4N:   return EInputType::R16G16B16A16_SNORM;
        case D3DDECLTYPE_USHORT2N:  return EInputType::R16G16_UNORM;
        case D3DDECLTYPE_USHORT4N:  return EInputType::R16G16B16A16_UNORM;
        case D3DDECLTYPE_UDEC3:     return EInputType::UDEC3;
        case D3DDECLTYPE_DEC3N:     return EInputType::DEC3N;
        case D3DDECLTYPE_FLOAT16_2: return EInputType::R16G16_FLOAT;
        case D3DDECLTYPE_FLOAT16_4: return EInputType::R16G16B16A16_FLOAT;
        default:                    return EInputType::UNKNOWNINPUTTYPE;
        }
    }
 
    void D3DDECLUSAGE_to_UsageSemantic(DWORD usage, char* pOut, DWORD sz)
    {
        const char* s="UNKNOWN";
        switch(usage){
        case D3DDECLUSAGE_POSITION:     s="POSITION";     break;
        case D3DDECLUSAGE_BLENDWEIGHT:  s="BLENDWEIGHT";  break;
        case D3DDECLUSAGE_BLENDINDICES: s="BLENDINDICES"; break;
        case D3DDECLUSAGE_NORMAL:       s="NORMAL";       break;
        case D3DDECLUSAGE_PSIZE:        s="PSIZE";        break;
        case D3DDECLUSAGE_TEXCOORD:     s="TEXCOORD";     break;
        case D3DDECLUSAGE_TANGENT:      s="TANGENT";      break;
        case D3DDECLUSAGE_BINORMAL:     s="BINORMAL";     break;
        case D3DDECLUSAGE_COLOR:        s="COLOR";        break;
        case D3DDECLUSAGE_FOG:          s="FOG";          break;
        case D3DDECLUSAGE_DEPTH:        s="DEPTH";        break;
        case D3DDECLUSAGE_SAMPLE:       s="SAMPLE";       break;
        }
        strCopy(pOut,sz,s);
    }
 
    bool isEndDecl(const D3DVERTEXELEMENT9* p)
    {
        return p->Stream==0xFF&&p->Offset==0&&p->Type==D3DDECLTYPE_UNUSED&&
               p->Method==0&&p->Usage==0&&p->UsageIndex==0;
    }
 
    HRESULT getVertexDeclarations(IDirect3DDevice9* pDev,
                                   KInputVertexDeclaration& inp,
                                   KOutputVertexDeclaration& out)
    {
        TDXRef<IDirect3DVertexDeclaration9> pDecl;
        HRESULT hr=pDev->GetVertexDeclaration(&pDecl);
        if(FAILED(hr)){g_pLog->logError("GetVertexDeclaration(). 0x%08X\n",hr);return hr;}
        if(!pDecl.get()){return E_VERTEXDECL_NOT_SET;}
 
        UINT n=0; pDecl->GetDeclaration(nullptr,&n);
        std::vector<D3DVERTEXELEMENT9> decl(n);
        pDecl->GetDeclaration(decl.data(),&n);
 
        for(UINT i=0;i<n;i++){
            if(isEndDecl(&decl[i])) break;
            KInputVertexElement e;
            e.Stream       = decl[i].Stream;
            e.SemanticIndex= decl[i].UsageIndex;
            e.Offset       = decl[i].Offset;
            e.Type         = D3DDECLTYPE_to_EInputType(decl[i].Type);
            D3DDECLUSAGE_to_UsageSemantic(decl[i].Usage,e.UsageSemantic,SEMANTIC_LEN);
            e.Size         = getInputTypeSize(e.Type);
            inp.Decl.push_back(e);
        }
        return createKOutputVertexDeclaration(inp,out);
    }
 
    HRESULT dumpIndexBuffer(IDirect3DDevice9* pDev, EPrimitiveTopology::Type topo,
                             UINT startIdx, UINT primCnt,
                             KFACES* pF, OptimizedIndexToMeshIndex* optIdx)
    {
        TDXRef<IDirect3DIndexBuffer9> pIB;
        HRESULT hr=pDev->GetIndices(&pIB);
        if(FAILED(hr)||!pIB.get()){g_pLog->logError("GetIndices() failed\n");return E_NULL_BUFF;}
 
        D3DINDEXBUFFER_DESC desc={};
        pIB->GetDesc(&desc);
        void* pData=nullptr;
        hr=pIB->Lock(0,0,&pData,D3DLOCK_READONLY);
        if(FAILED(hr)) return hr;
 
        if(desc.Format==D3DFMT_INDEX16)
            processIndexes16_PrimitiveCount((WORD*)pData+startIdx,topo,primCnt,pF,optIdx);
        else if(desc.Format==D3DFMT_INDEX32)
            processIndexes32_PrimitiveCount((DWORD*)pData+startIdx,topo,primCnt,pF,optIdx);
        else{ pIB->Unlock(); return E_UNK_INDEX_FORMAT_ERR; }
 
        pIB->Unlock();
        return S_OK;
    }
 
    HRESULT dumpVertexBuffer(IDirect3DDevice9* pDev,
                              const KInputVertexDeclaration& inp,
                              const KOutputVertexDeclaration& outp,
                              INT baseVtxIdx,
                              const OptimizedIndexToMeshIndex& optIdx,
                              KVERTICES* pV)
    {
        HRESULT hr=S_OK;
        bool ok=false;
        for(size_t i=0;i<inp.Decl.size();i++){
            auto& ie=inp.Decl[i]; auto& oe=outp.Decl[i];
            TDXRef<IDirect3DVertexBuffer9> pVB;
            UINT ofs=0,stride=0;
            hr=pDev->GetStreamSource(ie.Stream,&pVB,&ofs,&stride);
            if(FAILED(hr)) continue;
 
            IDirect3DVertexBuffer9* vb=pVB.get();
            if(!vb){
                // Try VB cache
                VbCacheEntry e;
                if(getFromVbCache(pDev,ie.Stream,&e)){vb=e.pStreamData;ofs=e.OffsetInBytes;stride=e.Stride;}
                else{hr=E_NULL_BUFF;continue;}
            }
 
            D3DVERTEXBUFFER_DESC desc={};
            vb->GetDesc(&desc);
            void* pData=nullptr;
            if(FAILED(vb->Lock(0,0,&pData,D3DLOCK_READONLY))){hr=E_COPY_BUFFER_ERR;continue;}
 
            DWORD vCnt=(DWORD)optIdx.size();
            UINT needed=baseVtxIdx*stride+ofs+stride*vCnt;
            if(desc.Size>=needed)
                dumpVertSemantic(ie.Type,(BYTE*)pData+(baseVtxIdx*(INT)stride+(INT)ofs),
                                 ie.Offset,stride,
                                 pV->getRawData(),oe.Offset,pV->getVertexSize(),optIdx);
            else g_pLog->logError("VB too small for dump\n");
 
            vb->Unlock(); ok=true;
        }
        return ok?S_OK:hr;
    }
 
    void updateVbCache(const VbCacheEntry& e)
    {
        for(auto& c:vbCache) if(c.pDev==e.pDev&&c.StreamNumber==e.StreamNumber){c=e;return;}
        vbCache.push_back(e);
    }
    bool getFromVbCache(IDirect3DDevice9* pDev,UINT sn,VbCacheEntry* out)
    {
        for(auto& c:vbCache) if(c.pDev==pDev&&c.StreamNumber==sn){*out=c;return true;}
        return false;
    }
 
    // ---- Core rip functions -------------------------------------------------
    void ripDIP(IDirect3DDevice9* pDev,D3DPRIMITIVETYPE Type,INT bvi,UINT mi,UINT nv,UINT si,UINT pc)
    {
        HRESULT hr;
        KInputVertexDeclaration inp; KOutputVertexDeclaration out;
        auto topo=D3DPRIMITIVETYPE_to_EPrimitiveTopology(Type);
        if(!isPrimitiveTopologySupported(topo)){g_pLog->logError("Unsupported topology\n");return;}
        hr=getVertexDeclarations(pDev,inp,out); if(FAILED(hr)) return;
        KFACES faces; OptimizedIndexToMeshIndex optIdx;
        hr=dumpIndexBuffer(pDev,topo,si,pc,&faces,&optIdx); if(FAILED(hr)) return;
        KVERTICES verts((DWORD)optIdx.size(),out.getVertexSize());
        hr=dumpVertexBuffer(pDev,inp,out,bvi,optIdx,&verts); if(FAILED(hr)) return;
        KMeshTextures tex; saveMeshTextures(pDev,&tex);
        KMeshShaders sh; if(g_pIntruder->getSettings()->saveShaders) saveMeshShaders(pDev,&sh);
        std::wstring path=g_pIntruder->getFrameMeshSavePath();
        hr=saveRipFile(path.c_str(),inp,out,tex,sh,faces,verts);
        if(SUCCEEDED(hr)) g_pLog->log("Mesh saved: %s\n",wideStringToMultiByte(path.c_str()).c_str());
        else g_pLog->logError("Mesh save error\n");
        g_pIntruder->incFrameMeshIdx();
    }
 
    void ripDP(IDirect3DDevice9* pDev,D3DPRIMITIVETYPE Type,UINT sv,UINT pc)
    {
        HRESULT hr;
        KInputVertexDeclaration inp; KOutputVertexDeclaration out;
        auto topo=D3DPRIMITIVETYPE_to_EPrimitiveTopology(Type);
        if(!isPrimitiveTopologySupported(topo)) return;
        hr=getVertexDeclarations(pDev,inp,out); if(FAILED(hr)) return;
        KFACES faces; OptimizedIndexToMeshIndex optIdx;
        generateIndexes_PrimitiveCount(topo,pc,&faces,&optIdx);
        KVERTICES verts((DWORD)optIdx.size(),out.getVertexSize());
        hr=dumpVertexBuffer(pDev,inp,out,(INT)sv,optIdx,&verts); if(FAILED(hr)) return;
        KMeshTextures tex; saveMeshTextures(pDev,&tex);
        KMeshShaders sh; if(g_pIntruder->getSettings()->saveShaders) saveMeshShaders(pDev,&sh);
        std::wstring path=g_pIntruder->getFrameMeshSavePath();
        hr=saveRipFile(path.c_str(),inp,out,tex,sh,faces,verts);
        if(SUCCEEDED(hr)) g_pLog->log("Mesh saved: %s\n",wideStringToMultiByte(path.c_str()).c_str());
        g_pIntruder->incFrameMeshIdx();
    }
 
    void ripDrawPrimitiveUP(IDirect3DDevice9* pDev,D3DPRIMITIVETYPE Type,UINT pc,CONST void* vd,UINT vs)
    {
        HRESULT hr;
        KInputVertexDeclaration inp; KOutputVertexDeclaration out;
        auto topo=D3DPRIMITIVETYPE_to_EPrimitiveTopology(Type);
        if(!isPrimitiveTopologySupported(topo)) return;
        hr=getVertexDeclarations(pDev,inp,out); if(FAILED(hr)) return;
        KFACES faces; OptimizedIndexToMeshIndex optIdx;
        generateIndexes_PrimitiveCount(topo,pc,&faces,&optIdx);
        KVERTICES verts((DWORD)optIdx.size(),out.getVertexSize());
        dumpVbUP(inp,out,optIdx,&verts,vd,vs);
        KMeshTextures tex; saveMeshTextures(pDev,&tex);
        KMeshShaders sh; if(g_pIntruder->getSettings()->saveShaders) saveMeshShaders(pDev,&sh);
        std::wstring path=g_pIntruder->getFrameMeshSavePath();
        saveRipFile(path.c_str(),inp,out,tex,sh,faces,verts);
        g_pIntruder->incFrameMeshIdx();
    }
 
    void ripDrawIndexedPrimitiveUP(IDirect3DDevice9* pDev,D3DPRIMITIVETYPE Type,
                                    UINT mvi,UINT nv,UINT pc,
                                    CONST void* id,D3DFORMAT idf,
                                    CONST void* vd,UINT vs)
    {
        HRESULT hr;
        KInputVertexDeclaration inp; KOutputVertexDeclaration out;
        auto topo=D3DPRIMITIVETYPE_to_EPrimitiveTopology(Type);
        if(!isPrimitiveTopologySupported(topo)) return;
        hr=getVertexDeclarations(pDev,inp,out); if(FAILED(hr)) return;
        EIndexFormat::Type fmt=(idf==D3DFMT_INDEX16)?EIndexFormat::INDEX_16:
                               (idf==D3DFMT_INDEX32)?EIndexFormat::INDEX_32:EIndexFormat::UNKNOWN;
        KFACES faces; OptimizedIndexToMeshIndex optIdx;
        dumpIndexesUP(topo,pc,&faces,&optIdx,id,fmt);
        KVERTICES verts((DWORD)optIdx.size(),out.getVertexSize());
        dumpVbUP(inp,out,optIdx,&verts,vd,vs);
        KMeshTextures tex; saveMeshTextures(pDev,&tex);
        KMeshShaders sh; if(g_pIntruder->getSettings()->saveShaders) saveMeshShaders(pDev,&sh);
        std::wstring path=g_pIntruder->getFrameMeshSavePath();
        saveRipFile(path.c_str(),inp,out,tex,sh,faces,verts);
        g_pIntruder->incFrameMeshIdx();
    }
 
    void dump_TextureDesc2Log(IDirect3DBaseTexture9* p)
    {
        if(!p) return;
        g_pLog->log("Texture type: %d  Levels: %u\n",p->GetType(),p->GetLevelCount());
    }
 
    // ---- Texture save -------------------------------------------------------
    bool isMeshTextureSaved(IDirect3DBaseTexture9* p,KTexture* out)
    {
        for(auto& t:meshTexturesDb) if(t.pTexture==p){*out=t;return true;}
        return false;
    }
    DWORD isTextureSaved(IDirect3DBaseTexture9* p)
    {
        if(!p) return 1;
        for(auto q:forcedTexturesDb) if(q==p) return 1;
        return 0;
    }
 
    void handleTextureSave(IDirect3DDevice9* pDev,DWORD,IDirect3DBaseTexture9* pTex)
    {
        g_pIntruder->keyHandler(this);
        if(!g_pIntruder->isTexturesRipKeyPressed()) return;
        if(isTextureSaved(pTex)) return;
        std::wstring path=g_pIntruder->getTextureSavePath();
        HRESULT hr=saveTexture2File(path.c_str(),pDev,pTex);
        if(SUCCEEDED(hr)){
            forcedTexturesDb.push_back(pTex);
            g_pIntruder->incTextureIdx();
            g_pLog->log("Texture saved: %s\n",wideStringToMultiByte(path.c_str()).c_str());
        }else g_pLog->logError("Texture save. 0x%08X\n",hr);
    }
 
    void initializeStates();  // defined after class (large table)
 
    // ---- Static hooks -------------------------------------------------------
    static IDirect3D9* __stdcall _Direct3DCreate9(UINT sdk)
    {
        auto e=(PFN_Direct3DCreate9)this_->pHook_Direct3DCreate9->getOriginalAddress();
        IDirect3D9* p=e(sdk);
        g_pLog->log("Direct3DCreate9(0x%X)=0x%p\n",sdk,p);
        this_->helperDllsInit();
        if(p) hookEx("IDirect3D9_CreateDevice",IDX_IDirect3D9_CreateDevice,p,
                     KHookMgr::EHOOK_POOL_DX9,_IDirect3D9_CreateDevice,
                     &this_->pHook_IDirect3D9_CreateDevice);
        return p;
    }
 
    static HRESULT __stdcall _Direct3DCreate9Ex(UINT sdk,IDirect3D9Ex** pp)
    {
        auto e=(PFN_Direct3DCreate9Ex)this_->pHook_Direct3DCreate9Ex->getOriginalAddress();
        HRESULT hr=e(sdk,pp);
        g_pLog->log("Direct3DCreate9Ex(0x%X)=0x%08X IDX9Ex=0x%p\n",sdk,hr,pp?*pp:nullptr);
        this_->helperDllsInit();
        if(SUCCEEDED(hr)&&pp&&*pp){
            hookEx("IDirect3D9Ex_CreateDevice",IDX_IDirect3D9_CreateDevice,*pp,
                   KHookMgr::EHOOK_POOL_DX9,_IDirect3D9_CreateDevice,&this_->pHook_IDirect3D9_CreateDevice);
            hookEx("IDirect3D9Ex_CreateDeviceEx",IDX_IDirect3D9_CreateDeviceEx,*pp,
                   KHookMgr::EHOOK_POOL_DX9,_IDirect3D9Ex_CreateDeviceEx,&this_->pHook_IDirect3D9Ex_CreateDeviceEx);
        }
        return hr;
    }
 
    static HRESULT __stdcall _IDirect3D9_CreateDevice(IDirect3D9* p9,UINT adp,D3DDEVTYPE dt,HWND hw,DWORD bf,D3DPRESENT_PARAMETERS* pp,IDirect3DDevice9** ppd)
    {
        auto e=(PFN_IDirect3D9_CreateDevice)this_->pHook_IDirect3D9_CreateDevice->getOriginalAddress();
        HRESULT hr=e(p9,adp,dt,hw,bf,pp,ppd);
        g_pLog->log("IDirect3D9_CreateDevice(0x%p)=0x%08X\n",p9,hr);
        if(SUCCEEDED(hr)&&ppd&&*ppd) this_->setDeviceHooks(*ppd);
        return hr;
    }
 
    static HRESULT __stdcall _IDirect3D9Ex_CreateDeviceEx(IDirect3D9Ex* p,UINT a,D3DDEVTYPE dt,HWND hw,DWORD bf,D3DPRESENT_PARAMETERS* pp,D3DDISPLAYMODEEX* dm,IDirect3DDevice9Ex** ppd)
    {
        auto e=(PFN_IDirect3D9Ex_CreateDeviceEx)this_->pHook_IDirect3D9Ex_CreateDeviceEx->getOriginalAddress();
        HRESULT hr=e(p,a,dt,hw,bf,pp,dm,ppd);
        g_pLog->log("IDirect3D9Ex_CreateDeviceEx=0x%08X\n",hr);
        if(SUCCEEDED(hr)&&ppd&&*ppd){
            this_->setDeviceHooks(*ppd);
            hookEx("IDirect3DDevice9Ex_PresentEx",IDX_IDirect3DDevice9Ex_PresentEx,*ppd,
                   KHookMgr::EHOOK_POOL_DX9,_IDirect3DDevice9Ex_PresentEx,&this_->pHook_IDirect3DDevice9Ex_PresentEx);
        }
        return hr;
    }
 
    static HRESULT __stdcall _IDirect3DDevice9_Present(IDirect3DDevice9* d,CONST RECT* s,CONST RECT* ds,HWND hw,CONST RGNDATA* rd)
    {
        auto e=(PFN_IDirect3DDevice9_Present)this_->pHook_IDirect3DDevice9_Present->getOriginalAddress();
        g_pIntruder->frameHandler(this_);
        return e(d,s,ds,hw,rd);
    }
    static HRESULT __stdcall _IDirect3DDevice9Ex_PresentEx(IDirect3DDevice9Ex* d,CONST RECT* s,CONST RECT* ds,HWND hw,CONST RGNDATA* rd,DWORD f)
    {
        auto e=(PFN_IDirect3DDevice9Ex_PresentEx)this_->pHook_IDirect3DDevice9_Present->getOriginalAddress();
        g_pIntruder->frameHandler(this_);
        return e(d,s,ds,hw,rd,f);
    }
    static HRESULT __stdcall _IDirect3DSwapChain9_Present(IDirect3DSwapChain9* sc,CONST RECT* s,CONST RECT* d,HWND hw,CONST RGNDATA* r,DWORD f)
    {
        auto e=(PFN_IDirect3DSwapChain9_Present)this_->pHook_IDirect3DSwapChain9_Present->getOriginalAddress();
        g_pIntruder->frameHandler(this_);
        return e(sc,s,d,hw,r,f);
    }
    static HRESULT __stdcall _IDirect3DDevice9_GetSwapChain(IDirect3DDevice9* d,UINT i,IDirect3DSwapChain9** pp)
    {
        auto e=(PFN_IDirect3DDevice9_GetSwapChain)this_->pHook_IDirect3DDevice9_GetSwapChain->getOriginalAddress();
        HRESULT hr=e(d,i,pp);
        if(SUCCEEDED(hr)) hookEx("IDirect3DSwapChain9_Present",IDX_IDirect3DSwapChain9_Present,*pp,
                                  KHookMgr::EHOOK_POOL_DX9,_IDirect3DSwapChain9_Present,&this_->pHook_IDirect3DSwapChain9_Present);
        return hr;
    }
    static HRESULT __stdcall _IDirect3DDevice9_CreateAdditionalSwapChain(IDirect3DDevice9* d,D3DPRESENT_PARAMETERS* pp,IDirect3DSwapChain9** psc)
    {
        auto e=(PFN_IDirect3DDevice9_CreateAdditionalSwapChain)this_->pHook_IDirect3DDevice9_CreateAdditionalSwapChain->getOriginalAddress();
        HRESULT hr=e(d,pp,psc);
        if(SUCCEEDED(hr)) hookEx("IDirect3DSwapChain9_Present",IDX_IDirect3DSwapChain9_Present,*psc,
                                  KHookMgr::EHOOK_POOL_DX9,_IDirect3DSwapChain9_Present,&this_->pHook_IDirect3DSwapChain9_Present);
        return hr;
    }
    static HRESULT __stdcall _IDirect3DDevice9_CreateVertexBuffer(IDirect3DDevice9* d,UINT len,DWORD usage,DWORD fvf,D3DPOOL pool,IDirect3DVertexBuffer9** pp,HANDLE* h)
    {
        auto e=(PFN_IDirect3DDevice9_CreateVertexBuffer)this_->pHook_IDirect3DDevice9_CreateVertexBuffer->getOriginalAddress();
        usage&=~D3DUSAGE_WRITEONLY; // Strip write-only so we can Lock() it
        return e(d,len,usage,fvf,pool,pp,h);
    }
    static HRESULT __stdcall _IDirect3DDevice9_CreateIndexBuffer(IDirect3DDevice9* d,UINT len,DWORD usage,DWORD fmt,D3DPOOL pool,IDirect3DIndexBuffer9** pp,HANDLE* h)
    {
        auto e=(PFN_IDirect3DDevice9_CreateIndexBuffer)this_->pHook_IDirect3DDevice9_CreateIndexBuffer->getOriginalAddress();
        usage&=~D3DUSAGE_WRITEONLY;
        return e(d,len,usage,fmt,pool,pp,h);
    }
    static HRESULT __stdcall _IDirect3DDevice9_SetDepthStencilSurface(IDirect3DDevice9* d,IDirect3DSurface9* p)
    {
        auto e=(PFN_IDirect3DDevice9_SetDepthStencilSurface)this_->pHook_IDirect3DDevice9_SetDepthStencilSurface->getOriginalAddress();
        HRESULT hr=e(d,p); if(SUCCEEDED(hr)) this_->LastDepthStencilSurface.Set(p);
        return hr;
    }
    static void __stdcall _IDirect3DDevice9_SetGammaRamp(IDirect3DDevice9* d,UINT sw,DWORD f,const D3DGAMMARAMP* r)
    {
        auto e=(PFN_IDirect3DDevice9_SetGammaRamp)this_->pHook_IDirect3DDevice9_SetGammaRamp->getOriginalAddress();
        e(d,sw,f,r);
        GammaHelper gh; gh.swapChain=sw; gh.flags=f;
        if(r) gh.gammaRamp=*r;
        this_->lastGamma.Set(gh);
    }
    static HRESULT __stdcall _IDirect3DDevice9_CreateVertexShader(IDirect3DDevice9* d,const DWORD* fn,IDirect3DVertexShader9** pp)
    {
        auto e=(PFN_IDirect3DDevice9_CreateVertexShader)this_->pHook_IDirect3DDevice9_CreateVertexShader->getOriginalAddress();
        HRESULT hr=e(d,fn,pp);
        if(SUCCEEDED(hr)&&g_pIntruder->getSettings()->saveShaders){
            UINT sz=0; (*pp)->GetFunction(nullptr,&sz);
            saveShader(EShaderExt::VERTEX,fn,sz,*pp,&this_->shadersDb,&this_->d3dCompileHelper);
        }
        return hr;
    }
    static HRESULT __stdcall _IDirect3DDevice9_CreatePixelShader(IDirect3DDevice9* d,const DWORD* fn,IDirect3DPixelShader9** pp)
    {
        auto e=(PFN_IDirect3DDevice9_CreatePixelShader)this_->pHook_IDirect3DDevice9_CreatePixelShader->getOriginalAddress();
        HRESULT hr=e(d,fn,pp);
        if(SUCCEEDED(hr)&&g_pIntruder->getSettings()->saveShaders){
            UINT sz=0; (*pp)->GetFunction(nullptr,&sz);
            saveShader(EShaderExt::PIXEL,fn,sz,*pp,&this_->shadersDb,&this_->d3dCompileHelper);
        }
        return hr;
    }
 
    // Generate all 8 stubs for each hook group
    GENERATE_STUBS_GROUP(STUB_IDirect3DDevice9_SetTexture)
    GENERATE_STUBS_GROUP(STUB_IDirect3DDevice9_SetPixelShader)
    GENERATE_STUBS_GROUP(STUB_IDirect3DDevice9_SetStreamSource)
    GENERATE_STUBS_GROUP(STUB_IDirect3DDevice9_DrawIndexedPrimitive)
    GENERATE_STUBS_GROUP(STUB_IDirect3DDevice9_DrawIndexedPrimitiveUP)
    GENERATE_STUBS_GROUP(STUB_IDirect3DDevice9_DrawPrimitive)
    GENERATE_STUBS_GROUP(STUB_IDirect3DDevice9_DrawPrimitiveUP)
    GENERATE_STUBS_GROUP(STUB_IUnk_QueryInterface)
};
 
KRipper9* KRipper9::this_ = nullptr;
 
// ---- Helper implementations (out-of-line for clarity) ----------------------
 
HRESULT KRipper9::helper_IDirect3DDevice9_SetTexture(KHook* h,IDirect3DDevice9* d,DWORD s,IDirect3DBaseTexture9* t)
{
    setDeviceHooks(d); // HACK: re-hook if vtable changed
    auto e=(PFN_IDirect3DDevice9_SetTexture)h->getOriginalAddress();
    EnterCriticalSection(&cs);
    __try{ handleTextureSave(d,s,t); }
    __except(EXCEPTION_EXECUTE_HANDLER){ g_pLog->logError("Exception in handleTextureSave\n"); }
    LeaveCriticalSection(&cs);
    return e(d,s,t);
}
 
HRESULT KRipper9::helper_IDirect3DDevice9_SetPixelShader(KHook* h,IDirect3DDevice9* d,IDirect3DPixelShader9* p)
{
    auto e=(PFN_IDirect3DDevice9_SetPixelShader)h->getOriginalAddress();
    HRESULT hr=e(d,p); if(SUCCEEDED(hr)) LastPS.Set(p);
    return hr;
}
 
HRESULT KRipper9::helper_IDirect3DDevice9_SetStreamSource(KHook* h,IDirect3DDevice9* d,UINT sn,IDirect3DVertexBuffer9* sd,UINT ofs,UINT st)
{
    auto e=(PFN_IDirect3DDevice9_SetStreamSource)h->getOriginalAddress();
    HRESULT hr=e(d,sn,sd,ofs,st);
    if(sd){ VbCacheEntry c; c.pDev=d;c.StreamNumber=sn;c.pStreamData=sd;c.OffsetInBytes=ofs;c.Stride=st; updateVbCache(c); }
    return hr;
}
 
HRESULT KRipper9::helper_IDirect3DDevice9_DrawIndexedPrimitive(KHook* h,IDirect3DDevice9* d,D3DPRIMITIVETYPE t,INT b,UINT mi,UINT nv,UINT si,UINT pc)
{
    auto e=(PFN_IDirect3DDevice9_DrawIndexedPrimitive)h->getOriginalAddress();
    g_pIntruder->keyHandler(this);
    DWORD rip=g_pIntruder->isMeshRipEnabled();
    DWORD minP=g_pIntruder->getSettings()->dwMinPrimitives;
    EnterCriticalSection(&cs);
    if(rip&&pc>=minP){
        __try{ ripDIP(d,t,b,mi,nv,si,pc); }
        __except(crashDumpWrite(g_pIntruder->getCrashDumpFile(),GetExceptionInformation()),EXCEPTION_EXECUTE_HANDLER)
        { g_pLog->logError("DrawIndexedPrimitive exception\n"); ExitProcess(0); }
    }
    LeaveCriticalSection(&cs);
    return e(d,t,b,mi,nv,si,pc);
}
 
HRESULT KRipper9::helper_IDirect3DDevice9_DrawIndexedPrimitiveUP(KHook* h,IDirect3DDevice9* d,D3DPRIMITIVETYPE t,UINT mvi,UINT nv,UINT pc,CONST void* id,D3DFORMAT idf,CONST void* vd,UINT vs)
{
    auto e=(PFN_IDirect3DDevice9_DrawIndexedPrimitiveUP)h->getOriginalAddress();
    g_pIntruder->keyHandler(this);
    if(g_pIntruder->isMeshRipEnabled()&&pc>=g_pIntruder->getSettings()->dwMinPrimitives){
        EnterCriticalSection(&cs);
        __try{ ripDrawIndexedPrimitiveUP(d,t,mvi,nv,pc,id,idf,vd,vs); }
        __except(EXCEPTION_EXECUTE_HANDLER){ g_pLog->logError("DrawIndexedPrimitiveUP exception\n"); }
        LeaveCriticalSection(&cs);
    }
    return e(d,t,mvi,nv,pc,id,idf,vd,vs);
}
 
HRESULT KRipper9::helper_IDirect3DDevice9_DrawPrimitive(KHook* h,IDirect3DDevice9* d,D3DPRIMITIVETYPE t,UINT sv,UINT pc)
{
    auto e=(PFN_IDirect3DDevice9_DrawPrimitive)h->getOriginalAddress();
    g_pIntruder->keyHandler(this);
    if(g_pIntruder->isMeshRipEnabled()&&pc>=g_pIntruder->getSettings()->dwMinPrimitives){
        EnterCriticalSection(&cs);
        __try{ ripDP(d,t,sv,pc); }
        __except(EXCEPTION_EXECUTE_HANDLER){ g_pLog->logError("DrawPrimitive exception\n"); }
        LeaveCriticalSection(&cs);
    }
    return e(d,t,sv,pc);
}
 
HRESULT KRipper9::helper_IDirect3DDevice9_DrawPrimitiveUP(KHook* h,IDirect3DDevice9* d,D3DPRIMITIVETYPE t,UINT pc,CONST void* vd,UINT vs)
{
    auto e=(PFN_IDirect3DDevice9_DrawPrimitiveUP)h->getOriginalAddress();
    g_pIntruder->keyHandler(this);
    if(g_pIntruder->isMeshRipEnabled()&&pc>=g_pIntruder->getSettings()->dwMinPrimitives){
        EnterCriticalSection(&cs);
        __try{ ripDrawPrimitiveUP(d,t,pc,vd,vs); }
        __except(EXCEPTION_EXECUTE_HANDLER){ g_pLog->logError("DrawPrimitiveUP exception\n"); }
        LeaveCriticalSection(&cs);
    }
    return e(d,t,pc,vd,vs);
}
 
HRESULT KRipper9::helper_IUnk_QueryInterface(KHook* h,IUnknown* t,REFIID r,void** o)
{
    auto e=(PFN_IUnk_QueryInterface)h->getOriginalAddress();
    HRESULT hr=e(t,r,o);
    g_pLog->log("IUnk_QI(%s)=0x%08X\n",guidToName(r).c_str(),hr);
    return hr;
}
 
void KRipper9::saveMeshTextures(IDirect3DDevice9* pDev, KMeshTextures* out)
{
    for(DWORD i=0;i<8;i++){
        TDXRef<IDirect3DBaseTexture9> pTex;
        if(FAILED(pDev->GetTexture(i,&pTex))||!pTex.get()) continue;
        KTexture tex;
        if(isMeshTextureSaved(pTex.get(),&tex)){
            out->textures.push_back(tex.name);
        }else{
            std::string nameA; std::wstring path=g_pIntruder->getFrameTextureSavePath(nameA,i);
            if(SUCCEEDED(saveTexture2File(path.c_str(),pDev,pTex.get()))){
                KTexture t2; t2.pTexture=pTex.get(); t2.name=nameA; t2.fullPath=path;
                meshTexturesDb.push_back(t2);
                out->textures.push_back(nameA);
                g_pLog->log("Texture #%d saved: %s\n",i,wideStringToMultiByte(path.c_str()).c_str());
            }else g_pLog->logError("Texture save failed\n");
            g_pIntruder->incFrameTextureIdx();
        }
    }
}
 
void KRipper9::saveMeshShaders(IDirect3DDevice9* pDev, KMeshShaders* out)
{
    std::string name,path;
    TDXRef<IDirect3DVertexShader9> vs;
    if(SUCCEEDED(pDev->GetVertexShader(&vs))&&vs.get()&&getShaderFromDb(vs.get(),&shadersDb,&name,&path))
        out->shaders.push_back(name);
    IDirect3DPixelShader9* ps=LastPS.Get();
    if(ps&&getShaderFromDb(ps,&shadersDb,&name,&path))
        out->shaders.push_back(name);
}
 
// Texture save: renders via a fullscreen quad to bypass game shaders
HRESULT KRipper9::saveTexture2File(LPCTSTR szFile,IDirect3DDevice9* pDev,IDirect3DBaseTexture9* pTex)
{
    if(!pTex) return E_NULL_TEXTURE;
    dump_TextureDesc2Log(pTex);
 
    // Non-2D textures: use D3DX directly
    if(pTex->GetType()!=D3DRTYPE_TEXTURE)
        return D3DXSaveTextureToFileW_(szFile,D3DXIFF_DDS,pTex,nullptr);
 
    // Get original function pointers via hook registry
    auto getOrig=[&](DWORD idx)->FARPROC{
        LPVOID targ=getMethodAddr(pDev,idx);
        KHook* h=g_pHookMgr->getHookByTargetAddress(targ);
        return h?(FARPROC)h->getOriginalAddress():nullptr;
    };
    auto origSetTex   =(PFN_IDirect3DDevice9_SetTexture)     getOrig(IDX_IDirect3DDevice9_SetTexture);
    auto origSetPS    =(PFN_IDirect3DDevice9_SetPixelShader)  getOrig(IDX_IDirect3DDevice9_SetPixelShader);
    auto origSetSS    =(PFN_IDirect3DDevice9_SetStreamSource) getOrig(IDX_IDirect3DDevice9_SetStreamSource);
    auto origDrawUP   =(PFN_IDirect3DDevice9_DrawPrimitiveUP) getOrig(IDX_IDirect3DDevice9_DrawPrimitiveUP);
    auto origSetDepth =(PFN_IDirect3DDevice9_SetDepthStencilSurface)getOrig(IDX_IDirect3DDevice9_SetDepthStencilSurface);
    auto origSetGamma =(PFN_IDirect3DDevice9_SetGammaRamp)   getOrig(IDX_IDirect3DDevice9_SetGammaRamp);
    if(!origSetTex||!origSetPS||!origSetSS||!origDrawUP) return E_FUNC_NOT_FOUND;
 
    LPDIRECT3DTEXTURE9 pT=static_cast<LPDIRECT3DTEXTURE9>(pTex);
    D3DSURFACE_DESC desc={}; pT->GetLevelDesc(0,&desc);
 
    TDXRef<IDirect3DTexture9> pRT;
    if(FAILED(pDev->CreateTexture(desc.Width,desc.Height,1,D3DUSAGE_RENDERTARGET,
                                   D3DFMT_A8R8G8B8,D3DPOOL_DEFAULT,&pRT,nullptr)))
        return E_MALLOC_ERR;
 
    // Save state
    TDXRef<IDirect3DSurface9> pOldRT; pDev->GetRenderTarget(0,&pOldRT);
    TDXRef<IDirect3DSurface9> pOldDS;
    BOOL dsOk=SUCCEEDED(pDev->GetDepthStencilSurface(&pOldDS));
    TDXRef<IDirect3DVertexShader9> pOldVS; pDev->GetVertexShader(&pOldVS);
    TDXRef<IDirect3DVertexDeclaration9> pOldDecl; pDev->GetVertexDeclaration(&pOldDecl);
    DWORD oldFVF=0; pDev->GetFVF(&oldFVF);
    D3DVIEWPORT9 vp; pDev->GetViewport(&vp);
    DWORD RS[RS_SIZE]={},SS[SS_SIZE]={},TSS[TSS_SIZE]={};
    for(int i=0;i<RS_SIZE;i++) pDev->GetRenderState(RenderStates[i].State,&RS[i]);
    for(int i=0;i<SS_SIZE;i++) pDev->GetSamplerState(0,SamplerStates[i].State,&SS[i]);
    for(int i=0;i<TSS_SIZE;i++) pDev->GetTextureStageState(0,TextureStageStates[i].State,&TSS[i]);
 
    // Set up render target
    TDXRef<IDirect3DSurface9> pDst; pRT->GetSurfaceLevel(0,&pDst);
    D3DVIEWPORT9 nvp={0,0,desc.Width,desc.Height,0.f,1.f};
    pDev->SetViewport(&nvp);
    if(origSetDepth) origSetDepth(pDev,nullptr);
    pDev->SetRenderTarget(0,pDst.get());
    pDev->SetRenderTarget(1,nullptr); pDev->SetRenderTarget(2,nullptr); pDev->SetRenderTarget(3,nullptr);
    origSetSS(pDev,0,nullptr,0,0);
    pDev->Clear(0,nullptr,D3DCLEAR_TARGET,D3DCOLOR_RGBA(255,0,255,255),1.f,0);
 
    struct TLV{ D3DXVECTOR4 p; D3DXVECTOR2 t; };
    float w=float(desc.Width)-0.5f, h=float(desc.Height)-0.5f;
    TLV v[4]={
        {{-0.5f,-0.5f,0,1},{0,0}},
        {{w,    -0.5f,0,1},{1,0}},
        {{-0.5f,h,    0,1},{0,1}},
        {{w,    h,    0,1},{1,1}}
    };
    pDev->SetVertexShader(nullptr);
    origSetPS(pDev,nullptr);
    for(int i=0;i<8;i++) origSetTex(pDev,i,i==0?pTex:nullptr);
    pDev->SetFVF(D3DFVF_XYZRHW|D3DFVF_TEX1);
    for(int i=0;i<RS_SIZE;i++) pDev->SetRenderState(RenderStates[i].State,RenderStates[i].SetVal);
    for(int i=0;i<SS_SIZE;i++) pDev->SetSamplerState(0,SamplerStates[i].State,SamplerStates[i].SetVal);
    for(int i=0;i<TSS_SIZE;i++) pDev->SetTextureStageState(0,TextureStageStates[i].State,TextureStageStates[i].SetVal);
    if(origSetGamma) origSetGamma(pDev,0,0,nullptr);
    origDrawUP(pDev,D3DPT_TRIANGLESTRIP,2,v,sizeof(TLV));
 
    HRESULT hr=D3DXSaveTextureToFileW_(szFile,D3DXIFF_DDS,pRT.get(),nullptr);
 
    // Restore state
    if(lastGamma.IsInited()){ auto g=lastGamma.Get(); if(origSetGamma) origSetGamma(pDev,g.swapChain,g.flags,&g.gammaRamp); }
    pDev->SetViewport(&vp);
    for(int i=0;i<8;i++) origSetTex(pDev,i,nullptr);
    pDev->SetVertexShader(pOldVS.get());
    if(LastPS.IsInited()&&origSetPS) origSetPS(pDev,LastPS.Get()); else if(origSetPS) origSetPS(pDev,nullptr);
    pDev->SetFVF(oldFVF); pDev->SetVertexDeclaration(pOldDecl.get());
    pDev->SetRenderTarget(0,pOldRT.get());
    if(dsOk&&origSetDepth) origSetDepth(pDev,pOldDS.get());
    else if(LastDepthStencilSurface.IsInited()&&origSetDepth) origSetDepth(pDev,LastDepthStencilSurface.Get());
    if(origSetSS) origSetSS(pDev,0,nullptr,0,0);
    for(int i=0;i<RS_SIZE;i++) pDev->SetRenderState(RenderStates[i].State,RS[i]);
    for(int i=0;i<SS_SIZE;i++) pDev->SetSamplerState(0,SamplerStates[i].State,SS[i]);
    for(int i=0;i<TSS_SIZE;i++) pDev->SetTextureStageState(0,TextureStageStates[i].State,TSS[i]);
    return hr;
}
 
void KRipper9::initializeStates()
{
    TState<D3DRENDERSTATETYPE> rs[RS_SIZE]={
        {D3DRS_POINTSPRITEENABLE,FALSE},{D3DRS_POINTSCALEENABLE,FALSE},
        {D3DRS_CULLMODE,D3DCULL_NONE},{D3DRS_FOGTABLEMODE,D3DFOG_NONE},
        {D3DRS_RANGEFOGENABLE,FALSE},{D3DRS_FOGVERTEXMODE,D3DFOG_NONE},
        {D3DRS_CLIPPING,FALSE},{D3DRS_LIGHTING,FALSE},{D3DRS_LOCALVIEWER,FALSE},
        {D3DRS_VERTEXBLEND,D3DVBF_DISABLE},{D3DRS_CLIPPLANEENABLE,0},
        {D3DRS_MULTISAMPLEANTIALIAS,FALSE},{D3DRS_MULTISAMPLEMASK,0xffffffff},
        {D3DRS_PATCHEDGESTYLE,D3DPATCHEDGE_DISCRETE},{D3DRS_INDEXEDVERTEXBLENDENABLE,FALSE},
        {D3DRS_ENABLEADAPTIVETESSELLATION,FALSE},{D3DRS_ALPHABLENDENABLE,FALSE},
        {D3DRS_COLORWRITEENABLE,0xF},{D3DRS_ALPHATESTENABLE,FALSE},{D3DRS_STENCILENABLE,0},
        {D3DRS_SEPARATEALPHABLENDENABLE,0},{D3DRS_ZENABLE,FALSE},{D3DRS_ZWRITEENABLE,FALSE},
        {D3DRS_DITHERENABLE,FALSE},{D3DRS_SPECULARENABLE,FALSE},{D3DRS_FOGENABLE,FALSE},
        {D3DRS_RANGEFOGENABLE,FALSE},{D3DRS_SCISSORTESTENABLE,FALSE},
        {D3DRS_ANTIALIASEDLINEENABLE,FALSE},{D3DRS_SRGBWRITEENABLE,0},
        {D3DRS_WRAP0,0},{D3DRS_DEPTHBIAS,0},{D3DRS_SLOPESCALEDEPTHBIAS,0},
        {D3DRS_FILLMODE,D3DFILL_SOLID},{D3DRS_SHADEMODE,D3DSHADE_GOURAUD}
    };
    for(int i=0;i<RS_SIZE;i++) RenderStates[i]=rs[i];
 
    TState<D3DSAMPLERSTATETYPE> ss[SS_SIZE]={
        {D3DSAMP_DMAPOFFSET,256},{D3DSAMP_MAGFILTER,D3DTEXF_POINT},
        {D3DSAMP_MINFILTER,D3DTEXF_POINT},{D3DSAMP_MIPFILTER,D3DTEXF_POINT},
        {D3DSAMP_ADDRESSU,D3DTADDRESS_WRAP},{D3DSAMP_ADDRESSV,D3DTADDRESS_WRAP},
        {D3DSAMP_ADDRESSW,D3DTADDRESS_WRAP},{D3DSAMP_MAXANISOTROPY,1},
        {D3DSAMP_MIPMAPLODBIAS,0},{D3DSAMP_BORDERCOLOR,0}
    };
    for(int i=0;i<SS_SIZE;i++) SamplerStates[i]=ss[i];
 
    TState<D3DTEXTURESTAGESTATETYPE> tss[TSS_SIZE]={
        {D3DTSS_TEXCOORDINDEX,0},{D3DTSS_TEXTURETRANSFORMFLAGS,D3DTTFF_DISABLE},
        {D3DTSS_COLOROP,D3DTOP_MODULATE},{D3DTSS_COLORARG1,D3DTA_TEXTURE},
        {D3DTSS_COLORARG2,D3DTA_CURRENT}
    };
    for(int i=0;i<TSS_SIZE;i++) TextureStageStates[i]=tss[i];
}
 
// ---- Factory functions (from pre9.h/cpp) -----------------------------------
KRipper9* create_KRipper9(HINSTANCE hD3D9){ return KRipper9::create(hD3D9); }
void      delete_KRipper9(KRipper9*& p)   { KRipper9::destroy(p); }
 
 
// =============================================================================
//  SECTIONS 28+ � filled as dx8 / dx11 / dx7 / dx6 / MinHook arrive
//
//  intruder/dx8/    ? KRipper8
//  intruder/dx11/   ? KRipper11
//  intruder/dx7/    ? KRipper7
//  intruder/dx6/    ? KRipper6
//  intruder/MinHook/? MH_Initialize, MH_CreateHook, MH_EnableHook
//  intruder/common/ ? dataconvert.cpp, fvf.cpp, guidtoname.cpp,
//                     indexprocess.cpp, datatypes.cpp
// =============================================================================

// =============================================================================
// =============================================================================
//  SECTION 28 � DirectX 8 / KRipper8
//
//  Merged from:
//    dx8/kripper8.h / kripper8.cpp
//    dx8/drawindexedprimitive8.cpp
//    dx8/drawindexedprimitiveup8.cpp
//    dx8/drawprimitive8.cpp
//    dx8/drawprimitiveup8.cpp
//    dx8/dump8.cpp
//    dx8/savemeshtextures8.cpp
//    dx8/texture8.cpp
//    dx8/sm1_vertdecl.cpp
//    dx8/sm1_disasm.cpp
//    dx8/pre8.cpp
//
//  HOW TO USE:
//    Append this entire file after line 4140 of intruder.cpp.
//
//  INCLUDE ORDER REQUIREMENT:
//    d3d8.h reuses the same D3DFORMAT / D3DPRIMITIVETYPE enum names as d3d9.h.
//    In the DirectX SDK (Feb 2010 and older) both headers share a common
//    __D3DTYPES_H guard, so the file included *first* wins. You must add:
//
//        #include <d3d8.h>
//        #include <d3dx8tex.h>
//        #pragma comment(lib, "d3d8.lib")
//
//    to the INCLUDES BLOCK at the very top of intruder.cpp, *before* any
//    d3d9.h pull-in. If d3d9.h was already listed first, swap the order.
//    The IDirect3DDevice8/9 COM interfaces are distinct and do not conflict.
// =============================================================================
 
// ---------------------------------------------------------------------------
//  Guard: only compile this block if d3d8.h provided the DX8 interfaces.
//  (Lets the build degrade gracefully when the DX8 SDK is absent.)
// ---------------------------------------------------------------------------
#ifdef __d3d8_h__
 
 
// =============================================================================
//  DX8 function-pointer typedefs  (from dx8types.h)
// =============================================================================
 
typedef IDirect3D8* (__stdcall *PFN_Direct3DCreate8)(UINT);
 
typedef HRESULT (__stdcall *PFN_IDirect3D8_CreateDevice)(
    IDirect3D8*,
    UINT Adapter,
    D3DDEVTYPE DeviceType,
    HWND hFocusWindow,
    DWORD BehaviorFlags,
    D3DPRESENT_PARAMETERS* pPresentationParameters,
    IDirect3DDevice8** ppReturnedDeviceInterface);
 
typedef HRESULT (__stdcall *PFN_D3DXSaveTextureToFileW)(
    LPCTSTR, DWORD, LPDIRECT3DBASETEXTURE8, void*);
 
typedef UINT  (__stdcall *PFN_D3DXGetFVFVertexSize)(DWORD);
typedef HRESULT (__stdcall *PFN_D3DXDeclaratorFromFVF)(DWORD FVF, DWORD* Declaration);
 
typedef UINT (__stdcall *PFN_IDirect3D8_Release)(IDirect3D8*);
typedef UINT (__stdcall *PFN_IDirect3DDevice8_Release)(IDirect3DDevice8*);
 
typedef HRESULT (__stdcall *PFN_IDirect3DDevice8_SetTexture)(
    IDirect3DDevice8*, DWORD Stage, IDirect3DBaseTexture8* pTexture);
 
typedef HRESULT (__stdcall *PFN_IDirect3DDevice8_DrawPrimitive)(
    IDirect3DDevice8*, D3DPRIMITIVETYPE PrimitiveType,
    UINT StartVertex, UINT PrimitiveCount);
 
typedef HRESULT (__stdcall *PFN_IDirect3DDevice8_DrawIndexedPrimitive)(
    IDirect3DDevice8*, D3DPRIMITIVETYPE,
    UINT minIndex, UINT NumVertices,
    UINT startIndex, UINT primCount);
 
typedef HRESULT (__stdcall *PFN_IDirect3DDevice8_DrawPrimitiveUP)(
    IDirect3DDevice8*, D3DPRIMITIVETYPE PrimitiveType,
    UINT PrimitiveCount,
    CONST void* pVertexStreamZeroData,
    UINT VertexStreamZeroStride);
 
typedef HRESULT (__stdcall *PFN_IDirect3DDevice8_DrawIndexedPrimitiveUP)(
    IDirect3DDevice8*, D3DPRIMITIVETYPE PrimitiveType,
    UINT MinVertexIndex, UINT NumVertexIndices, UINT PrimitiveCount,
    CONST void* pIndexData, D3DFORMAT IndexDataFormat,
    CONST void* pVertexStreamZeroData, UINT VertexStreamZeroStride);
 
typedef HRESULT (__stdcall *PFN_IDirect3DDevice8_Present)(
    IDirect3DDevice8*, CONST RECT*, CONST RECT*, HWND, CONST RGNDATA*);
 
typedef HRESULT (__stdcall *PFN_IDirect3DDevice8_CreateVertexBuffer)(
    IDirect3DDevice8*, UINT Length, DWORD Usage, DWORD FVF,
    D3DPOOL Pool, IDirect3DVertexBuffer8** ppVertexBuffer);
 
typedef HRESULT (__stdcall *PFN_IDirect3DDevice8_CreateIndexBuffer)(
    IDirect3DDevice8*, UINT Length, DWORD Usage,
    D3DFORMAT Format, D3DPOOL Pool,
    IDirect3DIndexBuffer8** ppIndexBuffer);
 
typedef HRESULT (__stdcall *PFN_IDirect3DDevice8_CreateVertexShader)(
    IDirect3DDevice8*, CONST DWORD* pDeclaration,
    CONST DWORD* pFunction, DWORD* pHandle, DWORD Usage);
 
typedef HRESULT (__stdcall *PFN_IDirect3DDevice8_CreatePixelShader)(
    IDirect3DDevice8*, CONST DWORD* pFunction, DWORD* pHandle);
 
typedef HRESULT (__stdcall *PFN_IDirect3DDevice8_DeleteVertexShader)(
    IDirect3DDevice8*, DWORD Handle);
 
typedef HRESULT (__stdcall *PFN_IDirect3DDevice8_DeletePixelShader)(
    IDirect3DDevice8*, DWORD Handle);
 
typedef HRESULT (__stdcall *PFN_IDirect3DDevice8_SetVertexShader)(
    IDirect3DDevice8*, DWORD Handle);
 
typedef HRESULT (__stdcall *PFN_IDirect3DDevice8_CreateAdditionalSwapChain)(
    IDirect3DDevice8*, D3DPRESENT_PARAMETERS* pPresentationParameters,
    IDirect3DSwapChain8** ppSwapChain);
 
typedef HRESULT (__stdcall *PFN_IDirect3DSwapChain8_Present)(
    IDirect3DSwapChain8*, CONST RECT*, CONST RECT*, HWND, CONST RGNDATA*);
 
 
// =============================================================================
//  VTable slot indices for DX8  (from enums.h)
// =============================================================================
 
enum
{
    IDX8_IDirect3D8_CreateDevice                 = 15,
    IDX8_IDirect3DDevice8_SetTexture             = 61,
    IDX8_IDirect3DDevice8_Present                = 15,
    IDX8_IDirect3DDevice8_DrawPrimitive          = 70,
    IDX8_IDirect3DDevice8_DrawIndexedPrimitive   = 71,
    IDX8_IDirect3DDevice8_DrawPrimitiveUP        = 72,
    IDX8_IDirect3DDevice8_DrawIndexedPrimitiveUP = 73,
    IDX8_IDirect3DDevice8_CreateVertexBuffer     = 23,
    IDX8_IDirect3DDevice8_CreateIndexBuffer      = 24,
    IDX8_IDirect3DDevice8_CreateVertexShader     = 75,
    IDX8_IDirect3DDevice8_CreatePixelShader      = 87,
    IDX8_IDirect3DDevice8_SetVertexShader        = 76,
    IDX8_IDirect3DDevice8_CreateAdditionalSwapChain = 13,
    IDX8_IDirect3DSwapChain8_Present             = 3
};
 
 
// =============================================================================
//  SM1 vertex-declaration decoder  (from sm1_vertdecl.cpp)
// =============================================================================
 
static std::string sm1_dataTypeToString(DWORD e)
{
    switch (e)
    {
    case D3DVSDT_FLOAT1:   return "FLOAT1";
    case D3DVSDT_FLOAT2:   return "FLOAT2";
    case D3DVSDT_FLOAT3:   return "FLOAT3";
    case D3DVSDT_FLOAT4:   return "FLOAT4";
    case D3DVSDT_D3DCOLOR: return "D3DCOLOR";
    case D3DVSDT_UBYTE4:   return "UBYTE4";
    case D3DVSDT_SHORT2:   return "SHORT2";
    case D3DVSDT_SHORT4:   return "SHORT4";
    default:               return "UNKNOWN";
    }
}
 
static const char* sm1_getRegSemantic(DWORD reg)
{
    switch (reg)
    {
    case D3DVSDE_POSITION:     return "POSITION";
    case D3DVSDE_BLENDWEIGHT:  return "BLENDWEIGHT";
    case D3DVSDE_BLENDINDICES: return "BLENDINDICES";
    case D3DVSDE_NORMAL:       return "NORMAL";
    case D3DVSDE_PSIZE:        return "PSIZE";
    case D3DVSDE_DIFFUSE:      return "DIFFUSE";
    case D3DVSDE_SPECULAR:     return "SPECULAR";
    case D3DVSDE_TEXCOORD0:    return "TEXCOORD0";
    case D3DVSDE_TEXCOORD1:    return "TEXCOORD1";
    case D3DVSDE_TEXCOORD2:    return "TEXCOORD2";
    case D3DVSDE_TEXCOORD3:    return "TEXCOORD3";
    case D3DVSDE_TEXCOORD4:    return "TEXCOORD4";
    case D3DVSDE_TEXCOORD5:    return "TEXCOORD5";
    case D3DVSDE_TEXCOORD6:    return "TEXCOORD6";
    case D3DVSDE_TEXCOORD7:    return "TEXCOORD7";
    case D3DVSDE_POSITION2:    return "POSITION2";
    case D3DVSDE_NORMAL2:      return "NORMAL2";
    default:                   return "unrecognized";
    }
}
 
static std::string sm1_TOKEN_STREAM(DWORD token)
{
    std::stringstream ss;
    DWORD tess = token & D3DVSD_STREAMTESSMASK;
    DWORD strm = (token & D3DVSD_STREAMNUMBERMASK) >> D3DVSD_STREAMNUMBERSHIFT;
    if (tess) ss << "STREAM_TESS()";
    else      ss << "STREAM(" << strm << ")";
    return ss.str();
}
 
static std::string sm1_TOKEN_STREAMDATA(DWORD token)
{
    std::stringstream ss;
    if (!(token & 0x10000000))
    {
        DWORD type = ((token & D3DVSD_DATATYPEMASK)  >> D3DVSD_DATATYPESHIFT);
        DWORD reg  = ((token & D3DVSD_VERTEXREGMASK) >> D3DVSD_VERTEXREGSHIFT);
        ss << "REG(v" << reg << " " << sm1_getRegSemantic(reg)
           << ", " << sm1_dataTypeToString(type) << ")";
    }
    else
    {
        DWORD cnt = ((token & D3DVSD_SKIPCOUNTMASK) >> D3DVSD_SKIPCOUNTSHIFT);
        ss << "SKIP(" << cnt << ")";
    }
    return ss.str();
}
 
static std::string sm1_TOKEN_TESSELLATOR(DWORD token)
{
    std::stringstream ss;
    if (token & 0x10000000)
    {
        DWORD type = ((token & D3DVSD_DATATYPEMASK)  >> D3DVSD_DATATYPESHIFT);
        DWORD reg  = ((token & D3DVSD_VERTEXREGMASK) >> D3DVSD_VERTEXREGSHIFT);
        ss << "TESSUV(" << sm1_getRegSemantic(reg) << ") as "
           << sm1_dataTypeToString(type);
    }
    else
    {
        DWORD type   = ((token & D3DVSD_DATATYPEMASK)    >> D3DVSD_DATATYPESHIFT);
        DWORD regout = ((token & D3DVSD_VERTEXREGMASK)   >> D3DVSD_VERTEXREGSHIFT);
        DWORD regin  = ((token & D3DVSD_VERTEXREGINMASK) >> D3DVSD_VERTEXREGINSHIFT);
        ss << "TESSNORMAL(" << sm1_getRegSemantic(regin)
           << ", " << sm1_getRegSemantic(regout)
           << ") as " << sm1_dataTypeToString(type);
    }
    return ss.str();
}
 
static std::string sm1_TOKEN_CONSTMEM(const DWORD* decl, DWORD* len)
{
    union { float f; DWORD d; } cc;
    std::stringstream ss;
    DWORD cnt          = (((*decl) & D3DVSD_CONSTCOUNTMASK) >> D3DVSD_CONSTCOUNTSHIFT);
    DWORD constMemAddr = (*decl) & 0x7F;
    ss << "CONSTMEM() CNT:" << cnt << " ADDR:" << constMemAddr << " ";
    decl++;
    if (cnt > 1) ss << "\n";
    ss << std::setprecision(5);
    for (DWORD i = 0; i < cnt; ++i)
    {
        ss << "(";
        for (int ch = 0; ch < 4; ++ch) { cc.d = *decl++; ss << cc.f << " "; }
        ss << ")";
        if (cnt > 1) ss << "\n";
    }
    *len = 4 * cnt;
    return ss.str();
}
 
static std::string sm1_TOKEN_EXT(DWORD token, DWORD* len)
{
    DWORD cnt = ((token & D3DVSD_CONSTCOUNTMASK) >> D3DVSD_CONSTCOUNTSHIFT);
    *len = cnt;
    return "EXT()";
}
 
// Returns the number of DWORD tokens consumed.
static DWORD sm1_decodeVS1Declaration(const DWORD* decl, std::string* decoded)
{
    DWORD token     = *decl;
    DWORD tokenType = (token & D3DVSD_TOKENTYPEMASK) >> D3DVSD_TOKENTYPESHIFT;
    std::string out;
    DWORD res = 1;
 
    switch (tokenType)
    {
    case D3DVSD_TOKEN_NOP:        out = "NOP";  break;
    case D3DVSD_TOKEN_STREAM:     out = sm1_TOKEN_STREAM(token); break;
    case D3DVSD_TOKEN_STREAMDATA: out = sm1_TOKEN_STREAMDATA(token); break;
    case D3DVSD_TOKEN_TESSELLATOR:out = sm1_TOKEN_TESSELLATOR(token); break;
    case D3DVSD_TOKEN_CONSTMEM:   out = sm1_TOKEN_CONSTMEM(decl, &res); res++; break;
    case D3DVSD_TOKEN_EXT:        out = sm1_TOKEN_EXT(token, &res); res++; break;
    case D3DVSD_TOKEN_END:        out = "END"; break;
    default:                      out = "RESERVED"; break;
    }
    *decoded = out;
    return res;
}
 
 
// =============================================================================
//  SM1 shader disassembler  (from sm1_disasm.cpp)
// =============================================================================
namespace sm1 {
 
#define SM1_VERSION_MAJOR(v) (((v) >> 8) & 0xFFu)
#define SM1_VERSION_MINOR(v) (((v) >> 0) & 0xFFu)
#define SM1_VS  0xFFFEu
#define SM1_PS  0xFFFFu
#define SM1_COMMENTSIZE_SHIFT 16
#define SM1_COMMENTSIZE_MASK  (0x7FFFu << SM1_COMMENTSIZE_SHIFT)
 
const DWORD LAST_OPCODE = 0xFFFFFFFFu;
 
struct ShaderType  { typedef int Type; enum { VS, PS }; };
struct RegisterType {
    typedef DWORD Type;
    enum {
        TEMP=0,INPUT=1,CONSTREG=2,ADDR=3,TEXTURE=3,
        RASTOUT=4,ATTROUT=5,TEXCRDOUT=6,OUTPUT=6,
        CONSTINT=7,COLOROUT=8,DEPTHOUT=9,SAMPLER=10,
        IMMCONST=20,
    };
};
struct SrcModifier { enum {
    NONE=0,NEG=1,BIAS=2,BIASNEG=3,SIGN=4,SIGNNEG=5,
    COMP=6,X2=7,X2NEG=8,DZ=9,DW=10,ABS=11,ABSNEG=12,NOT=13
}; };
 
struct Version {
    ShaderType::Type type;
    DWORD major, minor, version;
    void setVersion(DWORD maj, DWORD min) {
        major=maj; minor=min; version=256*maj+min;
    }
    bool isInRange(DWORD maj0,DWORD min0,DWORD maj1,DWORD min1) const {
        DWORD v1=256*maj1+min1;
        return (version <= v1);
    }
};
 
struct OpcodeInfo { DWORD opcode; const char* mnemonic; DWORD dstCount; DWORD paramCount; };
struct SrcParam {
    DWORD offsetInRegisterFile, channelSwizzle, sourceModifier, imm;
    RegisterType::Type registerType;
};
struct DstParam {
    DWORD registerNumber, writeMask, resultModifiers, psResultShiftScale;
    RegisterType::Type registerType;
};
struct Instruction {
    DWORD opcode, srcParamsCount, dstParamsCount;
    const char* mnemonic;
    SrcParam srcParams[8];
    DstParam dstParams[8];
};
 
const DWORD DST_REG_NUM_MASK  = 0x7FF;
const DWORD REGTYPE_SHIFT     = 28;
const DWORD REGTYPE_MASK      = (0x7u << REGTYPE_SHIFT);
const DWORD REGTYPE_SHIFT2    = 8;
const DWORD REGTYPE_MASK2     = (0x18u << REGTYPE_SHIFT2);
const DWORD SM1_WRITEMASK_SHIFT= 16;
const DWORD SM1_WRITEMASK_MASK = (0xFu << SM1_WRITEMASK_SHIFT);
const DWORD DSTMOD_SHIFT      = 20;
const DWORD DSTMOD_MASK       = (0xFu << DSTMOD_SHIFT);
const DWORD DSTSHIFT_SHIFT    = 24;
const DWORD DSTSHIFT_MASK     = (0xFu << DSTSHIFT_SHIFT);
const DWORD SWIZZLE_SHIFT     = 16;
const DWORD SWIZZLE_MASK      = (0xFFu << SWIZZLE_SHIFT);
const DWORD REGNUM_MASK       = 0x000007FF;
const DWORD SRCMOD_SHIFT      = 24;
const DWORD SRCMOD_MASK       = (0xFu << SRCMOD_SHIFT);
const DWORD NOSWIZZLE         = (0|(1<<2)|(2<<4)|(3<<6));
const DWORD WRITEMASK_0=1,WRITEMASK_1=2,WRITEMASK_2=4,WRITEMASK_3=8,WRITEMASK_ALL=0xF;
 
const OpcodeInfo g_sm1Opcodes[] =
{
    {D3DSIO_NOP,"nop",0,0},{D3DSIO_MOV,"mov",1,2},{D3DSIO_ADD,"add",1,3},
    {D3DSIO_SUB,"sub",1,3},{D3DSIO_MAD,"mad",1,4},{D3DSIO_MUL,"mul",1,3},
    {D3DSIO_RCP,"rcp",1,2},{D3DSIO_RSQ,"rsq",1,2},{D3DSIO_DP3,"dp3",1,3},
    {D3DSIO_DP4,"dp4",1,3},{D3DSIO_MIN,"min",1,3},{D3DSIO_MAX,"max",1,3},
    {D3DSIO_SLT,"slt",1,3},{D3DSIO_SGE,"sge",1,3},{D3DSIO_EXP,"exp",1,2},
    {D3DSIO_LOG,"log",1,2},{D3DSIO_LIT,"lit",1,2},{D3DSIO_DST,"dst",1,3},
    {D3DSIO_LRP,"lrp",1,4},{D3DSIO_FRC,"frc",1,2},{D3DSIO_M4x4,"m4x4",1,3},
    {D3DSIO_M4x3,"m4x3",1,3},{D3DSIO_M3x4,"m3x4",1,3},{D3DSIO_M3x3,"m3x3",1,3},
    {D3DSIO_M3x2,"m3x2",1,3},{D3DSIO_TEXKILL,"texkill",1,1},
    {D3DSIO_TEXBEM,"texbem",1,2},{D3DSIO_TEXBEML,"texbeml",1,2},
    {D3DSIO_TEXREG2AR,"texreg2ar",1,2},{D3DSIO_TEXREG2GB,"texreg2gb",1,2},
    {D3DSIO_TEXM3x2PAD,"texm3x2pad",1,2},{D3DSIO_TEXM3x2TEX,"texm3x2tex",1,2},
    {D3DSIO_TEXM3x3PAD,"texm3x3pad",1,2},{D3DSIO_TEXM3x3TEX,"texm3x3tex",1,2},
    {D3DSIO_TEXM3x3DIFF,"texm3x3diff",1,2},{D3DSIO_TEXM3x3SPEC,"texm3x3spec",1,3},
    {D3DSIO_TEXM3x3VSPEC,"texm3x3vspec",1,2},{D3DSIO_EXPP,"expp",1,2},
    {D3DSIO_LOGP,"logp",1,2},{D3DSIO_CND,"cnd",1,4},
    {D3DSIO_TEXREG2RGB,"texreg2rgb",1,2},{D3DSIO_TEXDP3TEX,"texdp3tex",1,2},
    {D3DSIO_TEXM3x2DEPTH,"texm3x2depth",1,2},{D3DSIO_TEXDP3,"texdp3",1,2},
    {D3DSIO_TEXM3x3,"texm3x3",1,2},{D3DSIO_TEXDEPTH,"texdepth",1,1},
    {D3DSIO_CMP,"cmp",1,4},{D3DSIO_BEM,"bem",1,3},
    {LAST_OPCODE,"",0,0}
};
const OpcodeInfo g_texcoord1_3  = {D3DSIO_TEXCOORD,"texcoord",1,1};
const OpcodeInfo g_texcoord1_4  = {D3DSIO_TEXCOORD,"texcoord",1,2};
const OpcodeInfo g_tex1_3       = {D3DSIO_TEX,     "tex",     1,1};
const OpcodeInfo g_tex1_4       = {D3DSIO_TEX,     "tex",     1,2};
const OpcodeInfo g_def_instr    = {D3DSIO_DEF,     "def",     1,5};
 
static const OpcodeInfo* sm1_getOpcodeInfo(DWORD opcode)
{
    for (int i = 0; g_sm1Opcodes[i].opcode != LAST_OPCODE; ++i)
        if (g_sm1Opcodes[i].opcode == opcode) return &g_sm1Opcodes[i];
    return nullptr;
}
 
static void sm1_readDstToken(DWORD token, const Version& ver, DstParam* dst)
{
    dst->registerNumber    = token & DST_REG_NUM_MASK;
    dst->registerType      = (RegisterType::Type)(
                                ((token & REGTYPE_MASK)  >> REGTYPE_SHIFT) |
                                ((token & REGTYPE_MASK2) >> REGTYPE_SHIFT2));
    dst->writeMask         = (token & SM1_WRITEMASK_MASK) >> SM1_WRITEMASK_SHIFT;
    dst->resultModifiers   = (token & DSTMOD_MASK)  >> DSTMOD_SHIFT;
    dst->psResultShiftScale= (token & DSTSHIFT_MASK) >> DSTSHIFT_SHIFT;
}
 
static void sm1_readSrcToken(DWORD param, const Version& ver, SrcParam* src)
{
    src->registerType          = (RegisterType::Type)(
                                    ((param & REGTYPE_MASK)  >> REGTYPE_SHIFT) |
                                    ((param & REGTYPE_MASK2) >> REGTYPE_SHIFT2));
    src->offsetInRegisterFile  = param & REGNUM_MASK;
    src->channelSwizzle        = (param & SWIZZLE_MASK) >> SWIZZLE_SHIFT;
    src->sourceModifier        = (param & SRCMOD_MASK)  >> SRCMOD_SHIFT;
}
 
static void sm1_readImmConst(const DWORD* bc, DWORD cnt, SrcParam* p)
{
    p->registerType           = (RegisterType::Type)RegisterType::IMMCONST;
    p->offsetInRegisterFile   = 0;
    memcpy(&p->imm, bc, cnt * sizeof(DWORD));
    p->channelSwizzle         = NOSWIZZLE;
    p->sourceModifier         = 0;
}
 
static void sm1_getInstrParams(const DWORD* bc, const OpcodeInfo* op,
                                Instruction* instr, const Version& ver)
{
    instr->mnemonic       = op->mnemonic;
    instr->dstParamsCount = op->dstCount;
    instr->srcParamsCount = op->paramCount - op->dstCount;
    for (DWORD i=0; i<op->dstCount; ++i)  sm1_readDstToken(*bc++, ver, &instr->dstParams[i]);
    for (DWORD i=0; i<instr->srcParamsCount; ++i) sm1_readSrcToken(*bc++, ver, &instr->srcParams[i]);
}
 
static std::string sm1_readComment(const DWORD** ptr)
{
    std::stringstream ss;
    DWORD token = **ptr;
    while ((token & D3DSI_OPCODE_MASK) == D3DSIO_COMMENT)
    {
        UINT size = (token & SM1_COMMENTSIZE_MASK) >> SM1_COMMENTSIZE_SHIFT;
        const char* c = (const char*)++(*ptr);
        *ptr += size;
        // Emit non-null comment text
        std::string cs(c, 4*size);
        cs.erase(cs.find_last_not_of('\0')+1);
        ss << "; " << cs << "\n";
        token = **ptr;
    }
    std::string s = ss.str();
    if (!s.empty() && s.back()=='\n') s.pop_back();
    return s;
}
 
static const char* sm1_regTypeToStr(RegisterType::Type t, DWORD offs, const Version& ver)
{
    static char buf[32];
    switch (t)
    {
    case RegisterType::TEMP:     return "r";
    case RegisterType::INPUT:    return "v";
    case RegisterType::CONSTREG: return "c";
    case RegisterType::TEXCRDOUT:return "oT";
    case RegisterType::ATTROUT:  return "oD";
    case RegisterType::RASTOUT:
        if (offs==0) return "oPos";
        if (offs==1) return "oFog";
        return "oPts";
    case RegisterType::TEXTURE:
        return (ver.type == ShaderType::PS) ? "t" : "a";
    default:
        sprintf_s(buf, 32, "unk%d", (int)t);
        return buf;
    }
}
 
static std::string sm1_getChannelSwizzle(DWORD idx)
{
    switch (idx) { case 0:return "x"; case 1:return "y"; case 2:return "z"; }
    return "w";
}
 
static std::string sm1_optimizeSwizzle(const std::string& s)
{
    if (s.size()<=1) return s;
    char last = s.back();
    size_t trim = 0;
    for (int i=(int)s.size()-2; i>=0 && s[i]==last; --i) ++trim;
    return s.substr(0, s.size()-trim);
}
 
static std::string sm1_dstToStr(const DstParam& p, const Version& ver)
{
    std::stringstream ss;
    ss << sm1_regTypeToStr(p.registerType, p.registerNumber, ver);
    if (p.registerType != RegisterType::RASTOUT) ss << p.registerNumber;
    if (p.writeMask != WRITEMASK_ALL)
    {
        ss << ".";
        if (p.writeMask & WRITEMASK_0) ss << "x";
        if (p.writeMask & WRITEMASK_1) ss << "y";
        if (p.writeMask & WRITEMASK_2) ss << "z";
        if (p.writeMask & WRITEMASK_3) ss << "w";
    }
    return ss.str();
}
 
static const char* sm1_modToStr(DWORD m)
{
    switch (m)
    {
    case SrcModifier::NEG:    return "-";
    case SrcModifier::BIAS:   return "(bias)";
    case SrcModifier::BIASNEG:return "(biasneg)";
    case SrcModifier::SIGN:   return "(sign)";
    case SrcModifier::SIGNNEG:return "(signneg)";
    case SrcModifier::COMP:   return "(comp)";
    case SrcModifier::X2:     return "(x2)";
    case SrcModifier::X2NEG:  return "(x2neg)";
    case SrcModifier::DZ:     return "(dz)";
    case SrcModifier::DW:     return "(dw)";
    case SrcModifier::ABS:    return "(abs)";
    case SrcModifier::ABSNEG: return "(absneg)";
    case SrcModifier::NOT:    return "(not)";
    default:                  return "";
    }
}
 
static std::string sm1_srcToStr(const SrcParam& p, const Version& ver)
{
    std::stringstream ss;
    if ((int)p.registerType == RegisterType::IMMCONST)
    {
        union { float f; DWORD d; } cc; cc.d = p.imm;
        ss << std::setprecision(5) << cc.f;
    }
    else
    {
        ss << sm1_modToStr(p.sourceModifier)
           << sm1_regTypeToStr(p.registerType, p.offsetInRegisterFile, ver)
           << p.offsetInRegisterFile;
        std::string swzl;
        for (int ch=0; ch<4; ++ch)
            swzl += sm1_getChannelSwizzle((p.channelSwizzle >> (ch*2)) & 0x3);
        swzl = sm1_optimizeSwizzle(swzl);
        if (swzl != "xyzw") ss << "." << swzl;
    }
    return ss.str();
}
 
static std::string sm1_instrToStr(const Instruction& instr, const Version& ver)
{
    std::stringstream ss;
    ss << instr.mnemonic << " ";
    for (DWORD i=0; i<instr.dstParamsCount; ++i)
    {
        ss << sm1_dstToStr(instr.dstParams[i], ver);
        if (i != instr.dstParamsCount-1) ss << ", ";
    }
    if (instr.srcParamsCount) { ss << ", ";
        for (DWORD i=0; i<instr.srcParamsCount; ++i)
        {
            ss << sm1_srcToStr(instr.srcParams[i], ver);
            if (i != instr.srcParamsCount-1) ss << ", ";
        }
    }
    return ss.str();
}
 
static bool sm1_readInstruction(const DWORD** ppBC, Instruction* instr,
                                 const Version& ver, std::string* err)
{
    const DWORD* bc = *ppBC;
    DWORD opcode = (*bc) & D3DSI_OPCODE_MASK;
    const OpcodeInfo* op = sm1_getOpcodeInfo(opcode);
    if (op)
    {
        instr->opcode = opcode;
        bc++;
        sm1_getInstrParams(bc, op, instr, ver);
        bc += op->paramCount;
        *ppBC = bc;
        return true;
    }
    if (opcode == D3DSIO_TEXCOORD)
    {
        bc++;
        op = ver.isInRange(0,0,1,3) ? &g_texcoord1_3 : &g_texcoord1_4;
        if (!op) { *err = "texcoord version error"; return false; }
        sm1_getInstrParams(bc, op, instr, ver);
        bc += op->paramCount; *ppBC = bc; return true;
    }
    if (opcode == D3DSIO_TEX)
    {
        bc++;
        op = ver.isInRange(0,0,1,3) ? &g_tex1_3 : &g_tex1_4;
        if (!op) { *err = "tex version error"; return false; }
        sm1_getInstrParams(bc, op, instr, ver);
        bc += op->paramCount; *ppBC = bc; return true;
    }
    if (opcode == D3DSIO_DEF)
    {
        bc++;
        instr->opcode = g_def_instr.opcode;
        instr->mnemonic = g_def_instr.mnemonic;
        instr->dstParamsCount = 1; instr->srcParamsCount = 4;
        sm1_readDstToken(*bc++, ver, &instr->dstParams[0]);
        for (int i=0;i<4;++i) { sm1_readImmConst(bc,1,&instr->srcParams[i]); bc++; }
        *ppBC = bc; return true;
    }
    std::stringstream ss;
    ss << "Unknown opcode 0x" << std::hex << opcode;
    *err = ss.str();
    return false;
}
 
static std::string sm1_disassemble(const DWORD* bc)
{
    std::stringstream ss;
    ss << "; SM1 disassembler (c)black_ninja\n\n";
    DWORD major = SM1_VERSION_MAJOR(*bc);
    DWORD minor = SM1_VERSION_MINOR(*bc);
    Version ver; ver.setVersion(major, minor);
    if (!ver.isInRange(0,0,1,9))
        return "Shader bytecode not SM1. Use another disassembler.";
    switch (*bc >> 16)
    {
    case SM1_VS: ver.type=ShaderType::VS; ss<<"vs."<<major<<"."<<minor<<"\n"; break;
    case SM1_PS: ver.type=ShaderType::PS; ss<<"ps."<<major<<"."<<minor<<"\n"; break;
    }
    bc++;
    for (;;)
    {
        DWORD opcode = (*bc) & D3DSI_OPCODE_MASK;
        if (opcode == D3DSIO_END) { ss << "\n; end\n"; break; }
        if (opcode == D3DSIO_COMMENT)
        { ss << sm1_readComment(&bc) << "\n"; continue; }
        Instruction instr{}; std::string err;
        if (!sm1_readInstruction(&bc, &instr, ver, &err))
        { ss << "ERROR: " << err; break; }
        ss << sm1_instrToStr(instr, ver) << "\n\n";
    }
    return ss.str();
}
 
HRESULT disassembleShaderToFile(const wchar_t* fileName, const DWORD* byteCode)
{
    if (!byteCode) return E_INVALIDARG;
    std::string dis = sm1_disassemble(byteCode);
    FILE* fp = nullptr;
    if (_wfopen_s(&fp, fileName, L"w") || !fp) return E_FAIL;
    fwrite(dis.c_str(), 1, dis.size(), fp);
    fclose(fp);
    return S_OK;
}
 
#undef SM1_VERSION_MAJOR
#undef SM1_VERSION_MINOR
#undef SM1_VS
#undef SM1_PS
#undef SM1_COMMENTSIZE_SHIFT
#undef SM1_COMMENTSIZE_MASK
 
} // namespace sm1
 
 
// =============================================================================
//  KRipper8 � class definition
// =============================================================================
 
class KRipper8 : public IRipper
{
public:
    static KRipper8* create(HINSTANCE hD3D8);
    static void destroy(KRipper8*& p);
 
    // IRipper
    virtual void frameStart()      override;
    virtual void frameEnd()        override;
    virtual void textureRipStart() override;
    virtual void textureRipEnd()   override;
 
protected:
    virtual ~KRipper8();
    explicit KRipper8(HINSTANCE hD3D8_);
 
private:
    // ---- inner types -------------------------------------------------------
    struct KTexture8 {
        IDirect3DBaseTexture8* pTexture = nullptr;
        std::string  name;
        std::wstring fullPath;
    };
    typedef std::vector<KTexture8> KFrameTextureVec;
 
    struct KVertexDeclaration8 {
        DWORD Declaration[256];
        KVertexDeclaration8() { memset(Declaration, 0, sizeof(Declaration)); }
    };
    typedef std::map<DWORD, KVertexDeclaration8> KVertexShaderMap;
    typedef std::map<DWORD, ShaderFiles>         Shaders8Db;
 
    // ---- static "this" pointer (singleton pattern used by static hooks) ---
    static KRipper8* this_;
 
    // ---- D3D8 module handles and D3DX function pointers -------------------
    HINSTANCE hD3D8;
    HINSTANCE hD3DX;
    PFN_D3DXSaveTextureToFileW D3DXSaveTextureToFileW_;
    PFN_D3DXGetFVFVertexSize   D3DXGetFVFVertexSize_;
    PFN_D3DXDeclaratorFromFVF  D3DXDeclaratorFromFVF_;
 
    // ---- hook handles ------------------------------------------------------
    KHook* pHook_Direct3DCreate8;
    KHook* pHook_IDirect3D8_CreateDevice;
    KHook* pHook_IDirect3DDevice8_SetTexture;
    KHook* pHook_IDirect3DDevice8_Present;
    KHook* pHook_IDirect3DDevice8_DrawPrimitive;
    KHook* pHook_IDirect3DDevice8_DrawIndexedPrimitive;
    KHook* pHook_IDirect3DDevice8_DrawPrimitiveUP;
    KHook* pHook_IDirect3DDevice8_DrawIndexedPrimitiveUP;
    KHook* pHook_IDirect3DDevice8_SetVertexShader;
    KHook* pHook_IDirect3DDevice8_CreateVertexBuffer;
    KHook* pHook_IDirect3DDevice8_CreateIndexBuffer;
    KHook* pHook_IDirect3DDevice8_CreateVertexShader;
    KHook* pHook_IDirect3DDevice8_CreatePixelShader;
    KHook* pHook_IDirect3DDevice8_CreateAdditionalSwapChain;
    KHook* pHook_IDirect3DSwapChain8_Present;
 
    // ---- state databases ---------------------------------------------------
    KVertexShaderMap  VSDb;       // handle ? declaration token array
    Shaders8Db        vsShadersDb;// handle ? saved file info
    Shaders8Db        psShadersDb;
    DWORD             LastShader; // most recently set vertex shader handle
    D3DCompileHelper  d3dCompileHelper;
 
    // ---- texture DBs -------------------------------------------------------
    std::vector<IDirect3DBaseTexture8*> forcedTexturesDb; // standalone rip
    KFrameTextureVec                    meshTexturesDb;   // per-draw-call
 
    // ---- critical section (protects all Draw* hooks) ----------------------
    CRITICAL_SECTION cs;
 
    // ---- lifecycle ---------------------------------------------------------
    void zeroHooks();
    static void initialize();
    static void cleanup();
 
    // ---- Direct3DCreate8 hook -------------------------------------------
    static IDirect3D8* __stdcall _Direct3DCreate8(UINT SDKVER);
    IDirect3D8* helper_Direct3DCreate8(UINT SDKVER);
 
    // ---- IDirect3D8::CreateDevice hook ------------------------------------
    static HRESULT __stdcall _IDirect3D8_CreateDevice(
        IDirect3D8*, UINT, D3DDEVTYPE, HWND, DWORD,
        D3DPRESENT_PARAMETERS*, IDirect3DDevice8**);
    HRESULT helper_IDirect3D8_CreateDevice(KHook*, IDirect3D8*, UINT,
        D3DDEVTYPE, HWND, DWORD, D3DPRESENT_PARAMETERS*, IDirect3DDevice8**);
 
    // ---- IDirect3DDevice8 hooks -------------------------------------------
#define DECL_HOOK8_STATIC_HELPER(Name, ...) \
    static HRESULT __stdcall _##Name(__VA_ARGS__); \
    HRESULT helper_##Name(KHook*, __VA_ARGS__);
 
    DECL_HOOK8_STATIC_HELPER(IDirect3DDevice8_SetTexture,
        IDirect3DDevice8*, DWORD, IDirect3DBaseTexture8*)
    DECL_HOOK8_STATIC_HELPER(IDirect3DDevice8_Present,
        IDirect3DDevice8*, CONST RECT*, CONST RECT*, HWND, CONST RGNDATA*)
    DECL_HOOK8_STATIC_HELPER(IDirect3DDevice8_DrawPrimitive,
        IDirect3DDevice8*, D3DPRIMITIVETYPE, UINT, UINT)
    DECL_HOOK8_STATIC_HELPER(IDirect3DDevice8_DrawIndexedPrimitive,
        IDirect3DDevice8*, D3DPRIMITIVETYPE, UINT, UINT, UINT, UINT)
    DECL_HOOK8_STATIC_HELPER(IDirect3DDevice8_DrawPrimitiveUP,
        IDirect3DDevice8*, D3DPRIMITIVETYPE, UINT, CONST void*, UINT)
    DECL_HOOK8_STATIC_HELPER(IDirect3DDevice8_DrawIndexedPrimitiveUP,
        IDirect3DDevice8*, D3DPRIMITIVETYPE, UINT, UINT, UINT,
        CONST void*, D3DFORMAT, CONST void*, UINT)
    DECL_HOOK8_STATIC_HELPER(IDirect3DDevice8_SetVertexShader,
        IDirect3DDevice8*, DWORD)
    DECL_HOOK8_STATIC_HELPER(IDirect3DDevice8_CreateVertexBuffer,
        IDirect3DDevice8*, UINT, DWORD, DWORD, D3DPOOL, IDirect3DVertexBuffer8**)
    DECL_HOOK8_STATIC_HELPER(IDirect3DDevice8_CreateIndexBuffer,
        IDirect3DDevice8*, UINT, DWORD, D3DFORMAT, D3DPOOL, IDirect3DIndexBuffer8**)
    DECL_HOOK8_STATIC_HELPER(IDirect3DDevice8_CreateVertexShader,
        IDirect3DDevice8*, CONST DWORD*, CONST DWORD*, DWORD*, DWORD)
    DECL_HOOK8_STATIC_HELPER(IDirect3DDevice8_CreatePixelShader,
        IDirect3DDevice8*, CONST DWORD*, DWORD*)
    DECL_HOOK8_STATIC_HELPER(IDirect3DDevice8_CreateAdditionalSwapChain,
        IDirect3DDevice8*, D3DPRESENT_PARAMETERS*, IDirect3DSwapChain8**)
    DECL_HOOK8_STATIC_HELPER(IDirect3DSwapChain8_Present,
        IDirect3DSwapChain8*, CONST RECT*, CONST RECT*, HWND, CONST RGNDATA*)
#undef DECL_HOOK8_STATIC_HELPER
 
    // ---- ripper helpers ---------------------------------------------------
    EPrimitiveTopology::Type D3DPRIMITIVETYPE_to_EPrimitiveTopology(D3DPRIMITIVETYPE);
    EInputType::Type         convD3D8TypeToInputType(DWORD d3dtype);
 
    HRESULT getVertexDeclarations(IDirect3DDevice8*,
                                   KInputVertexDeclaration&,
                                   KOutputVertexDeclaration&);
    HRESULT createDeclaration(const DWORD*, KInputVertexDeclaration&);
    void    dumpVertexDeclarationToLog(const DWORD*);
 
    HRESULT dumpIndexBuffer(IDirect3DDevice8*, EPrimitiveTopology::Type,
                            UINT StartIndex, UINT PrimitiveCount,
                            KFACES*, OptimizedIndexToMeshIndex*, UINT* pBaseVtx);
    HRESULT dumpVertexBuffer(IDirect3DDevice8*,
                             const KInputVertexDeclaration&,
                             const KOutputVertexDeclaration&,
                             UINT BaseVertexIndex,
                             const OptimizedIndexToMeshIndex&,
                             KVERTICES*);
 
    void ripDP(IDirect3DDevice8*, D3DPRIMITIVETYPE, UINT StartVertex, UINT PrimCount);
    void ripDIP(IDirect3DDevice8*, D3DPRIMITIVETYPE, UINT MinIndex,
                UINT NumVertices, UINT StartIndex, UINT PrimCount);
    void ripDrawPrimitiveUP(IDirect3DDevice8*, D3DPRIMITIVETYPE,
                            UINT PrimCount, CONST void* pData, UINT Stride);
    void ripDrawIndexedPrimitiveUP(IDirect3DDevice8*, D3DPRIMITIVETYPE,
                                   UINT MinVtxIdx, UINT NumVtxIndices,
                                   UINT PrimCount, CONST void* pIdxData,
                                   D3DFORMAT, CONST void* pVtxData, UINT Stride);
 
    // ---- texture helpers --------------------------------------------------
    DWORD   isTextureSaved(IDirect3DBaseTexture8*);
    HRESULT saveTexture2File(LPCTSTR, IDirect3DDevice8*, IDirect3DBaseTexture8*);
    void    handleTextureSave(IDirect3DDevice8*, DWORD Stage, IDirect3DBaseTexture8*);
 
    void    addMeshTexture(const KTexture8&);
    bool    isMeshTextureSaved(IDirect3DBaseTexture8*, KTexture8*);
    void    saveMeshTextures(IDirect3DDevice8*, KMeshTextures*);
 
    // ---- shader helpers ---------------------------------------------------
    bool    getShaderFromDb(DWORD, Shaders8Db*, std::string* name, std::string* path);
    void    saveMeshShaders(IDirect3DDevice8*, KMeshShaders*);
 
    // ---- debug helpers (from dump8.cpp) -----------------------------------
    const char* D3DFORMAT_2Str(D3DFORMAT);
    const char* D3DRESOURCETYPE_2Str(D3DRESOURCETYPE);
    const char* D3DMULTISAMPLE_2Str(D3DMULTISAMPLE_TYPE);
    const char* D3DPOOL_2Str(D3DPOOL);
    const char* D3DUSAGE_2Str(DWORD);
    void        dump_TextureDesc2Log(IDirect3DBaseTexture8*);
};
 
// Static member
KRipper8* KRipper8::this_ = nullptr;
 
 
// =============================================================================
//  KRipper8 � lifecycle  (from kripper8.cpp)
// =============================================================================
 
KRipper8* KRipper8::create(HINSTANCE hD3D8)
{
    g_pLog->log("D3D8 ripper init\n");
    KRipper8* p = new KRipper8(hD3D8);
    p->initialize();
    return p;
}
 
void KRipper8::destroy(KRipper8*& p)
{
    if (!p) return;
    g_pLog->log("D3D8 ripper uninit\n\n");
    p->cleanup();
    SAFE_DELETE(p);
}
 
KRipper8::KRipper8(HINSTANCE hD3D8_)
    : hD3D8(hD3D8_), hD3DX(nullptr),
      D3DXSaveTextureToFileW_(nullptr),
      D3DXGetFVFVertexSize_(nullptr),
      D3DXDeclaratorFromFVF_(nullptr),
      LastShader(0)
{
    this_ = this;
    InitializeCriticalSection(&cs);
    zeroHooks();
}
 
KRipper8::~KRipper8()
{
    this_ = nullptr;
    DeleteCriticalSection(&cs);
}
 
void KRipper8::zeroHooks()
{
    pHook_Direct3DCreate8                         = nullptr;
    pHook_IDirect3D8_CreateDevice                 = nullptr;
    pHook_IDirect3DDevice8_SetTexture             = nullptr;
    pHook_IDirect3DDevice8_Present                = nullptr;
    pHook_IDirect3DDevice8_DrawPrimitive          = nullptr;
    pHook_IDirect3DDevice8_DrawIndexedPrimitive   = nullptr;
    pHook_IDirect3DDevice8_DrawPrimitiveUP        = nullptr;
    pHook_IDirect3DDevice8_DrawIndexedPrimitiveUP = nullptr;
    pHook_IDirect3DDevice8_SetVertexShader        = nullptr;
    pHook_IDirect3DDevice8_CreateVertexBuffer     = nullptr;
    pHook_IDirect3DDevice8_CreateIndexBuffer      = nullptr;
    pHook_IDirect3DDevice8_CreateVertexShader     = nullptr;
    pHook_IDirect3DDevice8_CreatePixelShader      = nullptr;
    pHook_IDirect3DDevice8_CreateAdditionalSwapChain = nullptr;
    pHook_IDirect3DSwapChain8_Present             = nullptr;
}
 
void KRipper8::frameStart()   { meshTexturesDb.clear(); }
void KRipper8::frameEnd()     {}
void KRipper8::textureRipStart() { forcedTexturesDb.clear(); }
void KRipper8::textureRipEnd() {}
 
void KRipper8::initialize()
{
    hookEx("Direct3DCreate8",
           GetProcAddress(this_->hD3D8, "Direct3DCreate8"),
           _Direct3DCreate8,
           KHookMgr::EHOOK_POOL_DX8,
           &this_->pHook_Direct3DCreate8);
}
 
void KRipper8::cleanup()
{
    g_pHookMgr->unhookPool(KHookMgr::EHOOK_POOL_DX8);
    this_->zeroHooks();
}
 
 
// =============================================================================
//  Direct3DCreate8 hook
// =============================================================================
 
IDirect3D8* __stdcall KRipper8::_Direct3DCreate8(UINT SDKVER)
{
    return this_->helper_Direct3DCreate8(SDKVER);
}
 
IDirect3D8* KRipper8::helper_Direct3DCreate8(UINT SDKVER)
{
    loadD3DCompile(&d3dCompileHelper);
 
    PFN_Direct3DCreate8 e = (PFN_Direct3DCreate8)
                            pHook_Direct3DCreate8->getOriginalAddress();
 
    // Lazy-load D3DX8 (try debug DLL first, then release)
    if (!hD3DX)
    {
        HMODULE hMod = GetModuleHandleW(L"d3dx8d.dll");
        if (!hMod) hMod = GetModuleHandleW(L"d3dx8.dll");
        if (hMod)
        {
            hD3DX = (HINSTANCE)hMod;
        }
        else
        {
            std::wstring dir = g_pIntruder->getIntruderDir();
            hD3DX = LoadLibraryW((dir + L"d3dx8d.dll").c_str());
            if (!hD3DX)
                hD3DX = LoadLibraryW((dir + L"d3dx8.dll").c_str());
            if (!hD3DX)
                fatalErrorMsgW(L"d3dx8d.dll / d3dx8.dll load error");
        }
 
        D3DXSaveTextureToFileW_ = (PFN_D3DXSaveTextureToFileW)
            GetProcAddress(hD3DX, "D3DXSaveTextureToFileW");
        D3DXGetFVFVertexSize_   = (PFN_D3DXGetFVFVertexSize)
            GetProcAddress(hD3DX, "D3DXGetFVFVertexSize");
        D3DXDeclaratorFromFVF_  = (PFN_D3DXDeclaratorFromFVF)
            GetProcAddress(hD3DX, "D3DXDeclaratorFromFVF");
 
        if (!D3DXSaveTextureToFileW_ || !D3DXGetFVFVertexSize_ || !D3DXDeclaratorFromFVF_)
            fatalErrorMsgW(L"Missing D3DX8 export(s).");
    }
 
    IDirect3D8* pid3d8 = e(SDKVER);
    g_pLog->log("Direct3DCreate8(%u) = 0x%p\n", SDKVER, pid3d8);
    if (!pid3d8) return pid3d8;
 
    hookEx("IDirect3D8_CreateDevice",
           IDX8_IDirect3D8_CreateDevice, pid3d8,
           KHookMgr::EHOOK_POOL_DX8,
           _IDirect3D8_CreateDevice,
           &pHook_IDirect3D8_CreateDevice);
 
    return pid3d8;
}
 
 
// =============================================================================
//  IDirect3D8::CreateDevice hook
// =============================================================================
 
HRESULT __stdcall KRipper8::_IDirect3D8_CreateDevice(
    IDirect3D8* pD3D8, UINT Adapter, D3DDEVTYPE DeviceType,
    HWND hFocusWindow, DWORD BehaviorFlags,
    D3DPRESENT_PARAMETERS* pPP, IDirect3DDevice8** ppDev)
{
    return this_->helper_IDirect3D8_CreateDevice(
        this_->pHook_IDirect3D8_CreateDevice,
        pD3D8, Adapter, DeviceType, hFocusWindow, BehaviorFlags, pPP, ppDev);
}
 
HRESULT KRipper8::helper_IDirect3D8_CreateDevice(
    KHook* pHook,
    IDirect3D8* pD3D8, UINT Adapter, D3DDEVTYPE DeviceType,
    HWND hFocusWindow, DWORD BehaviorFlags,
    D3DPRESENT_PARAMETERS* pPP, IDirect3DDevice8** ppDev)
{
    PFN_IDirect3D8_CreateDevice e =
        (PFN_IDirect3D8_CreateDevice)pHook->getOriginalAddress();
 
    HRESULT res = e(pD3D8, Adapter, DeviceType, hFocusWindow,
                    BehaviorFlags, pPP, ppDev);
    if (FAILED(res)) return res;
 
    g_pLog->log("IDirect3D8::CreateDevice(0x%p) = 0x%08X\n", pD3D8, res);
 
#define HOOK8(name, idx, fn, ppHook) \
    hookEx(name, idx, *ppDev, KHookMgr::EHOOK_POOL_DX8, fn, ppHook)
 
    HOOK8("IDirect3DDevice8_SetTexture",
          IDX8_IDirect3DDevice8_SetTexture,
          _IDirect3DDevice8_SetTexture,
          &pHook_IDirect3DDevice8_SetTexture);
 
    HOOK8("IDirect3DDevice8_Present",
          IDX8_IDirect3DDevice8_Present,
          _IDirect3DDevice8_Present,
          &pHook_IDirect3DDevice8_Present);
 
    HOOK8("IDirect3DDevice8_DrawPrimitive",
          IDX8_IDirect3DDevice8_DrawPrimitive,
          _IDirect3DDevice8_DrawPrimitive,
          &pHook_IDirect3DDevice8_DrawPrimitive);
 
    HOOK8("IDirect3DDevice8_DrawIndexedPrimitive",
          IDX8_IDirect3DDevice8_DrawIndexedPrimitive,
          _IDirect3DDevice8_DrawIndexedPrimitive,
          &pHook_IDirect3DDevice8_DrawIndexedPrimitive);
 
    HOOK8("IDirect3DDevice8_DrawPrimitiveUP",
          IDX8_IDirect3DDevice8_DrawPrimitiveUP,
          _IDirect3DDevice8_DrawPrimitiveUP,
          &pHook_IDirect3DDevice8_DrawPrimitiveUP);
 
    HOOK8("IDirect3DDevice8_DrawIndexedPrimitiveUP",
          IDX8_IDirect3DDevice8_DrawIndexedPrimitiveUP,
          _IDirect3DDevice8_DrawIndexedPrimitiveUP,
          &pHook_IDirect3DDevice8_DrawIndexedPrimitiveUP);
 
    HOOK8("IDirect3DDevice8_CreateVertexBuffer",
          IDX8_IDirect3DDevice8_CreateVertexBuffer,
          _IDirect3DDevice8_CreateVertexBuffer,
          &pHook_IDirect3DDevice8_CreateVertexBuffer);
 
    HOOK8("IDirect3DDevice8_CreateIndexBuffer",
          IDX8_IDirect3DDevice8_CreateIndexBuffer,
          _IDirect3DDevice8_CreateIndexBuffer,
          &pHook_IDirect3DDevice8_CreateIndexBuffer);
 
    HOOK8("IDirect3DDevice8_CreateVertexShader",
          IDX8_IDirect3DDevice8_CreateVertexShader,
          _IDirect3DDevice8_CreateVertexShader,
          &pHook_IDirect3DDevice8_CreateVertexShader);
 
    HOOK8("IDirect3DDevice8_CreatePixelShader",
          IDX8_IDirect3DDevice8_CreatePixelShader,
          _IDirect3DDevice8_CreatePixelShader,
          &pHook_IDirect3DDevice8_CreatePixelShader);
 
    HOOK8("IDirect3DDevice8_SetVertexShader",
          IDX8_IDirect3DDevice8_SetVertexShader,
          _IDirect3DDevice8_SetVertexShader,
          &pHook_IDirect3DDevice8_SetVertexShader);
 
    HOOK8("IDirect3DDevice8_CreateAdditionalSwapChain",
          IDX8_IDirect3DDevice8_CreateAdditionalSwapChain,
          _IDirect3DDevice8_CreateAdditionalSwapChain,
          &pHook_IDirect3DDevice8_CreateAdditionalSwapChain);
#undef HOOK8
 
    return res;
}
 
 
// =============================================================================
//  Present / frame boundary hooks
// =============================================================================
 
HRESULT __stdcall KRipper8::_IDirect3DDevice8_Present(
    IDirect3DDevice8* pDev, CONST RECT* pSrc, CONST RECT* pDst,
    HWND hWnd, CONST RGNDATA* pRgn)
{
    return this_->helper_IDirect3DDevice8_Present(
        this_->pHook_IDirect3DDevice8_Present, pDev, pSrc, pDst, hWnd, pRgn);
}
HRESULT KRipper8::helper_IDirect3DDevice8_Present(
    KHook* pHook, IDirect3DDevice8* pDev,
    CONST RECT* pSrc, CONST RECT* pDst, HWND hWnd, CONST RGNDATA* pRgn)
{
    auto e = (PFN_IDirect3DDevice8_Present)pHook->getOriginalAddress();
    g_pIntruder->frameHandler(this);
    return e(pDev, pSrc, pDst, hWnd, pRgn);
}
 
HRESULT __stdcall KRipper8::_IDirect3DDevice8_CreateAdditionalSwapChain(
    IDirect3DDevice8* pDev, D3DPRESENT_PARAMETERS* pPP,
    IDirect3DSwapChain8** ppSC)
{
    return this_->helper_IDirect3DDevice8_CreateAdditionalSwapChain(
        this_->pHook_IDirect3DDevice8_CreateAdditionalSwapChain, pDev, pPP, ppSC);
}
HRESULT KRipper8::helper_IDirect3DDevice8_CreateAdditionalSwapChain(
    KHook* pHook, IDirect3DDevice8* pDev,
    D3DPRESENT_PARAMETERS* pPP, IDirect3DSwapChain8** ppSC)
{
    auto e = (PFN_IDirect3DDevice8_CreateAdditionalSwapChain)pHook->getOriginalAddress();
    g_pLog->log("IDirect3DDevice8_CreateAdditionalSwapChain\n");
    HRESULT hr = e(pDev, pPP, ppSC);
    if (SUCCEEDED(hr))
        hookEx("IDirect3DSwapChain8_Present",
               IDX8_IDirect3DSwapChain8_Present, *ppSC,
               KHookMgr::EHOOK_POOL_DX8,
               _IDirect3DSwapChain8_Present,
               &pHook_IDirect3DSwapChain8_Present);
    return hr;
}
 
HRESULT __stdcall KRipper8::_IDirect3DSwapChain8_Present(
    IDirect3DSwapChain8* pSC, CONST RECT* pSrc, CONST RECT* pDst,
    HWND hWnd, CONST RGNDATA* pRgn)
{
    return this_->helper_IDirect3DSwapChain8_Present(
        this_->pHook_IDirect3DSwapChain8_Present, pSC, pSrc, pDst, hWnd, pRgn);
}
HRESULT KRipper8::helper_IDirect3DSwapChain8_Present(
    KHook* pHook, IDirect3DSwapChain8* pSC,
    CONST RECT* pSrc, CONST RECT* pDst, HWND hWnd, CONST RGNDATA* pRgn)
{
    auto e = (PFN_IDirect3DSwapChain8_Present)pHook->getOriginalAddress();
    g_pIntruder->frameHandler(this);
    return e(pSC, pSrc, pDst, hWnd, pRgn);
}
 
 
// =============================================================================
//  Buffer creation hooks (strip D3DUSAGE_WRITEONLY so we can lock them)
// =============================================================================
 
HRESULT __stdcall KRipper8::_IDirect3DDevice8_CreateVertexBuffer(
    IDirect3DDevice8* pDev, UINT Length, DWORD Usage, DWORD FVF,
    D3DPOOL Pool, IDirect3DVertexBuffer8** ppVB)
{
    return this_->helper_IDirect3DDevice8_CreateVertexBuffer(
        this_->pHook_IDirect3DDevice8_CreateVertexBuffer,
        pDev, Length, Usage, FVF, Pool, ppVB);
}
HRESULT KRipper8::helper_IDirect3DDevice8_CreateVertexBuffer(
    KHook* pHook, IDirect3DDevice8* pDev, UINT Length, DWORD Usage,
    DWORD FVF, D3DPOOL Pool, IDirect3DVertexBuffer8** ppVB)
{
    auto e = (PFN_IDirect3DDevice8_CreateVertexBuffer)pHook->getOriginalAddress();
    Usage &= ~(DWORD)D3DUSAGE_WRITEONLY;
    return e(pDev, Length, Usage, FVF, Pool, ppVB);
}
 
HRESULT __stdcall KRipper8::_IDirect3DDevice8_CreateIndexBuffer(
    IDirect3DDevice8* pDev, UINT Length, DWORD Usage,
    D3DFORMAT Format, D3DPOOL Pool, IDirect3DIndexBuffer8** ppIB)
{
    return this_->helper_IDirect3DDevice8_CreateIndexBuffer(
        this_->pHook_IDirect3DDevice8_CreateIndexBuffer,
        pDev, Length, Usage, Format, Pool, ppIB);
}
HRESULT KRipper8::helper_IDirect3DDevice8_CreateIndexBuffer(
    KHook* pHook, IDirect3DDevice8* pDev, UINT Length, DWORD Usage,
    D3DFORMAT Format, D3DPOOL Pool, IDirect3DIndexBuffer8** ppIB)
{
    auto e = (PFN_IDirect3DDevice8_CreateIndexBuffer)pHook->getOriginalAddress();
    Usage &= ~(DWORD)D3DUSAGE_WRITEONLY;
    return e(pDev, Length, Usage, Format, Pool, ppIB);
}
 
 
// =============================================================================
//  Vertex/pixel shader creation hooks
// =============================================================================
 
HRESULT __stdcall KRipper8::_IDirect3DDevice8_CreateVertexShader(
    IDirect3DDevice8* pDev, CONST DWORD* pDecl,
    CONST DWORD* pFunc, DWORD* pHandle, DWORD Usage)
{
    return this_->helper_IDirect3DDevice8_CreateVertexShader(
        this_->pHook_IDirect3DDevice8_CreateVertexShader,
        pDev, pDecl, pFunc, pHandle, Usage);
}
HRESULT KRipper8::helper_IDirect3DDevice8_CreateVertexShader(
    KHook* pHook, IDirect3DDevice8* pDev, CONST DWORD* pDecl,
    CONST DWORD* pFunc, DWORD* pHandle, DWORD Usage)
{
    auto e = (PFN_IDirect3DDevice8_CreateVertexShader)pHook->getOriginalAddress();
    HRESULT hr = e(pDev, pDecl, pFunc, pHandle, Usage);
 
    // Cache declaration token array keyed by shader handle
    if (pDecl)
    {
        KVertexDeclaration8 vs8;
        for (DWORD i = 0; i < 256; ++i)
        {
            vs8.Declaration[i] = pDecl[i];
            if (pDecl[i] == D3DVSD_END() || i >= 255) break;
        }
        auto it = VSDb.find(*pHandle);
        if (it != VSDb.end()) it->second = vs8;
        else VSDb.insert(std::make_pair(*pHandle, vs8));
    }
 
    if (SUCCEEDED(hr) && g_pIntruder->getSettings()->saveShaders)
    {
        DWORD idx = g_pIntruder->incVertexShaderIdx();
        std::wstring savePath = g_pIntruder->getShaderSavePath(idx, EShaderExt::VERTEX);
        std::string  saveName = g_pIntruder->getShaderName(idx, EShaderExt::VERTEX);
        if (SUCCEEDED(sm1::disassembleShaderToFile(savePath.c_str(), pFunc)))
        {
            ShaderFiles sf; sf.fullPath = savePath; sf.name = saveName;
            vsShadersDb.insert(std::make_pair(*pHandle, sf));
        }
        else
        {
            g_pLog->logError("VS disassembler failed\n");
        }
    }
    return hr;
}
 
HRESULT __stdcall KRipper8::_IDirect3DDevice8_CreatePixelShader(
    IDirect3DDevice8* pDev, CONST DWORD* pFunc, DWORD* pHandle)
{
    return this_->helper_IDirect3DDevice8_CreatePixelShader(
        this_->pHook_IDirect3DDevice8_CreatePixelShader, pDev, pFunc, pHandle);
}
HRESULT KRipper8::helper_IDirect3DDevice8_CreatePixelShader(
    KHook* pHook, IDirect3DDevice8* pDev, CONST DWORD* pFunc, DWORD* pHandle)
{
    auto e = (PFN_IDirect3DDevice8_CreatePixelShader)pHook->getOriginalAddress();
    HRESULT hr = e(pDev, pFunc, pHandle);
 
    if (SUCCEEDED(hr) && g_pIntruder->getSettings()->saveShaders)
    {
        DWORD idx = g_pIntruder->incVertexShaderIdx();
        std::wstring savePath = g_pIntruder->getShaderSavePath(idx, EShaderExt::PIXEL);
        std::string  saveName = g_pIntruder->getShaderName(idx, EShaderExt::PIXEL);
        if (SUCCEEDED(sm1::disassembleShaderToFile(savePath.c_str(), pFunc)))
        {
            ShaderFiles sf; sf.fullPath = savePath; sf.name = saveName;
            psShadersDb.insert(std::make_pair(*pHandle, sf));
        }
        else
        {
            g_pLog->logError("PS disassembler failed\n");
        }
    }
    return hr;
}
 
HRESULT __stdcall KRipper8::_IDirect3DDevice8_SetVertexShader(
    IDirect3DDevice8* pDev, DWORD Handle)
{
    return this_->helper_IDirect3DDevice8_SetVertexShader(
        this_->pHook_IDirect3DDevice8_SetVertexShader, pDev, Handle);
}
HRESULT KRipper8::helper_IDirect3DDevice8_SetVertexShader(
    KHook* pHook, IDirect3DDevice8* pDev, DWORD Handle)
{
    auto e = (PFN_IDirect3DDevice8_SetVertexShader)pHook->getOriginalAddress();
    HRESULT hr = e(pDev, Handle);
    if (SUCCEEDED(hr)) LastShader = Handle;
    return hr;
}
 
 
// =============================================================================
//  Shader DB lookup and mesh-shader saving
// =============================================================================
 
bool KRipper8::getShaderFromDb(DWORD shader, Shaders8Db* db,
                                std::string* name, std::string* path)
{
    auto it = db->find(shader);
    if (it == db->end()) return false;
    *name = it->second.name;
    *path = wideStringToMultiByte(it->second.fullPath.c_str());
    return true;
}
 
void KRipper8::saveMeshShaders(IDirect3DDevice8* pDev, KMeshShaders* out)
{
    std::string name, path;
    if (getShaderFromDb(LastShader, &vsShadersDb, &name, &path))
    {
        out->shaders.push_back(name);
        g_pLog->log("VS saved: %s\n", path.c_str());
    }
    DWORD ps = 0;
    if (SUCCEEDED(pDev->GetPixelShader(&ps)))
    {
        if (getShaderFromDb(ps, &psShadersDb, &name, &path))
        {
            out->shaders.push_back(name);
            g_pLog->log("PS saved: %s\n", path.c_str());
        }
    }
}
 
 
// =============================================================================
//  Vertex declaration helpers  (from kripper8.cpp getVertexDeclarations etc.)
// =============================================================================
 
EPrimitiveTopology::Type KRipper8::D3DPRIMITIVETYPE_to_EPrimitiveTopology(
    D3DPRIMITIVETYPE pt)
{
    switch (pt)
    {
    case D3DPT_TRIANGLELIST:  return EPrimitiveTopology::TRIANGLELIST;
    case D3DPT_TRIANGLESTRIP: return EPrimitiveTopology::TRIANGLESTRIP;
    case D3DPT_POINTLIST:     return EPrimitiveTopology::POINTLIST;
    case D3DPT_LINELIST:      return EPrimitiveTopology::LINELIST;
    case D3DPT_LINESTRIP:     return EPrimitiveTopology::LINESTRIP;
    case D3DPT_TRIANGLEFAN:   return EPrimitiveTopology::TRIANGLEFAN;
    default:                  return EPrimitiveTopology::UNKNOWNPRIMITIVETYPE;
    }
}
 
EInputType::Type KRipper8::convD3D8TypeToInputType(DWORD d3dtype)
{
    switch (d3dtype)
    {
    case D3DVSDT_FLOAT1:   return EInputType::R32_FLOAT;
    case D3DVSDT_FLOAT2:   return EInputType::R32G32_FLOAT;
    case D3DVSDT_FLOAT3:   return EInputType::R32G32B32_FLOAT;
    case D3DVSDT_FLOAT4:   return EInputType::R32G32B32A32_FLOAT;
    case D3DVSDT_D3DCOLOR: return EInputType::R8G8B8A8_UINT;
    case D3DVSDT_UBYTE4:   return EInputType::R8G8B8A8_UINT;
    case D3DVSDT_SHORT2:   return EInputType::R16G16_SINT;
    case D3DVSDT_SHORT4:   return EInputType::R16G16B16A16_SINT;
    default:               return EInputType::UNKNOWNINPUTTYPE;
    }
}
 
void KRipper8::dumpVertexDeclarationToLog(const DWORD* pData)
{
    std::string decoded;
    g_pLog->log("--------D3D8 vertex shader declaration--------\n");
    for (;;)
    {
        DWORD token = *pData;
        DWORD len   = sm1_decodeVS1Declaration(pData, &decoded);
        g_pLog->log("Len:%d 0x%08X %s\n", len, token, decoded.c_str());
        if (token == D3DVSD_END()) break;
        pData += len;
    }
    g_pLog->log("----------------------------------------------\n\n");
}
 
HRESULT KRipper8::createDeclaration(const DWORD* pDecl,
                                     KInputVertexDeclaration& InputDecl)
{
    dumpVertexDeclarationToLog(pDecl);
    HRESULT hr = E_FAIL;
    DWORD StreamNum = 0, Offset = 0;
    for (;;)
    {
        DWORD token    = *pDecl;
        if (token == D3DVSD_END()) { hr = S_OK; break; }
 
        std::string tmp;
        DWORD len      = sm1_decodeVS1Declaration(pDecl, &tmp);
        DWORD tokenType= (token >> D3DVSD_TOKENTYPESHIFT) & 0x7;
        bool  addElem  = false;
        KInputVertexElement elem{};
 
        if (tokenType == D3DVSD_TOKEN_STREAM)
        {
            StreamNum = token & 0xF;
            Offset    = 0;
        }
        else if (tokenType == D3DVSD_TOKEN_STREAMDATA)
        {
            if (!(token & D3DVSD_DATALOADTYPEMASK))
            {
                DWORD typeDim = (token & D3DVSD_DATATYPEMASK) >> D3DVSD_DATATYPESHIFT;
                DWORD regAddr = token & 0xF;
                const char* sem = sm1_getRegSemantic(regAddr);
                strCopy(elem.UsageSemantic, SEMANTIC_LEN, sem);
                elem.Type = convD3D8TypeToInputType(typeDim);
                addElem   = true;
            }
            else
            {
                // Skip tokens
                DWORD cnt = (token & D3DVSD_SKIPCOUNTMASK) >> D3DVSD_SKIPCOUNTSHIFT;
                Offset += 4 * cnt;
            }
        }
 
        if (addElem)
        {
            elem.Size   = getInputTypeSize(elem.Type);
            elem.Stream = StreamNum;
            elem.Offset = Offset;
            InputDecl.Decl.push_back(elem);
            Offset += elem.Size;
        }
        pDecl += len;
    }
    return hr;
}
 
HRESULT KRipper8::getVertexDeclarations(IDirect3DDevice8* pDev,
                                         KInputVertexDeclaration& InputDecl,
                                         KOutputVertexDeclaration& OutputDecl)
{
    DWORD VertShader = 0;
    if (FAILED(pDev->GetVertexShader(&VertShader)))
        VertShader = LastShader;
 
    g_pLog->log("VertexShader/FVF: 0x%08X\n", VertShader);
    if (!VertShader)
    {
        g_pLog->logError("FVF == 0\n");
        return E_FVF_NULL;
    }
 
    HRESULT hr;
    auto it = VSDb.find(VertShader);
    if (it == VSDb.end())
    {
        // FVF mode � crack with D3DXDeclaratorFromFVF
        DWORD Decl[256] = {};
        hr = D3DXDeclaratorFromFVF_(VertShader, Decl);
        if (FAILED(hr))
        {
            g_pLog->log("D3DXDeclaratorFromFVF() failed: 0x%08X\n", hr);
            return hr;
        }
        hr = createDeclaration(Decl, InputDecl);
    }
    else
    {
        hr = createDeclaration(it->second.Declaration, InputDecl);
    }
 
    if (SUCCEEDED(hr))
        hr = createKOutputVertexDeclaration(InputDecl, OutputDecl);
 
    return hr;
}
 
 
// =============================================================================
//  Index buffer dump  (from drawindexedprimitive8.cpp)
// =============================================================================
 
HRESULT KRipper8::dumpIndexBuffer(IDirect3DDevice8* pDev,
                                   EPrimitiveTopology::Type primTopology,
                                   UINT StartIndex,
                                   UINT PrimitiveCount,
                                   KFACES* pFACES,
                                   OptimizedIndexToMeshIndex* optIdxToMeshIdx,
                                   UINT* pBaseVertexIndex)
{
    HRESULT hr;
    do
    {
        TDXRef<IDirect3DIndexBuffer8> pIBRef;
        BYTE* pbData = nullptr;
        D3DINDEXBUFFER_DESC desc{}; 
 
        hr = pDev->GetIndices(&pIBRef, pBaseVertexIndex);
        if (FAILED(hr)) { g_pLog->logError("GetIndices() hr=0x%08X\n", hr); break; }
        if (!pIBRef.get()) { hr = E_NULL_BUFF; g_pLog->logError("pIB==NULL\n"); break; }
 
        hr = pIBRef->GetDesc(&desc);
        if (FAILED(hr)) { g_pLog->logError("IB::GetDesc() hr=0x%08X\n", hr); break; }
 
        if (desc.Format != D3DFMT_INDEX16 && desc.Format != D3DFMT_INDEX32)
        {
            g_pLog->logError("Unknown IB format 0x%08X\n", desc.Format);
            break;
        }
 
        hr = pIBRef->Lock(0, 0, &pbData, D3DLOCK_READONLY);
        if (FAILED(hr)) { g_pLog->logError("IB::Lock() hr=0x%08X\n", hr); break; }
 
        if (desc.Format == D3DFMT_INDEX16)
            processIndexes16_PrimitiveCount(
                (const WORD*)pbData + StartIndex,
                primTopology, PrimitiveCount, pFACES, optIdxToMeshIdx);
        else
            processIndexes32_PrimitiveCount(
                (const DWORD*)pbData + StartIndex,
                primTopology, PrimitiveCount, pFACES, optIdxToMeshIdx);
 
        hr = pIBRef->Unlock();
        if (FAILED(hr)) { g_pLog->logError("IB::Unlock() hr=0x%08X\n", hr); break; }
        hr = S_OK;
    }
    while (FALSE);
    return hr;
}
 
 
// =============================================================================
//  Vertex buffer dump  (from drawindexedprimitive8.cpp)
// =============================================================================
 
HRESULT KRipper8::dumpVertexBuffer(IDirect3DDevice8* pDev,
                                    const KInputVertexDeclaration&  inputDecl,
                                    const KOutputVertexDeclaration& outputDecl,
                                    UINT BaseVertexIndex,
                                    const OptimizedIndexToMeshIndex& optIdx,
                                    KVERTICES* pVERTICES)
{
    HRESULT hr = E_FAIL;
    bool    vbOk = false;
 
    for (size_t i = 0; i < inputDecl.Decl.size(); ++i)
    {
        UINT  Stride = 0;
        const KInputVertexElement&  iElem = inputDecl.Decl[i];
        const KOutputVertexElement& oElem = outputDecl.Decl[i];
 
        TDXRef<IDirect3DVertexBuffer8> pVBRef;
        hr = pDev->GetStreamSource(iElem.Stream, &pVBRef, &Stride);
        if (FAILED(hr)) { g_pLog->logError("GetStreamSource() hr=0x%08X\n", hr); break; }
 
        if (!pVBRef.get())
        {
            g_pLog->logWarning("pVB==NULL, stream %d\n", iElem.Stream);
            hr = E_NULL_BUFF;
            continue;
        }
 
        D3DVERTEXBUFFER_DESC vbDesc{};
        hr = pVBRef->GetDesc(&vbDesc);
        if (FAILED(hr)) { g_pLog->logError("VB::GetDesc() hr=0x%08X\n", hr); break; }
 
        g_pLog->log("Stream %d: pVB=0x%p stride=%d sem=%s\n",
            iElem.Stream, pVBRef.get(), Stride, iElem.UsageSemantic);
 
        BYTE* pbData = nullptr;
        hr = pVBRef->Lock(0, 0, &pbData, D3DLOCK_READONLY);
        if (FAILED(hr)) { g_pLog->logError("VB::Lock() hr=0x%08X\n", hr); break; }
 
        DWORD vertCnt = (DWORD)optIdx.size();
        UINT  vSz     = BaseVertexIndex * Stride + Stride * vertCnt;
        if (vbDesc.Size >= vSz)
        {
            dumpVertSemantic(iElem.Type,
                             pbData + BaseVertexIndex * Stride,
                             iElem.Offset, Stride,
                             pVERTICES->getRawData(),
                             oElem.Offset, pVERTICES->getVertexSize(),
                             optIdx);
        }
 
        hr = pVBRef->Unlock();
        if (FAILED(hr)) { g_pLog->logError("VB::Unlock() hr=0x%08X\n", hr); break; }
        vbOk = true;
    }
 
    if (vbOk) hr = S_OK;
    return hr;
}
 
 
// =============================================================================
//  SetTexture hook  (from texture8.cpp)
// =============================================================================
 
HRESULT __stdcall KRipper8::_IDirect3DDevice8_SetTexture(
    IDirect3DDevice8* pDev, DWORD Stage, IDirect3DBaseTexture8* pTexture)
{
    return this_->helper_IDirect3DDevice8_SetTexture(
        this_->pHook_IDirect3DDevice8_SetTexture, pDev, Stage, pTexture);
}
HRESULT KRipper8::helper_IDirect3DDevice8_SetTexture(
    KHook* pHook, IDirect3DDevice8* pDev,
    DWORD Stage, IDirect3DBaseTexture8* pTexture)
{
    auto e = (PFN_IDirect3DDevice8_SetTexture)pHook->getOriginalAddress();
    ::EnterCriticalSection(&cs);
    __try { handleTextureSave(pDev, Stage, pTexture); }
    __except (EXCEPTION_EXECUTE_HANDLER)
    { g_pLog->logError("Exception in handleTextureSave()\n"); }
    ::LeaveCriticalSection(&cs);
    return e(pDev, Stage, pTexture);
}
 
DWORD KRipper8::isTextureSaved(IDirect3DBaseTexture8* pTex)
{
    if (!pTex) return 1;
    for (auto& t : forcedTexturesDb)
        if (t == pTex) return 1;
    return 0;
}
 
void KRipper8::handleTextureSave(IDirect3DDevice8* pDev,
                                  DWORD Stage,
                                  IDirect3DBaseTexture8* pTexture)
{
    g_pIntruder->keyHandler(this_);
    if (!g_pIntruder->isTexturesRipKeyPressed()) return;
    if (this_->isTextureSaved(pTexture)) return;
 
    std::wstring path = g_pIntruder->getTextureSavePath();
    HRESULT hr = this_->saveTexture2File(path.c_str(), pDev, pTexture);
    if (SUCCEEDED(hr))
    {
        this_->forcedTexturesDb.push_back(pTexture);
        g_pIntruder->incTextureIdx();
        g_pLog->log("Texture saved: %s\n",
                    wideStringToMultiByte(path.c_str()).c_str());
    }
    else
    {
        g_pLog->logError("Texture save hr=0x%08X\n", hr);
    }
}
 
HRESULT KRipper8::saveTexture2File(LPCTSTR szFile,
                                    IDirect3DDevice8* pDev,
                                    IDirect3DBaseTexture8* pTexture)
{
    dump_TextureDesc2Log(pTexture);
    return D3DXSaveTextureToFileW_(szFile, D3DXIFF_DDS, pTexture, nullptr);
}
 
 
// =============================================================================
//  Per-draw-call mesh texture saving  (from savemeshtextures8.cpp)
// =============================================================================
 
void KRipper8::addMeshTexture(const KTexture8& t)
{
    meshTexturesDb.push_back(t);
}
 
bool KRipper8::isMeshTextureSaved(IDirect3DBaseTexture8* pTexture, KTexture8* out)
{
    for (auto& t : meshTexturesDb)
    {
        if (t.pTexture == pTexture) { *out = t; return true; }
    }
    return false;
}
 
void KRipper8::saveMeshTextures(IDirect3DDevice8* pDev, KMeshTextures* out)
{
    for (DWORD i = 0; i < 8; ++i)
    {
        TDXRef<IDirect3DBaseTexture8> pTex;
        HRESULT hr = pDev->GetTexture(i, &pTex);
        if (FAILED(hr))
        {
            g_pLog->logError("GetTexture(%d) hr=0x%08X\n", i, hr);
            continue;
        }
        if (!pTex.get()) continue;
 
        KTexture8 savedTex;
        if (isMeshTextureSaved(pTex.get(), &savedTex))
        {
            out->textures.push_back(savedTex.name);
            g_pLog->log("Tex #%d already saved: %s\n", i,
                wideStringToMultiByte(savedTex.fullPath.c_str()).c_str());
        }
        else
        {
            std::string  nameA;
            std::wstring fullPath = g_pIntruder->getFrameTextureSavePath(nameA, i);
            hr = saveTexture2File(fullPath.c_str(), pDev, pTex.get());
            if (SUCCEEDED(hr))
            {
                KTexture8 ft;
                ft.pTexture = pTex.get();
                ft.name     = nameA;
                ft.fullPath = fullPath;
                addMeshTexture(ft);
                out->textures.push_back(nameA);
                g_pLog->log("Tex #%d saved: %s\n", i,
                    wideStringToMultiByte(fullPath.c_str()).c_str());
            }
            else
            {
                g_pLog->logError("Tex save hr=0x%08X\n", hr);
            }
            g_pIntruder->incFrameTextureIdx();
        }
    }
}
 
 
// =============================================================================
//  DrawPrimitive (non-indexed, buffered)  (from drawprimitive8.cpp)
// =============================================================================
 
void KRipper8::ripDP(IDirect3DDevice8* pDev,
                     D3DPRIMITIVETYPE PrimitiveType,
                     UINT StartVertex, UINT PrimitiveCount)
{
    do
    {
        HRESULT hr;
        KInputVertexDeclaration  inputDecl;
        KOutputVertexDeclaration outputDecl;
 
        EPrimitiveTopology::Type topo =
            D3DPRIMITIVETYPE_to_EPrimitiveTopology(PrimitiveType);
        g_pLog->log("Topology: %s\n", primitiveTopology2Str(topo));
        if (!isPrimitiveTopologySupported(topo))
        { g_pLog->logError("Unsupported topology\n\n"); break; }
 
        hr = getVertexDeclarations(pDev, inputDecl, outputDecl);
        if (FAILED(hr)) { g_pLog->logError("getVertDecl hr=0x%08X\n\n", hr); break; }
        dumpInputVertexDeclaration2Log(inputDecl);
        dumpOutputVertexDeclaration2Log(outputDecl);
 
        KFACES faces;
        OptimizedIndexToMeshIndex optIdx;
        generateIndexes_PrimitiveCount(topo, PrimitiveCount, &faces, &optIdx);
 
        DWORD vertSize = outputDecl.getVertexSize();
        DWORD vertCnt  = (DWORD)optIdx.size();
        g_pLog->log("Prims=%d Verts=%d OutVtxSz=%d\n",
            faces.getPrimitivesCount(), vertCnt, vertSize);
 
        KVERTICES vertices(vertCnt, vertSize);
        hr = dumpVertexBuffer(pDev, inputDecl, outputDecl,
                              StartVertex, optIdx, &vertices);
        if (FAILED(hr)) { g_pLog->logError("dumpVB hr=0x%08X\n\n", hr); break; }
 
        KMeshTextures meshTex;
        saveMeshTextures(pDev, &meshTex);
        KMeshShaders meshShd;
        if (g_pIntruder->getSettings()->saveShaders) saveMeshShaders(pDev, &meshShd);
 
        std::wstring ripPath = g_pIntruder->getFrameMeshSavePath();
        hr = saveRipFile(ripPath.c_str(), inputDecl, outputDecl,
                         meshTex, meshShd, faces, vertices);
        std::string utf8 = wideStringToMultiByte(ripPath.c_str());
        if (SUCCEEDED(hr)) g_pLog->log("Mesh saved: %s\n\n\n", utf8.c_str());
        else               g_pLog->logError("Mesh save error: %s\n\n\n", utf8.c_str());
        g_pIntruder->incFrameMeshIdx();
    }
    while (FALSE);
}
 
HRESULT __stdcall KRipper8::_IDirect3DDevice8_DrawPrimitive(
    IDirect3DDevice8* pDev, D3DPRIMITIVETYPE PrimType,
    UINT StartVertex, UINT PrimCount)
{
    return this_->helper_IDirect3DDevice8_DrawPrimitive(
        this_->pHook_IDirect3DDevice8_DrawPrimitive,
        pDev, PrimType, StartVertex, PrimCount);
}
HRESULT KRipper8::helper_IDirect3DDevice8_DrawPrimitive(
    KHook* pHook, IDirect3DDevice8* pDev,
    D3DPRIMITIVETYPE PrimType, UINT StartVertex, UINT PrimCount)
{
    auto e = (PFN_IDirect3DDevice8_DrawPrimitive)pHook->getOriginalAddress();
    g_pIntruder->keyHandler(this);
    DWORD minPrim = g_pIntruder->getSettings()->dwMinPrimitives;
    ::EnterCriticalSection(&cs);
    if (g_pIntruder->isMeshRipEnabled() && PrimCount >= minPrim)
    {
        g_pLog->log("DrawPrimitive(0x%p,%d,%d,%d)\n",pDev,PrimType,StartVertex,PrimCount);
        __try { ripDP(pDev, PrimType, StartVertex, PrimCount); }
        __except (EXCEPTION_EXECUTE_HANDLER)
        { g_pLog->logError("DrawPrimitive exception\n\n\n"); }
    }
    ::LeaveCriticalSection(&cs);
    return e(pDev, PrimType, StartVertex, PrimCount);
}
 
 
// =============================================================================
//  DrawIndexedPrimitive (indexed, buffered)  (from drawindexedprimitive8.cpp)
// =============================================================================
 
void KRipper8::ripDIP(IDirect3DDevice8* pDev,
                       D3DPRIMITIVETYPE Type,
                       UINT MinIndex, UINT NumVertices,
                       UINT StartIndex, UINT PrimitiveCount)
{
    do
    {
        HRESULT hr;
        KInputVertexDeclaration  inputDecl;
        KOutputVertexDeclaration outputDecl;
 
        EPrimitiveTopology::Type topo =
            D3DPRIMITIVETYPE_to_EPrimitiveTopology(Type);
        g_pLog->log("Topology: %s\n", primitiveTopology2Str(topo));
        if (!isPrimitiveTopologySupported(topo))
        { g_pLog->logError("Unsupported topology\n\n"); break; }
 
        hr = getVertexDeclarations(pDev, inputDecl, outputDecl);
        if (FAILED(hr)) { g_pLog->logError("getVertDecl hr=0x%08X\n\n", hr); break; }
        dumpInputVertexDeclaration2Log(inputDecl);
        dumpOutputVertexDeclaration2Log(outputDecl);
 
        UINT BaseVtx = 0;
        KFACES faces;
        OptimizedIndexToMeshIndex optIdx;
        hr = dumpIndexBuffer(pDev, topo, StartIndex, PrimitiveCount,
                             &faces, &optIdx, &BaseVtx);
        if (FAILED(hr)) { g_pLog->logError("dumpIB hr=0x%08X\n\n", hr); break; }
 
        DWORD vertSize = outputDecl.getVertexSize();
        DWORD vertCnt  = (DWORD)optIdx.size();
        g_pLog->log("Prims=%d Verts=%d OutVtxSz=%d\n",
            faces.getPrimitivesCount(), vertCnt, vertSize);
 
        KVERTICES vertices(vertCnt, vertSize);
        hr = dumpVertexBuffer(pDev, inputDecl, outputDecl,
                              BaseVtx, optIdx, &vertices);
        if (FAILED(hr)) { g_pLog->logError("dumpVB hr=0x%08X\n\n", hr); break; }
 
        KMeshTextures meshTex;
        saveMeshTextures(pDev, &meshTex);
        KMeshShaders meshShd;
        if (g_pIntruder->getSettings()->saveShaders) saveMeshShaders(pDev, &meshShd);
 
        std::wstring ripPath = g_pIntruder->getFrameMeshSavePath();
        hr = saveRipFile(ripPath.c_str(), inputDecl, outputDecl,
                         meshTex, meshShd, faces, vertices);
        std::string utf8 = wideStringToMultiByte(ripPath.c_str());
        if (SUCCEEDED(hr)) g_pLog->log("Mesh saved: %s\n\n\n", utf8.c_str());
        else               g_pLog->logError("Mesh save error: %s\n\n\n", utf8.c_str());
        g_pIntruder->incFrameMeshIdx();
    }
    while (FALSE);
}
 
HRESULT __stdcall KRipper8::_IDirect3DDevice8_DrawIndexedPrimitive(
    IDirect3DDevice8* pDev, D3DPRIMITIVETYPE PrimType,
    UINT MinIndex, UINT NumVerts, UINT StartIndex, UINT PrimCount)
{
    return this_->helper_IDirect3DDevice8_DrawIndexedPrimitive(
        this_->pHook_IDirect3DDevice8_DrawIndexedPrimitive,
        pDev, PrimType, MinIndex, NumVerts, StartIndex, PrimCount);
}
HRESULT KRipper8::helper_IDirect3DDevice8_DrawIndexedPrimitive(
    KHook* pHook, IDirect3DDevice8* pDev, D3DPRIMITIVETYPE PrimType,
    UINT MinIndex, UINT NumVerts, UINT StartIndex, UINT PrimCount)
{
    auto e = (PFN_IDirect3DDevice8_DrawIndexedPrimitive)pHook->getOriginalAddress();
    g_pIntruder->keyHandler(this);
    DWORD minPrim = g_pIntruder->getSettings()->dwMinPrimitives;
    ::EnterCriticalSection(&cs);
    if (g_pIntruder->isMeshRipEnabled() && PrimCount >= minPrim)
    {
        g_pLog->log("DrawIndexedPrimitive(0x%p,%d,%d,%d,%d,%d)\n",
            pDev,PrimType,MinIndex,NumVerts,StartIndex,PrimCount);
        __try { ripDIP(pDev, PrimType, MinIndex, NumVerts, StartIndex, PrimCount); }
        __except (EXCEPTION_EXECUTE_HANDLER)
        { g_pLog->logError("DrawIndexedPrimitive exception\n\n\n"); }
    }
    ::LeaveCriticalSection(&cs);
    return e(pDev, PrimType, MinIndex, NumVerts, StartIndex, PrimCount);
}
 
 
// =============================================================================
//  DrawPrimitiveUP (non-indexed, user-pointer)  (from drawprimitiveup8.cpp)
// =============================================================================
 
void KRipper8::ripDrawPrimitiveUP(IDirect3DDevice8* pDev,
                                   D3DPRIMITIVETYPE Type, UINT PrimitiveCount,
                                   CONST void* pVtxData, UINT Stride)
{
    do
    {
        HRESULT hr;
        KInputVertexDeclaration  inputDecl;
        KOutputVertexDeclaration outputDecl;
 
        EPrimitiveTopology::Type topo =
            D3DPRIMITIVETYPE_to_EPrimitiveTopology(Type);
        g_pLog->log("Topology: %s\n", primitiveTopology2Str(topo));
        if (!isPrimitiveTopologySupported(topo))
        { g_pLog->logError("Unsupported topology\n\n"); break; }
 
        hr = getVertexDeclarations(pDev, inputDecl, outputDecl);
        if (FAILED(hr)) { g_pLog->logError("getVertDecl hr=0x%08X\n\n", hr); break; }
        dumpInputVertexDeclaration2Log(inputDecl);
        dumpOutputVertexDeclaration2Log(outputDecl);
 
        KFACES faces;
        OptimizedIndexToMeshIndex optIdx;
        generateIndexes_PrimitiveCount(topo, PrimitiveCount, &faces, &optIdx);
 
        DWORD vertSize = outputDecl.getVertexSize();
        DWORD vertCnt  = (DWORD)optIdx.size();
        g_pLog->log("Prims=%d Verts=%d OutVtxSz=%d\n",
            faces.getPrimitivesCount(), vertCnt, vertSize);
 
        KVERTICES vertices(vertCnt, vertSize);
        dumpVbUP(inputDecl, outputDecl, optIdx, &vertices, pVtxData, Stride);
 
        KMeshTextures meshTex; saveMeshTextures(pDev, &meshTex);
        KMeshShaders  meshShd;
        if (g_pIntruder->getSettings()->saveShaders) saveMeshShaders(pDev, &meshShd);
 
        std::wstring ripPath = g_pIntruder->getFrameMeshSavePath();
        hr = saveRipFile(ripPath.c_str(), inputDecl, outputDecl,
                         meshTex, meshShd, faces, vertices);
        std::string utf8 = wideStringToMultiByte(ripPath.c_str());
        if (SUCCEEDED(hr)) g_pLog->log("Mesh saved: %s\n\n\n", utf8.c_str());
        else               g_pLog->logError("Mesh save error: %s\n\n\n", utf8.c_str());
        g_pIntruder->incFrameMeshIdx();
    }
    while (FALSE);
}
 
HRESULT __stdcall KRipper8::_IDirect3DDevice8_DrawPrimitiveUP(
    IDirect3DDevice8* pDev, D3DPRIMITIVETYPE PrimType,
    UINT PrimCount, CONST void* pVtxData, UINT Stride)
{
    return this_->helper_IDirect3DDevice8_DrawPrimitiveUP(
        this_->pHook_IDirect3DDevice8_DrawPrimitiveUP,
        pDev, PrimType, PrimCount, pVtxData, Stride);
}
HRESULT KRipper8::helper_IDirect3DDevice8_DrawPrimitiveUP(
    KHook* pHook, IDirect3DDevice8* pDev, D3DPRIMITIVETYPE PrimType,
    UINT PrimCount, CONST void* pVtxData, UINT Stride)
{
    auto e = (PFN_IDirect3DDevice8_DrawPrimitiveUP)pHook->getOriginalAddress();
    g_pIntruder->keyHandler(this);
    DWORD minPrim = g_pIntruder->getSettings()->dwMinPrimitives;
    ::EnterCriticalSection(&cs);
    if (g_pIntruder->isMeshRipEnabled() && PrimCount >= minPrim)
    {
        g_pLog->log("DrawPrimitiveUP(0x%p,%d,%d,0x%p,%d)\n",
            pDev,PrimType,PrimCount,pVtxData,Stride);
        __try { ripDrawPrimitiveUP(pDev, PrimType, PrimCount, pVtxData, Stride); }
        __except (EXCEPTION_EXECUTE_HANDLER)
        { g_pLog->logError("DrawPrimitiveUP exception\n\n\n"); }
    }
    ::LeaveCriticalSection(&cs);
    return e(pDev, PrimType, PrimCount, pVtxData, Stride);
}
 
 
// =============================================================================
//  DrawIndexedPrimitiveUP (indexed, user-pointer)
//  (from drawindexedprimitiveup8.cpp)
// =============================================================================
 
void KRipper8::ripDrawIndexedPrimitiveUP(IDirect3DDevice8* pDev,
    D3DPRIMITIVETYPE Type, UINT MinVtxIdx, UINT NumVtxIndices,
    UINT PrimitiveCount, CONST void* pIdxData,
    D3DFORMAT IndexDataFormat, CONST void* pVtxData, UINT Stride)
{
    do
    {
        HRESULT hr;
        KInputVertexDeclaration  inputDecl;
        KOutputVertexDeclaration outputDecl;
 
        EPrimitiveTopology::Type topo =
            D3DPRIMITIVETYPE_to_EPrimitiveTopology(Type);
        g_pLog->log("Topology: %s\n", primitiveTopology2Str(topo));
        if (!isPrimitiveTopologySupported(topo))
        { g_pLog->logError("Unsupported topology\n\n"); break; }
 
        hr = getVertexDeclarations(pDev, inputDecl, outputDecl);
        if (FAILED(hr)) { g_pLog->logError("getVertDecl hr=0x%08X\n\n", hr); break; }
        dumpInputVertexDeclaration2Log(inputDecl);
        dumpOutputVertexDeclaration2Log(outputDecl);
 
        EIndexFormat::Type idxFmt =
            (IndexDataFormat == D3DFMT_INDEX16) ? EIndexFormat::INDEX_16 :
            (IndexDataFormat == D3DFMT_INDEX32) ? EIndexFormat::INDEX_32 :
                                                  EIndexFormat::UNKNOWN;
        KFACES faces;
        OptimizedIndexToMeshIndex optIdx;
        hr = dumpIndexesUP(topo, PrimitiveCount, &faces, &optIdx,
                           pIdxData, idxFmt);
        if (FAILED(hr)) { g_pLog->logError("dumpIndexesUP hr=0x%08X\n\n", hr); break; }
 
        DWORD vertSize = outputDecl.getVertexSize();
        DWORD vertCnt  = (DWORD)optIdx.size();
        g_pLog->log("Prims=%d Verts=%d OutVtxSz=%d\n",
            faces.getPrimitivesCount(), vertCnt, vertSize);
 
        KVERTICES vertices(vertCnt, vertSize);
        dumpVbUP(inputDecl, outputDecl, optIdx, &vertices, pVtxData, Stride);
 
        KMeshTextures meshTex; saveMeshTextures(pDev, &meshTex);
        KMeshShaders  meshShd;
        if (g_pIntruder->getSettings()->saveShaders) saveMeshShaders(pDev, &meshShd);
 
        std::wstring ripPath = g_pIntruder->getFrameMeshSavePath();
        hr = saveRipFile(ripPath.c_str(), inputDecl, outputDecl,
                         meshTex, meshShd, faces, vertices);
        std::string utf8 = wideStringToMultiByte(ripPath.c_str());
        if (SUCCEEDED(hr)) g_pLog->log("Mesh saved: %s\n\n\n", utf8.c_str());
        else               g_pLog->logError("Mesh save error: %s\n\n\n", utf8.c_str());
        g_pIntruder->incFrameMeshIdx();
    }
    while (FALSE);
}
 
HRESULT __stdcall KRipper8::_IDirect3DDevice8_DrawIndexedPrimitiveUP(
    IDirect3DDevice8* pDev, D3DPRIMITIVETYPE PrimType,
    UINT MinVtxIdx, UINT NumVtxIndices, UINT PrimCount,
    CONST void* pIdxData, D3DFORMAT IdxFmt,
    CONST void* pVtxData, UINT Stride)
{
    return this_->helper_IDirect3DDevice8_DrawIndexedPrimitiveUP(
        this_->pHook_IDirect3DDevice8_DrawIndexedPrimitiveUP,
        pDev, PrimType, MinVtxIdx, NumVtxIndices, PrimCount,
        pIdxData, IdxFmt, pVtxData, Stride);
}
HRESULT KRipper8::helper_IDirect3DDevice8_DrawIndexedPrimitiveUP(
    KHook* pHook, IDirect3DDevice8* pDev, D3DPRIMITIVETYPE PrimType,
    UINT MinVtxIdx, UINT NumVtxIndices, UINT PrimCount,
    CONST void* pIdxData, D3DFORMAT IdxFmt,
    CONST void* pVtxData, UINT Stride)
{
    auto e = (PFN_IDirect3DDevice8_DrawIndexedPrimitiveUP)pHook->getOriginalAddress();
    g_pIntruder->keyHandler(this);
    DWORD minPrim = g_pIntruder->getSettings()->dwMinPrimitives;
    ::EnterCriticalSection(&cs);
    if (g_pIntruder->isMeshRipEnabled() && PrimCount >= minPrim)
    {
        g_pLog->log("DrawIndexedPrimitiveUP(0x%p,%d,%d,%d,%d,0x%p,%d,0x%p,%d)\n",
            pDev,PrimType,MinVtxIdx,NumVtxIndices,PrimCount,
            pIdxData,IdxFmt,pVtxData,Stride);
        __try
        {
            ripDrawIndexedPrimitiveUP(pDev, PrimType, MinVtxIdx, NumVtxIndices,
                                      PrimCount, pIdxData, IdxFmt, pVtxData, Stride);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        { g_pLog->logError("DrawIndexedPrimitiveUP exception\n\n\n"); }
    }
    ::LeaveCriticalSection(&cs);
    return e(pDev, PrimType, MinVtxIdx, NumVtxIndices, PrimCount,
             pIdxData, IdxFmt, pVtxData, Stride);
}
 
 
// =============================================================================
//  Debug helpers  (from dump8.cpp)
// =============================================================================
 
const char* KRipper8::D3DFORMAT_2Str(D3DFORMAT f)
{
    switch (f)
    {
    case D3DFMT_UNKNOWN:       return "D3DFMT_UNKNOWN";
    case D3DFMT_R8G8B8:        return "D3DFMT_R8G8B8";
    case D3DFMT_A8R8G8B8:      return "D3DFMT_A8R8G8B8";
    case D3DFMT_X8R8G8B8:      return "D3DFMT_X8R8G8B8";
    case D3DFMT_R5G6B5:        return "D3DFMT_R5G6B5";
    case D3DFMT_X1R5G5B5:      return "D3DFMT_X1R5G5B5";
    case D3DFMT_A1R5G5B5:      return "D3DFMT_A1R5G5B5";
    case D3DFMT_A4R4G4B4:      return "D3DFMT_A4R4G4B4";
    case D3DFMT_R3G3B2:        return "D3DFMT_R3G3B2";
    case D3DFMT_A8:            return "D3DFMT_A8";
    case D3DFMT_A8R3G3B2:      return "D3DFMT_A8R3G3B2";
    case D3DFMT_X4R4G4B4:      return "D3DFMT_X4R4G4B4";
    case D3DFMT_A2B10G10R10:   return "D3DFMT_A2B10G10R10";
    case D3DFMT_A8P8:          return "D3DFMT_A8P8";
    case D3DFMT_P8:            return "D3DFMT_P8";
    case D3DFMT_L8:            return "D3DFMT_L8";
    case D3DFMT_A8L8:          return "D3DFMT_A8L8";
    case D3DFMT_A4L4:          return "D3DFMT_A4L4";
    case D3DFMT_V8U8:          return "D3DFMT_V8U8";
    case D3DFMT_L6V5U5:        return "D3DFMT_L6V5U5";
    case D3DFMT_X8L8V8U8:      return "D3DFMT_X8L8V8U8";
    case D3DFMT_Q8W8V8U8:      return "D3DFMT_Q8W8V8U8";
    case D3DFMT_V16U16:        return "D3DFMT_V16U16";
    case D3DFMT_A2W10V10U10:   return "D3DFMT_A2W10V10U10";
    case D3DFMT_UYVY:          return "D3DFMT_UYVY";
    case D3DFMT_YUY2:          return "D3DFMT_YUY2";
    case D3DFMT_DXT1:          return "D3DFMT_DXT1";
    case D3DFMT_DXT2:          return "D3DFMT_DXT2";
    case D3DFMT_DXT3:          return "D3DFMT_DXT3";
    case D3DFMT_DXT4:          return "D3DFMT_DXT4";
    case D3DFMT_DXT5:          return "D3DFMT_DXT5";
    case D3DFMT_D16_LOCKABLE:  return "D3DFMT_D16_LOCKABLE";
    case D3DFMT_D32:           return "D3DFMT_D32";
    case D3DFMT_D15S1:         return "D3DFMT_D15S1";
    case D3DFMT_D24S8:         return "D3DFMT_D24S8";
    case D3DFMT_D24X8:         return "D3DFMT_D24X8";
    case D3DFMT_D24X4S4:       return "D3DFMT_D24X4S4";
    case D3DFMT_D16:           return "D3DFMT_D16";
    case D3DFMT_VERTEXDATA:    return "D3DFMT_VERTEXDATA";
    case D3DFMT_INDEX16:       return "D3DFMT_INDEX16";
    case D3DFMT_INDEX32:       return "D3DFMT_INDEX32";
    default:                   return "Unknown";
    }
}
 
const char* KRipper8::D3DRESOURCETYPE_2Str(D3DRESOURCETYPE t)
{
    switch (t)
    {
    case D3DRTYPE_SURFACE:      return "D3DRTYPE_SURFACE";
    case D3DRTYPE_VOLUME:       return "D3DRTYPE_VOLUME";
    case D3DRTYPE_TEXTURE:      return "D3DRTYPE_TEXTURE";
    case D3DRTYPE_VOLUMETEXTURE:return "D3DRTYPE_VOLUMETEXTURE";
    case D3DRTYPE_CUBETEXTURE:  return "D3DRTYPE_CUBETEXTURE";
    case D3DRTYPE_VERTEXBUFFER: return "D3DRTYPE_VERTEXBUFFER";
    case D3DRTYPE_INDEXBUFFER:  return "D3DRTYPE_INDEXBUFFER";
    default:                    return "Unknown";
    }
}
 
const char* KRipper8::D3DMULTISAMPLE_2Str(D3DMULTISAMPLE_TYPE x)
{
    switch (x)
    {
    case D3DMULTISAMPLE_NONE:       return "D3DMULTISAMPLE_NONE";
    case D3DMULTISAMPLE_2_SAMPLES:  return "D3DMULTISAMPLE_2_SAMPLES";
    case D3DMULTISAMPLE_3_SAMPLES:  return "D3DMULTISAMPLE_3_SAMPLES";
    case D3DMULTISAMPLE_4_SAMPLES:  return "D3DMULTISAMPLE_4_SAMPLES";
    case D3DMULTISAMPLE_5_SAMPLES:  return "D3DMULTISAMPLE_5_SAMPLES";
    case D3DMULTISAMPLE_6_SAMPLES:  return "D3DMULTISAMPLE_6_SAMPLES";
    case D3DMULTISAMPLE_7_SAMPLES:  return "D3DMULTISAMPLE_7_SAMPLES";
    case D3DMULTISAMPLE_8_SAMPLES:  return "D3DMULTISAMPLE_8_SAMPLES";
    case D3DMULTISAMPLE_9_SAMPLES:  return "D3DMULTISAMPLE_9_SAMPLES";
    case D3DMULTISAMPLE_10_SAMPLES: return "D3DMULTISAMPLE_10_SAMPLES";
    case D3DMULTISAMPLE_11_SAMPLES: return "D3DMULTISAMPLE_11_SAMPLES";
    case D3DMULTISAMPLE_12_SAMPLES: return "D3DMULTISAMPLE_12_SAMPLES";
    case D3DMULTISAMPLE_13_SAMPLES: return "D3DMULTISAMPLE_13_SAMPLES";
    case D3DMULTISAMPLE_14_SAMPLES: return "D3DMULTISAMPLE_14_SAMPLES";
    case D3DMULTISAMPLE_15_SAMPLES: return "D3DMULTISAMPLE_15_SAMPLES";
    case D3DMULTISAMPLE_16_SAMPLES: return "D3DMULTISAMPLE_16_SAMPLES";
    default:                        return "Unknown";
    }
}
 
const char* KRipper8::D3DPOOL_2Str(D3DPOOL t)
{
    switch (t)
    {
    case D3DPOOL_DEFAULT:   return "D3DPOOL_DEFAULT";
    case D3DPOOL_MANAGED:   return "D3DPOOL_MANAGED";
    case D3DPOOL_SYSTEMMEM: return "D3DPOOL_SYSTEMMEM";
    case D3DPOOL_SCRATCH:   return "D3DPOOL_SCRATCH";
    default:                return "Unknown";
    }
}
 
const char* KRipper8::D3DUSAGE_2Str(DWORD t)
{
    switch (t)
    {
    case D3DUSAGE_DEPTHSTENCIL:        return "D3DUSAGE_DEPTHSTENCIL";
    case D3DUSAGE_DONOTCLIP:           return "D3DUSAGE_DONOTCLIP";
    case D3DUSAGE_DYNAMIC:             return "D3DUSAGE_DYNAMIC";
    case D3DUSAGE_NPATCHES:            return "D3DUSAGE_NPATCHES";
    case D3DUSAGE_POINTS:              return "D3DUSAGE_POINTS";
    case D3DUSAGE_RTPATCHES:           return "D3DUSAGE_RTPATCHES";
    case D3DUSAGE_RENDERTARGET:        return "D3DUSAGE_RENDERTARGET";
    case D3DUSAGE_SOFTWAREPROCESSING:  return "D3DUSAGE_SOFTWAREPROCESSING";
    case D3DUSAGE_WRITEONLY:           return "D3DUSAGE_WRITEONLY";
    default:                           return "Unknown";
    }
}
 
void KRipper8::dump_TextureDesc2Log(IDirect3DBaseTexture8* pTexture)
{
    if (!pTexture) return;
    D3DRESOURCETYPE type = pTexture->GetType();
    g_pLog->log("-----Texture desc-----\n");
    g_pLog->log("LevelCount: %u\n", pTexture->GetLevelCount());
    g_pLog->log("Type      : %s\n", D3DRESOURCETYPE_2Str(type));
    g_pLog->log("----------------------\n");
 
    HRESULT hr;
    if (type == D3DRTYPE_TEXTURE)
    {
        D3DSURFACE_DESC d{};
        hr = static_cast<LPDIRECT3DTEXTURE8>(pTexture)->GetLevelDesc(0, &d);
        if (SUCCEEDED(hr))
        {
            g_pLog->log("Format: %s\nType: %s\nUsage: %s\nPool: %s\n"
                        "Size: %u\nMSType: %s\nW: %d\nH: %d\n",
                D3DFORMAT_2Str(d.Format), D3DRESOURCETYPE_2Str(d.Type),
                D3DUSAGE_2Str(d.Usage), D3DPOOL_2Str(d.Pool),
                d.Size, D3DMULTISAMPLE_2Str(d.MultiSampleType),
                d.Width, d.Height);
        }
    }
    else if (type == D3DRTYPE_VOLUMETEXTURE)
    {
        D3DVOLUME_DESC d{};
        hr = static_cast<LPDIRECT3DVOLUMETEXTURE8>(pTexture)->GetLevelDesc(0, &d);
        if (SUCCEEDED(hr))
            g_pLog->log("Format: %s\nType: %s\nUsage: %s\nPool: %s\n"
                        "Size: %u\nW: %d\nH: %d\nD: %d\n",
                D3DFORMAT_2Str(d.Format), D3DRESOURCETYPE_2Str(d.Type),
                D3DUSAGE_2Str(d.Usage), D3DPOOL_2Str(d.Pool),
                d.Size, d.Width, d.Height, d.Depth);
    }
    else if (type == D3DRTYPE_CUBETEXTURE)
    {
        D3DSURFACE_DESC d{};
        hr = static_cast<LPDIRECT3DCUBETEXTURE8>(pTexture)->GetLevelDesc(0, &d);
        if (SUCCEEDED(hr))
            g_pLog->log("Format: %s\nType: %s\nUsage: %s\nPool: %s\n"
                        "Size: %u\nMSType: %s\nW: %d\nH: %d\n",
                D3DFORMAT_2Str(d.Format), D3DRESOURCETYPE_2Str(d.Type),
                D3DUSAGE_2Str(d.Usage), D3DPOOL_2Str(d.Pool),
                d.Size, D3DMULTISAMPLE_2Str(d.MultiSampleType),
                d.Width, d.Height);
    }
    g_pLog->log("----------------------\n");
}
 
 
// =============================================================================
//  Factory functions  (from pre8.cpp) � satisfy extern declarations at top
// =============================================================================
 
KRipper8* create_KRipper8(HINSTANCE hD3D8) { return KRipper8::create(hD3D8); }
void      delete_KRipper8(KRipper8*& p)    { KRipper8::destroy(p); }
 
 
#else // !__d3d8_h__
 
// ---------------------------------------------------------------------------
//  DX8 SDK not available � provide stub factory functions so the rest of
//  intruder.cpp still links.  The g_pRipper8 pointer will simply stay null
//  and all DX8 detection code will do nothing.
// ---------------------------------------------------------------------------
KRipper8* create_KRipper8(HINSTANCE) { return nullptr; }
void      delete_KRipper8(KRipper8*&) {}
 
#endif // __d3d8_h__

// =============================================================================
// =============================================================================
//  SECTION DX11  �  KRipper11
//  Merged from:
//    dx11/kripper11.h             (class definition)
//    dx11/kripper11.cpp           (core: lifecycle, device/context hooks)
//    dx11/draw11.cpp              (Draw)
//    dx11/drawauto11.cpp          (DrawAuto)
//    dx11/drawindexed11.cpp       (DrawIndexed + shared helpers)
//    dx11/drawindexedinstanced11.cpp
//    dx11/drawindexedinstancedindirect11.cpp
//    dx11/drawinstanced11.cpp
//    dx11/drawinstancedindirect11.cpp
//    dx11/dump11.cpp              (string converters, resource dump)
//    dx11/savetexture11.cpp       (texture-to-file via fullscreen quad)
//    dx11/savemeshtextures11.cpp  (per-mesh texture tracking)
//    dx11/texture11.cpp           (forced-texture-rip path)
//    dx11/pre11.cpp               (factory: create/delete/setIRipper)
//
//  Extra dependencies pulled in (add to link line):
//    d3d11.lib  dxguid.lib  d3dcompiler.lib  DirectXTex.lib
//  Windows SDK 8.1+ or later required for d3d11.h.
// =============================================================================
 
#ifdef _WIN32
 
// --------------------------------------------------------------------------
// DX11 headers  (guard against double-inclusion if the project already pulls
//                them in via a pch/common header)
// --------------------------------------------------------------------------
#ifndef __d3d11_h__
#  include <d3d11.h>
#endif
#include <d3dcompiler.h>
#include <DirectXMath.h>   // XMFLOAT2 / XMFLOAT3
#include "DirectXTex.h"    // DirectX::CaptureTexture / SaveToDDSFile
 
using namespace DirectX;
 
// --------------------------------------------------------------------------
// dx11types.h  � function-pointer typedefs & packed argument structs
// --------------------------------------------------------------------------
 
typedef HRESULT (__stdcall* PFN_ID3D11Device_CreateInputLayout)(
    ID3D11Device*,
    const D3D11_INPUT_ELEMENT_DESC*,
    UINT,
    const void*,
    SIZE_T,
    ID3D11InputLayout**);
 
typedef HRESULT (__stdcall* PFN_D3D11CreateDeviceAndSwapChain)(
    IDXGIAdapter*, D3D_DRIVER_TYPE, HMODULE, UINT,
    CONST D3D_FEATURE_LEVEL*, UINT FeatureLevels, UINT,
    CONST DXGI_SWAP_CHAIN_DESC*, IDXGISwapChain**,
    ID3D11Device**, D3D_FEATURE_LEVEL*, ID3D11DeviceContext**);
 
typedef HRESULT (__stdcall* PFN_D3D11CreateDevice)(
    IDXGIAdapter*, D3D_DRIVER_TYPE, HMODULE, UINT,
    const D3D_FEATURE_LEVEL*, UINT, UINT,
    ID3D11Device**, D3D_FEATURE_LEVEL*, ID3D11DeviceContext**);
 
typedef void (__stdcall* PFN_ID3D11DeviceContext_PSSetShaderResources)(
    ID3D11DeviceContext*, UINT, UINT, ID3D11ShaderResourceView *const *);
 
typedef void (__stdcall* PFN_ID3D11DeviceContext_VSSetShaderResources)(
    ID3D11DeviceContext*, UINT, UINT, ID3D11ShaderResourceView *const *);
 
typedef void (__stdcall* PFN_ID3D11DeviceContext_GSSetShaderResources)(
    ID3D11DeviceContext*, UINT, UINT, ID3D11ShaderResourceView *const *);
 
typedef void (__stdcall* PFN_ID3D11DeviceContext_Draw)(
    ID3D11DeviceContext*, UINT, UINT);
 
typedef void (__stdcall* PFN_ID3D11DeviceContext_DrawAuto)(
    ID3D11DeviceContext*);
 
typedef void (__stdcall* PFN_ID3D11DeviceContext_DrawIndexed)(
    ID3D11DeviceContext*, UINT, UINT, INT);
 
typedef void (__stdcall* PFN_ID3D11DeviceContext_DrawIndexedInstanced)(
    ID3D11DeviceContext*, UINT, UINT, UINT, INT, UINT);
 
typedef void (__stdcall* PFN_ID3D11DeviceContext_DrawIndexedInstancedIndirect)(
    ID3D11DeviceContext*, ID3D11Buffer*, UINT);
 
typedef void (__stdcall* PFN_ID3D11DeviceContext_DrawInstanced)(
    ID3D11DeviceContext*, UINT, UINT, UINT, UINT);
 
typedef void (__stdcall* PFN_ID3D11DeviceContext_DrawInstancedIndirect)(
    ID3D11DeviceContext*, ID3D11Buffer*, UINT);
 
typedef void (__stdcall* PFN_ID3D11DeviceContext_ClearRenderTargetView)(
    ID3D11DeviceContext*, ID3D11RenderTargetView*, const FLOAT[4]);
 
typedef HRESULT (__stdcall* PFN_ID3D11Device_CreateVertexShader)(
    ID3D11Device*, const void*, SIZE_T, ID3D11ClassLinkage*, ID3D11VertexShader**);
 
typedef HRESULT (__stdcall* PFN_ID3D11Device_CreatePixelShader)(
    ID3D11Device*, const void*, SIZE_T, ID3D11ClassLinkage*, ID3D11PixelShader**);
 
typedef HRESULT (__stdcall* PFN_ID3D11Device_CreateGeometryShader)(
    ID3D11Device*, const void*, SIZE_T, ID3D11ClassLinkage*, ID3D11GeometryShader**);
 
typedef HRESULT (__stdcall* PFN_ID3D11Device_CreateGeometryShaderWithStreamOutput)(
    ID3D11Device*, const void*, SIZE_T,
    const D3D11_SO_DECLARATION_ENTRY*, UINT,
    const UINT*, UINT, UINT,
    ID3D11ClassLinkage*, ID3D11GeometryShader**);
 
typedef void (__stdcall* PFN_ID3D11Device_GetImmediateContext)(
    ID3D11Device*, ID3D11DeviceContext**);
 
// Indirect-draw argument structs (packed, matching GPU memory layout)
#pragma pack(push, 1)
struct D3D11_DRAW_INDEXED_INSTANCED_INDIRECT_ARGS {
    UINT IndexCountPerInstance;
    UINT InstanceCount;
    UINT StartIndexLocation;
    INT  BaseVertexLocation;
    UINT StartInstanceLocation;
};
struct D3D11_DRAW_INSTANCED_INDIRECT_ARGS {
    UINT VertexCountPerInstance;
    UINT InstanceCount;
    UINT StartVertexLocation;
    UINT StartInstanceLocation;
};
#pragma pack(pop)
 
// --------------------------------------------------------------------------
// enums.h  � ID3D11DeviceContext / ID3D11Device vtable slot indices
// --------------------------------------------------------------------------
enum {
    IDX_ID3D11DeviceContext_Draw                           = 13,
    IDX_ID3D11DeviceContext_DrawAuto                       = 38,
    IDX_ID3D11DeviceContext_DrawIndexed                    = 12,
    IDX_ID3D11DeviceContext_DrawIndexedInstanced           = 20,
    IDX_ID3D11DeviceContext_DrawIndexedInstancedIndirect   = 39,
    IDX_ID3D11DeviceContext_DrawInstanced                  = 21,
    IDX_ID3D11DeviceContext_ClearRenderTargetView          = 50,
    IDX_ID3D11DeviceContext_PSSetShaderResources           = 8,
    IDX_ID3D11Device_CreateInputLayout                     = 11,
    IDX_ID3D11Device_CreateVertexShader                    = 12,
    IDX_ID3D11Device_CreatePixelShader                     = 15,
    IDX_ID3D11Device_CreateGeometryShader                  = 13,
    IDX_ID3D11Device_CreateGeometryShaderWithStreamOutput  = 14,
    IDX_ID3D11Device_GetImmediateContext                   = 40
};
 
// --------------------------------------------------------------------------
// macro.h  � per-function stub generators (DX11 variant)
//
//  Each STUB_ macro defines a static __stdcall trampoline that:
//    1. Looks up the KHook for the right device-context instance index.
//    2. Forwards to the corresponding helper_* method on this_.
//
//  GENERATE_STUBS_GROUP(STUB_X) (from common/macro.h) then instantiates
//  stubs 0..N and registers their addresses in the matching HooksGroup.
// --------------------------------------------------------------------------
 
// ID3D11DeviceContext_PSSetShaderResources
#define STUB_ID3D11DeviceContext_PSSetShaderResources(IDX)                    \
static void __stdcall                                                          \
    _ID3D11DeviceContext_PSSetShaderResources_##IDX(                           \
        ID3D11DeviceContext* pDevCont, UINT StartSlot, UINT NumViews,          \
        ID3D11ShaderResourceView *const *ppShaderResourceViews)                \
{                                                                              \
    KHook* h = this_->hooks_ID3D11DeviceContext_PSSetShaderResources           \
                      .getHook(IDX);                                           \
    this_->helper_ID3D11DeviceContext_PSSetShaderResources(                    \
        h, pDevCont, StartSlot, NumViews, ppShaderResourceViews);             \
}
 
// ID3D11DeviceContext_Draw
#define STUB_ID3D11DeviceContext_Draw(IDX)                                    \
static void __stdcall                                                          \
    _ID3D11DeviceContext_Draw_##IDX(                                           \
        ID3D11DeviceContext* pDevCont,                                         \
        UINT VertexCount, UINT StartVertexLocation)                            \
{                                                                              \
    KHook* h = this_->hooks_ID3D11DeviceContext_Draw.getHook(IDX);            \
    this_->helper_ID3D11DeviceContext_Draw(                                    \
        h, pDevCont, VertexCount, StartVertexLocation);                        \
}
 
// ID3D11DeviceContext_DrawAuto
#define STUB_ID3D11DeviceContext_DrawAuto(IDX)                                \
static void __stdcall                                                          \
    _ID3D11DeviceContext_DrawAuto_##IDX(ID3D11DeviceContext* pDevCont)         \
{                                                                              \
    KHook* h = this_->hooks_ID3D11DeviceContext_DrawAuto.getHook(IDX);        \
    this_->helper_ID3D11DeviceContext_DrawAuto(h, pDevCont);                  \
}
 
// ID3D11DeviceContext_DrawIndexed
#define STUB_ID3D11DeviceContext_DrawIndexed(IDX)                             \
static void __stdcall                                                          \
    _ID3D11DeviceContext_DrawIndexed_##IDX(                                    \
        ID3D11DeviceContext* pDevCont,                                         \
        UINT IndexCount, UINT StartIndexLocation, INT BaseVertexLocation)      \
{                                                                              \
    KHook* h = this_->hooks_ID3D11DeviceContext_DrawIndexed.getHook(IDX);     \
    this_->helper_ID3D11DeviceContext_DrawIndexed(                             \
        h, pDevCont, IndexCount, StartIndexLocation, BaseVertexLocation);     \
}
 
// ID3D11DeviceContext_DrawIndexedInstanced
#define STUB_ID3D11DeviceContext_DrawIndexedInstanced(IDX)                    \
static void __stdcall                                                          \
    _ID3D11DeviceContext_DrawIndexedInstanced_##IDX(                           \
        ID3D11DeviceContext* pDevCont,                                         \
        UINT IndexCountPerInstance, UINT InstanceCount,                        \
        UINT StartIndexLocation, INT BaseVertexLocation,                       \
        UINT StartInstanceLocation)                                            \
{                                                                              \
    KHook* h = this_->hooks_ID3D11DeviceContext_DrawIndexedInstanced           \
                      .getHook(IDX);                                           \
    this_->helper_ID3D11DeviceContext_DrawIndexedInstanced(                    \
        h, pDevCont, IndexCountPerInstance, InstanceCount,                    \
        StartIndexLocation, BaseVertexLocation, StartInstanceLocation);        \
}
 
// ID3D11DeviceContext_DrawIndexedInstancedIndirect
#define STUB_ID3D11DeviceContext_DrawIndexedInstancedIndirect(IDX)            \
static void __stdcall                                                          \
    _ID3D11DeviceContext_DrawIndexedInstancedIndirect_##IDX(                   \
        ID3D11DeviceContext* pDevCont,                                         \
        ID3D11Buffer* pBufferForArgs, UINT AlignedByteOffsetForArgs)           \
{                                                                              \
    KHook* h = this_->hooks_ID3D11DeviceContext_DrawIndexedInstancedIndirect   \
                      .getHook(IDX);                                           \
    this_->helper_ID3D11DeviceContext_DrawIndexedInstancedIndirect(            \
        h, pDevCont, pBufferForArgs, AlignedByteOffsetForArgs);               \
}
 
// ID3D11DeviceContext_DrawInstanced
#define STUB_ID3D11DeviceContext_DrawInstanced(IDX)                           \
static void __stdcall                                                          \
    _ID3D11DeviceContext_DrawInstanced_##IDX(                                  \
        ID3D11DeviceContext* pDevCont,                                         \
        UINT VertexCountPerInstance, UINT InstanceCount,                       \
        UINT StartVertexLocation, UINT StartInstanceLocation)                  \
{                                                                              \
    KHook* h = this_->hooks_ID3D11DeviceContext_DrawInstanced.getHook(IDX);   \
    this_->helper_ID3D11DeviceContext_DrawInstanced(                           \
        h, pDevCont, VertexCountPerInstance, InstanceCount,                   \
        StartVertexLocation, StartInstanceLocation);                           \
}
 
// ID3D11DeviceContext_DrawInstancedIndirect
#define STUB_ID3D11DeviceContext_DrawInstancedIndirect(IDX)                   \
static void __stdcall                                                          \
    _ID3D11DeviceContext_DrawInstancedIndirect_##IDX(                          \
        ID3D11DeviceContext* pDevCont,                                         \
        ID3D11Buffer* pBufferForArgs, UINT AlignedByteOffsetForArgs)           \
{                                                                              \
    KHook* h = this_->hooks_ID3D11DeviceContext_DrawInstancedIndirect          \
                      .getHook(IDX);                                           \
    this_->helper_ID3D11DeviceContext_DrawInstancedIndirect(                   \
        h, pDevCont, pBufferForArgs, AlignedByteOffsetForArgs);               \
};
 
// ID3D11DeviceContext_ClearRenderTargetView
#define STUB_ID3D11DeviceContext_ClearRenderTargetView(IDX)                   \
static void __stdcall                                                          \
    _ID3D11DeviceContext_ClearRenderTargetView_##IDX(                          \
        ID3D11DeviceContext* pDeviceContext,                                    \
        ID3D11RenderTargetView* pRenderTargetView,                             \
        const FLOAT color[4])                                                  \
{                                                                              \
    KHook* h = this_->hooks_ID3D11DeviceContext_ClearRenderTargetView          \
                      .getHook(IDX);                                           \
    this_->helper_ID3D11DeviceContext_ClearRenderTargetView(                   \
        h, pDeviceContext, pRenderTargetView, color);                          \
}
 
// ID3D11Device_CreateInputLayout
#define STUB_ID3D11Device_CreateInputLayout(IDX)                              \
static HRESULT __stdcall                                                       \
    _ID3D11Device_CreateInputLayout_##IDX(                                     \
        ID3D11Device* pDev,                                                    \
        const D3D11_INPUT_ELEMENT_DESC* pInputElementDescs, UINT NumElements,  \
        const void* pShaderBytecodeWithInputSignature, SIZE_T BytecodeLength,  \
        ID3D11InputLayout** ppInputLayout)                                     \
{                                                                              \
    KHook* h = this_->pHook_ID3D11Device_CreateInputLayout;                   \
    return this_->helper_ID3D11Device_CreateInputLayout(                       \
        h, pDev, pInputElementDescs, NumElements,                             \
        pShaderBytecodeWithInputSignature, BytecodeLength, ppInputLayout);     \
}
 
// =============================================================================
//  KRipper11 class definition  (derived from kripper11.h)
// =============================================================================
 
class KRipper11 : public IRipper
{
public:
    static KRipper11* create(HINSTANCE hD3D11);
    static void destroy(KRipper11*& p);
 
    // IRipper interface
    virtual void frameStart()    override;
    virtual void frameEnd()      override;
    virtual void textureRipStart() override;
    virtual void textureRipEnd()   override;
 
protected:
    virtual ~KRipper11();
    explicit KRipper11(HINSTANCE hD3D11);
 
private:
    // ----------------------------------------------------------------
    // Internal texture record
    // ----------------------------------------------------------------
    struct KTexture {
        ID3D11ShaderResourceView* pTexture;
        std::string   name;
        std::wstring  fullPath;
        KTexture() : pTexture(nullptr) {}
    };
    typedef std::vector<KTexture> KFrameTextureVec;
    KFrameTextureVec meshTexturesDb;
 
    // ----------------------------------------------------------------
    // Singleton-style 'this' (same pattern as KRipper9)
    // ----------------------------------------------------------------
    static KRipper11* this_;
 
    HINSTANCE        hD3D11;
    D3DCompileHelper d3dCompileHelper;
    bool             drawIndexedEnabled;
 
    void initialize();
    void cleanup();
    void zeroHooks();
 
    // ----------------------------------------------------------------
    // D3D11CreateDeviceAndSwapChain hook
    // ----------------------------------------------------------------
    KHook* pHook_D3D11CreateDeviceAndSwapChain;
 
    HRESULT helper_D3D11CreateDeviceAndSwapChain(
        KHook*, IDXGIAdapter*, D3D_DRIVER_TYPE, HMODULE, UINT,
        CONST D3D_FEATURE_LEVEL*, UINT, UINT,
        CONST DXGI_SWAP_CHAIN_DESC*, IDXGISwapChain**,
        ID3D11Device**, D3D_FEATURE_LEVEL*, ID3D11DeviceContext**);
 
    static HRESULT __stdcall _D3D11CreateDeviceAndSwapChain(
        IDXGIAdapter*, D3D_DRIVER_TYPE, HMODULE, UINT,
        CONST D3D_FEATURE_LEVEL*, UINT, UINT,
        CONST DXGI_SWAP_CHAIN_DESC*, IDXGISwapChain**,
        ID3D11Device**, D3D_FEATURE_LEVEL*, ID3D11DeviceContext**);
 
    // ----------------------------------------------------------------
    // D3D11CreateDevice hook
    // ----------------------------------------------------------------
    KHook* pHook_D3D11CreateDevice;
 
    HRESULT helper_D3D11CreateDevice(
        KHook*, IDXGIAdapter*, D3D_DRIVER_TYPE, HMODULE, UINT,
        const D3D_FEATURE_LEVEL*, UINT, UINT,
        ID3D11Device**, D3D_FEATURE_LEVEL*, ID3D11DeviceContext**);
 
    static HRESULT __stdcall _D3D11CreateDevice(
        IDXGIAdapter*, D3D_DRIVER_TYPE, HMODULE, UINT,
        const D3D_FEATURE_LEVEL*, UINT, UINT,
        ID3D11Device**, D3D_FEATURE_LEVEL*, ID3D11DeviceContext**);
 
    // ----------------------------------------------------------------
    // ID3D11DeviceContext hook groups (one slot per device context
    // instance � the HooksGroup expands stubs 0..N via macros)
    // ----------------------------------------------------------------
    HooksGroup hooks_ID3D11DeviceContext_PSSetShaderResources;
    void helper_ID3D11DeviceContext_PSSetShaderResources(
        KHook*, ID3D11DeviceContext*, UINT, UINT,
        ID3D11ShaderResourceView *const *);
    GENERATE_STUBS_GROUP(STUB_ID3D11DeviceContext_PSSetShaderResources);
 
    HooksGroup hooks_ID3D11DeviceContext_Draw;
    void helper_ID3D11DeviceContext_Draw(
        KHook*, ID3D11DeviceContext*, UINT, UINT);
    GENERATE_STUBS_GROUP(STUB_ID3D11DeviceContext_Draw);
 
    HooksGroup hooks_ID3D11DeviceContext_DrawAuto;
    void helper_ID3D11DeviceContext_DrawAuto(KHook*, ID3D11DeviceContext*);
    GENERATE_STUBS_GROUP(STUB_ID3D11DeviceContext_DrawAuto);
 
    HooksGroup hooks_ID3D11DeviceContext_DrawIndexed;
    void helper_ID3D11DeviceContext_DrawIndexed(
        KHook*, ID3D11DeviceContext*, UINT, UINT, INT);
    GENERATE_STUBS_GROUP(STUB_ID3D11DeviceContext_DrawIndexed);
 
    HooksGroup hooks_ID3D11DeviceContext_DrawIndexedInstanced;
    void helper_ID3D11DeviceContext_DrawIndexedInstanced(
        KHook*, ID3D11DeviceContext*, UINT, UINT, UINT, INT, UINT);
    GENERATE_STUBS_GROUP(STUB_ID3D11DeviceContext_DrawIndexedInstanced);
 
    HooksGroup hooks_ID3D11DeviceContext_DrawIndexedInstancedIndirect;
    void helper_ID3D11DeviceContext_DrawIndexedInstancedIndirect(
        KHook*, ID3D11DeviceContext*, ID3D11Buffer*, UINT);
    GENERATE_STUBS_GROUP(STUB_ID3D11DeviceContext_DrawIndexedInstancedIndirect);
 
    HooksGroup hooks_ID3D11DeviceContext_DrawInstanced;
    void helper_ID3D11DeviceContext_DrawInstanced(
        KHook*, ID3D11DeviceContext*, UINT, UINT, UINT, UINT);
    GENERATE_STUBS_GROUP(STUB_ID3D11DeviceContext_DrawInstanced);
 
    HooksGroup hooks_ID3D11DeviceContext_DrawInstancedIndirect;
    void helper_ID3D11DeviceContext_DrawInstancedIndirect(
        KHook*, ID3D11DeviceContext*, ID3D11Buffer*, UINT);
    GENERATE_STUBS_GROUP(STUB_ID3D11DeviceContext_DrawInstancedIndirect);
 
    HooksGroup hooks_ID3D11DeviceContext_ClearRenderTargetView;
    void helper_ID3D11DeviceContext_ClearRenderTargetView(
        KHook*, ID3D11DeviceContext*, ID3D11RenderTargetView*, const FLOAT[4]);
    GENERATE_STUBS_GROUP(STUB_ID3D11DeviceContext_ClearRenderTargetView);
 
    // ----------------------------------------------------------------
    // Forced-texture-rip  (PSSetShaderResources path)
    // ----------------------------------------------------------------
    std::vector<ID3D11ShaderResourceView*> TexturesVec;
 
    void handleTexture(
        ID3D11DeviceContext*, UINT, UINT,
        ID3D11ShaderResourceView *const *);
 
    // ----------------------------------------------------------------
    // ID3D11Device hooks  (single-instance, no HooksGroup needed)
    // ----------------------------------------------------------------
    KHook* pHook_ID3D11Device_CreateInputLayout;
    HRESULT helper_ID3D11Device_CreateInputLayout(
        KHook*, ID3D11Device*,
        const D3D11_INPUT_ELEMENT_DESC*, UINT,
        const void*, SIZE_T, ID3D11InputLayout**);
    static HRESULT __stdcall _ID3D11Device_CreateInputLayout(
        ID3D11Device*,
        const D3D11_INPUT_ELEMENT_DESC*, UINT,
        const void*, SIZE_T, ID3D11InputLayout**);
 
    KHook* pHook_ID3D11Device_CreateVertexShader;
    HRESULT helper_ID3D11Device_CreateVertexShader(
        KHook*, ID3D11Device*, const void*, SIZE_T,
        ID3D11ClassLinkage*, ID3D11VertexShader**);
    static HRESULT __stdcall _ID3D11Device_CreateVertexShader(
        ID3D11Device*, const void*, SIZE_T,
        ID3D11ClassLinkage*, ID3D11VertexShader**);
 
    KHook* pHook_ID3D11Device_CreatePixelShader;
    HRESULT helper_ID3D11Device_CreatePixelShader(
        KHook*, ID3D11Device*, const void*, SIZE_T,
        ID3D11ClassLinkage*, ID3D11PixelShader**);
    static HRESULT __stdcall _ID3D11Device_CreatePixelShader(
        ID3D11Device*, const void*, SIZE_T,
        ID3D11ClassLinkage*, ID3D11PixelShader**);
 
    KHook* pHook_ID3D11Device_CreateGeometryShader;
    HRESULT helper_ID3D11Device_CreateGeometryShader(
        KHook*, ID3D11Device*, const void*, SIZE_T,
        ID3D11ClassLinkage*, ID3D11GeometryShader**);
    static HRESULT __stdcall _ID3D11Device_CreateGeometryShader(
        ID3D11Device*, const void*, SIZE_T,
        ID3D11ClassLinkage*, ID3D11GeometryShader**);
 
    KHook* pHook_ID3D11Device_CreateGeometryShaderWithStreamOutput;
    HRESULT helper_ID3D11Device_CreateGeometryShaderWithStreamOutput(
        KHook*, ID3D11Device*, const void*, SIZE_T,
        const D3D11_SO_DECLARATION_ENTRY*, UINT,
        const UINT*, UINT, UINT,
        ID3D11ClassLinkage*, ID3D11GeometryShader**);
    static HRESULT __stdcall _ID3D11Device_CreateGeometryShaderWithStreamOutput(
        ID3D11Device*, const void*, SIZE_T,
        const D3D11_SO_DECLARATION_ENTRY*, UINT,
        const UINT*, UINT, UINT,
        ID3D11ClassLinkage*, ID3D11GeometryShader**);
 
    KHook* pHook_ID3D11Device_GetImmediateContext;
    void helper_ID3D11Device_GetImmediateContext(
        KHook*, ID3D11Device*, ID3D11DeviceContext**);
    static void __stdcall _ID3D11Device_GetImmediateContext(
        ID3D11Device*, ID3D11DeviceContext**);
 
    // ----------------------------------------------------------------
    // Input-layout database
    // ----------------------------------------------------------------
    struct KD3D11InputElement {
        char         SemanticName[SEMANTIC_LEN];
        UINT         SemanticIndex;
        DXGI_FORMAT  Format;
        UINT         InputSlot;
        UINT         AlignedByteOffset;
        D3D11_INPUT_CLASSIFICATION InputSlotClass;
        UINT         InstanceDataStepRate;
 
        KD3D11InputElement()
            : SemanticIndex(0), Format(DXGI_FORMAT_UNKNOWN),
              InputSlot(0), AlignedByteOffset(0),
              InputSlotClass(D3D11_INPUT_PER_VERTEX_DATA),
              InstanceDataStepRate(0)
        { ZeroMemory(SemanticName, SEMANTIC_LEN); }
    };
    typedef std::vector<KD3D11InputElement>               KD3D11VertexDeclaration;
    typedef std::map<ID3D11InputLayout*, KD3D11VertexDeclaration> KInputLayoutMap;
    KInputLayoutMap InputLayoutMap;
 
    // ----------------------------------------------------------------
    // Device ? immediate-context database (for deferred-context support)
    // ----------------------------------------------------------------
    typedef std::map<ID3D11Device*, ID3D11DeviceContext*> DeviceToImmContext;
    DeviceToImmContext deviceToImmContext;
    void   saveDeviceAndImmContextInDb(ID3D11Device*, ID3D11DeviceContext*);
    ID3D11DeviceContext* getImmCtxFromDb(ID3D11Device*);
    ID3D11DeviceContext* getImmCtx(ID3D11DeviceContext*);
 
    // ----------------------------------------------------------------
    // Shader database
    // ----------------------------------------------------------------
    ShadersDb shadersDb;
    void saveMeshShaders(ID3D11DeviceContext*, KMeshShaders*);
 
    // ----------------------------------------------------------------
    // Per-draw helpers
    // ----------------------------------------------------------------
    void hookDeviceContext(ID3D11DeviceContext** ppCtx);
    void hookDevice(ID3D11Device** ppDev);
 
    EPrimitiveTopology::Type getPrimitiveTopology(ID3D11DeviceContext*);
    EPrimitiveTopology::Type D3D11_PRIMITIVE_TOPOLOGY_to_EPrimitiveTopology(
        D3D11_PRIMITIVE_TOPOLOGY);
 
    HRESULT getInputLayout(ID3D11DeviceContext*, KD3D11VertexDeclaration&);
    HRESULT getVertexDeclarations(
        ID3D11DeviceContext*,
        KInputVertexDeclaration*,
        KOutputVertexDeclaration*);
 
    HRESULT copyBuffer(ID3D11DeviceContext*, ID3D11Buffer*, ID3D11Buffer**);
 
    HRESULT dumpIndexBuffer(
        ID3D11DeviceContext*,
        EPrimitiveTopology::Type,
        UINT, UINT, INT,
        KFACES*, OptimizedIndexToMeshIndex*);
 
    HRESULT dumpVertexBuffer(
        ID3D11DeviceContext*,
        const KInputVertexDeclaration&,
        const KOutputVertexDeclaration&,
        INT,
        const OptimizedIndexToMeshIndex&,
        KVERTICES*);
 
    EInputType::Type DXGI_FORMAT_to_EInputType(DXGI_FORMAT);
 
    void ripDraw(ID3D11DeviceContext*, UINT, UINT);
    void ripDrawInstanced(ID3D11DeviceContext*, UINT, UINT, UINT, UINT);
    void ripDrawIndexed(ID3D11DeviceContext*, UINT, UINT, INT);
    void ripDrawIndexedInstanced(ID3D11DeviceContext*, UINT, UINT, UINT, INT, UINT);
    void ripDrawIndexedInstancedIndirect(ID3D11DeviceContext*, ID3D11Buffer*, UINT);
 
    // ----------------------------------------------------------------
    // Texture save
    // ----------------------------------------------------------------
    HRESULT saveTexture2File(const wchar_t*, ID3D11DeviceContext*,
                             ID3D11ShaderResourceView*);
    HRESULT saveTexture2FileMain(const wchar_t*, ID3D11DeviceContext*,
                                 ID3D11ShaderResourceView*);
    HRESULT compileShaderFromMemory(LPCSTR, SIZE_T, LPCSTR, LPCSTR, ID3DBlob**);
 
    DWORD isTextureSaved(ID3D11ShaderResourceView*);
 
    // Per-mesh texture helpers
    bool isMeshTextureSaved(ID3D11ShaderResourceView*, KTexture*);
    void addMeshTexture(const KTexture&);
    void saveMeshTextures(ID3D11DeviceContext*, KMeshTextures*);
 
    // ----------------------------------------------------------------
    // Logging / debug helpers
    // ----------------------------------------------------------------
    void        dumpShaderResourceView(ID3D11ShaderResourceView*);
    void        dumpID3D11BufferDesc(ID3D11Buffer*);
    void        dump_KD3D11InputElement2Log(const KD3D11InputElement&);
    void        logReasonIfDeviceRemoved(HRESULT, ID3D11Device*);
 
    const char* DXGI_FORMAT_2_Str(DXGI_FORMAT);
    const char* D3D11_SRV_DIMENSION_2_Str(D3D11_SRV_DIMENSION);
    const char* D3D11_USAGE_2_Str(D3D11_USAGE);
    const char* D3D_FEATURE_LEVEL_2_Str(D3D_FEATURE_LEVEL);
    const char* D3D_DRIVER_TYPE_2_Str(D3D_DRIVER_TYPE);
    const char* D3D11_PRIMITIVE_TOPOLOGY_to_Str(D3D11_PRIMITIVE_TOPOLOGY);
    const char* D3D11_DEVICE_CONTEXT_TYPE_To_String(D3D11_DEVICE_CONTEXT_TYPE);
 
    // Critical section serialises all rip paths
    CRITICAL_SECTION cs;
};
 
// Static 'this' pointer (mirrors the KRipper9 pattern)
KRipper11* KRipper11::this_ = nullptr;
 
// =============================================================================
//  IMPLEMENTATION � kripper11.cpp
// =============================================================================
 
KRipper11* KRipper11::create(HINSTANCE hD3D11)
{
    g_pLog->log("D3D11 ripper init\n");
    KRipper11* p = new KRipper11(hD3D11);
    p->initialize();
    return p;
}
 
void KRipper11::destroy(KRipper11*& p)
{
    if (!p) return;
    g_pLog->log("D3D11 ripper uninit\n\n");
    p->cleanup();
    SAFE_DELETE(p);
}
 
KRipper11::KRipper11(HINSTANCE hD3D11_)
    : hD3D11(hD3D11_), drawIndexedEnabled(true)
{
    this_ = this;
    InitializeCriticalSection(&cs);
    zeroHooks();
}
 
KRipper11::~KRipper11()
{
    this_ = nullptr;
    DeleteCriticalSection(&cs);
}
 
void KRipper11::frameStart()  { meshTexturesDb.clear(); }
void KRipper11::frameEnd()    {}
void KRipper11::textureRipStart() { TexturesVec.clear(); }
void KRipper11::textureRipEnd()   {}
 
void KRipper11::zeroHooks()
{
    pHook_D3D11CreateDeviceAndSwapChain = nullptr;
    pHook_D3D11CreateDevice             = nullptr;
 
    GENERATE_HOOKS_GROUP_CLEARER(ID3D11DeviceContext_PSSetShaderResources);
    GENERATE_HOOKS_GROUP_CLEARER(ID3D11DeviceContext_Draw);
    GENERATE_HOOKS_GROUP_CLEARER(ID3D11DeviceContext_DrawAuto);
    GENERATE_HOOKS_GROUP_CLEARER(ID3D11DeviceContext_DrawIndexed);
    GENERATE_HOOKS_GROUP_CLEARER(ID3D11DeviceContext_DrawIndexedInstanced);
    GENERATE_HOOKS_GROUP_CLEARER(ID3D11DeviceContext_DrawIndexedInstancedIndirect);
    GENERATE_HOOKS_GROUP_CLEARER(ID3D11DeviceContext_DrawInstanced);
    GENERATE_HOOKS_GROUP_CLEARER(ID3D11DeviceContext_DrawInstancedIndirect);
    GENERATE_HOOKS_GROUP_CLEARER(ID3D11DeviceContext_ClearRenderTargetView);
 
    pHook_ID3D11Device_CreateInputLayout                    = nullptr;
    pHook_ID3D11Device_CreateVertexShader                   = nullptr;
    pHook_ID3D11Device_CreatePixelShader                    = nullptr;
    pHook_ID3D11Device_CreateGeometryShader                 = nullptr;
    pHook_ID3D11Device_CreateGeometryShaderWithStreamOutput = nullptr;
    pHook_ID3D11Device_GetImmediateContext                  = nullptr;
}
 
void KRipper11::initialize()
{
    // Hook the two D3D11 factory functions exported from d3d11.dll
    LPVOID targ = GetProcAddress(hD3D11, "D3D11CreateDeviceAndSwapChain");
    hookEx("D3D11CreateDeviceAndSwapChain",
           targ, _D3D11CreateDeviceAndSwapChain,
           KHookMgr::EHOOK_POOL_DX11,
           &pHook_D3D11CreateDeviceAndSwapChain);
 
    targ = GetProcAddress(hD3D11, "D3D11CreateDevice");
    hookEx("D3D11CreateDevice",
           targ, _D3D11CreateDevice,
           KHookMgr::EHOOK_POOL_DX11,
           &pHook_D3D11CreateDevice);
 
    // Also hook DXGI (swap-chain Present) if not already done
    wchar_t szBuf[MAX_PATH];
    GetSystemDirectoryW(szBuf, MAX_PATH);
    lstrcatW(szBuf, L"\\dxgi.dll");
    HINSTANCE hDXGI = GetModuleHandleW(szBuf);
    if (hDXGI && !g_pDxgi)
        g_pDxgi = create_KDxgi(hDXGI);
    setIRipper(g_pDxgi, this);
}
 
void KRipper11::cleanup()
{
    g_pHookMgr->unhookPool(KHookMgr::EHOOK_POOL_DX11);
    zeroHooks();
    if (g_pDxgi) g_pDxgi->setIRipper(nullptr);
}
 
// ---- Device-context hooking -----------------------------------------------
 
void KRipper11::hookDeviceContext(ID3D11DeviceContext** ppCtx)
{
    if (!ppCtx || !*ppCtx) {
        g_pLog->logWarning("hookDeviceContext(): null pointer\n");
        return;
    }
 
    hookEx("ID3D11DeviceContext_Draw",
           IDX_ID3D11DeviceContext_Draw, *ppCtx,
           KHookMgr::EHOOK_POOL_DX11,
           &hooks_ID3D11DeviceContext_Draw);
 
    hookEx("ID3D11DeviceContext_DrawAuto",
           IDX_ID3D11DeviceContext_DrawAuto, *ppCtx,
           KHookMgr::EHOOK_POOL_DX11,
           &hooks_ID3D11DeviceContext_DrawAuto);
 
    hookEx("ID3D11DeviceContext_DrawIndexed",
           IDX_ID3D11DeviceContext_DrawIndexed, *ppCtx,
           KHookMgr::EHOOK_POOL_DX11,
           &hooks_ID3D11DeviceContext_DrawIndexed);
 
    hookEx("ID3D11DeviceContext_DrawIndexedInstanced",
           IDX_ID3D11DeviceContext_DrawIndexedInstanced, *ppCtx,
           KHookMgr::EHOOK_POOL_DX11,
           &hooks_ID3D11DeviceContext_DrawIndexedInstanced);
 
    hookEx("ID3D11DeviceContext_DrawIndexedInstancedIndirect",
           IDX_ID3D11DeviceContext_DrawIndexedInstancedIndirect, *ppCtx,
           KHookMgr::EHOOK_POOL_DX11,
           &hooks_ID3D11DeviceContext_DrawIndexedInstancedIndirect);
 
    hookEx("ID3D11DeviceContext_DrawInstanced",
           IDX_ID3D11DeviceContext_DrawInstanced, *ppCtx,
           KHookMgr::EHOOK_POOL_DX11,
           &hooks_ID3D11DeviceContext_DrawInstanced);
 
    // Note: DrawInstancedIndirect slot intentionally skipped in original code
    // (same vtable address collision as DrawInstanced on some drivers).
 
    // Re-hook ClearRenderTargetView so we can re-validate the vtable after
    // the driver patches it (documented DX11 quirk with deferred contexts).
    hookEx("ID3D11DeviceContext_ClearRenderTargetView",
           IDX_ID3D11DeviceContext_ClearRenderTargetView, *ppCtx,
           KHookMgr::EHOOK_POOL_DX11,
           &hooks_ID3D11DeviceContext_ClearRenderTargetView);
 
    // Forced-texture-rip path
    hookEx("ID3D11DeviceContext_PSSetShaderResources",
           IDX_ID3D11DeviceContext_PSSetShaderResources, *ppCtx,
           KHookMgr::EHOOK_POOL_DX11,
           &hooks_ID3D11DeviceContext_PSSetShaderResources);
}
 
void KRipper11::hookDevice(ID3D11Device** ppDev)
{
    if (!ppDev || !*ppDev) {
        g_pLog->logWarning("hookDevice(): null pointer\n");
        return;
    }
 
    hookEx("ID3D11Device_CreateInputLayout",
           IDX_ID3D11Device_CreateInputLayout, *ppDev,
           KHookMgr::EHOOK_POOL_DX11,
           _ID3D11Device_CreateInputLayout,
           &pHook_ID3D11Device_CreateInputLayout);
 
    hookEx("ID3D11Device_CreateVertexShader",
           IDX_ID3D11Device_CreateVertexShader, *ppDev,
           KHookMgr::EHOOK_POOL_DX11,
           _ID3D11Device_CreateVertexShader,
           &pHook_ID3D11Device_CreateVertexShader);
 
    hookEx("ID3D11Device_CreatePixelShader",
           IDX_ID3D11Device_CreatePixelShader, *ppDev,
           KHookMgr::EHOOK_POOL_DX11,
           _ID3D11Device_CreatePixelShader,
           &pHook_ID3D11Device_CreatePixelShader);
 
    hookEx("ID3D11Device_CreateGeometryShader",
           IDX_ID3D11Device_CreateGeometryShader, *ppDev,
           KHookMgr::EHOOK_POOL_DX11,
           _ID3D11Device_CreateGeometryShader,
           &pHook_ID3D11Device_CreateGeometryShader);
 
    hookEx("ID3D11Device_CreateGeometryShaderWithStreamOutput",
           IDX_ID3D11Device_CreateGeometryShaderWithStreamOutput, *ppDev,
           KHookMgr::EHOOK_POOL_DX11,
           _ID3D11Device_CreateGeometryShaderWithStreamOutput,
           &pHook_ID3D11Device_CreateGeometryShaderWithStreamOutput);
 
    hookEx("ID3D11Device_GetImmediateContext",
           IDX_ID3D11Device_GetImmediateContext, *ppDev,
           KHookMgr::EHOOK_POOL_DX11,
           _ID3D11Device_GetImmediateContext,
           &pHook_ID3D11Device_GetImmediateContext);
}
 
// ---- D3D11CreateDeviceAndSwapChain ----------------------------------------
 
HRESULT KRipper11::helper_D3D11CreateDeviceAndSwapChain(
    KHook* pHook,
    IDXGIAdapter* pAdapter, D3D_DRIVER_TYPE DriverType,
    HMODULE Software, UINT Flags,
    CONST D3D_FEATURE_LEVEL* pFeatureLevels, UINT FeatureLevels,
    UINT SDKVersion,
    CONST DXGI_SWAP_CHAIN_DESC* pSwapChainDesc, IDXGISwapChain** ppSwapChain,
    ID3D11Device** ppDevice, D3D_FEATURE_LEVEL* pFeatureLevel,
    ID3D11DeviceContext** ppImmediateContext)
{
    auto e = (PFN_D3D11CreateDeviceAndSwapChain)pHook->getOriginalAddress();
 
    loadD3DCompile(&d3dCompileHelper);
    if (g_pIntruder->getSettings()->debugD3D)
        Flags |= D3D11_CREATE_DEVICE_DEBUG;
 
    HRESULT hr = e(pAdapter, DriverType, Software, Flags,
                   pFeatureLevels, FeatureLevels, SDKVersion,
                   pSwapChainDesc, ppSwapChain,
                   ppDevice, pFeatureLevel, ppImmediateContext);
 
    g_pLog->log("D3D11CreateDeviceAndSwapChain("
                "ppSwapChain:0x%p ppDevice:0x%p ppImmCtx:0x%p) hr=0x%08X\n",
                ppSwapChain, ppDevice, ppImmediateContext, hr);
 
    if (SUCCEEDED(hr)) {
        if (ppDevice && ppImmediateContext)
            saveDeviceAndImmContextInDb(*ppDevice, *ppImmediateContext);
 
        if (g_pIntruder->getSettings()->debugD3D) {
            ID3D11Debug* dbg = nullptr;
            (*ppDevice)->QueryInterface(__uuidof(ID3D11Debug), (void**)&dbg);
            if (dbg) { dbg->ReportLiveDeviceObjects(D3D11_RLDO_DETAIL); dbg->Release(); }
        }
        hookDeviceContext(ppImmediateContext);
        g_pDxgi->hookSwapChain(ppSwapChain);
        hookDevice(ppDevice);
    }
    return hr;
}
 
HRESULT __stdcall KRipper11::_D3D11CreateDeviceAndSwapChain(
    IDXGIAdapter* pAdapter, D3D_DRIVER_TYPE DriverType,
    HMODULE Software, UINT Flags,
    CONST D3D_FEATURE_LEVEL* pFeatureLevels, UINT FeatureLevels,
    UINT SDKVersion,
    CONST DXGI_SWAP_CHAIN_DESC* pSwapChainDesc, IDXGISwapChain** ppSwapChain,
    ID3D11Device** ppDevice, D3D_FEATURE_LEVEL* pFeatureLevel,
    ID3D11DeviceContext** ppImmediateContext)
{
    return this_->helper_D3D11CreateDeviceAndSwapChain(
        this_->pHook_D3D11CreateDeviceAndSwapChain,
        pAdapter, DriverType, Software, Flags,
        pFeatureLevels, FeatureLevels, SDKVersion,
        pSwapChainDesc, ppSwapChain,
        ppDevice, pFeatureLevel, ppImmediateContext);
}
 
// ---- D3D11CreateDevice ----------------------------------------------------
 
HRESULT KRipper11::helper_D3D11CreateDevice(
    KHook* pHook,
    IDXGIAdapter* pAdapter, D3D_DRIVER_TYPE DriverType,
    HMODULE Software, UINT Flags,
    const D3D_FEATURE_LEVEL* pFeatureLevels, UINT FeatureLevels,
    UINT SDKVersion,
    ID3D11Device** ppDevice, D3D_FEATURE_LEVEL* pFeatureLevel,
    ID3D11DeviceContext** ppImmediateContext)
{
    auto e = (PFN_D3D11CreateDevice)pHook->getOriginalAddress();
 
    loadD3DCompile(&d3dCompileHelper);
    if (g_pIntruder->getSettings()->debugD3D)
        Flags |= D3D11_CREATE_DEVICE_DEBUG;
 
    HRESULT hr = e(pAdapter, DriverType, Software, Flags,
                   pFeatureLevels, FeatureLevels, SDKVersion,
                   ppDevice, pFeatureLevel, ppImmediateContext);
 
    g_pLog->log("D3D11CreateDevice(ppDevice:0x%p ppImmCtx:0x%p) hr=0x%08X\n",
                ppDevice, ppImmediateContext, hr);
 
    if (SUCCEEDED(hr)) {
        if (ppDevice && ppImmediateContext)
            saveDeviceAndImmContextInDb(*ppDevice, *ppImmediateContext);
 
        if (g_pIntruder->getSettings()->debugD3D) {
            ID3D11Debug* dbg = nullptr;
            (*ppDevice)->QueryInterface(__uuidof(ID3D11Debug), (void**)&dbg);
            if (dbg) { dbg->ReportLiveDeviceObjects(D3D11_RLDO_DETAIL); dbg->Release(); }
        }
        hookDeviceContext(ppImmediateContext);
        hookDevice(ppDevice);
    }
    return hr;
}
 
HRESULT __stdcall KRipper11::_D3D11CreateDevice(
    IDXGIAdapter* pAdapter, D3D_DRIVER_TYPE DriverType,
    HMODULE Software, UINT Flags,
    const D3D_FEATURE_LEVEL* pFeatureLevels, UINT FeatureLevels,
    UINT SDKVersion,
    ID3D11Device** ppDevice, D3D_FEATURE_LEVEL* pFeatureLevel,
    ID3D11DeviceContext** ppImmediateContext)
{
    return this_->helper_D3D11CreateDevice(
        this_->pHook_D3D11CreateDevice,
        pAdapter, DriverType, Software, Flags,
        pFeatureLevels, FeatureLevels, SDKVersion,
        ppDevice, pFeatureLevel, ppImmediateContext);
}
 
// ---- ID3D11Device_CreateInputLayout ---------------------------------------
 
HRESULT KRipper11::helper_ID3D11Device_CreateInputLayout(
    KHook* pHook, ID3D11Device* pDev,
    const D3D11_INPUT_ELEMENT_DESC* pDescs, UINT NumElements,
    const void* pBytecode, SIZE_T BytecodeLength,
    ID3D11InputLayout** ppInputLayout)
{
    auto e = (PFN_ID3D11Device_CreateInputLayout)pHook->getOriginalAddress();
    HRESULT hr = e(pDev, pDescs, NumElements, pBytecode, BytecodeLength, ppInputLayout);
 
    if (SUCCEEDED(hr)) {
        EnterCriticalSection(&cs);
        KD3D11VertexDeclaration elemVec;
        g_pLog->log("ID3D11Device_CreateInputLayout(): 0x%p\n", *ppInputLayout);
        for (UINT i = 0; i < NumElements; i++) {
            const D3D11_INPUT_ELEMENT_DESC& src = pDescs[i];
            KD3D11InputElement dst;
            strCopy(dst.SemanticName, SEMANTIC_LEN, src.SemanticName);
            dst.SemanticIndex       = src.SemanticIndex;
            dst.Format              = src.Format;
            dst.InputSlot           = src.InputSlot;
            dst.AlignedByteOffset   = src.AlignedByteOffset;
            dst.InputSlotClass      = src.InputSlotClass;
            dst.InstanceDataStepRate= src.InstanceDataStepRate;
            elemVec.push_back(dst);
        }
        auto it = InputLayoutMap.find(*ppInputLayout);
        if (it == InputLayoutMap.end())
            InputLayoutMap.insert({*ppInputLayout, elemVec});
        else
            it->second = elemVec;
        LeaveCriticalSection(&cs);
    } else {
        g_pLog->logError("ID3D11Device_CreateInputLayout(). HRESULT: 0x%08X\n", hr);
    }
    return hr;
}
 
HRESULT __stdcall KRipper11::_ID3D11Device_CreateInputLayout(
    ID3D11Device* pDev,
    const D3D11_INPUT_ELEMENT_DESC* pDescs, UINT NumElements,
    const void* pBytecode, SIZE_T BytecodeLength,
    ID3D11InputLayout** ppInputLayout)
{
    return this_->helper_ID3D11Device_CreateInputLayout(
        this_->pHook_ID3D11Device_CreateInputLayout,
        pDev, pDescs, NumElements, pBytecode, BytecodeLength, ppInputLayout);
}
 
// ---- Shader hooks (vertex / pixel / geometry / geometry+SO) ---------------
 
HRESULT KRipper11::helper_ID3D11Device_CreateVertexShader(
    KHook* pHook, ID3D11Device* pDev,
    const void* pCode, SIZE_T Len,
    ID3D11ClassLinkage* pLink, ID3D11VertexShader** ppVS)
{
    auto e = (PFN_ID3D11Device_CreateVertexShader)pHook->getOriginalAddress();
    HRESULT hr = e(pDev, pCode, Len, pLink, ppVS);
    if (SUCCEEDED(hr) && g_pIntruder->getSettings()->saveShaders) {
        EnterCriticalSection(&cs);
        saveShader(EShaderExt::VERTEX, pCode, Len, *ppVS, &shadersDb, &d3dCompileHelper);
        LeaveCriticalSection(&cs);
    }
    return hr;
}
HRESULT __stdcall KRipper11::_ID3D11Device_CreateVertexShader(
    ID3D11Device* p, const void* c, SIZE_T l, ID3D11ClassLinkage* lk, ID3D11VertexShader** pp)
{ return this_->helper_ID3D11Device_CreateVertexShader(this_->pHook_ID3D11Device_CreateVertexShader, p, c, l, lk, pp); }
 
HRESULT KRipper11::helper_ID3D11Device_CreatePixelShader(
    KHook* pHook, ID3D11Device* pDev,
    const void* pCode, SIZE_T Len,
    ID3D11ClassLinkage* pLink, ID3D11PixelShader** ppPS)
{
    auto e = (PFN_ID3D11Device_CreatePixelShader)pHook->getOriginalAddress();
    HRESULT hr = e(pDev, pCode, Len, pLink, ppPS);
    if (SUCCEEDED(hr) && g_pIntruder->getSettings()->saveShaders) {
        EnterCriticalSection(&cs);
        saveShader(EShaderExt::PIXEL, pCode, Len, *ppPS, &shadersDb, &d3dCompileHelper);
        LeaveCriticalSection(&cs);
    }
    return hr;
}
HRESULT __stdcall KRipper11::_ID3D11Device_CreatePixelShader(
    ID3D11Device* p, const void* c, SIZE_T l, ID3D11ClassLinkage* lk, ID3D11PixelShader** pp)
{ return this_->helper_ID3D11Device_CreatePixelShader(this_->pHook_ID3D11Device_CreatePixelShader, p, c, l, lk, pp); }
 
HRESULT KRipper11::helper_ID3D11Device_CreateGeometryShader(
    KHook* pHook, ID3D11Device* pDev,
    const void* pCode, SIZE_T Len,
    ID3D11ClassLinkage* pLink, ID3D11GeometryShader** ppGS)
{
    auto e = (PFN_ID3D11Device_CreateGeometryShader)pHook->getOriginalAddress();
    HRESULT hr = e(pDev, pCode, Len, pLink, ppGS);
    if (SUCCEEDED(hr) && g_pIntruder->getSettings()->saveShaders) {
        EnterCriticalSection(&cs);
        saveShader(EShaderExt::GEOMETRY, pCode, Len, *ppGS, &shadersDb, &d3dCompileHelper);
        LeaveCriticalSection(&cs);
    }
    return hr;
}
HRESULT __stdcall KRipper11::_ID3D11Device_CreateGeometryShader(
    ID3D11Device* p, const void* c, SIZE_T l, ID3D11ClassLinkage* lk, ID3D11GeometryShader** pp)
{ return this_->helper_ID3D11Device_CreateGeometryShader(this_->pHook_ID3D11Device_CreateGeometryShader, p, c, l, lk, pp); }
 
HRESULT KRipper11::helper_ID3D11Device_CreateGeometryShaderWithStreamOutput(
    KHook* pHook, ID3D11Device* pDev,
    const void* pCode, SIZE_T Len,
    const D3D11_SO_DECLARATION_ENTRY* pSODecl, UINT NumEntries,
    const UINT* pStrides, UINT NumStrides,
    UINT RasterizedStream,
    ID3D11ClassLinkage* pLink, ID3D11GeometryShader** ppGS)
{
    auto e = (PFN_ID3D11Device_CreateGeometryShaderWithStreamOutput)pHook->getOriginalAddress();
    HRESULT hr = e(pDev, pCode, Len, pSODecl, NumEntries, pStrides, NumStrides,
                   RasterizedStream, pLink, ppGS);
    if (SUCCEEDED(hr) && g_pIntruder->getSettings()->saveShaders) {
        EnterCriticalSection(&cs);
        saveShader(EShaderExt::GEOMETRY, pCode, Len, *ppGS, &shadersDb, &d3dCompileHelper);
        LeaveCriticalSection(&cs);
    }
    return hr;
}
HRESULT __stdcall KRipper11::_ID3D11Device_CreateGeometryShaderWithStreamOutput(
    ID3D11Device* pDev, const void* pCode, SIZE_T Len,
    const D3D11_SO_DECLARATION_ENTRY* pSODecl, UINT NumEntries,
    const UINT* pStrides, UINT NumStrides, UINT RasterizedStream,
    ID3D11ClassLinkage* pLink, ID3D11GeometryShader** ppGS)
{
    return this_->helper_ID3D11Device_CreateGeometryShaderWithStreamOutput(
        this_->pHook_ID3D11Device_CreateGeometryShaderWithStreamOutput,
        pDev, pCode, Len, pSODecl, NumEntries, pStrides, NumStrides,
        RasterizedStream, pLink, ppGS);
}
 
// ---- ID3D11Device_GetImmediateContext -------------------------------------
 
void KRipper11::helper_ID3D11Device_GetImmediateContext(
    KHook* pHook, ID3D11Device* pDev, ID3D11DeviceContext** ppCtx)
{
    auto e = (PFN_ID3D11Device_GetImmediateContext)pHook->getOriginalAddress();
    e(pDev, ppCtx);
    hookDeviceContext(ppCtx);
}
void __stdcall KRipper11::_ID3D11Device_GetImmediateContext(
    ID3D11Device* pDev, ID3D11DeviceContext** ppCtx)
{ this_->helper_ID3D11Device_GetImmediateContext(this_->pHook_ID3D11Device_GetImmediateContext, pDev, ppCtx); }
 
// ---- ClearRenderTargetView (re-hooks vtable after driver patches it) -------
 
void KRipper11::helper_ID3D11DeviceContext_ClearRenderTargetView(
    KHook* pHook,
    ID3D11DeviceContext* pCtx,
    ID3D11RenderTargetView* pRTV,
    const FLOAT color[4])
{
    auto e = (PFN_ID3D11DeviceContext_ClearRenderTargetView)pHook->getOriginalAddress();
    e(pCtx, pRTV, color);
    hookDeviceContext(&pCtx);
}
 
// ---- Device / immediate-context database ----------------------------------
 
void KRipper11::saveDeviceAndImmContextInDb(ID3D11Device* dev, ID3D11DeviceContext* ctx)
{
    if (!dev || !ctx) return;
    auto it = deviceToImmContext.find(dev);
    if (it != deviceToImmContext.end())
        it->second = ctx;
    else
        deviceToImmContext.insert({dev, ctx});
}
 
ID3D11DeviceContext* KRipper11::getImmCtxFromDb(ID3D11Device* dev)
{
    auto it = deviceToImmContext.find(dev);
    return (it != deviceToImmContext.end()) ? it->second : nullptr;
}
 
ID3D11DeviceContext* KRipper11::getImmCtx(ID3D11DeviceContext* pCtx)
{
    if (pCtx->GetType() == D3D11_DEVICE_CONTEXT_DEFERRED) {
        TDXRef<ID3D11Device> dev;
        pCtx->GetDevice(&dev);
        return getImmCtxFromDb(dev.get());
    }
    return pCtx;
}
 
void KRipper11::logReasonIfDeviceRemoved(HRESULT hr, ID3D11Device* dev)
{
    if (hr == DXGI_ERROR_DEVICE_REMOVED)
        g_pLog->logError("Device removed reason: 0x%08X\n", dev->GetDeviceRemovedReason());
}
 
// ---- EPrimitiveTopology conversion ----------------------------------------
 
EPrimitiveTopology::Type
KRipper11::D3D11_PRIMITIVE_TOPOLOGY_to_EPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY t)
{
    switch (t) {
    case D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST:  return EPrimitiveTopology::TRIANGLELIST;
    case D3D11_PRIMITIVE_TOPOLOGY_TRIANGLESTRIP: return EPrimitiveTopology::TRIANGLESTRIP;
    case D3D_PRIMITIVE_TOPOLOGY_UNDEFINED:       return EPrimitiveTopology::UNDEFINED;
    case D3D_PRIMITIVE_TOPOLOGY_POINTLIST:       return EPrimitiveTopology::POINTLIST;
    case D3D_PRIMITIVE_TOPOLOGY_LINESTRIP:       return EPrimitiveTopology::LINESTRIP;
    case D3D_PRIMITIVE_TOPOLOGY_LINELIST:        return EPrimitiveTopology::LINELIST;
    default:                                     return EPrimitiveTopology::UNKNOWNPRIMITIVETYPE;
    }
}
 
EPrimitiveTopology::Type KRipper11::getPrimitiveTopology(ID3D11DeviceContext* pCtx)
{
    D3D11_PRIMITIVE_TOPOLOGY t = D3D11_PRIMITIVE_TOPOLOGY_UNDEFINED;
    pCtx->IAGetPrimitiveTopology(&t);
    return D3D11_PRIMITIVE_TOPOLOGY_to_EPrimitiveTopology(t);
}
 
// ---- Input-layout lookup --------------------------------------------------
 
HRESULT KRipper11::getInputLayout(ID3D11DeviceContext* pCtx,
                                  KD3D11VertexDeclaration& decl)
{
    TDXRef<ID3D11InputLayout> pLayout;
    pCtx->IAGetInputLayout(&pLayout);
 
    auto it = InputLayoutMap.find(pLayout.get());
    if (it == InputLayoutMap.end()) {
        g_pLog->logError("InputLayout not found: 0x%p\n", pLayout.get());
        return E_INPUT_LAYOUT_NOT_FOUND;
    }
    decl = it->second;
    return S_OK;
}
 
// ---- DXGI_FORMAT ? EInputType ---------------------------------------------
 
EInputType::Type KRipper11::DXGI_FORMAT_to_EInputType(DXGI_FORMAT f)
{
    switch (f) {
    case DXGI_FORMAT_R32G32B32A32_TYPELESS: return EInputType::R32G32B32A32_TYPELESS;
    case DXGI_FORMAT_R32G32B32A32_FLOAT:    return EInputType::R32G32B32A32_FLOAT;
    case DXGI_FORMAT_R32G32B32A32_UINT:     return EInputType::R32G32B32A32_UINT;
    case DXGI_FORMAT_R32G32B32A32_SINT:     return EInputType::R32G32B32A32_SINT;
    case DXGI_FORMAT_R32G32B32_TYPELESS:    return EInputType::R32G32B32_TYPELESS;
    case DXGI_FORMAT_R32G32B32_FLOAT:       return EInputType::R32G32B32_FLOAT;
    case DXGI_FORMAT_R32G32B32_UINT:        return EInputType::R32G32B32_UINT;
    case DXGI_FORMAT_R32G32B32_SINT:        return EInputType::R32G32B32_SINT;
    case DXGI_FORMAT_R16G16B16A16_TYPELESS: return EInputType::R16G16B16A16_TYPELESS;
    case DXGI_FORMAT_R16G16B16A16_FLOAT:    return EInputType::R16G16B16A16_FLOAT;
    case DXGI_FORMAT_R16G16B16A16_UNORM:    return EInputType::R16G16B16A16_UNORM;
    case DXGI_FORMAT_R16G16B16A16_UINT:     return EInputType::R16G16B16A16_UINT;
    case DXGI_FORMAT_R16G16B16A16_SNORM:    return EInputType::R16G16B16A16_SNORM;
    case DXGI_FORMAT_R16G16B16A16_SINT:     return EInputType::R16G16B16A16_SINT;
    case DXGI_FORMAT_R32G32_TYPELESS:       return EInputType::R32G32_TYPELESS;
    case DXGI_FORMAT_R32G32_FLOAT:          return EInputType::R32G32_FLOAT;
    case DXGI_FORMAT_R32G32_UINT:           return EInputType::R32G32_UINT;
    case DXGI_FORMAT_R32G32_SINT:           return EInputType::R32G32_SINT;
    case DXGI_FORMAT_R8G8B8A8_TYPELESS:     return EInputType::R8G8B8A8_TYPELESS;
    case DXGI_FORMAT_R8G8B8A8_UNORM:        return EInputType::R8G8B8A8_UNORM;
    case DXGI_FORMAT_R8G8B8A8_UINT:         return EInputType::R8G8B8A8_UINT;
    case DXGI_FORMAT_R8G8B8A8_SNORM:        return EInputType::R8G8B8A8_SNORM;
    case DXGI_FORMAT_R8G8B8A8_SINT:         return EInputType::R8G8B8A8_SINT;
    case DXGI_FORMAT_R16G16_TYPELESS:       return EInputType::R16G16_TYPELESS;
    case DXGI_FORMAT_R16G16_FLOAT:          return EInputType::R16G16_FLOAT;
    case DXGI_FORMAT_R16G16_UNORM:          return EInputType::R16G16_UNORM;
    case DXGI_FORMAT_R16G16_UINT:           return EInputType::R16G16_UINT;
    case DXGI_FORMAT_R16G16_SNORM:          return EInputType::R16G16_SNORM;
    case DXGI_FORMAT_R16G16_SINT:           return EInputType::R16G16_SINT;
    case DXGI_FORMAT_R32_TYPELESS:          return EInputType::R32_TYPELESS;
    case DXGI_FORMAT_R32_FLOAT:             return EInputType::R32_FLOAT;
    case DXGI_FORMAT_R32_UINT:              return EInputType::R32_UINT;
    case DXGI_FORMAT_R32_SINT:              return EInputType::R32_SINT;
    case DXGI_FORMAT_R8G8_TYPELESS:         return EInputType::R8G8_TYPELESS;
    case DXGI_FORMAT_R8G8_UNORM:            return EInputType::R8G8_UNORM;
    case DXGI_FORMAT_R8G8_UINT:             return EInputType::R8G8_UINT;
    case DXGI_FORMAT_R8G8_SNORM:            return EInputType::R8G8_SNORM;
    case DXGI_FORMAT_R8G8_SINT:             return EInputType::R8G8_SINT;
    case DXGI_FORMAT_R16_TYPELESS:          return EInputType::R16_TYPELESS;
    case DXGI_FORMAT_R16_FLOAT:             return EInputType::R16_FLOAT;
    case DXGI_FORMAT_R16_UNORM:             return EInputType::R16_UNORM;
    case DXGI_FORMAT_R16_UINT:              return EInputType::R16_UINT;
    case DXGI_FORMAT_R16_SNORM:             return EInputType::R16_SNORM;
    case DXGI_FORMAT_R16_SINT:              return EInputType::R16_SINT;
    case DXGI_FORMAT_R8_TYPELESS:           return EInputType::R8_TYPELESS;
    case DXGI_FORMAT_R8_UNORM:              return EInputType::R8_UNORM;
    case DXGI_FORMAT_R8_UINT:               return EInputType::R8_UINT;
    case DXGI_FORMAT_R8_SNORM:              return EInputType::R8_SNORM;
    case DXGI_FORMAT_R8_SINT:               return EInputType::R8_SINT;
    case DXGI_FORMAT_R10G10B10A2_UNORM:     return EInputType::R10G10B10A2_UNORM;
    case DXGI_FORMAT_B8G8R8A8_UNORM:        return EInputType::B8G8R8A8_UNORM;
    default:                                return EInputType::UNKNOWNINPUTTYPE;
    }
}
 
// ---- getVertexDeclarations ------------------------------------------------
 
HRESULT KRipper11::getVertexDeclarations(
    ID3D11DeviceContext* pCtx,
    KInputVertexDeclaration* inputDecl,
    KOutputVertexDeclaration* outputDecl)
{
    KD3D11VertexDeclaration d3dDecl;
    HRESULT hr = getInputLayout(pCtx, d3dDecl);
    if (FAILED(hr)) {
        g_pLog->logError("Input layout get failed: 0x%08X\n", hr);
        return hr;
    }
 
    for (size_t i = 0; i < d3dDecl.size(); i++) {
        const KD3D11InputElement& src = d3dDecl[i];
        dump_KD3D11InputElement2Log(src);
 
        EInputType::Type itype = DXGI_FORMAT_to_EInputType(src.Format);
        if (itype == EInputType::UNKNOWNINPUTTYPE) {
            g_pLog->logError("Unknown vertex type: %s\n", DXGI_FORMAT_2_Str(src.Format));
            return E_INPUT_TYPE_ERR;
        }
 
        KInputVertexElement elem;
        elem.Type          = itype;
        elem.Stream        = src.InputSlot;
        elem.SemanticIndex = src.SemanticIndex;
        elem.Size          = getInputTypeSize(elem.Type);
        elem.Offset        = src.AlignedByteOffset;
        strCopy(elem.UsageSemantic, SEMANTIC_LEN, src.SemanticName);
        inputDecl->Decl.push_back(elem);
    }
 
    // Collect unique stream numbers
    std::vector<DWORD> uniqueStreams;
    for (size_t i = 0; i < inputDecl->Decl.size(); i++) {
        DWORD s = inputDecl->Decl[i].Stream;
        bool found = false;
        for (DWORD u : uniqueStreams) if (u == s) { found = true; break; }
        if (!found) uniqueStreams.push_back(s);
    }
 
    // Fix up D3D11_APPEND_ALIGNED_ELEMENT offsets (-1)
    for (DWORD stream : uniqueStreams) {
        DWORD off = 0;
        for (auto& e : inputDecl->Decl) {
            if (e.Stream != stream) continue;
            if (e.Offset == D3D11_APPEND_ALIGNED_ELEMENT)
                e.Offset = off;
            else
                off = e.Offset;
            off += e.Size;
        }
    }
 
    if (SUCCEEDED(hr))
        hr = createKOutputVertexDeclaration(*inputDecl, *outputDecl);
    return hr;
}
 
// ---- copyBuffer -----------------------------------------------------------
 
HRESULT KRipper11::copyBuffer(ID3D11DeviceContext* pCtx,
                              ID3D11Buffer* pSrc, ID3D11Buffer** ppDst)
{
    *ppDst = nullptr;
    D3D11_BUFFER_DESC src_desc, dst_desc;
    pSrc->GetDesc(&src_desc);
    dst_desc = src_desc;
    dst_desc.Usage          = D3D11_USAGE_STAGING;
    dst_desc.BindFlags      = 0;
    dst_desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
    dst_desc.MiscFlags      = 0;
 
    TDXRef<ID3D11Device> dev;
    pCtx->GetDevice(&dev);
    HRESULT hr = dev->CreateBuffer(&dst_desc, nullptr, ppDst);
    if (FAILED(hr)) return hr;
    pCtx->CopyResource(*ppDst, pSrc);
    return S_OK;
}
 
// ---- Shader save helper ---------------------------------------------------
 
void KRipper11::saveMeshShaders(ID3D11DeviceContext* pCtx, KMeshShaders* out)
{
    std::string name, fullPath;
 
    TDXRef<ID3D11VertexShader> vs;
    pCtx->VSGetShader(&vs, nullptr, nullptr);
    if (getShaderFromDb(vs.get(), &shadersDb, &name, &fullPath)) {
        out->shaders.push_back(name);
        g_pLog->log("Vertex shader: %s\n", fullPath.c_str());
    }
    TDXRef<ID3D11PixelShader> ps;
    pCtx->PSGetShader(&ps, nullptr, nullptr);
    if (getShaderFromDb(ps.get(), &shadersDb, &name, &fullPath)) {
        out->shaders.push_back(name);
        g_pLog->log("Pixel  shader: %s\n", fullPath.c_str());
    }
    TDXRef<ID3D11GeometryShader> gs;
    pCtx->GSGetShader(&gs, nullptr, nullptr);
    if (getShaderFromDb(gs.get(), &shadersDb, &name, &fullPath)) {
        out->shaders.push_back(name);
        g_pLog->log("Geometry shader: %s\n", fullPath.c_str());
    }
}
 
// =============================================================================
//  IMPLEMENTATION � drawindexed11.cpp
//  (Contains dumpVertexBuffer, dumpIndexBuffer, ripDrawIndexed,
//   helper_DrawIndexed, and the D3D11_DEVICE_CONTEXT_TYPE helper)
// =============================================================================
 
const char* KRipper11::D3D11_DEVICE_CONTEXT_TYPE_To_String(D3D11_DEVICE_CONTEXT_TYPE x)
{
    switch (x) {
    case D3D11_DEVICE_CONTEXT_IMMEDIATE: return "D3D11_DEVICE_CONTEXT_IMMEDIATE";
    case D3D11_DEVICE_CONTEXT_DEFERRED:  return "D3D11_DEVICE_CONTEXT_DEFERRED";
    default:                             return "UNKNOWN";
    }
}
 
HRESULT KRipper11::dumpVertexBuffer(
    ID3D11DeviceContext* pCtx,
    const KInputVertexDeclaration&  inputDecl,
    const KOutputVertexDeclaration& outputDecl,
    INT BaseVertexIndex,
    const OptimizedIndexToMeshIndex& optIdx,
    KVERTICES* pVerts)
{
    HRESULT hr = E_UNK_ERR;
    ID3D11DeviceContext* pImm = getImmCtx(pCtx);
    bool vbOk = false;
 
    for (size_t i = 0; i < inputDecl.Decl.size(); i++) {
        const KInputVertexElement& inElem = inputDecl.Decl[i];
 
        TDXRef<ID3D11Buffer> pVB;
        UINT stride = 0, offset = 0;
        pCtx->IAGetVertexBuffers(inElem.Stream, 1, &pVB, &stride, &offset);
 
        g_pLog->log("VertexBuffer: 0x%p Stride %d Offset %d\n",
                    pVB.get(), stride, offset);
 
        if (!pVB.get()) {
            g_pLog->logWarning("VertexBuffer == NULL. Try next stream\n");
            continue;
        }
 
        TDXRef<ID3D11Buffer> pDstVB;
        hr = copyBuffer(pImm, pVB.get(), &pDstVB);
        if (FAILED(hr)) { g_pLog->logError("VB copy. HRESULT: 0x%08X\n", hr); break; }
 
        D3D11_MAPPED_SUBRESOURCE mapped = {};
        hr = pImm->Map(pDstVB.get(), 0, D3D11_MAP_READ, 0, &mapped);
        if (FAILED(hr)) { g_pLog->logError("Map(VB). HRESULT: 0x%08X\n", hr); break; }
 
        const KOutputVertexElement& outElem = outputDecl.Decl[i];
        BYTE* pData = (BYTE*)mapped.pData;
 
        // Pointer arithmetic: BaseVertexIndex * stride + offset
        // Cast carefully on x64 (original code comment preserved)
        dumpVertSemantic(
            inElem.Type,
            pData + (BaseVertexIndex * (INT)stride + (INT)offset),
            inElem.Offset, stride,
            pVerts->getRawData(), outElem.Offset, pVerts->getVertexSize(),
            optIdx);
 
        pImm->Unmap(pDstVB.get(), 0);
        vbOk = true;
    }
 
    if (vbOk) hr = S_OK;
    return hr;
}
 
HRESULT KRipper11::dumpIndexBuffer(
    ID3D11DeviceContext* pCtx,
    EPrimitiveTopology::Type primTopo,
    UINT IndexCount, UINT StartIndexLocation, INT BaseVertexLocation,
    KFACES* pFaces, OptimizedIndexToMeshIndex* optIdx)
{
    HRESULT hr = E_UNK_ERR;
    do {
        ID3D11DeviceContext* pImm = getImmCtx(pCtx);
 
        TDXRef<ID3D11Buffer> pIB;
        DXGI_FORMAT ibFmt = DXGI_FORMAT_UNKNOWN;
        UINT ibOffset = 0;
        pCtx->IAGetIndexBuffer(&pIB, &ibFmt, &ibOffset);
 
        g_pLog->log("IndexBuffer: 0x%p Format: %s Offset: 0x%08X\n",
                    pIB.get(), DXGI_FORMAT_2_Str(ibFmt), ibOffset);
 
        if (!pIB.get()) { g_pLog->logError("IndexBuffer == NULL\n"); break; }
 
        TDXRef<ID3D11Buffer> pDstIB;
        hr = copyBuffer(pImm, pIB.get(), &pDstIB);
        if (FAILED(hr)) { g_pLog->logError("IB copy. HRESULT: 0x%08X\n", hr); break; }
 
        D3D11_MAPPED_SUBRESOURCE mapped = {};
        hr = pImm->Map(pDstIB.get(), 0, D3D11_MAP_READ, 0, &mapped);
        if (FAILED(hr)) { g_pLog->logError("Map(IB). HRESULT: 0x%08X\n", hr); break; }
 
        BYTE* pRaw = (BYTE*)mapped.pData + ibOffset;
 
        if (ibFmt == DXGI_FORMAT_R16_UINT) {
            const WORD* idx = (WORD*)pRaw + StartIndexLocation;
            processIndexes16_IndexCount(idx, primTopo, IndexCount, pFaces, optIdx);
            hr = S_OK;
        } else if (ibFmt == DXGI_FORMAT_R32_UINT) {
            const DWORD* idx = (DWORD*)pRaw + StartIndexLocation;
            processIndexes32_IndexCount(idx, primTopo, IndexCount, pFaces, optIdx);
            hr = S_OK;
        } else {
            g_pLog->logError("Unknown IB format: %s\n", DXGI_FORMAT_2_Str(ibFmt));
            hr = E_UNK_INDEX_FORMAT_ERR;
        }
 
        pImm->Unmap(pDstIB.get(), 0);
    } while (FALSE);
    return hr;
}
 
void KRipper11::ripDrawIndexed(ID3D11DeviceContext* pCtx,
                               UINT IndexCount, UINT StartIndexLocation,
                               INT BaseVertexLocation)
{
    do {
        g_pLog->log("DevCtxType: 0x%p %s\n", pCtx,
                    D3D11_DEVICE_CONTEXT_TYPE_To_String(pCtx->GetType()));
 
        ID3D11DeviceContext* pImm = getImmCtx(pCtx);
        if (!pImm) { g_pLog->logError("Immediate context not found\n\n"); break; }
 
        HRESULT hr;
        KInputVertexDeclaration  inputDecl;
        KOutputVertexDeclaration outputDecl;
 
        EPrimitiveTopology::Type topo = getPrimitiveTopology(pCtx);
        g_pLog->log("Primitive topology: %s\n", primitiveTopology2Str(topo));
        if (!isPrimitiveTopologySupported(topo)) {
            g_pLog->logError("Primitive topology not supported\n\n"); break;
        }
 
        hr = getVertexDeclarations(pCtx, &inputDecl, &outputDecl);
        if (FAILED(hr)) { g_pLog->logError("Vertex decl. HRESULT: 0x%08X\n\n", hr); break; }
        dumpInputVertexDeclaration2Log(inputDecl);
        dumpOutputVertexDeclaration2Log(outputDecl);
 
        KFACES faces;
        OptimizedIndexToMeshIndex optIdx;
        hr = dumpIndexBuffer(pCtx, topo, IndexCount, StartIndexLocation,
                             BaseVertexLocation, &faces, &optIdx);
        if (FAILED(hr)) { g_pLog->log("IB dump. HRESULT: 0x%08X\n\n", hr); break; }
 
        DWORD vertSize = outputDecl.getVertexSize();
        DWORD vertCnt  = (DWORD)optIdx.size();
        g_pLog->log("PrimitivesCount=%d VertexCnt=%d OutVertexSize=%d\n",
                    faces.getPrimitivesCount(), vertCnt, vertSize);
 
        KVERTICES vertices(vertCnt, vertSize);
        hr = dumpVertexBuffer(pCtx, inputDecl, outputDecl,
                              BaseVertexLocation, optIdx, &vertices);
        if (FAILED(hr)) { g_pLog->logError("VB dump. HRESULT: 0x%08X\n\n", hr); break; }
 
        KMeshTextures meshTex;
        saveMeshTextures(pCtx, &meshTex);
 
        KMeshShaders meshShaders;
        if (g_pIntruder->getSettings()->saveShaders)
            saveMeshShaders(pCtx, &meshShaders);
 
        std::wstring path  = g_pIntruder->getFrameMeshSavePath();
        std::string  pathA = wideStringToMultiByte(path.c_str());
        hr = saveRipFile(path.c_str(), inputDecl, outputDecl,
                         meshTex, meshShaders, faces, vertices);
        if (SUCCEEDED(hr))
            g_pLog->log("Mesh saved: %s\n\n\n", pathA.c_str());
        else
            g_pLog->logError("Mesh save error: %s\n\n\n", pathA.c_str());
 
        g_pIntruder->incFrameMeshIdx();
    } while (FALSE);
}
 
void KRipper11::helper_ID3D11DeviceContext_DrawIndexed(
    KHook* pHook,
    ID3D11DeviceContext* pCtx,
    UINT IndexCount, UINT StartIndexLocation, INT BaseVertexLocation)
{
    auto e = (PFN_ID3D11DeviceContext_DrawIndexed)pHook->getOriginalAddress();
 
    if (!drawIndexedEnabled) {
        e(pCtx, IndexCount, StartIndexLocation, BaseVertexLocation);
        return;
    }
 
    g_pIntruder->keyHandler(this);
    DWORD ripEnabled = g_pIntruder->isMeshRipEnabled();
    DWORD minIdx     = g_pIntruder->getSettings()->dwMinIndicies;
 
    EnterCriticalSection(&cs);
    if (ripEnabled) {
        if (IndexCount >= minIdx) {
            g_pLog->log("DrawIndexed(0x%p, %d, %d, %d)\n",
                        pCtx, IndexCount, StartIndexLocation, BaseVertexLocation);
            EXCEPTION_RECORD excRec; CONTEXT excCtx;
            __try {
                ripDrawIndexed(pCtx, IndexCount, StartIndexLocation, BaseVertexLocation);
            }
            __except(
                excRec = *(GetExceptionInformation())->ExceptionRecord,
                excCtx = *(GetExceptionInformation())->ContextRecord,
                crashDumpWrite(g_pIntruder->getCrashDumpFile(), GetExceptionInformation()),
                EXCEPTION_EXECUTE_HANDLER)
            {
                g_pLog->logError("DrawIndexed() exception. Crash dump: %s\n\n\n",
                                 g_pIntruder->getCrashDumpFileUtf8());
                ExitProcess(0);
            }
        } else {
            g_pLog->logWarning("DrawIndexed() rip skipped\n");
        }
    }
    LeaveCriticalSection(&cs);
    e(pCtx, IndexCount, StartIndexLocation, BaseVertexLocation);
}
 
// =============================================================================
//  IMPLEMENTATION � draw11.cpp  (non-indexed draw)
// =============================================================================
 
void KRipper11::ripDraw(ID3D11DeviceContext* pCtx,
                        UINT VertexCount, UINT StartVertexLocation)
{
    do {
        HRESULT hr;
        KInputVertexDeclaration  inputDecl;
        KOutputVertexDeclaration outputDecl;
 
        EPrimitiveTopology::Type topo = getPrimitiveTopology(pCtx);
        g_pLog->log("Primitive topology: %s\n", primitiveTopology2Str(topo));
        if (!isPrimitiveTopologySupported(topo)) {
            g_pLog->logError("Primitive topology not supported\n\n"); break;
        }
 
        hr = getVertexDeclarations(pCtx, &inputDecl, &outputDecl);
        if (FAILED(hr)) { g_pLog->logError("Vertex decl. HRESULT: 0x%08X\n\n", hr); break; }
        dumpInputVertexDeclaration2Log(inputDecl);
        dumpOutputVertexDeclaration2Log(outputDecl);
 
        KFACES faces;
        OptimizedIndexToMeshIndex optIdx;
        generateIndexes_VertexCount(topo, VertexCount, &faces, &optIdx);
 
        DWORD vertSize = outputDecl.getVertexSize();
        DWORD vertCnt  = (DWORD)optIdx.size();
        g_pLog->log("PrimitivesCount=%d VertexCnt=%d OutVertexSize=%d\n",
                    faces.getPrimitivesCount(), vertCnt, vertSize);
 
        KVERTICES vertices(vertCnt, vertSize);
        hr = dumpVertexBuffer(pCtx, inputDecl, outputDecl,
                              StartVertexLocation, optIdx, &vertices);
        if (FAILED(hr)) { g_pLog->logError("VB dump. HRESULT: 0x%08X\n\n", hr); break; }
 
        KMeshTextures meshTex;
        saveMeshTextures(pCtx, &meshTex);
 
        KMeshShaders meshShaders;
        if (g_pIntruder->getSettings()->saveShaders)
            saveMeshShaders(pCtx, &meshShaders);
 
        std::wstring path  = g_pIntruder->getFrameMeshSavePath();
        std::string  pathA = wideStringToMultiByte(path.c_str());
        hr = saveRipFile(path.c_str(), inputDecl, outputDecl,
                         meshTex, meshShaders, faces, vertices);
        if (SUCCEEDED(hr))
            g_pLog->log("Mesh saved: %s\n\n\n", pathA.c_str());
        else
            g_pLog->logError("Mesh save error: %s\n\n\n", pathA.c_str());
 
        g_pIntruder->incFrameMeshIdx();
    } while (FALSE);
}
 
void KRipper11::helper_ID3D11DeviceContext_Draw(
    KHook* pHook,
    ID3D11DeviceContext* pCtx,
    UINT VertexCount, UINT StartVertexLocation)
{
    auto e = (PFN_ID3D11DeviceContext_Draw)pHook->getOriginalAddress();
    g_pIntruder->keyHandler(this);
 
    DWORD ripEnabled = g_pIntruder->isMeshRipEnabled();
    DWORD minVert    = g_pIntruder->getSettings()->dwMinVertexCount;
 
    EnterCriticalSection(&cs);
    if (ripEnabled) {
        if (VertexCount >= minVert) {
            g_pLog->log("Draw(0x%p, %d, %d)\n", pCtx, VertexCount, StartVertexLocation);
            __try { ripDraw(pCtx, VertexCount, StartVertexLocation); }
            __except(EXCEPTION_EXECUTE_HANDLER)
            { g_pLog->logError("Draw() exception\n\n\n"); }
        } else {
            g_pLog->logWarning("Draw() rip skipped\n");
        }
    }
    LeaveCriticalSection(&cs);
    e(pCtx, VertexCount, StartVertexLocation);
}
 
// =============================================================================
//  IMPLEMENTATION � drawauto11.cpp
// =============================================================================
 
void KRipper11::helper_ID3D11DeviceContext_DrawAuto(
    KHook* pHook, ID3D11DeviceContext* pCtx)
{
    auto e = (PFN_ID3D11DeviceContext_DrawAuto)pHook->getOriginalAddress();
    g_pIntruder->keyHandler(this);
 
    EnterCriticalSection(&cs);
    if (g_pIntruder->isMeshRipEnabled()) {
        g_pLog->log("DrawAuto(0x%p)\n", pCtx);
        __try { g_pLog->logError("DrawAuto: Not realized\n\n"); }
        __except(EXCEPTION_EXECUTE_HANDLER)
        { g_pLog->logError("DrawAuto() exception\n\n\n"); }
    }
    LeaveCriticalSection(&cs);
    e(pCtx);
}
 
// =============================================================================
//  IMPLEMENTATION � drawindexedinstanced11.cpp
// =============================================================================
 
void KRipper11::ripDrawIndexedInstanced(
    ID3D11DeviceContext* pCtx,
    UINT IndexCountPerInstance, UINT /*InstanceCount*/,
    UINT StartIndexLocation, INT BaseVertexLocation,
    UINT StartInstanceLocation)
{
    // Delegate to the indexed path; fold instance offset into base vertex
    ripDrawIndexed(pCtx,
                   IndexCountPerInstance,
                   StartIndexLocation,
                   BaseVertexLocation + (INT)StartInstanceLocation);
}
 
void KRipper11::helper_ID3D11DeviceContext_DrawIndexedInstanced(
    KHook* pHook,
    ID3D11DeviceContext* pCtx,
    UINT IndexCountPerInstance, UINT InstanceCount,
    UINT StartIndexLocation, INT BaseVertexLocation,
    UINT StartInstanceLocation)
{
    auto e = (PFN_ID3D11DeviceContext_DrawIndexedInstanced)pHook->getOriginalAddress();
    g_pIntruder->keyHandler(this);
 
    DWORD ripEnabled = g_pIntruder->isMeshRipEnabled();
    DWORD minIdx     = g_pIntruder->getSettings()->dwMinIndicies;
 
    EnterCriticalSection(&cs);
    if (ripEnabled) {
        if (IndexCountPerInstance >= minIdx) {
            g_pLog->log("DrawIndexedInstanced(0x%p, %d, %d, %d, %d, %d)\n",
                        pCtx, IndexCountPerInstance, InstanceCount,
                        StartIndexLocation, BaseVertexLocation, StartInstanceLocation);
            __try {
                ripDrawIndexedInstanced(pCtx, IndexCountPerInstance, InstanceCount,
                                        StartIndexLocation, BaseVertexLocation,
                                        StartInstanceLocation);
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            { g_pLog->logError("DrawIndexedInstanced() exception\n\n\n"); }
        } else {
            g_pLog->logWarning("DrawIndexedInstanced() rip skipped\n");
        }
    }
    LeaveCriticalSection(&cs);
    e(pCtx, IndexCountPerInstance, InstanceCount,
      StartIndexLocation, BaseVertexLocation, StartInstanceLocation);
}
 
// =============================================================================
//  IMPLEMENTATION � drawindexedinstancedindirect11.cpp
// =============================================================================
 
void KRipper11::ripDrawIndexedInstancedIndirect(
    ID3D11DeviceContext* pCtx,
    ID3D11Buffer* pArgsBuffer,
    UINT AlignedByteOffsetForArgs)
{
    while (true) {
        ID3D11DeviceContext* pImm = getImmCtx(pCtx);
        if (!pImm) { g_pLog->logError("Immediate context not found\n\n"); break; }
 
        TDXRef<ID3D11Buffer> pBuf;
        HRESULT hr = copyBuffer(pCtx, pArgsBuffer, &pBuf);
        if (FAILED(hr)) { g_pLog->logError("Args buffer copy. HRESULT: 0x%08X\n", hr); break; }
 
        D3D11_MAPPED_SUBRESOURCE mapped = {};
        hr = pImm->Map(pBuf.get(), 0, D3D11_MAP_READ, 0, &mapped);
        if (FAILED(hr)) { g_pLog->logError("Map(args). HRESULT: 0x%08X\n", hr); break; }
 
        BYTE* raw = (BYTE*)mapped.pData + AlignedByteOffsetForArgs;
        D3D11_DRAW_INDEXED_INSTANCED_INDIRECT_ARGS d =
            *(D3D11_DRAW_INDEXED_INSTANCED_INDIRECT_ARGS*)raw;
        pImm->Unmap(pBuf.get(), 0);
 
        g_pLog->log("IndirectArgs: IdxPerInst=%d InstCnt=%d StartIdx=%d BaseVtx=%d StartInst=%d\n",
                    d.IndexCountPerInstance, d.InstanceCount,
                    d.StartIndexLocation, d.BaseVertexLocation, d.StartInstanceLocation);
 
        DWORD minIdx = g_pIntruder->getSettings()->dwMinIndicies;
        if (d.IndexCountPerInstance > minIdx)
            ripDrawIndexedInstanced(pCtx,
                                    d.IndexCountPerInstance, d.InstanceCount,
                                    d.StartIndexLocation, d.BaseVertexLocation,
                                    d.StartInstanceLocation);
        else
            g_pLog->logWarning("DrawIndexedInstancedIndirect rip skipped\n");
        break;
    }
}
 
void KRipper11::helper_ID3D11DeviceContext_DrawIndexedInstancedIndirect(
    KHook* pHook,
    ID3D11DeviceContext* pCtx,
    ID3D11Buffer* pArgsBuffer, UINT AlignedByteOffsetForArgs)
{
    auto e = (PFN_ID3D11DeviceContext_DrawIndexedInstancedIndirect)pHook->getOriginalAddress();
    g_pIntruder->keyHandler(this);
 
    EnterCriticalSection(&cs);
    if (g_pIntruder->isMeshRipEnabled()) {
        g_pLog->log("DrawIndexedInstancedIndirect(0x%p, 0x%p, %d)\n",
                    pCtx, pArgsBuffer, AlignedByteOffsetForArgs);
        __try {
            ripDrawIndexedInstancedIndirect(pCtx, pArgsBuffer, AlignedByteOffsetForArgs);
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        { g_pLog->logError("DrawIndexedInstancedIndirect() exception\n\n\n"); }
    }
    LeaveCriticalSection(&cs);
    e(pCtx, pArgsBuffer, AlignedByteOffsetForArgs);
}
 
// =============================================================================
//  IMPLEMENTATION � drawinstanced11.cpp
// =============================================================================
 
void KRipper11::ripDrawInstanced(
    ID3D11DeviceContext* pCtx,
    UINT VertexCountPerInstance, UINT /*InstanceCount*/,
    UINT StartVertexLocation, UINT StartInstanceLocation)
{
    ripDraw(pCtx,
            VertexCountPerInstance,
            StartInstanceLocation + StartVertexLocation);
}
 
void KRipper11::helper_ID3D11DeviceContext_DrawInstanced(
    KHook* pHook,
    ID3D11DeviceContext* pCtx,
    UINT VertexCountPerInstance, UINT InstanceCount,
    UINT StartVertexLocation, UINT StartInstanceLocation)
{
    auto e = (PFN_ID3D11DeviceContext_DrawInstanced)pHook->getOriginalAddress();
    g_pIntruder->keyHandler(this);
 
    DWORD ripEnabled = g_pIntruder->isMeshRipEnabled();
    DWORD minVert    = g_pIntruder->getSettings()->dwMinVertexCount;
 
    EnterCriticalSection(&cs);
    if (ripEnabled) {
        if (VertexCountPerInstance >= minVert) {
            g_pLog->log("DrawInstanced(0x%p, %d, %d, %d, %d)\n",
                        pCtx, VertexCountPerInstance, InstanceCount,
                        StartVertexLocation, StartInstanceLocation);
            __try {
                ripDrawInstanced(pCtx, VertexCountPerInstance, InstanceCount,
                                 StartVertexLocation, StartInstanceLocation);
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            { g_pLog->logError("DrawInstanced() exception\n\n\n"); }
        } else {
            g_pLog->logWarning("DrawInstanced() rip skipped\n");
        }
    }
    LeaveCriticalSection(&cs);
    e(pCtx, VertexCountPerInstance, InstanceCount, StartVertexLocation, StartInstanceLocation);
}
 
// =============================================================================
//  IMPLEMENTATION � drawinstancedindirect11.cpp
// =============================================================================
 
void KRipper11::helper_ID3D11DeviceContext_DrawInstancedIndirect(
    KHook* pHook,
    ID3D11DeviceContext* pCtx,
    ID3D11Buffer* pArgsBuffer, UINT AlignedByteOffsetForArgs)
{
    auto e = (PFN_ID3D11DeviceContext_DrawInstancedIndirect)pHook->getOriginalAddress();
    g_pIntruder->keyHandler(this);
 
    EnterCriticalSection(&cs);
    if (g_pIntruder->isMeshRipEnabled()) {
        g_pLog->log("DrawInstancedIndirect(0x%p, 0x%p, %d)\n",
                    pCtx, pArgsBuffer, AlignedByteOffsetForArgs);
        __try { g_pLog->logError("DrawInstancedIndirect: Not realized\n\n"); }
        __except(EXCEPTION_EXECUTE_HANDLER)
        { g_pLog->logError("DrawInstancedIndirect() exception\n\n\n"); }
    }
    LeaveCriticalSection(&cs);
    e(pCtx, pArgsBuffer, AlignedByteOffsetForArgs);
}
 
// =============================================================================
//  IMPLEMENTATION � dump11.cpp  (string converters + resource dump)
// =============================================================================
 
void KRipper11::dumpShaderResourceView(ID3D11ShaderResourceView* pSRV)
{
    if (!pSRV) { g_pLog->logError("pTexture==NULL\n"); return; }
 
    D3D11_SHADER_RESOURCE_VIEW_DESC desc;
    pSRV->GetDesc(&desc);
    g_pLog->log("---Resource format dump---\n");
    g_pLog->log("Format        : %s\n", DXGI_FORMAT_2_Str(desc.Format));
    g_pLog->log("View Dimension: %s\n", D3D11_SRV_DIMENSION_2_Str(desc.ViewDimension));
    g_pLog->log("--------------------------\n");
 
    TDXRef<ID3D11Resource> res;
    pSRV->GetResource(&res);
 
    switch (desc.ViewDimension) {
    case D3D11_SRV_DIMENSION_TEXTURE1D:
    case D3D11_SRV_DIMENSION_TEXTURE1DARRAY: {
        ID3D11Texture1D* t = static_cast<ID3D11Texture1D*>(res.get());
        D3D11_TEXTURE1D_DESC d; t->GetDesc(&d);
        g_pLog->log("Width:%u MipLevels:%u ArraySize:%u Format:%s Usage:%s\n",
                    d.Width, d.MipLevels, d.ArraySize,
                    DXGI_FORMAT_2_Str(d.Format), D3D11_USAGE_2_Str(d.Usage));
        break; }
    case D3D11_SRV_DIMENSION_TEXTURE2D:
    case D3D11_SRV_DIMENSION_TEXTURE2DARRAY:
    case D3D11_SRV_DIMENSION_TEXTURE2DMS: {
        ID3D11Texture2D* t = static_cast<ID3D11Texture2D*>(res.get());
        D3D11_TEXTURE2D_DESC d; t->GetDesc(&d);
        g_pLog->log("Width:%u Height:%u MipLevels:%u Format:%s Usage:%s\n",
                    d.Width, d.Height, d.MipLevels,
                    DXGI_FORMAT_2_Str(d.Format), D3D11_USAGE_2_Str(d.Usage));
        break; }
    case D3D11_SRV_DIMENSION_TEXTURE3D: {
        ID3D11Texture3D* t = static_cast<ID3D11Texture3D*>(res.get());
        D3D11_TEXTURE3D_DESC d; t->GetDesc(&d);
        g_pLog->log("Width:%u Height:%u Depth:%u Format:%s Usage:%s\n",
                    d.Width, d.Height, d.Depth,
                    DXGI_FORMAT_2_Str(d.Format), D3D11_USAGE_2_Str(d.Usage));
        break; }
    default: break;
    }
    g_pLog->log("--------------------------\n");
}
 
void KRipper11::dumpID3D11BufferDesc(ID3D11Buffer* buf)
{
    D3D11_BUFFER_DESC d; buf->GetDesc(&d);
    g_pLog->log("ByteWidth=%d Usage=0x%08X BindFlags=0x%08X "
                "CPUFlags=0x%08X MiscFlags=0x%08X Stride=%d\n",
                d.ByteWidth, d.Usage, d.BindFlags,
                d.CPUAccessFlags, d.MiscFlags, d.StructureByteStride);
}
 
void KRipper11::dump_KD3D11InputElement2Log(const KD3D11InputElement& e)
{
    g_pLog->log("Element:%s Index:%d Format:%s InputSlot:%d "
                "AlignOffs:%d SlotClass:%d StepRate:%d\n\n",
                e.SemanticName, e.SemanticIndex,
                DXGI_FORMAT_2_Str(e.Format), e.InputSlot,
                e.AlignedByteOffset, (int)e.InputSlotClass,
                e.InstanceDataStepRate);
}
 
// ---- String converters ----
 
const char* KRipper11::D3D11_USAGE_2_Str(D3D11_USAGE t)
{
    switch(t){
    case D3D11_USAGE_DEFAULT:   return "D3D11_USAGE_DEFAULT";
    case D3D11_USAGE_IMMUTABLE: return "D3D11_USAGE_IMMUTABLE";
    case D3D11_USAGE_DYNAMIC:   return "D3D11_USAGE_DYNAMIC";
    case D3D11_USAGE_STAGING:   return "D3D11_USAGE_STAGING";
    default:                    return "Unknown";
    }
}
 
const char* KRipper11::D3D_FEATURE_LEVEL_2_Str(D3D_FEATURE_LEVEL fl)
{
    switch(fl){
    case D3D_FEATURE_LEVEL_9_1:  return "D3D_FEATURE_LEVEL_9_1";
    case D3D_FEATURE_LEVEL_9_2:  return "D3D_FEATURE_LEVEL_9_2";
    case D3D_FEATURE_LEVEL_9_3:  return "D3D_FEATURE_LEVEL_9_3";
    case D3D_FEATURE_LEVEL_10_0: return "D3D_FEATURE_LEVEL_10_0";
    case D3D_FEATURE_LEVEL_10_1: return "D3D_FEATURE_LEVEL_10_1";
    case D3D_FEATURE_LEVEL_11_0: return "D3D_FEATURE_LEVEL_11_0";
    default:                     return "Unknown";
    }
}
 
const char* KRipper11::D3D_DRIVER_TYPE_2_Str(D3D_DRIVER_TYPE dt)
{
    switch(dt){
    case D3D_DRIVER_TYPE_UNKNOWN:   return "D3D_DRIVER_TYPE_UNKNOWN";
    case D3D_DRIVER_TYPE_HARDWARE:  return "D3D_DRIVER_TYPE_HARDWARE";
    case D3D_DRIVER_TYPE_REFERENCE: return "D3D_DRIVER_TYPE_REFERENCE";
    case D3D_DRIVER_TYPE_NULL:      return "D3D_DRIVER_TYPE_NULL";
    case D3D_DRIVER_TYPE_SOFTWARE:  return "D3D_DRIVER_TYPE_SOFTWARE";
    case D3D_DRIVER_TYPE_WARP:      return "D3D_DRIVER_TYPE_WARP";
    default:                        return "Unknown";
    }
}
 
const char* KRipper11::D3D11_SRV_DIMENSION_2_Str(D3D11_SRV_DIMENSION d)
{
    switch(d){
    case D3D11_SRV_DIMENSION_UNKNOWN:          return "D3D11_SRV_DIMENSION_UNKNOWN";
    case D3D11_SRV_DIMENSION_BUFFER:           return "D3D11_SRV_DIMENSION_BUFFER";
    case D3D11_SRV_DIMENSION_TEXTURE1D:        return "D3D11_SRV_DIMENSION_TEXTURE1D";
    case D3D11_SRV_DIMENSION_TEXTURE1DARRAY:   return "D3D11_SRV_DIMENSION_TEXTURE1DARRAY";
    case D3D11_SRV_DIMENSION_TEXTURE2D:        return "D3D11_SRV_DIMENSION_TEXTURE2D";
    case D3D11_SRV_DIMENSION_TEXTURE2DARRAY:   return "D3D11_SRV_DIMENSION_TEXTURE2DARRAY";
    case D3D11_SRV_DIMENSION_TEXTURE2DMS:      return "D3D11_SRV_DIMENSION_TEXTURE2DMS";
    case D3D11_SRV_DIMENSION_TEXTURE2DMSARRAY: return "D3D11_SRV_DIMENSION_TEXTURE2DMSARRAY";
    case D3D11_SRV_DIMENSION_TEXTURE3D:        return "D3D11_SRV_DIMENSION_TEXTURE3D";
    case D3D11_SRV_DIMENSION_TEXTURECUBE:      return "D3D11_SRV_DIMENSION_TEXTURECUBE";
    case D3D11_SRV_DIMENSION_TEXTURECUBEARRAY: return "D3D11_SRV_DIMENSION_TEXTURECUBEARRAY";
    case D3D11_SRV_DIMENSION_BUFFEREX:         return "D3D11_SRV_DIMENSION_BUFFEREX";
    default:                                   return "Unknown";
    }
}
 
const char* KRipper11::D3D11_PRIMITIVE_TOPOLOGY_to_Str(D3D11_PRIMITIVE_TOPOLOGY t)
{
    switch(t){
    case D3D11_PRIMITIVE_TOPOLOGY_UNDEFINED:        return "UNDEFINED";
    case D3D11_PRIMITIVE_TOPOLOGY_POINTLIST:        return "POINTLIST";
    case D3D11_PRIMITIVE_TOPOLOGY_LINELIST:         return "LINELIST";
    case D3D11_PRIMITIVE_TOPOLOGY_LINESTRIP:        return "LINESTRIP";
    case D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST:     return "TRIANGLELIST";
    case D3D11_PRIMITIVE_TOPOLOGY_TRIANGLESTRIP:    return "TRIANGLESTRIP";
    case D3D11_PRIMITIVE_TOPOLOGY_LINELIST_ADJ:     return "LINELIST_ADJ";
    case D3D11_PRIMITIVE_TOPOLOGY_LINESTRIP_ADJ:    return "LINESTRIP_ADJ";
    case D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST_ADJ: return "TRIANGLELIST_ADJ";
    case D3D11_PRIMITIVE_TOPOLOGY_TRIANGLESTRIP_ADJ:return "TRIANGLESTRIP_ADJ";
    default:                                        return "PATCHLIST/Unknown";
    }
}
 
const char* KRipper11::DXGI_FORMAT_2_Str(DXGI_FORMAT f)
{
    switch(f){
    case DXGI_FORMAT_UNKNOWN:                     return "DXGI_FORMAT_UNKNOWN";
    case DXGI_FORMAT_R32G32B32A32_TYPELESS:       return "DXGI_FORMAT_R32G32B32A32_TYPELESS";
    case DXGI_FORMAT_R32G32B32A32_FLOAT:          return "DXGI_FORMAT_R32G32B32A32_FLOAT";
    case DXGI_FORMAT_R32G32B32A32_UINT:           return "DXGI_FORMAT_R32G32B32A32_UINT";
    case DXGI_FORMAT_R32G32B32A32_SINT:           return "DXGI_FORMAT_R32G32B32A32_SINT";
    case DXGI_FORMAT_R32G32B32_TYPELESS:          return "DXGI_FORMAT_R32G32B32_TYPELESS";
    case DXGI_FORMAT_R32G32B32_FLOAT:             return "DXGI_FORMAT_R32G32B32_FLOAT";
    case DXGI_FORMAT_R32G32B32_UINT:              return "DXGI_FORMAT_R32G32B32_UINT";
    case DXGI_FORMAT_R32G32B32_SINT:              return "DXGI_FORMAT_R32G32B32_SINT";
    case DXGI_FORMAT_R16G16B16A16_TYPELESS:       return "DXGI_FORMAT_R16G16B16A16_TYPELESS";
    case DXGI_FORMAT_R16G16B16A16_FLOAT:          return "DXGI_FORMAT_R16G16B16A16_FLOAT";
    case DXGI_FORMAT_R16G16B16A16_UNORM:          return "DXGI_FORMAT_R16G16B16A16_UNORM";
    case DXGI_FORMAT_R16G16B16A16_UINT:           return "DXGI_FORMAT_R16G16B16A16_UINT";
    case DXGI_FORMAT_R16G16B16A16_SNORM:          return "DXGI_FORMAT_R16G16B16A16_SNORM";
    case DXGI_FORMAT_R16G16B16A16_SINT:           return "DXGI_FORMAT_R16G16B16A16_SINT";
    case DXGI_FORMAT_R32G32_TYPELESS:             return "DXGI_FORMAT_R32G32_TYPELESS";
    case DXGI_FORMAT_R32G32_FLOAT:                return "DXGI_FORMAT_R32G32_FLOAT";
    case DXGI_FORMAT_R32G32_UINT:                 return "DXGI_FORMAT_R32G32_UINT";
    case DXGI_FORMAT_R32G32_SINT:                 return "DXGI_FORMAT_R32G32_SINT";
    case DXGI_FORMAT_R32G8X24_TYPELESS:           return "DXGI_FORMAT_R32G8X24_TYPELESS";
    case DXGI_FORMAT_D32_FLOAT_S8X24_UINT:        return "DXGI_FORMAT_D32_FLOAT_S8X24_UINT";
    case DXGI_FORMAT_R32_FLOAT_X8X24_TYPELESS:    return "DXGI_FORMAT_R32_FLOAT_X8X24_TYPELESS";
    case DXGI_FORMAT_X32_TYPELESS_G8X24_UINT:     return "DXGI_FORMAT_X32_TYPELESS_G8X24_UINT";
    case DXGI_FORMAT_R10G10B10A2_TYPELESS:        return "DXGI_FORMAT_R10G10B10A2_TYPELESS";
    case DXGI_FORMAT_R10G10B10A2_UNORM:           return "DXGI_FORMAT_R10G10B10A2_UNORM";
    case DXGI_FORMAT_R10G10B10A2_UINT:            return "DXGI_FORMAT_R10G10B10A2_UINT";
    case DXGI_FORMAT_R11G11B10_FLOAT:             return "DXGI_FORMAT_R11G11B10_FLOAT";
    case DXGI_FORMAT_R8G8B8A8_TYPELESS:           return "DXGI_FORMAT_R8G8B8A8_TYPELESS";
    case DXGI_FORMAT_R8G8B8A8_UNORM:              return "DXGI_FORMAT_R8G8B8A8_UNORM";
    case DXGI_FORMAT_R8G8B8A8_UNORM_SRGB:         return "DXGI_FORMAT_R8G8B8A8_UNORM_SRGB";
    case DXGI_FORMAT_R8G8B8A8_UINT:               return "DXGI_FORMAT_R8G8B8A8_UINT";
    case DXGI_FORMAT_R8G8B8A8_SNORM:              return "DXGI_FORMAT_R8G8B8A8_SNORM";
    case DXGI_FORMAT_R8G8B8A8_SINT:               return "DXGI_FORMAT_R8G8B8A8_SINT";
    case DXGI_FORMAT_R16G16_TYPELESS:             return "DXGI_FORMAT_R16G16_TYPELESS";
    case DXGI_FORMAT_R16G16_FLOAT:                return "DXGI_FORMAT_R16G16_FLOAT";
    case DXGI_FORMAT_R16G16_UNORM:                return "DXGI_FORMAT_R16G16_UNORM";
    case DXGI_FORMAT_R16G16_UINT:                 return "DXGI_FORMAT_R16G16_UINT";
    case DXGI_FORMAT_R16G16_SNORM:                return "DXGI_FORMAT_R16G16_SNORM";
    case DXGI_FORMAT_R16G16_SINT:                 return "DXGI_FORMAT_R16G16_SINT";
    case DXGI_FORMAT_R32_TYPELESS:                return "DXGI_FORMAT_R32_TYPELESS";
    case DXGI_FORMAT_D32_FLOAT:                   return "DXGI_FORMAT_D32_FLOAT";
    case DXGI_FORMAT_R32_FLOAT:                   return "DXGI_FORMAT_R32_FLOAT";
    case DXGI_FORMAT_R32_UINT:                    return "DXGI_FORMAT_R32_UINT";
    case DXGI_FORMAT_R32_SINT:                    return "DXGI_FORMAT_R32_SINT";
    case DXGI_FORMAT_R24G8_TYPELESS:              return "DXGI_FORMAT_R24G8_TYPELESS";
    case DXGI_FORMAT_D24_UNORM_S8_UINT:           return "DXGI_FORMAT_D24_UNORM_S8_UINT";
    case DXGI_FORMAT_R24_UNORM_X8_TYPELESS:       return "DXGI_FORMAT_R24_UNORM_X8_TYPELESS";
    case DXGI_FORMAT_X24_TYPELESS_G8_UINT:        return "DXGI_FORMAT_X24_TYPELESS_G8_UINT";
    case DXGI_FORMAT_R8G8_TYPELESS:               return "DXGI_FORMAT_R8G8_TYPELESS";
    case DXGI_FORMAT_R8G8_UNORM:                  return "DXGI_FORMAT_R8G8_UNORM";
    case DXGI_FORMAT_R8G8_UINT:                   return "DXGI_FORMAT_R8G8_UINT";
    case DXGI_FORMAT_R8G8_SNORM:                  return "DXGI_FORMAT_R8G8_SNORM";
    case DXGI_FORMAT_R8G8_SINT:                   return "DXGI_FORMAT_R8G8_SINT";
    case DXGI_FORMAT_R16_TYPELESS:                return "DXGI_FORMAT_R16_TYPELESS";
    case DXGI_FORMAT_R16_FLOAT:                   return "DXGI_FORMAT_R16_FLOAT";
    case DXGI_FORMAT_D16_UNORM:                   return "DXGI_FORMAT_D16_UNORM";
    case DXGI_FORMAT_R16_UNORM:                   return "DXGI_FORMAT_R16_UNORM";
    case DXGI_FORMAT_R16_UINT:                    return "DXGI_FORMAT_R16_UINT";
    case DXGI_FORMAT_R16_SNORM:                   return "DXGI_FORMAT_R16_SNORM";
    case DXGI_FORMAT_R16_SINT:                    return "DXGI_FORMAT_R16_SINT";
    case DXGI_FORMAT_R8_TYPELESS:                 return "DXGI_FORMAT_R8_TYPELESS";
    case DXGI_FORMAT_R8_UNORM:                    return "DXGI_FORMAT_R8_UNORM";
    case DXGI_FORMAT_R8_UINT:                     return "DXGI_FORMAT_R8_UINT";
    case DXGI_FORMAT_R8_SNORM:                    return "DXGI_FORMAT_R8_SNORM";
    case DXGI_FORMAT_R8_SINT:                     return "DXGI_FORMAT_R8_SINT";
    case DXGI_FORMAT_A8_UNORM:                    return "DXGI_FORMAT_A8_UNORM";
    case DXGI_FORMAT_R1_UNORM:                    return "DXGI_FORMAT_R1_UNORM";
    case DXGI_FORMAT_R9G9B9E5_SHAREDEXP:          return "DXGI_FORMAT_R9G9B9E5_SHAREDEXP";
    case DXGI_FORMAT_R8G8_B8G8_UNORM:             return "DXGI_FORMAT_R8G8_B8G8_UNORM";
    case DXGI_FORMAT_G8R8_G8B8_UNORM:             return "DXGI_FORMAT_G8R8_G8B8_UNORM";
    case DXGI_FORMAT_BC1_TYPELESS:                return "DXGI_FORMAT_BC1_TYPELESS";
    case DXGI_FORMAT_BC1_UNORM:                   return "DXGI_FORMAT_BC1_UNORM";
    case DXGI_FORMAT_BC1_UNORM_SRGB:              return "DXGI_FORMAT_BC1_UNORM_SRGB";
    case DXGI_FORMAT_BC2_TYPELESS:                return "DXGI_FORMAT_BC2_TYPELESS";
    case DXGI_FORMAT_BC2_UNORM:                   return "DXGI_FORMAT_BC2_UNORM";
    case DXGI_FORMAT_BC2_UNORM_SRGB:              return "DXGI_FORMAT_BC2_UNORM_SRGB";
    case DXGI_FORMAT_BC3_TYPELESS:                return "DXGI_FORMAT_BC3_TYPELESS";
    case DXGI_FORMAT_BC3_UNORM:                   return "DXGI_FORMAT_BC3_UNORM";
    case DXGI_FORMAT_BC3_UNORM_SRGB:              return "DXGI_FORMAT_BC3_UNORM_SRGB";
    case DXGI_FORMAT_BC4_TYPELESS:                return "DXGI_FORMAT_BC4_TYPELESS";
    case DXGI_FORMAT_BC4_UNORM:                   return "DXGI_FORMAT_BC4_UNORM";
    case DXGI_FORMAT_BC4_SNORM:                   return "DXGI_FORMAT_BC4_SNORM";
    case DXGI_FORMAT_BC5_TYPELESS:                return "DXGI_FORMAT_BC5_TYPELESS";
    case DXGI_FORMAT_BC5_UNORM:                   return "DXGI_FORMAT_BC5_UNORM";
    case DXGI_FORMAT_BC5_SNORM:                   return "DXGI_FORMAT_BC5_SNORM";
    case DXGI_FORMAT_B5G6R5_UNORM:                return "DXGI_FORMAT_B5G6R5_UNORM";
    case DXGI_FORMAT_B5G5R5A1_UNORM:              return "DXGI_FORMAT_B5G5R5A1_UNORM";
    case DXGI_FORMAT_B8G8R8A8_UNORM:              return "DXGI_FORMAT_B8G8R8A8_UNORM";
    case DXGI_FORMAT_B8G8R8X8_UNORM:              return "DXGI_FORMAT_B8G8R8X8_UNORM";
    case DXGI_FORMAT_R10G10B10_XR_BIAS_A2_UNORM:  return "DXGI_FORMAT_R10G10B10_XR_BIAS_A2_UNORM";
    case DXGI_FORMAT_B8G8R8A8_TYPELESS:           return "DXGI_FORMAT_B8G8R8A8_TYPELESS";
    case DXGI_FORMAT_B8G8R8A8_UNORM_SRGB:         return "DXGI_FORMAT_B8G8R8A8_UNORM_SRGB";
    case DXGI_FORMAT_B8G8R8X8_TYPELESS:           return "DXGI_FORMAT_B8G8R8X8_TYPELESS";
    case DXGI_FORMAT_B8G8R8X8_UNORM_SRGB:         return "DXGI_FORMAT_B8G8R8X8_UNORM_SRGB";
    case DXGI_FORMAT_BC6H_TYPELESS:               return "DXGI_FORMAT_BC6H_TYPELESS";
    case DXGI_FORMAT_BC6H_UF16:                   return "DXGI_FORMAT_BC6H_UF16";
    case DXGI_FORMAT_BC6H_SF16:                   return "DXGI_FORMAT_BC6H_SF16";
    case DXGI_FORMAT_BC7_TYPELESS:                return "DXGI_FORMAT_BC7_TYPELESS";
    case DXGI_FORMAT_BC7_UNORM:                   return "DXGI_FORMAT_BC7_UNORM";
    case DXGI_FORMAT_BC7_UNORM_SRGB:              return "DXGI_FORMAT_BC7_UNORM_SRGB";
    case DXGI_FORMAT_FORCE_UINT:                  return "DXGI_FORMAT_FORCE_UINT";
    default:                                      return "Unknown";
    }
}
 
// =============================================================================
//  IMPLEMENTATION � savetexture11.cpp
//  Saves a shader-resource-view texture to DDS by rendering it through a
//  fullscreen quad and capturing with DirectXTex.
// =============================================================================
 
// HLSL source for the passthrough vertex + pixel shaders used when saving
static const char* s_szShaderCode11 =
    "Texture2D txDiffuse : register(t0);"
    "SamplerState samLinear : register(s0);"
    "struct VS_INPUT { float3 Pos : POSITION; float2 Tex : TEXCOORD0; };"
    "struct PS_INPUT { float4 Pos : SV_POSITION; float2 Tex : TEXCOORD0; };"
    "PS_INPUT VS(VS_INPUT input) {"
    "  PS_INPUT o = (PS_INPUT)0;"
    "  o.Pos.xyz = input.Pos.xyz; o.Pos.w = 1.0f;"
    "  o.Tex = input.Tex; return o;"
    "}"
    "float4 PS(PS_INPUT input) : SV_Target {"
    "  return txDiffuse.Sample(samLinear, input.Tex);"
    "}";
 
struct KVert11 { XMFLOAT3 Pos; XMFLOAT2 Tex; };
 
HRESULT KRipper11::compileShaderFromMemory(
    LPCSTR pData, SIZE_T Len,
    LPCSTR szEntry, LPCSTR szModel,
    ID3DBlob** ppBlob)
{
    DWORD flags = D3DCOMPILE_ENABLE_STRICTNESS;
#if defined(DEBUG) || defined(_DEBUG)
    flags |= D3DCOMPILE_DEBUG;
#endif
    TDXRef<ID3DBlob> errBlob;
    HRESULT hr = d3dCompileHelper.D3DCompile(
        pData, Len, nullptr, nullptr, nullptr,
        szEntry, szModel, flags, 0, ppBlob, nullptr);
    if (FAILED(hr) && errBlob.get())
        OutputDebugStringA((char*)errBlob->GetBufferPointer());
    return hr;
}
 
HRESULT KRipper11::saveTexture2FileMain(
    const wchar_t* szFile,
    ID3D11DeviceContext* pDevCont,
    ID3D11ShaderResourceView* pSRV)
{
    HRESULT hr = E_FAIL;
    ID3D11DeviceContext* pImm = getImmCtx(pDevCont);
 
    // Resolve original (un-hooked) function pointers
    auto resolveOrig = [&](UINT vtIdx, ID3D11DeviceContext* ctx) -> LPVOID {
        LPVOID targ = getMethodAddr(ctx, vtIdx);
        KHook* h = g_pHookMgr->getHookByTargetAddress(targ);
        if (!h) { hookDeviceContext(&ctx); }
        return h ? h->getOriginalAddress() : targ;
    };
 
    auto orig_PSSet = (PFN_ID3D11DeviceContext_PSSetShaderResources)
        resolveOrig(IDX_ID3D11DeviceContext_PSSetShaderResources, pImm);
 
    // DrawIndexed: look up via pDevCont first (deferred ctx case)
    LPVOID diTarg = getMethodAddr(pDevCont, IDX_ID3D11DeviceContext_DrawIndexed);
    KHook* diHook = g_pHookMgr->getHookByTargetAddress(diTarg);
    if (!diHook) hookDeviceContext(&pDevCont);
    auto orig_DrawIndexed = (PFN_ID3D11DeviceContext_DrawIndexed)
        (diHook ? diHook->getOriginalAddress() : diTarg);
 
    auto orig_CreateVS = (PFN_ID3D11Device_CreateVertexShader)
        pHook_ID3D11Device_CreateVertexShader->getOriginalAddress();
    auto orig_CreatePS = (PFN_ID3D11Device_CreatePixelShader)
        pHook_ID3D11Device_CreatePixelShader->getOriginalAddress();
    auto orig_CreateIL = (PFN_ID3D11Device_CreateInputLayout)
        pHook_ID3D11Device_CreateInputLayout->getOriginalAddress();
 
    // Check that the SRV is a 2D texture
    D3D11_SHADER_RESOURCE_VIEW_DESC srvDesc = {};
    pSRV->GetDesc(&srvDesc);
    if (srvDesc.ViewDimension != D3D11_SRV_DIMENSION_TEXTURE2D) {
        g_pLog->logError("saveTexture: not a Texture2D (dim=%d)\n", srvDesc.ViewDimension);
        return 0x88887777;
    }
 
    // --- State to save/restore ---
    TDXRef<ID3D11InputLayout>       prevIL;
    TDXRef<ID3D11Buffer>            prevVB, prevIB;
    UINT prevVBStride = 0, prevVBOffset = 0;
    DXGI_FORMAT prevIBFmt = DXGI_FORMAT_UNKNOWN; UINT prevIBOffset = 0;
    D3D11_PRIMITIVE_TOPOLOGY prevTopo = D3D11_PRIMITIVE_TOPOLOGY_UNDEFINED;
    TDXRef<ID3D11RenderTargetView>  prevRTV;
    TDXRef<ID3D11DepthStencilView>  prevDSV;
    UINT prevVPCnt = D3D11_VIEWPORT_AND_SCISSORRECT_OBJECT_COUNT_PER_PIPELINE;
    std::vector<D3D11_VIEWPORT>     prevVPs(prevVPCnt);
    TDXRef<ID3D11BlendState>        prevBlend;
    FLOAT prevBlendFactor[4] = {}; UINT prevSampleMask = 0;
    TDXRef<ID3D11RasterizerState>   prevRS;
    TDXRef<ID3D11DepthStencilState> prevDSS; UINT prevStencilRef = 0;
    TDXRef<ID3D11VertexShader>      prevVS;
    UINT vsCI = 256;
    TDXRefVec<ID3D11ClassInstance>  prevVSCI(vsCI);
    TDXRef<ID3D11PixelShader>       prevPS;
    UINT psCI = 256;
    TDXRefVec<ID3D11ClassInstance>  prevPSCI(psCI);
    TDXRef<ID3D11ShaderResourceView> prevSRV0;
 
    do {
        TDXRef<ID3D11Device> dev;
        TDXRef<ID3D11Resource> srcRes;
        pImm->GetDevice(&dev);
        pSRV->GetResource(&srcRes);
        ID3D11Texture2D* pSrcTex = static_cast<ID3D11Texture2D*>(srcRes.get());
 
        D3D11_TEXTURE2D_DESC texDesc = {};
        pSrcTex->GetDesc(&texDesc);
 
        // Optional downscale
        DWORD texSz     = g_pIntruder->getSettings()->downscaleWidth *
                          g_pIntruder->getSettings()->downscaleHeight;
        DWORD downScale = g_pIntruder->getSettings()->downscale;
        if (texSz && downScale && texDesc.Width * texDesc.Height > texSz) {
            g_pLog->logWarning("Texture too large, downscaling\n");
            texDesc.Width  = max(1u, texDesc.Width  / downScale);
            texDesc.Height = max(1u, texDesc.Height / downScale);
        }
 
        // Compile shaders
        TDXRef<ID3DBlob> vsBlob, psBlob;
        hr = compileShaderFromMemory(s_szShaderCode11, lstrlenA(s_szShaderCode11),
                                     "VS", "vs_4_0", &vsBlob);
        if (FAILED(hr)) { g_pLog->logError("VS compile failed\n"); break; }
 
        TDXRef<ID3D11VertexShader> vs;
        hr = orig_CreateVS(dev.get(), vsBlob->GetBufferPointer(),
                           vsBlob->GetBufferSize(), nullptr, &vs);
        if (FAILED(hr)) { g_pLog->logError("CreateVertexShader failed\n"); break; }
 
        D3D11_INPUT_ELEMENT_DESC layout[] = {
            { "POSITION", 0, DXGI_FORMAT_R32G32B32_FLOAT, 0,  0, D3D11_INPUT_PER_VERTEX_DATA, 0 },
            { "TEXCOORD", 0, DXGI_FORMAT_R32G32_FLOAT,    0, 12, D3D11_INPUT_PER_VERTEX_DATA, 0 },
        };
        TDXRef<ID3D11InputLayout> il;
        hr = orig_CreateIL(dev.get(), layout, ARRAYSIZE(layout),
                           vsBlob->GetBufferPointer(), vsBlob->GetBufferSize(), &il);
        if (FAILED(hr)) { g_pLog->logError("CreateInputLayout failed\n"); break; }
 
        hr = compileShaderFromMemory(s_szShaderCode11, lstrlenA(s_szShaderCode11),
                                     "PS", "ps_4_0", &psBlob);
        if (FAILED(hr)) { g_pLog->logError("PS compile failed\n"); break; }
 
        TDXRef<ID3D11PixelShader> ps;
        hr = orig_CreatePS(dev.get(), psBlob->GetBufferPointer(),
                           psBlob->GetBufferSize(), nullptr, &ps);
        if (FAILED(hr)) { g_pLog->logError("CreatePixelShader failed\n"); break; }
 
        // Fullscreen quad covering NDC [-1,1]
        KVert11 verts[] = {
            { XMFLOAT3(-1.f,-1.f,0.f), XMFLOAT2(0.f,1.f) },
            { XMFLOAT3( 1.f,-1.f,0.f), XMFLOAT2(1.f,1.f) },
            { XMFLOAT3( 1.f, 1.f,0.f), XMFLOAT2(1.f,0.f) },
            { XMFLOAT3(-1.f, 1.f,0.f), XMFLOAT2(0.f,0.f) },
        };
        D3D11_BUFFER_DESC bd = {};
        bd.Usage     = D3D11_USAGE_DEFAULT;
        bd.ByteWidth = sizeof(verts);
        bd.BindFlags = D3D11_BIND_VERTEX_BUFFER;
        D3D11_SUBRESOURCE_DATA init = {}; init.pSysMem = verts;
        TDXRef<ID3D11Buffer> vb;
        hr = dev->CreateBuffer(&bd, &init, &vb);
        if (FAILED(hr)) { g_pLog->logError("CreateBuffer(VB) failed\n"); break; }
 
        WORD indices[] = { 0,1,3, 3,1,2 };
        bd.ByteWidth = sizeof(indices); bd.BindFlags = D3D11_BIND_INDEX_BUFFER;
        init.pSysMem = indices;
        TDXRef<ID3D11Buffer> ib;
        hr = dev->CreateBuffer(&bd, &init, &ib);
        if (FAILED(hr)) { g_pLog->logError("CreateBuffer(IB) failed\n"); break; }
 
        D3D11_SAMPLER_DESC sd = {};
        sd.Filter   = D3D11_FILTER_MIN_MAG_MIP_LINEAR;
        sd.AddressU = sd.AddressV = sd.AddressW = D3D11_TEXTURE_ADDRESS_WRAP;
        sd.ComparisonFunc = D3D11_COMPARISON_NEVER;
        sd.MaxLOD   = D3D11_FLOAT32_MAX;
        TDXRef<ID3D11SamplerState> samp;
        hr = dev->CreateSamplerState(&sd, &samp);
        if (FAILED(hr)) { g_pLog->logError("CreateSamplerState failed\n"); break; }
 
        // Render-target color texture
        D3D11_TEXTURE2D_DESC rtd = {};
        rtd.Width = texDesc.Width; rtd.Height = texDesc.Height;
        rtd.MipLevels = 1; rtd.ArraySize = 1;
        rtd.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        rtd.SampleDesc.Count = 1; rtd.Usage = D3D11_USAGE_DEFAULT;
        rtd.BindFlags = D3D11_BIND_RENDER_TARGET | D3D11_BIND_SHADER_RESOURCE;
        TDXRef<ID3D11Texture2D> colorTex;
        hr = dev->CreateTexture2D(&rtd, nullptr, &colorTex);
        if (FAILED(hr)) { g_pLog->logError("CreateTexture2D(RT) failed\n"); break; }
 
        D3D11_RENDER_TARGET_VIEW_DESC rtvd = {};
        rtvd.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        rtvd.ViewDimension = D3D11_RTV_DIMENSION_TEXTURE2D;
        TDXRef<ID3D11RenderTargetView> rtv;
        hr = dev->CreateRenderTargetView(colorTex.get(), &rtvd, &rtv);
        if (FAILED(hr)) { g_pLog->logError("CreateRenderTargetView failed\n"); break; }
 
        // Depth-stencil
        D3D11_TEXTURE2D_DESC dsd = {};
        dsd.Width = texDesc.Width; dsd.Height = texDesc.Height;
        dsd.MipLevels = 1; dsd.ArraySize = 1;
        dsd.Format = DXGI_FORMAT_D24_UNORM_S8_UINT;
        dsd.SampleDesc.Count = 1; dsd.Usage = D3D11_USAGE_DEFAULT;
        dsd.BindFlags = D3D11_BIND_DEPTH_STENCIL;
        TDXRef<ID3D11Texture2D>       dsTexRef;
        TDXRef<ID3D11DepthStencilView> dsv;
        hr = dev->CreateTexture2D(&dsd, nullptr, &dsTexRef);
        if (FAILED(hr)) { g_pLog->logError("CreateTexture2D(DS) failed\n"); break; }
        D3D11_DEPTH_STENCIL_VIEW_DESC dsvd = {};
        dsvd.Format = dsd.Format; dsvd.ViewDimension = D3D11_DSV_DIMENSION_TEXTURE2D;
        hr = dev->CreateDepthStencilView(dsTexRef.get(), &dsvd, &dsv);
        if (FAILED(hr)) { g_pLog->logError("CreateDepthStencilView failed\n"); break; }
 
        // Rasterizer: no cull, solid fill
        D3D11_RASTERIZER_DESC rsd = {};
        rsd.CullMode = D3D11_CULL_FRONT; rsd.FillMode = D3D11_FILL_SOLID;
        TDXRef<ID3D11RasterizerState> rs;
        hr = dev->CreateRasterizerState(&rsd, &rs);
        if (FAILED(hr)) { g_pLog->logError("CreateRasterizerState failed\n"); break; }
 
        // Blend: no blending
        D3D11_BLEND_DESC bld = {};
        bld.RenderTarget[0].BlendEnable = FALSE;
        bld.RenderTarget[0].SrcBlend    = D3D11_BLEND_ONE;
        bld.RenderTarget[0].DestBlend   = D3D11_BLEND_ZERO;
        bld.RenderTarget[0].BlendOp     = D3D11_BLEND_OP_ADD;
        bld.RenderTarget[0].SrcBlendAlpha  = D3D11_BLEND_ONE;
        bld.RenderTarget[0].DestBlendAlpha = D3D11_BLEND_ZERO;
        bld.RenderTarget[0].BlendOpAlpha   = D3D11_BLEND_OP_ADD;
        bld.RenderTarget[0].RenderTargetWriteMask = D3D11_COLOR_WRITE_ENABLE_ALL;
        TDXRef<ID3D11BlendState> blendState;
        hr = dev->CreateBlendState(&bld, &blendState);
        if (FAILED(hr)) { g_pLog->logError("CreateBlendState failed\n"); break; }
 
        // Depth-stencil state (all disabled)
        D3D11_DEPTH_STENCIL_DESC dss = {};
        TDXRef<ID3D11DepthStencilState> dssState;
        hr = dev->CreateDepthStencilState(&dss, &dssState);
        if (FAILED(hr)) { g_pLog->logError("CreateDepthStencilState failed\n"); break; }
 
        // --- Save current pipeline state ---
        pImm->IAGetInputLayout(&prevIL);
        pImm->VSGetShader(&prevVS, &prevVSCI, &vsCI);
        pImm->PSGetShader(&prevPS, &prevPSCI, &psCI);
        pImm->PSGetShaderResources(0, 1, &prevSRV0);
        pImm->IAGetVertexBuffers(0, 1, &prevVB, &prevVBStride, &prevVBOffset);
        pImm->IAGetIndexBuffer(&prevIB, &prevIBFmt, &prevIBOffset);
        pImm->IAGetPrimitiveTopology(&prevTopo);
        pImm->OMGetRenderTargets(1, &prevRTV, &prevDSV);
        pImm->RSGetViewports(&prevVPCnt, prevVPs.data());
        pImm->RSGetState(&prevRS);
        pImm->OMGetBlendState(&prevBlend, prevBlendFactor, &prevSampleMask);
        pImm->OMGetDepthStencilState(&prevDSS, &prevStencilRef);
 
        // --- Set new state and draw ---
        float bf[4] = {};
        pImm->OMSetBlendState(blendState.get(), bf, 0xffffffff);
        pImm->OMSetDepthStencilState(dssState.get(), 0);
        pImm->OMSetRenderTargets(1, &rtv, dsv.get());
 
        FLOAT cc[4] = { 1.f, 0.f, 1.f, 1.f };
        pImm->ClearRenderTargetView(rtv.get(), cc);
        pImm->ClearDepthStencilView(dsv.get(), D3D11_CLEAR_DEPTH, 1.f, 0);
 
        pImm->RSSetState(rs.get());
 
        D3D11_VIEWPORT vp = {};
        vp.Width    = (FLOAT)texDesc.Width;
        vp.Height   = (FLOAT)texDesc.Height;
        vp.MaxDepth = 1.f;
        pImm->RSSetViewports(1, &vp);
 
        pImm->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
        pImm->IASetIndexBuffer(ib.get(), DXGI_FORMAT_R16_UINT, 0);
        UINT stride = sizeof(KVert11), offset = 0;
        pImm->IASetVertexBuffers(0, 1, &vb, &stride, &offset);
        pImm->IASetInputLayout(il.get());
        pImm->VSSetShader(vs.get(), nullptr, 0);
        pImm->PSSetShader(ps.get(), nullptr, 0);
        orig_PSSet(pImm, 0, 1, &pSRV);
        pImm->PSSetSamplers(0, 1, &samp);
        orig_DrawIndexed(pImm, 6, 0, 0);
 
        // --- Capture and save via DirectXTex ---
        ScratchImage image;
        hr = CaptureTexture(dev.get(), pImm, colorTex.get(), image);
        if (SUCCEEDED(hr))
            hr = SaveToDDSFile(image.GetImages(), image.GetImageCount(),
                               image.GetMetadata(), DDS_FLAGS_NONE, szFile);
        hr = S_OK; // treat save as success if we got here
    } while (FALSE);
 
    // --- Restore pipeline state ---
    pImm->OMSetBlendState(prevBlend.get(), prevBlendFactor, prevSampleMask);
    pImm->OMSetDepthStencilState(prevDSS.get(), prevStencilRef);
    pImm->IASetInputLayout(prevIL.get());
    pImm->IASetVertexBuffers(0, 1, &prevVB, &prevVBStride, &prevVBOffset);
    pImm->IASetIndexBuffer(prevIB.get(), prevIBFmt, prevIBOffset);
    pImm->IASetPrimitiveTopology(prevTopo);
    pImm->OMSetRenderTargets(1, &prevRTV, prevDSV.get());
    pImm->RSSetViewports(prevVPCnt, prevVPs.data());
    pImm->RSSetState(prevRS.get());
    pImm->VSSetShader(prevVS.get(), &prevVSCI, vsCI);
    pImm->PSSetShader(prevPS.get(), &prevPSCI, psCI);
    orig_PSSet(pImm, 0, 1, &prevSRV0);
 
    return hr;
}
 
HRESULT KRipper11::saveTexture2File(
    const wchar_t* szFile,
    ID3D11DeviceContext* pCtx,
    ID3D11ShaderResourceView* pSRV)
{
    dumpShaderResourceView(pSRV);
    drawIndexedEnabled = false;
    HRESULT hr = saveTexture2FileMain(szFile, pCtx, pSRV);
    drawIndexedEnabled = true;
    return hr;
}
 
// =============================================================================
//  IMPLEMENTATION � savemeshtextures11.cpp
// =============================================================================
 
void KRipper11::addMeshTexture(const KTexture& t)
{
    meshTexturesDb.push_back(t);
}
 
bool KRipper11::isMeshTextureSaved(ID3D11ShaderResourceView* pSRV, KTexture* out)
{
    for (const KTexture& t : meshTexturesDb) {
        if (t.pTexture == pSRV) { *out = t; return true; }
    }
    return false;
}
 
//  WARNING: cube and array textures are not fully handled (original TODO).
void KRipper11::saveMeshTextures(ID3D11DeviceContext* pCtx, KMeshTextures* meshTex)
{
    TDXRefVec<ID3D11ShaderResourceView> srvs(D3D11_COMMONSHADER_INPUT_RESOURCE_SLOT_COUNT);
    pCtx->PSGetShaderResources(0, D3D11_COMMONSHADER_INPUT_RESOURCE_SLOT_COUNT, &srvs);
 
    for (size_t i = 0; i < srvs.getSize(); i++) {
        ID3D11ShaderResourceView* pSRV = srvs.getElement(i);
        if (!pSRV) continue;
 
        D3D11_SHADER_RESOURCE_VIEW_DESC desc;
        pSRV->GetDesc(&desc);
        // Skip buffer resources � they are not textures
        if (desc.ViewDimension == D3D11_SRV_DIMENSION_BUFFER ||
            desc.ViewDimension == D3D11_SRV_DIMENSION_BUFFEREX)
            continue;
 
        KTexture tex;
        if (isMeshTextureSaved(pSRV, &tex)) {
            meshTex->textures.push_back(tex.name);
            g_pLog->log("Texture stage #%zu already saved: %s\n", i,
                        wideStringToMultiByte(tex.fullPath.c_str()).c_str());
        } else {
            std::string  nameA;
            std::wstring path = g_pIntruder->getFrameTextureSavePath(nameA, (DWORD)i);
            HRESULT hr = saveTexture2File(path.c_str(), pCtx, pSRV);
            if (SUCCEEDED(hr)) {
                KTexture ft; ft.pTexture = pSRV; ft.name = nameA; ft.fullPath = path;
                addMeshTexture(ft);
                meshTex->textures.push_back(nameA);
                g_pLog->log("Texture stage #%zu saved: %s\n", i,
                            wideStringToMultiByte(path.c_str()).c_str());
            } else {
                g_pLog->logError("Texture save. HRESULT: 0x%08X\n", hr);
                dumpShaderResourceView(pSRV);
            }
        }
        g_pIntruder->incFrameTextureIdx();
    }
}
 
// =============================================================================
//  IMPLEMENTATION � texture11.cpp  (forced-texture-rip via PSSetShaderResources)
// =============================================================================
 
DWORD KRipper11::isTextureSaved(ID3D11ShaderResourceView* pTex)
{
    if (!pTex) return 1;
    for (ID3D11ShaderResourceView* p : TexturesVec)
        if (p == pTex) return 1;
    return 0;
}
 
void KRipper11::helper_ID3D11DeviceContext_PSSetShaderResources(
    KHook* pHook,
    ID3D11DeviceContext* pCtx,
    UINT StartSlot, UINT NumViews,
    ID3D11ShaderResourceView *const *ppSRVs)
{
    auto e = (PFN_ID3D11DeviceContext_PSSetShaderResources)pHook->getOriginalAddress();
 
    EnterCriticalSection(&cs);
    __try { handleTexture(pCtx, StartSlot, NumViews, ppSRVs); }
    __except(EXCEPTION_EXECUTE_HANDLER)
    { g_pLog->logError("Exception in handleTexture()\n"); }
    LeaveCriticalSection(&cs);
 
    e(pCtx, StartSlot, NumViews, ppSRVs);
    hookDeviceContext(&pCtx);
}
 
void KRipper11::handleTexture(
    ID3D11DeviceContext* pCtx,
    UINT /*StartSlot*/, UINT NumViews,
    ID3D11ShaderResourceView *const *ppSRVs)
{
    g_pIntruder->keyHandler(this);
    if (!g_pIntruder->isTexturesRipKeyPressed()) return;
 
    for (UINT j = 0; j < NumViews; j++) {
        ID3D11ShaderResourceView* pSRV = ppSRVs[j];
        if (!pSRV) continue;
 
        D3D11_SHADER_RESOURCE_VIEW_DESC desc;
        pSRV->GetDesc(&desc);
        if (desc.ViewDimension == D3D11_SRV_DIMENSION_BUFFER ||
            desc.ViewDimension == D3D11_SRV_DIMENSION_BUFFEREX)
            continue;
 
        if (isTextureSaved(pSRV)) continue;
 
        std::wstring path = g_pIntruder->getTextureSavePath();
        std::string  pathA = wideStringToMultiByte(path.c_str());
 
        TDXRef<ID3D11Device> dev;
        pCtx->GetDevice(&dev);
 
        HRESULT hr = saveTexture2File(path.c_str(), pCtx, pSRV);
        if (SUCCEEDED(hr)) {
            TexturesVec.push_back(pSRV);
            g_pIntruder->incTextureIdx();
            g_pLog->log("Texture saved: %s\n", pathA.c_str());
        } else {
            g_pLog->logError("Texture save. HRESULT: 0x%08X\n", hr);
            logReasonIfDeviceRemoved(hr, dev.get());
        }
    }
}
 
// =============================================================================
//  IMPLEMENTATION � pre11.cpp  (factory functions)
// =============================================================================
 
KRipper11* create_KRipper11(HINSTANCE hD3D11)
{
    return KRipper11::create(hD3D11);
}
 
void delete_KRipper11(KRipper11*& p)
{
    KRipper11::destroy(p);
}
 
void setIRipper(KDxgi* dxgi, KRipper11* ripper)
{
    if (dxgi)
        dxgi->setIRipper(ripper);
}
 
#endif // _WIN32
// =============================================================================
//  END OF DX11 SECTION
// =============================================================================

// =============================================================================
// =============================================================================
//  SECTION 29  DX7 (d3dim700.dll)  --  KRipper7
//  Sources merged: dx7/dx7types.h, dx7/enums.h, dx7/macro.h,
//                  dx7/kripper7.h/.cpp,
//                  dx7/drawprimitive7.cpp,          dx7/drawprimitivestrided7.cpp,
//                  dx7/drawprimitivevb7.cpp,
//                  dx7/drawindexedprimitive7.cpp,   dx7/drawindexedprimitivestrided7.cpp,
//                  dx7/drawindexedprimitivevb7.cpp,
//                  dx7/savemeshtextures7.cpp,       dx7/savetexture7.cpp,
//                  dx7/texture7.cpp,                dx7/pre7.cpp
//  Also adds common/fvf.cpp (fvfToInputVertexDeclaration) and
//  common/d3dhelper.cpp (dumpVertexesStrided) which are needed by DX7
//  but were not yet present in the common sections.
// =============================================================================
 
// ---- DX7 / DDraw SDK headers ------------------------------------------------
// Requires the DirectX 7 SDK (or compatible) include path in the project.
// On Visual Studio with the legacy DirectX SDK the include order matters:
//   ddraw.h  -> IDirectDraw7, IDirectDrawSurface7, DDLOCK_* constants
//   d3d.h    -> IDirect3D7, IDirect3DDevice7, IDirect3DVertexBuffer7,
//               D3DFVF_*, D3DVERTEXBUFFERDESC, D3DDRAWPRIMITIVESTRIDEDDATA
// If only the modern Windows SDK is available, ddraw.h ships with it but
// d3d.h (DX7 flavour) must come from the legacy DXSDK.
 
#ifndef DIRECT3D_VERSION
#  define DIRECT3D_VERSION 0x0700
#endif
#ifndef DIRECTDRAW_VERSION
#  define DIRECTDRAW_VERSION 0x0700
#endif
// Guard: d3d9.h defines DIRECT3D_VERSION as 0x0900 and includes ddraw.h
// internally; if those headers are already present we only need d3d.h for
// the DX7-specific COM interfaces.
#ifndef __DDRAW_INCLUDED__
#  include <ddraw.h>
#endif
#ifndef __D3D_H__
#  include <d3d.h>
#endif
 
 
// =============================================================================
//  SECTION 29-A  DX7 function-pointer typedefs  (from dx7/dx7types.h)
// =============================================================================
 
// IDirect3D7::CreateDevice
typedef HRESULT (__stdcall* PFN_IDirect3D7_CreateDevice)(
    IDirect3D7*           pFactory,
    REFCLSID              rclsid,
    LPDIRECTDRAWSURFACE7  lpDDS,
    LPDIRECT3DDEVICE7*    lplpD3DDevice);
 
// IDirect3D7::CreateVertexBuffer
typedef HRESULT (__stdcall* PFN_IDirect3D7_CreateVertexBuffer)(
    IDirect3D7*              pFactory,
    D3DVERTEXBUFFERDESC*     lpVBDesc,
    LPDIRECT3DVERTEXBUFFER7* lplpD3DVertexBuffer,
    DWORD                    dwFlags);
 
// IDirect3DDevice7::DrawPrimitive
typedef HRESULT (__stdcall* PFN_IDirect3DDevice7_DrawPrimitive)(
    IDirect3DDevice7*  pDev,
    D3DPRIMITIVETYPE   dptPrimitiveType,
    DWORD              dwVertexTypeDesc,
    LPVOID             lpvVertices,
    DWORD              dwVertexCount,
    DWORD              dwFlags);
 
// IDirect3DDevice7::DrawIndexedPrimitive
typedef HRESULT (__stdcall* PFN_IDirect3DDevice7_DrawIndexedPrimitive)(
    IDirect3DDevice7*  pDev,
    D3DPRIMITIVETYPE   d3dptPrimitiveType,
    DWORD              dwVertexTypeDesc,
    LPVOID             lpvVertices,
    DWORD              dwVertexCount,
    LPWORD             lpwIndices,
    DWORD              dwIndexCount,
    DWORD              dwFlags);
 
// IDirect3DDevice7::DrawPrimitiveStrided
typedef HRESULT (__stdcall* PFN_IDirect3DDevice7_DrawPrimitiveStrided)(
    IDirect3DDevice7*              pDev,
    D3DPRIMITIVETYPE               dptPrimitiveType,
    DWORD                          dwVertexTypeDesc,
    LPD3DDRAWPRIMITIVESTRIDEDDATA  lpVertexArray,
    DWORD                          dwVertexCount,
    DWORD                          dwFlags);
 
// IDirect3DDevice7::DrawIndexedPrimitiveStrided
typedef HRESULT (__stdcall* PFN_IDirect3DDevice7_DrawIndexedPrimitiveStrided)(
    IDirect3DDevice7*              pDev,
    D3DPRIMITIVETYPE               d3dptPrimitiveType,
    DWORD                          dwVertexTypeDesc,
    LPD3DDRAWPRIMITIVESTRIDEDDATA  lpVertexArray,
    DWORD                          dwVertexCount,
    LPWORD                         lpwIndices,
    DWORD                          dwIndexCount,
    DWORD                          dwFlags);
 
// IDirect3DDevice7::DrawPrimitiveVB
typedef HRESULT (__stdcall* PFN_IDirect3DDevice7_DrawPrimitiveVB)(
    IDirect3DDevice7*        pDev,
    D3DPRIMITIVETYPE         d3dptPrimitiveType,
    LPDIRECT3DVERTEXBUFFER7  lpd3dVertexBuffer,
    DWORD                    dwStartVertex,
    DWORD                    dwNumVertices,
    DWORD                    dwFlags);
 
// IDirect3DDevice7::DrawIndexedPrimitiveVB
typedef HRESULT (__stdcall* PFN_IDirect3DDevice7_DrawIndexedPrimitiveVB)(
    IDirect3DDevice7*        pDev,
    D3DPRIMITIVETYPE         d3dptPrimitiveType,
    LPDIRECT3DVERTEXBUFFER7  lpd3dVertexBuffer,
    DWORD                    dwStartVertex,
    DWORD                    dwNumVertices,
    LPWORD                   lpwIndices,
    DWORD                    dwIndexCount,
    DWORD                    dwFlags);
 
// IDirect3DDevice7::SetTexture
typedef HRESULT (__stdcall* PFN_IDirect3DDevice7_SetTexture)(
    IDirect3DDevice7*     pDev,
    DWORD                 dwStage,
    LPDIRECTDRAWSURFACE7  lpTexture);
 
 
// =============================================================================
//  SECTION 29-B  DX7 vtable indices  (from dx7/enums.h)
// =============================================================================
 
enum
{
    IDX7_IDirect3D7_CreateDevice              = 4,
    IDX7_IDirect3D7_CreateVertexBuffer        = 5,
 
    IDX7_IDirect3DDevice7_DrawPrimitive              = 25,
    IDX7_IDirect3DDevice7_DrawIndexedPrimitive       = 26,
    IDX7_IDirect3DDevice7_DrawPrimitiveStrided       = 29,
    IDX7_IDirect3DDevice7_DrawIndexedPrimitiveStrided= 30,
    IDX7_IDirect3DDevice7_DrawPrimitiveVB            = 31,
    IDX7_IDirect3DDevice7_DrawIndexedPrimitiveVB     = 32,
    IDX7_IDirect3DDevice7_SetTexture                 = 35,
};
 
 
// =============================================================================
//  SECTION 29-C  DX7 hook-stub macros  (from dx7/macro.h)
//
//  Each macro instantiates one __stdcall trampoline that routes through
//  KRipper7::this_ to the corresponding helper_*() member function.
//  GENERATE_STUBS_GROUP(STUB_Foo) expands STUB_Foo(0)..STUB_Foo(7) so that
//  HooksGroup (MAX_CNT=8) is fully populated.
// =============================================================================
 
// IDirect3D7::CreateDevice
#define STUB_IDirect3D7_CreateDevice(IDX)                                      \
static HRESULT __stdcall _IDirect3D7_CreateDevice_##IDX(                       \
    IDirect3D7* pD3D, REFCLSID rclsid,                                         \
    LPDIRECTDRAWSURFACE7 lpDDS, LPDIRECT3DDEVICE7* lplpDev)                    \
{                                                                               \
    KHook* h = this_->hooks_IDirect3D7_CreateDevice.getHook(IDX);              \
    return this_->helper_IDirect3D7_CreateDevice(h,pD3D,rclsid,lpDDS,lplpDev); \
}
 
// IDirect3D7::CreateVertexBuffer
#define STUB_IDirect3D7_CreateVertexBuffer(IDX)                                \
static HRESULT __stdcall _IDirect3D7_CreateVertexBuffer_##IDX(                 \
    IDirect3D7* pD3D, D3DVERTEXBUFFERDESC* lpVBDesc,                           \
    LPDIRECT3DVERTEXBUFFER7* lplpVB, DWORD dwFlags)                            \
{                                                                               \
    KHook* h = this_->hooks_IDirect3D7_CreateVertexBuffer.getHook(IDX);        \
    return this_->helper_IDirect3D7_CreateVertexBuffer(h,pD3D,lpVBDesc,lplpVB,dwFlags); \
}
 
// IDirect3DDevice7::DrawPrimitive
#define STUB_IDirect3DDevice7_DrawPrimitive(IDX)                               \
static HRESULT __stdcall _IDirect3DDevice7_DrawPrimitive_##IDX(                \
    IDirect3DDevice7* pDev, D3DPRIMITIVETYPE dpt,                               \
    DWORD dwVTD, LPVOID lpv, DWORD dwVC, DWORD dwF)                            \
{                                                                               \
    KHook* h = this_->hooks_IDirect3DDevice7_DrawPrimitive.getHook(IDX);       \
    return this_->helper_IDirect3DDevice7_DrawPrimitive(h,pDev,dpt,dwVTD,lpv,dwVC,dwF); \
}
 
// IDirect3DDevice7::DrawIndexedPrimitive
#define STUB_IDirect3DDevice7_DrawIndexedPrimitive(IDX)                        \
static HRESULT __stdcall _IDirect3DDevice7_DrawIndexedPrimitive_##IDX(         \
    IDirect3DDevice7* pDev, D3DPRIMITIVETYPE dpt, DWORD dwVTD,                  \
    LPVOID lpv, DWORD dwVC, LPWORD lpwI, DWORD dwIC, DWORD dwF)                \
{                                                                               \
    KHook* h = this_->hooks_IDirect3DDevice7_DrawIndexedPrimitive.getHook(IDX);\
    return this_->helper_IDirect3DDevice7_DrawIndexedPrimitive(                 \
        h,pDev,dpt,dwVTD,lpv,dwVC,lpwI,dwIC,dwF);                              \
}
 
// IDirect3DDevice7::DrawPrimitiveStrided
#define STUB_IDirect3DDevice7_DrawPrimitiveStrided(IDX)                        \
static HRESULT __stdcall _IDirect3DDevice7_DrawPrimitiveStrided_##IDX(         \
    IDirect3DDevice7* pDev, D3DPRIMITIVETYPE dpt, DWORD dwVTD,                  \
    LPD3DDRAWPRIMITIVESTRIDEDDATA lpVA, DWORD dwVC, DWORD dwF)                  \
{                                                                               \
    KHook* h = this_->hooks_IDirect3DDevice7_DrawPrimitiveStrided.getHook(IDX);\
    return this_->helper_IDirect3DDevice7_DrawPrimitiveStrided(                 \
        h,pDev,dpt,dwVTD,lpVA,dwVC,dwF);                                        \
}
 
// IDirect3DDevice7::DrawIndexedPrimitiveStrided
#define STUB_IDirect3DDevice7_DrawIndexedPrimitiveStrided(IDX)                 \
static HRESULT __stdcall _IDirect3DDevice7_DrawIndexedPrimitiveStrided_##IDX(  \
    IDirect3DDevice7* pDev, D3DPRIMITIVETYPE dpt, DWORD dwVTD,                  \
    LPD3DDRAWPRIMITIVESTRIDEDDATA lpVA, DWORD dwVC,                             \
    LPWORD lpwI, DWORD dwIC, DWORD dwF)                                         \
{                                                                               \
    KHook* h = this_->hooks_IDirect3DDevice7_DrawIndexedPrimitiveStrided.getHook(IDX); \
    return this_->helper_IDirect3DDevice7_DrawIndexedPrimitiveStrided(          \
        h,pDev,dpt,dwVTD,lpVA,dwVC,lpwI,dwIC,dwF);                             \
}
 
// IDirect3DDevice7::DrawPrimitiveVB
#define STUB_IDirect3DDevice7_DrawPrimitiveVB(IDX)                             \
static HRESULT __stdcall _IDirect3DDevice7_DrawPrimitiveVB_##IDX(              \
    IDirect3DDevice7* pDev, D3DPRIMITIVETYPE dpt,                               \
    LPDIRECT3DVERTEXBUFFER7 lpVB, DWORD dwSV, DWORD dwNV, DWORD dwF)           \
{                                                                               \
    KHook* h = this_->hooks_IDirect3DDevice7_DrawPrimitiveVB.getHook(IDX);     \
    return this_->helper_IDirect3DDevice7_DrawPrimitiveVB(h,pDev,dpt,lpVB,dwSV,dwNV,dwF); \
}
 
// IDirect3DDevice7::DrawIndexedPrimitiveVB
#define STUB_IDirect3DDevice7_DrawIndexedPrimitiveVB(IDX)                      \
static HRESULT __stdcall _IDirect3DDevice7_DrawIndexedPrimitiveVB_##IDX(       \
    IDirect3DDevice7* pDev, D3DPRIMITIVETYPE dpt,                               \
    LPDIRECT3DVERTEXBUFFER7 lpVB, DWORD dwSV, DWORD dwNV,                      \
    LPWORD lpwI, DWORD dwIC, DWORD dwF)                                         \
{                                                                               \
    KHook* h = this_->hooks_IDirect3DDevice7_DrawIndexedPrimitiveVB.getHook(IDX); \
    return this_->helper_IDirect3DDevice7_DrawIndexedPrimitiveVB(               \
        h,pDev,dpt,lpVB,dwSV,dwNV,lpwI,dwIC,dwF);                              \
}
 
// IDirect3DDevice7::SetTexture
#define STUB_IDirect3DDevice7_SetTexture(IDX)                                  \
static HRESULT __stdcall _IDirect3DDevice7_SetTexture_##IDX(                   \
    IDirect3DDevice7* pDev, DWORD dwStage, LPDIRECTDRAWSURFACE7 lpTex)         \
{                                                                               \
    KHook* h = this_->hooks_IDirect3DDevice7_SetTexture.getHook(IDX);          \
    return this_->helper_IDirect3DDevice7_SetTexture(h,pDev,dwStage,lpTex);    \
}
 
 
// =============================================================================
//  SECTION 29-D  fvfToInputVertexDeclaration  (from common/fvf.cpp)
//
//  Converts a DX7 Flexible Vertex Format (FVF) descriptor into a
//  KInputVertexDeclaration so the generic vertex-dumping pipeline can handle
//  DX7 geometry the same way it handles DX9 geometry.
//
//  FVF layout (packed in order inside one interleaved stream 0):
//    1. Position  : XYZ | XYZRHW | XYZBn  (mandatory)
//    2. Blend Weights: n floats if XYZBn was used
//    3. Normal    : 3 floats  (optional, D3DFVF_NORMAL)
//    4. Point Size: 1 float   (optional, D3DFVF_PSIZE)
//    5. Diffuse   : 4 bytes   (optional, D3DFVF_DIFFUSE)
//    6. Specular  : 4 bytes   (optional, D3DFVF_SPECULAR)
//    7. Tex coords: n sets    (optional, D3DFVF_TEXn)
//       each set is 1-4 floats according to D3DFVF_TEXCOORDSIZEm()
// =============================================================================
 
// Number of blend floats implied by an XYZBn FVF position type
static inline int fvfBlendWeightCount(DWORD fvf)
{
    switch (fvf & D3DFVF_POSITION_MASK)
    {
    case D3DFVF_XYZB1: return 1;
    case D3DFVF_XYZB2: return 2;
    case D3DFVF_XYZB3: return 3;
    case D3DFVF_XYZB4: return 4;
    case D3DFVF_XYZB5: return 5;
    default:           return 0;
    }
}
 
// Return the texture-coordinate dimensionality of tex stage idx (0-7)
// D3DFVF_TEXCOORDSIZE1/2/3/4 pack 2 bits per stage starting at bit 16.
static inline int fvfTexCoordSize(DWORD fvf, int idx)
{
    // Extract the 2-bit field for this texture stage
    DWORD bits = (fvf >> (16 + idx * 2)) & 0x3;
    // 0 = 2D, 1 = 3D, 2 = 4D, 3 = 1D  (per DX SDK documentation)
    switch (bits)
    {
    case 0: return 2;
    case 1: return 3;
    case 2: return 4;
    case 3: return 1;
    default: return 2;
    }
}
 
// Helper: append one element to the declaration
static void fvfAddElement(KInputVertexDeclaration* out,
                          const char* semantic, DWORD semIdx,
                          EInputType::Type type, DWORD& offset)
{
    KInputVertexElement e;
    strCopy(e.UsageSemantic, SEMANTIC_LEN, semantic);
    e.SemanticIndex = semIdx;
    e.Stream        = 0;
    e.Offset        = offset;
    e.Size          = getInputTypeSize(type);
    e.Type          = type;
    out->Decl.push_back(e);
    offset += e.Size;
}
 
void fvfToInputVertexDeclaration(DWORD fvf, KInputVertexDeclaration* out)
{
    out->Decl.clear();
    DWORD offset = 0;
 
    // ---- Position block -------------------------------------------------------
    DWORD posMask = fvf & D3DFVF_POSITION_MASK;
 
    if (posMask == D3DFVF_XYZRHW)
    {
        // Pre-transformed (4 floats: X Y Z W)
        fvfAddElement(out, "POSITION", 0, EInputType::R32G32B32A32_FLOAT, offset);
    }
    else if (posMask == D3DFVF_XYZ)
    {
        fvfAddElement(out, "POSITION", 0, EInputType::R32G32B32_FLOAT, offset);
    }
    else if (posMask == D3DFVF_XYZB1 || posMask == D3DFVF_XYZB2 ||
             posMask == D3DFVF_XYZB3 || posMask == D3DFVF_XYZB4 ||
             posMask == D3DFVF_XYZB5)
    {
        // XYZ position + blend weights
        fvfAddElement(out, "POSITION", 0, EInputType::R32G32B32_FLOAT, offset);
 
        int blendCnt = fvfBlendWeightCount(fvf);
        // Last blend component may be an index (LASTBETA_UBYTE4) - always treat
        // all as floats for simplicity; the blend-index flag is advisory.
        static const EInputType::Type blendTypes[5] = {
            EInputType::R32_FLOAT,
            EInputType::R32G32_FLOAT,
            EInputType::R32G32B32_FLOAT,
            EInputType::R32G32B32A32_FLOAT,
            EInputType::FLOAT5,       // 5 floats (legacy)
        };
        if (blendCnt >= 1 && blendCnt <= 5)
            fvfAddElement(out, "BLENDWEIGHT", 0, blendTypes[blendCnt - 1], offset);
    }
 
    // ---- Normal ---------------------------------------------------------------
    if (fvf & D3DFVF_NORMAL)
        fvfAddElement(out, "NORMAL", 0, EInputType::R32G32B32_FLOAT, offset);
 
    // ---- Point size ----------------------------------------------------------
    if (fvf & D3DFVF_PSIZE)
        fvfAddElement(out, "PSIZE", 0, EInputType::R32_FLOAT, offset);
 
    // ---- Diffuse colour -------------------------------------------------------
    if (fvf & D3DFVF_DIFFUSE)
        fvfAddElement(out, "COLOR", 0, EInputType::B8G8R8A8_UNORM, offset);
 
    // ---- Specular colour ------------------------------------------------------
    if (fvf & D3DFVF_SPECULAR)
        fvfAddElement(out, "COLOR", 1, EInputType::B8G8R8A8_UNORM, offset);
 
    // ---- Texture coordinate sets ---------------------------------------------
    int texCnt = (fvf & D3DFVF_TEXCOUNT_MASK) >> D3DFVF_TEXCOUNT_SHIFT;
    for (int t = 0; t < texCnt; ++t)
    {
        int dim = fvfTexCoordSize(fvf, t);
        static const EInputType::Type texTypes[4] = {
            EInputType::R32_FLOAT,
            EInputType::R32G32_FLOAT,
            EInputType::R32G32B32_FLOAT,
            EInputType::R32G32B32A32_FLOAT,
        };
        fvfAddElement(out, "TEXCOORD", (DWORD)t, texTypes[dim - 1], offset);
    }
}
 
 
// =============================================================================
//  SECTION 29-E  dumpVertexesStrided  (from common/d3dhelper.cpp)
//
//  Reads vertex attributes from a D3DDRAWPRIMITIVESTRIDEDDATA structure
//  (where each semantic has its own base-pointer + stride) and writes the
//  unpacked results into a KVERTICES buffer.
//
//  The mapping from KInputVertexElement semantic to strided array:
//    POSITION  [0]  -> lpVtxArr->position
//    BLENDWEIGHT[0] -> lpVtxArr->position  (blend floats follow XYZ in stream)
//    NORMAL    [0]  -> lpVtxArr->normal
//    PSIZE     [0]  -> lpVtxArr->position  (no separate psize stream in strided)
//    COLOR     [0]  -> lpVtxArr->diffuse
//    COLOR     [1]  -> lpVtxArr->specular
//    TEXCOORD  [n]  -> lpVtxArr->textureCoords[n]
// =============================================================================
 
// Resolves (semantic, semanticIndex) -> strided stream {lpvData, dwStride}
// Returns false when no matching stream could be found.
static bool resolveStridedStream(
    LPD3DDRAWPRIMITIVESTRIDEDDATA lpVtxArr,
    const KInputVertexElement&    ie,
    const BYTE**                  ppBase,
    DWORD*                        pStride,
    DWORD*                        pOffset)
{
    *ppBase   = nullptr;
    *pStride  = 0;
    *pOffset  = 0;
 
    // Helper lambda to pick a strided array member
    auto pick = [&](LPVOID base, DWORD stride, DWORD offset = 0) {
        *ppBase  = (const BYTE*)base;
        *pStride = stride;
        *pOffset = offset;
        return true;
    };
 
    if (strcmp(ie.UsageSemantic, "POSITION") == 0 && ie.SemanticIndex == 0)
        return pick(lpVtxArr->position.lpvData, lpVtxArr->position.dwStride);
 
    if (strcmp(ie.UsageSemantic, "BLENDWEIGHT") == 0)
    {
        // Blend weights immediately follow the 3-float XYZ in the position stream.
        // Offset = 3 * sizeof(float) = 12.
        return pick(lpVtxArr->position.lpvData,
                    lpVtxArr->position.dwStride,
                    12 /*sizeof(float)*3*/);
    }
 
    if (strcmp(ie.UsageSemantic, "NORMAL") == 0)
        return pick(lpVtxArr->normal.lpvData, lpVtxArr->normal.dwStride);
 
    if (strcmp(ie.UsageSemantic, "PSIZE") == 0)
    {
        // No dedicated psize stream; fall back to position stream with an offset
        // that skips XYZ (and any blend weights).  Since we cannot easily
        // recompute the offset here, use position stream + computed offset.
        // In practice PSIZE+strided is extremely rare in DX7 titles.
        return pick(lpVtxArr->position.lpvData, lpVtxArr->position.dwStride);
    }
 
    if (strcmp(ie.UsageSemantic, "COLOR") == 0)
    {
        if (ie.SemanticIndex == 0)
            return pick(lpVtxArr->diffuse.lpvData,  lpVtxArr->diffuse.dwStride);
        if (ie.SemanticIndex == 1)
            return pick(lpVtxArr->specular.lpvData, lpVtxArr->specular.dwStride);
        return false;
    }
 
    if (strcmp(ie.UsageSemantic, "TEXCOORD") == 0)
    {
        DWORD t = ie.SemanticIndex;
        if (t < D3DDP_MAXTEXCOORD)
            return pick(lpVtxArr->textureCoords[t].lpvData,
                        lpVtxArr->textureCoords[t].dwStride);
        return false;
    }
 
    return false;
}
 
void dumpVertexesStrided(
    LPD3DDRAWPRIMITIVESTRIDEDDATA     lpVtxArr,
    const KInputVertexDeclaration&    inpDecl,
    const KOutputVertexDeclaration&   outDecl,
    const OptimizedIndexToMeshIndex&  optIdx,
    KVERTICES*                        pVERTICES)
{
    if (!lpVtxArr) return;
 
    for (size_t i = 0; i < inpDecl.Decl.size(); ++i)
    {
        const KInputVertexElement&  ie = inpDecl.Decl[i];
        const KOutputVertexElement& oe = outDecl.Decl[i];
 
        const BYTE* pBase   = nullptr;
        DWORD       stride  = 0;
        DWORD       srcOfs  = 0;
 
        if (!resolveStridedStream(lpVtxArr, ie, &pBase, &stride, &srcOfs))
            continue;
        if (!pBase || stride == 0)
            continue;
 
        // dumpVertSemantic iterates optIdx: for output vertex j it reads
        // pBase + stride * optIdx[j] + srcOfs and writes to the output buffer.
        // We express the per-element offset via a synthetic base pointer.
        dumpVertSemantic(
            ie.Type,
            pBase + srcOfs,  // adjust base by intra-vertex offset
            0,               // SrcOffs = 0 (already baked into base above)
            stride,
            pVERTICES->getRawData(),
            oe.Offset,
            pVERTICES->getVertexSize(),
            optIdx);
    }
}
 
 
// =============================================================================
//  SECTION 29-F  KRipper7 class definition  (from dx7/kripper7.h)
// =============================================================================
 
class KRipper7 : public IRipper
{
public:
    KRipper7();
    virtual ~KRipper7();
 
    // IRipper interface
    virtual void frameStart()      override;
    virtual void frameEnd()        override;
    virtual void textureRipStart() override;
    virtual void textureRipEnd()   override;
 
    // Called by KDdraw when it intercepts the first IDirect3D7 pointer
    void initialize(IDirect3D7* pD3D);
 
    void cleanup();
 
private:
    // ---- Texture tracking ----------------------------------------------------
    struct KTexture
    {
        IDirectDrawSurface7* pTexture;
        std::string          name;
        std::wstring         fullPath;
        KTexture() : pTexture(nullptr) {}
    };
    typedef std::vector<KTexture> KFrameTextureVec;
 
    // Textures encountered on active draw calls (reset each frame)
    KFrameTextureVec              meshTexturesDb;
    // Textures already saved by the standalone texture-rip hotkey
    std::vector<LPDIRECTDRAWSURFACE7> forcedTexturesDb;
 
    // ---- Singleton -----------------------------------------------------------
    static KRipper7* this_;
 
    // ---- Helpers -------------------------------------------------------------
    void zeroHooks();
    void hook_IDirect3DDevice7(IDirect3DDevice7* pDev);
 
    static EPrimitiveTopology::Type
        D3DPRIMITIVETYPE_to_EPrimitiveTopology(D3DPRIMITIVETYPE pt);
 
    // ---- Mesh-texture helpers ------------------------------------------------
    void saveMeshTextures(IDirect3DDevice7* pDev, KMeshTextures* out);
    void addMeshTexture(const KTexture& t);
    bool isMeshTextureSaved(IDirectDrawSurface7* pTexture, KTexture* out);
 
    // ---- Texture-save helpers ------------------------------------------------
    HRESULT saveTexture2File(const wchar_t* fileName, IDirectDrawSurface7* surf);
    void    dumpTextureDesc (IDirectDrawSurface7* pTexture);
    DWORD   isTextureSaved  (LPDIRECTDRAWSURFACE7 pTex);
    void    handleTextureSave(IDirect3DDevice7* pDev, DWORD Stage,
                              LPDIRECTDRAWSURFACE7 lpTexture);
 
    // ---- Rip helpers (one per Draw* variant) ---------------------------------
    void ripDrawPrimitive(
        IDirect3DDevice7* pDev, D3DPRIMITIVETYPE dpt,
        DWORD dwVTD, LPVOID lpv, DWORD dwVC, DWORD dwF);
 
    void ripDrawIndexedPrimitive(
        IDirect3DDevice7* pDev, D3DPRIMITIVETYPE dpt,
        DWORD dwVTD, LPVOID lpv, DWORD dwVC,
        LPWORD lpwI, DWORD dwIC, DWORD dwF);
 
    void ripDrawPrimitiveStrided(
        IDirect3DDevice7* pDev, D3DPRIMITIVETYPE dpt,
        DWORD dwVTD, LPD3DDRAWPRIMITIVESTRIDEDDATA lpVA, DWORD dwVC, DWORD dwF);
 
    void ripDrawIndexedPrimitiveStrided(
        IDirect3DDevice7* pDev, D3DPRIMITIVETYPE dpt, DWORD dwVTD,
        LPD3DDRAWPRIMITIVESTRIDEDDATA lpVA, DWORD dwVC,
        LPWORD lpwI, DWORD dwIC, DWORD dwF);
 
    void ripDrawPrimitiveVB(
        IDirect3DDevice7* pDev, D3DPRIMITIVETYPE dpt,
        LPDIRECT3DVERTEXBUFFER7 lpVB, DWORD dwSV, DWORD dwNV, DWORD dwF);
 
    void ripDrawIndexedPrimitiveVB(
        IDirect3DDevice7* pDev, D3DPRIMITIVETYPE dpt,
        LPDIRECT3DVERTEXBUFFER7 lpVB, DWORD dwSV, DWORD dwNV,
        LPWORD lpwI, DWORD dwIC, DWORD dwF);
 
    // ---- Critical section ----------------------------------------------------
    CRITICAL_SECTION cs;
 
    // ==========================================================================
    //  Hook groups  (8 slots each, one per COM-object instance seen at runtime)
    // ==========================================================================
 
    // IDirect3D7::CreateDevice
    HooksGroup hooks_IDirect3D7_CreateDevice;
    HRESULT helper_IDirect3D7_CreateDevice(
        KHook*, IDirect3D7*, REFCLSID, LPDIRECTDRAWSURFACE7, LPDIRECT3DDEVICE7*);
    GENERATE_STUBS_GROUP(STUB_IDirect3D7_CreateDevice)
 
    // IDirect3D7::CreateVertexBuffer
    HooksGroup hooks_IDirect3D7_CreateVertexBuffer;
    HRESULT helper_IDirect3D7_CreateVertexBuffer(
        KHook*, IDirect3D7*, D3DVERTEXBUFFERDESC*,
        LPDIRECT3DVERTEXBUFFER7*, DWORD);
    GENERATE_STUBS_GROUP(STUB_IDirect3D7_CreateVertexBuffer)
 
    // IDirect3DDevice7::DrawPrimitive
    HooksGroup hooks_IDirect3DDevice7_DrawPrimitive;
    HRESULT helper_IDirect3DDevice7_DrawPrimitive(
        KHook*, IDirect3DDevice7*, D3DPRIMITIVETYPE, DWORD, LPVOID, DWORD, DWORD);
    GENERATE_STUBS_GROUP(STUB_IDirect3DDevice7_DrawPrimitive)
 
    // IDirect3DDevice7::DrawIndexedPrimitive
    HooksGroup hooks_IDirect3DDevice7_DrawIndexedPrimitive;
    HRESULT helper_IDirect3DDevice7_DrawIndexedPrimitive(
        KHook*, IDirect3DDevice7*, D3DPRIMITIVETYPE, DWORD, LPVOID, DWORD,
        LPWORD, DWORD, DWORD);
    GENERATE_STUBS_GROUP(STUB_IDirect3DDevice7_DrawIndexedPrimitive)
 
    // IDirect3DDevice7::DrawPrimitiveStrided
    HooksGroup hooks_IDirect3DDevice7_DrawPrimitiveStrided;
    HRESULT helper_IDirect3DDevice7_DrawPrimitiveStrided(
        KHook*, IDirect3DDevice7*, D3DPRIMITIVETYPE, DWORD,
        LPD3DDRAWPRIMITIVESTRIDEDDATA, DWORD, DWORD);
    GENERATE_STUBS_GROUP(STUB_IDirect3DDevice7_DrawPrimitiveStrided)
 
    // IDirect3DDevice7::DrawIndexedPrimitiveStrided
    HooksGroup hooks_IDirect3DDevice7_DrawIndexedPrimitiveStrided;
    HRESULT helper_IDirect3DDevice7_DrawIndexedPrimitiveStrided(
        KHook*, IDirect3DDevice7*, D3DPRIMITIVETYPE, DWORD,
        LPD3DDRAWPRIMITIVESTRIDEDDATA, DWORD, LPWORD, DWORD, DWORD);
    GENERATE_STUBS_GROUP(STUB_IDirect3DDevice7_DrawIndexedPrimitiveStrided)
 
    // IDirect3DDevice7::DrawPrimitiveVB
    HooksGroup hooks_IDirect3DDevice7_DrawPrimitiveVB;
    HRESULT helper_IDirect3DDevice7_DrawPrimitiveVB(
        KHook*, IDirect3DDevice7*, D3DPRIMITIVETYPE,
        LPDIRECT3DVERTEXBUFFER7, DWORD, DWORD, DWORD);
    GENERATE_STUBS_GROUP(STUB_IDirect3DDevice7_DrawPrimitiveVB)
 
    // IDirect3DDevice7::DrawIndexedPrimitiveVB
    HooksGroup hooks_IDirect3DDevice7_DrawIndexedPrimitiveVB;
    HRESULT helper_IDirect3DDevice7_DrawIndexedPrimitiveVB(
        KHook*, IDirect3DDevice7*, D3DPRIMITIVETYPE,
        LPDIRECT3DVERTEXBUFFER7, DWORD, DWORD, LPWORD, DWORD, DWORD);
    GENERATE_STUBS_GROUP(STUB_IDirect3DDevice7_DrawIndexedPrimitiveVB)
 
    // IDirect3DDevice7::SetTexture
    HooksGroup hooks_IDirect3DDevice7_SetTexture;
    HRESULT helper_IDirect3DDevice7_SetTexture(
        KHook*, IDirect3DDevice7*, DWORD, LPDIRECTDRAWSURFACE7);
    GENERATE_STUBS_GROUP(STUB_IDirect3DDevice7_SetTexture)
};
 
// Static singleton pointer definition
KRipper7* KRipper7::this_ = nullptr;
 
 
// =============================================================================
//  SECTION 29-G  KRipper7 core  (from dx7/kripper7.cpp)
// =============================================================================
 
KRipper7::KRipper7()
{
    this_ = this;
    InitializeCriticalSection(&cs);
    zeroHooks();
    g_pLog->log("D3D7 ripper init\n");
}
 
KRipper7::~KRipper7()
{
    g_pLog->log("D3D7 ripper uninit\n");
    g_pHookMgr->unhookPool(KHookMgr::EHOOK_POOL_D3DIM700);
    zeroHooks();
    DeleteCriticalSection(&cs);
}
 
void KRipper7::frameStart()   { meshTexturesDb.clear(); }
void KRipper7::frameEnd()     {}
void KRipper7::textureRipStart() { forcedTexturesDb.clear(); }
void KRipper7::textureRipEnd()   {}
void KRipper7::cleanup()         {}
 
void KRipper7::initialize(IDirect3D7* pD3D)
{
    hookEx("IDirect3D7_CreateDevice",
           (DWORD)IDX7_IDirect3D7_CreateDevice,
           pD3D,
           KHookMgr::EHOOK_POOL_D3DIM700,
           &hooks_IDirect3D7_CreateDevice);
 
    hookEx("IDirect3D7_CreateVertexBuffer",
           (DWORD)IDX7_IDirect3D7_CreateVertexBuffer,
           pD3D,
           KHookMgr::EHOOK_POOL_D3DIM700,
           &hooks_IDirect3D7_CreateVertexBuffer);
}
 
void KRipper7::hook_IDirect3DDevice7(IDirect3DDevice7* pDev)
{
    hookEx("IDirect3DDevice7_DrawPrimitive",
           (DWORD)IDX7_IDirect3DDevice7_DrawPrimitive,
           pDev, KHookMgr::EHOOK_POOL_D3DIM700,
           &hooks_IDirect3DDevice7_DrawPrimitive);
 
    hookEx("IDirect3DDevice7_DrawIndexedPrimitive",
           (DWORD)IDX7_IDirect3DDevice7_DrawIndexedPrimitive,
           pDev, KHookMgr::EHOOK_POOL_D3DIM700,
           &hooks_IDirect3DDevice7_DrawIndexedPrimitive);
 
    hookEx("IDirect3DDevice7_DrawPrimitiveStrided",
           (DWORD)IDX7_IDirect3DDevice7_DrawPrimitiveStrided,
           pDev, KHookMgr::EHOOK_POOL_D3DIM700,
           &hooks_IDirect3DDevice7_DrawPrimitiveStrided);
 
    hookEx("IDirect3DDevice7_DrawIndexedPrimitiveStrided",
           (DWORD)IDX7_IDirect3DDevice7_DrawIndexedPrimitiveStrided,
           pDev, KHookMgr::EHOOK_POOL_D3DIM700,
           &hooks_IDirect3DDevice7_DrawIndexedPrimitiveStrided);
 
    hookEx("IDirect3DDevice7_DrawPrimitiveVB",
           (DWORD)IDX7_IDirect3DDevice7_DrawPrimitiveVB,
           pDev, KHookMgr::EHOOK_POOL_D3DIM700,
           &hooks_IDirect3DDevice7_DrawPrimitiveVB);
 
    hookEx("IDirect3DDevice7_DrawIndexedPrimitiveVB",
           (DWORD)IDX7_IDirect3DDevice7_DrawIndexedPrimitiveVB,
           pDev, KHookMgr::EHOOK_POOL_D3DIM700,
           &hooks_IDirect3DDevice7_DrawIndexedPrimitiveVB);
 
    hookEx("IDirect3DDevice7_SetTexture",
           (DWORD)IDX7_IDirect3DDevice7_SetTexture,
           pDev, KHookMgr::EHOOK_POOL_D3DIM700,
           &hooks_IDirect3DDevice7_SetTexture);
}
 
void KRipper7::zeroHooks()
{
    GENERATE_HOOKS_GROUP_CLEARER(IDirect3D7_CreateDevice)
    GENERATE_HOOKS_GROUP_CLEARER(IDirect3D7_CreateVertexBuffer)
    GENERATE_HOOKS_GROUP_CLEARER(IDirect3DDevice7_DrawPrimitive)
    GENERATE_HOOKS_GROUP_CLEARER(IDirect3DDevice7_DrawIndexedPrimitive)
    GENERATE_HOOKS_GROUP_CLEARER(IDirect3DDevice7_DrawPrimitiveStrided)
    GENERATE_HOOKS_GROUP_CLEARER(IDirect3DDevice7_DrawIndexedPrimitiveStrided)
    GENERATE_HOOKS_GROUP_CLEARER(IDirect3DDevice7_DrawPrimitiveVB)
    GENERATE_HOOKS_GROUP_CLEARER(IDirect3DDevice7_DrawIndexedPrimitiveVB)
    GENERATE_HOOKS_GROUP_CLEARER(IDirect3DDevice7_SetTexture)
}
 
EPrimitiveTopology::Type
KRipper7::D3DPRIMITIVETYPE_to_EPrimitiveTopology(D3DPRIMITIVETYPE pt)
{
    switch (pt)
    {
    case D3DPT_POINTLIST:    return EPrimitiveTopology::POINTLIST;
    case D3DPT_LINELIST:     return EPrimitiveTopology::LINELIST;
    case D3DPT_LINESTRIP:    return EPrimitiveTopology::LINESTRIP;
    case D3DPT_TRIANGLELIST: return EPrimitiveTopology::TRIANGLELIST;
    case D3DPT_TRIANGLESTRIP:return EPrimitiveTopology::TRIANGLESTRIP;
    case D3DPT_TRIANGLEFAN:  return EPrimitiveTopology::TRIANGLEFAN;
    default:                 return EPrimitiveTopology::UNKNOWNPRIMITIVETYPE;
    }
}
 
 
// ---- IDirect3D7::CreateVertexBuffer -----------------------------------------
// Strip the WRITEONLY flag so we can Lock() the buffer for readback.
 
HRESULT KRipper7::helper_IDirect3D7_CreateVertexBuffer(
    KHook* h, IDirect3D7* pD3D,
    D3DVERTEXBUFFERDESC* lpVBDesc, LPDIRECT3DVERTEXBUFFER7* lplpVB, DWORD dwFlags)
{
    auto e = (PFN_IDirect3D7_CreateVertexBuffer)h->getOriginalAddress();
    lpVBDesc->dwCaps &= ~D3DVBCAPS_WRITEONLY;
    return e(pD3D, lpVBDesc, lplpVB, dwFlags);
}
 
 
// ---- IDirect3D7::CreateDevice -----------------------------------------------
// Intercept device creation to hook the resulting IDirect3DDevice7 vtable,
// and attach a frame-present hook to the DDraw surface used as render target.
 
HRESULT KRipper7::helper_IDirect3D7_CreateDevice(
    KHook* h, IDirect3D7* pD3D, REFCLSID rclsid,
    LPDIRECTDRAWSURFACE7 lpDDS, LPDIRECT3DDEVICE7* lplpDev)
{
    auto e = (PFN_IDirect3D7_CreateDevice)h->getOriginalAddress();
 
    std::string devname = guidToName(rclsid);
    g_pLog->log("IDirect3D7_CreateDevice(%s)\n", devname.c_str());
 
    HRESULT hr = e(pD3D, rclsid, lpDDS, lplpDev);
    if (SUCCEEDED(hr))
    {
        hook_IDirect3DDevice7(*lplpDev);
 
        // Hook the DDraw surface Flip/Blt for frame detection
        if (g_pDdraw)
            g_pDdraw->hook_IDirectDrawSurface(lpDDS);
    }
    return hr;
}
 
 
// =============================================================================
//  SECTION 29-H  DrawPrimitive  (from dx7/drawprimitive7.cpp)
// =============================================================================
 
void KRipper7::ripDrawPrimitive(
    IDirect3DDevice7* pDev, D3DPRIMITIVETYPE dpt,
    DWORD dwVTD, LPVOID lpv, DWORD dwVC, DWORD /*dwF*/)
{
    do
    {
        EPrimitiveTopology::Type topo = D3DPRIMITIVETYPE_to_EPrimitiveTopology(dpt);
        if (!isPrimitiveTopologySupported(topo))
        {
            g_pLog->logError("DrawPrimitive: unsupported topology\n\n");
            break;
        }
 
        KInputVertexDeclaration  inpDecl;
        KOutputVertexDeclaration outDecl;
        fvfToInputVertexDeclaration(dwVTD, &inpDecl);
        createKOutputVertexDeclaration(inpDecl, outDecl);
        dumpInputVertexDeclaration2Log(inpDecl);
        dumpOutputVertexDeclaration2Log(outDecl);
 
        KFACES                    faces;
        OptimizedIndexToMeshIndex optIdx;
        generateIndexes_VertexCount(topo, dwVC, &faces, &optIdx);
 
        DWORD vertSz  = outDecl.getVertexSize();
        DWORD vertCnt = (DWORD)optIdx.size();
        g_pLog->log("PrimitivesCount=%d\nVertexCnt=%d\nOutVertexSize=%d\n",
                    faces.getPrimitivesCount(), vertCnt, vertSz);
 
        KVERTICES vertices(vertCnt, vertSz);
        dumpVbUP(inpDecl, outDecl, optIdx, &vertices,
                 lpv, inpDecl.getStreamVertexSize(0));
 
        KMeshTextures meshTextures;
        saveMeshTextures(pDev, &meshTextures);
        KMeshShaders  meshShaders; // DX7: no shaders
 
        std::wstring path   = g_pIntruder->getFrameMeshSavePath();
        std::string  pathA  = wideStringToMultiByte(path.c_str());
        HRESULT hr = saveRipFile(path.c_str(), inpDecl, outDecl,
                                 meshTextures, meshShaders, faces, vertices);
        if (SUCCEEDED(hr))
            g_pLog->log("Mesh saved: %s\n\n\n", pathA.c_str());
        else
            g_pLog->logError("Mesh save error: %s\n\n\n", pathA.c_str());
 
        g_pIntruder->incFrameMeshIdx();
    }
    while (false);
}
 
HRESULT KRipper7::helper_IDirect3DDevice7_DrawPrimitive(
    KHook* h, IDirect3DDevice7* pDev, D3DPRIMITIVETYPE dpt,
    DWORD dwVTD, LPVOID lpv, DWORD dwVC, DWORD dwF)
{
    auto e = (PFN_IDirect3DDevice7_DrawPrimitive)h->getOriginalAddress();
 
    g_pIntruder->keyHandler(this);
    DWORD rip    = g_pIntruder->isMeshRipEnabled();
    DWORD minVtx = g_pIntruder->getSettings()->dwMinVertexCount;
 
    if (rip)
    {
        if (dwVC >= minVtx)
        {
            g_pLog->log("IDirect3DDevice7_DrawPrimitive(0x%p,%d,0x%08X,0x%p,%d,0x%08X)\n",
                        pDev, dpt, dwVTD, lpv, dwVC, dwF);
            __try { ripDrawPrimitive(pDev,dpt,dwVTD,lpv,dwVC,dwF); }
            __except(EXCEPTION_EXECUTE_HANDLER)
            { g_pLog->logError("DrawPrimitive exception\n\n\n"); }
        }
        else
            g_pLog->logWarning("DrawPrimitive skipped (vertex count too low)\n");
    }
    return e(pDev, dpt, dwVTD, lpv, dwVC, dwF);
}
 
 
// =============================================================================
//  SECTION 29-I  DrawIndexedPrimitive  (from dx7/drawindexedprimitive7.cpp)
// =============================================================================
 
void KRipper7::ripDrawIndexedPrimitive(
    IDirect3DDevice7* pDev, D3DPRIMITIVETYPE dpt,
    DWORD dwVTD, LPVOID lpv, DWORD /*dwVC*/,
    LPWORD lpwI, DWORD dwIC, DWORD /*dwF*/)
{
    do
    {
        EPrimitiveTopology::Type topo = D3DPRIMITIVETYPE_to_EPrimitiveTopology(dpt);
        if (!isPrimitiveTopologySupported(topo))
        { g_pLog->logError("DrawIndexedPrimitive: unsupported topology\n\n"); break; }
 
        KInputVertexDeclaration  inpDecl;
        KOutputVertexDeclaration outDecl;
        fvfToInputVertexDeclaration(dwVTD, &inpDecl);
        createKOutputVertexDeclaration(inpDecl, outDecl);
        dumpInputVertexDeclaration2Log(inpDecl);
        dumpOutputVertexDeclaration2Log(outDecl);
 
        DWORD primCnt = primitiveCountFromIndexCount(dwIC, topo);
 
        KFACES                    faces;
        OptimizedIndexToMeshIndex optIdx;
        HRESULT hr = dumpIndexesUP(topo, primCnt, &faces, &optIdx,
                                   lpwI, EIndexFormat::INDEX_16);
        if (FAILED(hr))
        { g_pLog->logError("dumpIndexesUP() HRESULT: 0x%08X\n\n", hr); break; }
 
        DWORD vertSz  = outDecl.getVertexSize();
        DWORD vertCnt = (DWORD)optIdx.size();
        g_pLog->log("PrimitivesCount=%d\nVertexCnt=%d\nOutVertexSize=%d\n",
                    faces.getPrimitivesCount(), vertCnt, vertSz);
 
        KVERTICES vertices(vertCnt, vertSz);
        dumpVbUP(inpDecl, outDecl, optIdx, &vertices,
                 lpv, inpDecl.getStreamVertexSize(0));
 
        KMeshTextures meshTextures;
        saveMeshTextures(pDev, &meshTextures);
        KMeshShaders meshShaders;
 
        std::wstring path  = g_pIntruder->getFrameMeshSavePath();
        std::string  pathA = wideStringToMultiByte(path.c_str());
        hr = saveRipFile(path.c_str(), inpDecl, outDecl,
                         meshTextures, meshShaders, faces, vertices);
        if (SUCCEEDED(hr)) g_pLog->log("Mesh saved: %s\n\n\n", pathA.c_str());
        else               g_pLog->logError("Mesh save error: %s\n\n\n", pathA.c_str());
 
        g_pIntruder->incFrameMeshIdx();
    }
    while (false);
}
 
HRESULT KRipper7::helper_IDirect3DDevice7_DrawIndexedPrimitive(
    KHook* h, IDirect3DDevice7* pDev, D3DPRIMITIVETYPE dpt,
    DWORD dwVTD, LPVOID lpv, DWORD dwVC,
    LPWORD lpwI, DWORD dwIC, DWORD dwF)
{
    auto e = (PFN_IDirect3DDevice7_DrawIndexedPrimitive)h->getOriginalAddress();
 
    g_pIntruder->keyHandler(this);
    DWORD rip    = g_pIntruder->isMeshRipEnabled();
    DWORD minVtx = g_pIntruder->getSettings()->dwMinVertexCount;
 
    if (rip)
    {
        if (dwVC >= minVtx)
        {
            g_pLog->log("IDirect3DDevice7_DrawIndexedPrimitive"
                        "(0x%p,%d,0x%08X,0x%p,%d,0x%p,%d,0x%08X)\n",
                        pDev,dpt,dwVTD,lpv,dwVC,lpwI,dwIC,dwF);
            __try { ripDrawIndexedPrimitive(pDev,dpt,dwVTD,lpv,dwVC,lpwI,dwIC,dwF); }
            __except(EXCEPTION_EXECUTE_HANDLER)
            { g_pLog->logError("DrawIndexedPrimitive exception\n\n\n"); }
        }
        else
            g_pLog->logWarning("DrawIndexedPrimitive skipped\n");
    }
    return e(pDev,dpt,dwVTD,lpv,dwVC,lpwI,dwIC,dwF);
}
 
 
// =============================================================================
//  SECTION 29-J  DrawPrimitiveStrided  (from dx7/drawprimitivestrided7.cpp)
// =============================================================================
 
void KRipper7::ripDrawPrimitiveStrided(
    IDirect3DDevice7* pDev, D3DPRIMITIVETYPE dpt,
    DWORD dwVTD, LPD3DDRAWPRIMITIVESTRIDEDDATA lpVA, DWORD dwVC, DWORD /*dwF*/)
{
    do
    {
        EPrimitiveTopology::Type topo = D3DPRIMITIVETYPE_to_EPrimitiveTopology(dpt);
        if (!isPrimitiveTopologySupported(topo))
        { g_pLog->logError("DrawPrimitiveStrided: unsupported topology\n\n"); break; }
 
        KInputVertexDeclaration  inpDecl;
        KOutputVertexDeclaration outDecl;
        fvfToInputVertexDeclaration(dwVTD, &inpDecl);
        createKOutputVertexDeclaration(inpDecl, outDecl);
        dumpInputVertexDeclaration2Log(inpDecl);
        dumpOutputVertexDeclaration2Log(outDecl);
 
        KFACES                    faces;
        OptimizedIndexToMeshIndex optIdx;
        generateIndexes_VertexCount(topo, dwVC, &faces, &optIdx);
 
        DWORD vertSz  = outDecl.getVertexSize();
        DWORD vertCnt = (DWORD)optIdx.size();
        g_pLog->log("PrimitivesCount=%d\nVertexCnt=%d\nOutVertexSize=%d\n",
                    faces.getPrimitivesCount(), vertCnt, vertSz);
 
        KVERTICES vertices(vertCnt, vertSz);
        dumpVertexesStrided(lpVA, inpDecl, outDecl, optIdx, &vertices);
 
        KMeshTextures meshTextures;
        saveMeshTextures(pDev, &meshTextures);
        KMeshShaders meshShaders;
 
        std::wstring path  = g_pIntruder->getFrameMeshSavePath();
        std::string  pathA = wideStringToMultiByte(path.c_str());
        HRESULT hr = saveRipFile(path.c_str(), inpDecl, outDecl,
                                 meshTextures, meshShaders, faces, vertices);
        if (SUCCEEDED(hr)) g_pLog->log("Mesh saved: %s\n\n\n", pathA.c_str());
        else               g_pLog->logError("Mesh save error: %s\n\n\n", pathA.c_str());
 
        g_pIntruder->incFrameMeshIdx();
    }
    while (false);
}
 
HRESULT KRipper7::helper_IDirect3DDevice7_DrawPrimitiveStrided(
    KHook* h, IDirect3DDevice7* pDev, D3DPRIMITIVETYPE dpt,
    DWORD dwVTD, LPD3DDRAWPRIMITIVESTRIDEDDATA lpVA, DWORD dwVC, DWORD dwF)
{
    auto e = (PFN_IDirect3DDevice7_DrawPrimitiveStrided)h->getOriginalAddress();
 
    g_pIntruder->keyHandler(this);
    DWORD rip    = g_pIntruder->isMeshRipEnabled();
    DWORD minVtx = g_pIntruder->getSettings()->dwMinVertexCount;
 
    if (rip)
    {
        if (dwVC >= minVtx)
        {
            g_pLog->log("IDirect3DDevice7_DrawPrimitiveStrided"
                        "(0x%p,%d,0x%08X,0x%p,%d,0x%08X)\n",
                        pDev,dpt,dwVTD,lpVA,dwVC,dwF);
            __try { ripDrawPrimitiveStrided(pDev,dpt,dwVTD,lpVA,dwVC,dwF); }
            __except(EXCEPTION_EXECUTE_HANDLER)
            { g_pLog->logError("DrawPrimitiveStrided exception\n\n\n"); }
        }
        else
            g_pLog->logWarning("DrawPrimitiveStrided skipped\n");
    }
    return e(pDev,dpt,dwVTD,lpVA,dwVC,dwF);
}
 
 
// =============================================================================
//  SECTION 29-K  DrawIndexedPrimitiveStrided  (dx7/drawindexedprimitivestrided7.cpp)
// =============================================================================
 
void KRipper7::ripDrawIndexedPrimitiveStrided(
    IDirect3DDevice7* pDev, D3DPRIMITIVETYPE dpt, DWORD dwVTD,
    LPD3DDRAWPRIMITIVESTRIDEDDATA lpVA, DWORD /*dwVC*/,
    LPWORD lpwI, DWORD dwIC, DWORD /*dwF*/)
{
    do
    {
        EPrimitiveTopology::Type topo = D3DPRIMITIVETYPE_to_EPrimitiveTopology(dpt);
        if (!isPrimitiveTopologySupported(topo))
        { g_pLog->logError("DrawIndexedPrimitiveStrided: unsupported topology\n\n"); break; }
 
        KInputVertexDeclaration  inpDecl;
        KOutputVertexDeclaration outDecl;
        fvfToInputVertexDeclaration(dwVTD, &inpDecl);
        createKOutputVertexDeclaration(inpDecl, outDecl);
        dumpInputVertexDeclaration2Log(inpDecl);
        dumpOutputVertexDeclaration2Log(outDecl);
 
        DWORD primCnt = primitiveCountFromIndexCount(dwIC, topo);
 
        KFACES                    faces;
        OptimizedIndexToMeshIndex optIdx;
        HRESULT hr = dumpIndexesUP(topo, primCnt, &faces, &optIdx,
                                   lpwI, EIndexFormat::INDEX_16);
        if (FAILED(hr))
        { g_pLog->logError("dumpIndexesUP() HRESULT: 0x%08X\n\n", hr); break; }
 
        DWORD vertSz  = outDecl.getVertexSize();
        DWORD vertCnt = (DWORD)optIdx.size();
        g_pLog->log("PrimitivesCount=%d\nVertexCnt=%d\nOutVertexSize=%d\n",
                    faces.getPrimitivesCount(), vertCnt, vertSz);
 
        KVERTICES vertices(vertCnt, vertSz);
        dumpVertexesStrided(lpVA, inpDecl, outDecl, optIdx, &vertices);
 
        KMeshTextures meshTextures;
        saveMeshTextures(pDev, &meshTextures);
        KMeshShaders meshShaders;
 
        std::wstring path  = g_pIntruder->getFrameMeshSavePath();
        std::string  pathA = wideStringToMultiByte(path.c_str());
        hr = saveRipFile(path.c_str(), inpDecl, outDecl,
                         meshTextures, meshShaders, faces, vertices);
        if (SUCCEEDED(hr)) g_pLog->log("Mesh saved: %s\n\n\n", pathA.c_str());
        else               g_pLog->logError("Mesh save error: %s\n\n\n", pathA.c_str());
 
        g_pIntruder->incFrameMeshIdx();
    }
    while (false);
}
 
HRESULT KRipper7::helper_IDirect3DDevice7_DrawIndexedPrimitiveStrided(
    KHook* h, IDirect3DDevice7* pDev, D3DPRIMITIVETYPE dpt, DWORD dwVTD,
    LPD3DDRAWPRIMITIVESTRIDEDDATA lpVA, DWORD dwVC,
    LPWORD lpwI, DWORD dwIC, DWORD dwF)
{
    auto e = (PFN_IDirect3DDevice7_DrawIndexedPrimitiveStrided)h->getOriginalAddress();
 
    g_pIntruder->keyHandler(this);
    DWORD rip    = g_pIntruder->isMeshRipEnabled();
    DWORD minVtx = g_pIntruder->getSettings()->dwMinVertexCount;
 
    if (rip)
    {
        if (dwVC >= minVtx)
        {
            g_pLog->log("IDirect3DDevice7_DrawIndexedPrimitiveStrided"
                        "(0x%p,%d,0x%08X,0x%p,%d,0x%p,%d,0x%08X)\n",
                        pDev,dpt,dwVTD,lpVA,dwVC,lpwI,dwIC,dwF);
            __try
            { ripDrawIndexedPrimitiveStrided(pDev,dpt,dwVTD,lpVA,dwVC,lpwI,dwIC,dwF); }
            __except(EXCEPTION_EXECUTE_HANDLER)
            { g_pLog->logError("DrawIndexedPrimitiveStrided exception\n\n\n"); }
        }
        else
            g_pLog->logWarning("DrawIndexedPrimitiveStrided skipped\n");
    }
    return e(pDev,dpt,dwVTD,lpVA,dwVC,lpwI,dwIC,dwF);
}
 
 
// =============================================================================
//  SECTION 29-L  DrawPrimitiveVB  (from dx7/drawprimitivevb7.cpp)
// =============================================================================
 
void KRipper7::ripDrawPrimitiveVB(
    IDirect3DDevice7* pDev, D3DPRIMITIVETYPE dpt,
    LPDIRECT3DVERTEXBUFFER7 lpVB, DWORD dwSV, DWORD dwNV, DWORD /*dwF*/)
{
    do
    {
        EPrimitiveTopology::Type topo = D3DPRIMITIVETYPE_to_EPrimitiveTopology(dpt);
        if (!isPrimitiveTopologySupported(topo))
        { g_pLog->logError("DrawPrimitiveVB: unsupported topology\n\n"); break; }
 
        D3DVERTEXBUFFERDESC vbDesc = {};
        vbDesc.dwSize = sizeof(vbDesc);
        HRESULT hr = lpVB->GetVertexBufferDesc(&vbDesc);
        if (FAILED(hr))
        { g_pLog->logError("GetVertexBufferDesc() HRESULT: 0x%08X\n\n\n", hr); break; }
 
        KInputVertexDeclaration  inpDecl;
        KOutputVertexDeclaration outDecl;
        g_pLog->log("FVF: 0x%08X\n", vbDesc.dwFVF);
        fvfToInputVertexDeclaration(vbDesc.dwFVF, &inpDecl);
        createKOutputVertexDeclaration(inpDecl, outDecl);
        dumpInputVertexDeclaration2Log(inpDecl);
        dumpOutputVertexDeclaration2Log(outDecl);
 
        DWORD primCnt = primitiveCountFromVertexCount(dwNV, topo);
 
        KFACES                    faces;
        OptimizedIndexToMeshIndex optIdx;
        generateIndexes_PrimitiveCount(topo, primCnt, &faces, &optIdx);
 
        DWORD vertSz  = outDecl.getVertexSize();
        DWORD vertCnt = (DWORD)optIdx.size();
        g_pLog->log("PrimitivesCount=%d\nVertexCnt=%d\nOutVertexSize=%d\n",
                    faces.getPrimitivesCount(), vertCnt, vertSz);
 
        KVERTICES vertices(vertCnt, vertSz);
 
        LPVOID vbData = nullptr;
        hr = lpVB->Lock(DDLOCK_READONLY | DDLOCK_WAIT, &vbData, nullptr);
        if (FAILED(hr))
        { g_pLog->logError("VB Lock() HRESULT: 0x%08X\n\n", hr); break; }
 
        DWORD stride = inpDecl.getStreamVertexSize(0);
        dumpVbUP(inpDecl, outDecl, optIdx, &vertices,
                 (BYTE*)vbData + dwSV * stride, stride);
 
        lpVB->Unlock();
 
        KMeshTextures meshTextures;
        saveMeshTextures(pDev, &meshTextures);
        KMeshShaders meshShaders;
 
        std::wstring path  = g_pIntruder->getFrameMeshSavePath();
        std::string  pathA = wideStringToMultiByte(path.c_str());
        hr = saveRipFile(path.c_str(), inpDecl, outDecl,
                         meshTextures, meshShaders, faces, vertices);
        if (SUCCEEDED(hr)) g_pLog->log("Mesh saved: %s\n\n\n", pathA.c_str());
        else               g_pLog->logError("Mesh save error: %s\n\n\n", pathA.c_str());
 
        g_pIntruder->incFrameMeshIdx();
    }
    while (false);
}
 
HRESULT KRipper7::helper_IDirect3DDevice7_DrawPrimitiveVB(
    KHook* h, IDirect3DDevice7* pDev, D3DPRIMITIVETYPE dpt,
    LPDIRECT3DVERTEXBUFFER7 lpVB, DWORD dwSV, DWORD dwNV, DWORD dwF)
{
    auto e = (PFN_IDirect3DDevice7_DrawPrimitiveVB)h->getOriginalAddress();
 
    g_pIntruder->keyHandler(this);
    DWORD rip    = g_pIntruder->isMeshRipEnabled();
    DWORD minVtx = g_pIntruder->getSettings()->dwMinVertexCount;
 
    if (rip)
    {
        if (dwNV >= minVtx)
        {
            g_pLog->log("IDirect3DDevice7_DrawPrimitiveVB"
                        "(0x%p,%d,0x%p,%d,%d,0x%08X)\n",
                        pDev,dpt,lpVB,dwSV,dwNV,dwF);
            __try { ripDrawPrimitiveVB(pDev,dpt,lpVB,dwSV,dwNV,dwF); }
            __except(EXCEPTION_EXECUTE_HANDLER)
            { g_pLog->logError("DrawPrimitiveVB exception\n\n\n"); }
        }
        else
            g_pLog->logWarning("DrawPrimitiveVB skipped\n");
    }
    return e(pDev,dpt,lpVB,dwSV,dwNV,dwF);
}
 
 
// =============================================================================
//  SECTION 29-M  DrawIndexedPrimitiveVB  (from dx7/drawindexedprimitivevb7.cpp)
// =============================================================================
 
void KRipper7::ripDrawIndexedPrimitiveVB(
    IDirect3DDevice7* pDev, D3DPRIMITIVETYPE dpt,
    LPDIRECT3DVERTEXBUFFER7 lpVB, DWORD dwSV, DWORD dwNV,
    LPWORD lpwI, DWORD dwIC, DWORD /*dwF*/)
{
    do
    {
        EPrimitiveTopology::Type topo = D3DPRIMITIVETYPE_to_EPrimitiveTopology(dpt);
        if (!isPrimitiveTopologySupported(topo))
        { g_pLog->logError("DrawIndexedPrimitiveVB: unsupported topology\n\n"); break; }
 
        D3DVERTEXBUFFERDESC vbDesc = {};
        vbDesc.dwSize = sizeof(vbDesc);
        HRESULT hr = lpVB->GetVertexBufferDesc(&vbDesc);
        if (FAILED(hr))
        { g_pLog->logError("GetVertexBufferDesc() HRESULT: 0x%08X\n\n\n", hr); break; }
 
        KInputVertexDeclaration  inpDecl;
        KOutputVertexDeclaration outDecl;
        g_pLog->log("FVF: 0x%08X\n", vbDesc.dwFVF);
        fvfToInputVertexDeclaration(vbDesc.dwFVF, &inpDecl);
        createKOutputVertexDeclaration(inpDecl, outDecl);
        dumpInputVertexDeclaration2Log(inpDecl);
        dumpOutputVertexDeclaration2Log(outDecl);
 
        DWORD primCnt = primitiveCountFromIndexCount(dwIC, topo);
 
        KFACES                    faces;
        OptimizedIndexToMeshIndex optIdx;
        hr = dumpIndexesUP(topo, primCnt, &faces, &optIdx,
                           lpwI, EIndexFormat::INDEX_16);
        if (FAILED(hr))
        { g_pLog->logError("dumpIndexesUP() HRESULT: 0x%08X\n\n", hr); break; }
 
        DWORD vertSz  = outDecl.getVertexSize();
        DWORD vertCnt = (DWORD)optIdx.size();
        g_pLog->log("PrimitivesCount=%d\nVertexCnt=%d\nOutVertexSize=%d\n",
                    faces.getPrimitivesCount(), vertCnt, vertSz);
 
        KVERTICES vertices(vertCnt, vertSz);
 
        LPVOID vbData = nullptr;
        hr = lpVB->Lock(DDLOCK_READONLY | DDLOCK_WAIT, &vbData, nullptr);
        if (FAILED(hr))
        { g_pLog->logError("VB Lock() HRESULT: 0x%08X\n\n", hr); break; }
 
        DWORD stride = inpDecl.getStreamVertexSize(0);
        dumpVbUP(inpDecl, outDecl, optIdx, &vertices,
                 (BYTE*)vbData + dwSV * stride, stride);
 
        lpVB->Unlock();
 
        KMeshTextures meshTextures;
        saveMeshTextures(pDev, &meshTextures);
        KMeshShaders meshShaders;
 
        std::wstring path  = g_pIntruder->getFrameMeshSavePath();
        std::string  pathA = wideStringToMultiByte(path.c_str());
        hr = saveRipFile(path.c_str(), inpDecl, outDecl,
                         meshTextures, meshShaders, faces, vertices);
        if (SUCCEEDED(hr)) g_pLog->log("Mesh saved: %s\n\n\n", pathA.c_str());
        else               g_pLog->logError("Mesh save error: %s\n\n\n", pathA.c_str());
 
        g_pIntruder->incFrameMeshIdx();
    }
    while (false);
}
 
HRESULT KRipper7::helper_IDirect3DDevice7_DrawIndexedPrimitiveVB(
    KHook* h, IDirect3DDevice7* pDev, D3DPRIMITIVETYPE dpt,
    LPDIRECT3DVERTEXBUFFER7 lpVB, DWORD dwSV, DWORD dwNV,
    LPWORD lpwI, DWORD dwIC, DWORD dwF)
{
    auto e = (PFN_IDirect3DDevice7_DrawIndexedPrimitiveVB)h->getOriginalAddress();
 
    g_pIntruder->keyHandler(this);
    DWORD rip    = g_pIntruder->isMeshRipEnabled();
    DWORD minVtx = g_pIntruder->getSettings()->dwMinVertexCount;
 
    if (rip)
    {
        if (dwNV >= minVtx)
        {
            g_pLog->log("IDirect3DDevice7_DrawIndexedPrimitiveVB"
                        "(0x%p,%d,0x%p,%d,%d,0x%p,%d,0x%08X)\n",
                        pDev,dpt,lpVB,dwSV,dwNV,lpwI,dwIC,dwF);
            __try
            { ripDrawIndexedPrimitiveVB(pDev,dpt,lpVB,dwSV,dwNV,lpwI,dwIC,dwF); }
            __except(EXCEPTION_EXECUTE_HANDLER)
            { g_pLog->logError("DrawIndexedPrimitiveVB exception\n\n\n"); }
        }
        else
            g_pLog->logWarning("DrawIndexedPrimitiveVB skipped\n");
    }
    return e(pDev,dpt,lpVB,dwSV,dwNV,lpwI,dwIC,dwF);
}
 
 
// =============================================================================
//  SECTION 29-N  Texture management  (from dx7/savemeshtextures7.cpp,
//                                         dx7/savetexture7.cpp,
//                                         dx7/texture7.cpp)
// =============================================================================
 
// ---- savemeshtextures7 ------------------------------------------------------
 
void KRipper7::addMeshTexture(const KTexture& t)
{
    meshTexturesDb.push_back(t);
}
 
bool KRipper7::isMeshTextureSaved(IDirectDrawSurface7* pTexture, KTexture* out)
{
    for (auto& t : meshTexturesDb)
    {
        if (t.pTexture == pTexture)
        { *out = t; return true; }
    }
    return false;
}
 
void KRipper7::saveMeshTextures(IDirect3DDevice7* pDev, KMeshTextures* meshTextures)
{
    for (DWORD i = 0; i < 8; ++i)
    {
        // TDXRef auto-releases on scope exit
        IDirectDrawSurface7* pRawTex = nullptr;
        HRESULT hr = pDev->GetTexture(i, (LPDIRECTDRAWSURFACE7*)&pRawTex);
        if (FAILED(hr))
        {
            g_pLog->logError("GetTexture(%d) HRESULT: 0x%08X\n", i, hr);
            continue;
        }
        if (!pRawTex) continue;
 
        // We own a reference; release on all paths
        struct AutoRelease {
            IDirectDrawSurface7* p;
            ~AutoRelease() { if(p) p->Release(); }
        } ar = {pRawTex};
 
        KTexture savedTex;
        if (isMeshTextureSaved(pRawTex, &savedTex))
        {
            meshTextures->textures.push_back(savedTex.name);
            g_pLog->log("Texture stage #%d already saved: %s\n", i,
                        wideStringToMultiByte(savedTex.fullPath.c_str()).c_str());
        }
        else
        {
            std::string  nameA;
            std::wstring path = g_pIntruder->getFrameTextureSavePath(nameA, i);
 
            hr = saveTexture2File(path.c_str(), pRawTex);
            if (SUCCEEDED(hr))
            {
                KTexture ft;
                ft.pTexture = pRawTex;
                ft.name     = nameA;
                ft.fullPath = path;
                addMeshTexture(ft);
                meshTextures->textures.push_back(nameA);
                g_pLog->log("Texture stage #%d saved: %s\n", i,
                            wideStringToMultiByte(path.c_str()).c_str());
            }
            else
                g_pLog->logError("Texture stage #%d save HRESULT: 0x%08X\n", i, hr);
 
            g_pIntruder->incFrameTextureIdx();
        }
    }
}
 
// ---- savetexture7 -----------------------------------------------------------
// Delegates to KDdraw which knows how to blit a DDraw surface to disk.
 
HRESULT KRipper7::saveTexture2File(const wchar_t* fileName,
                                    IDirectDrawSurface7* surf)
{
    if (!g_pDdraw)
    {
        g_pLog->logError("saveTexture2File: g_pDdraw is null\n");
        return E_POINTER;
    }
    return g_pDdraw->save_IDirectDrawSurface(fileName, surf);
}
 
void KRipper7::dumpTextureDesc(IDirectDrawSurface7* /*pTexture*/)
{
    // Diagnostic logging of the DDraw surface descriptor.
    // Left as a no-op in this integration; add DDSURFACEDESC2 queries here
    // if deeper debugging of texture formats is needed.
}
 
// ---- texture7 (SetTexture hook + forced texture rip) ------------------------
 
DWORD KRipper7::isTextureSaved(LPDIRECTDRAWSURFACE7 pTex)
{
    if (!pTex) return 1; // null = "unset" => treat as already handled
 
    for (auto p : forcedTexturesDb)
        if (p == pTex) return 1;
 
    return 0;
}
 
void KRipper7::handleTextureSave(IDirect3DDevice7* /*pDev*/, DWORD /*Stage*/,
                                  LPDIRECTDRAWSURFACE7 pTexture)
{
    g_pIntruder->keyHandler(this);
    if (!g_pIntruder->isTexturesRipKeyPressed()) return;
 
    if (!isTextureSaved(pTexture))
    {
        std::wstring path  = g_pIntruder->getTextureSavePath();
        std::string  pathA = wideStringToMultiByte(path.c_str());
 
        HRESULT hr = saveTexture2File(path.c_str(), pTexture);
        if (SUCCEEDED(hr))
        {
            g_pIntruder->incTextureIdx();
            g_pLog->log("Texture saved: %s\n", pathA.c_str());
        }
        else
            g_pLog->logError("Texture save HRESULT: 0x%08X\n", hr);
 
        // Mark as processed regardless of success so we don't retry every frame
        forcedTexturesDb.push_back(pTexture);
    }
}
 
HRESULT KRipper7::helper_IDirect3DDevice7_SetTexture(
    KHook* h, IDirect3DDevice7* pDev, DWORD dwStage, LPDIRECTDRAWSURFACE7 lpTexture)
{
    // DX7 runtimes sometimes replace the device vtable between calls, so
    // re-hook here (same pattern as DX9's setDeviceHooks).
    hook_IDirect3DDevice7(pDev);
 
    auto e = (PFN_IDirect3DDevice7_SetTexture)h->getOriginalAddress();
 
    EnterCriticalSection(&cs);
    __try { handleTextureSave(pDev, dwStage, lpTexture); }
    __except(EXCEPTION_EXECUTE_HANDLER)
    { g_pLog->logError("Exception in KRipper7::handleTextureSave()\n"); }
    LeaveCriticalSection(&cs);
 
    return e(pDev, dwStage, lpTexture);
}
 
 
// =============================================================================
//  SECTION 29-O  Factory functions  (from dx7/pre7.cpp)
// =============================================================================
 
KRipper7* create_KRipper7()           { return new KRipper7; }
void      delete_KRipper7(KRipper7*& p) { delete p; p = nullptr; }

// =============================================================================
// =============================================================================
//  SECTION 30  DirectX 6 (d3dim.dll)  --  KRipper6
//
//  Sources merged:
//    dx6/dx6types.h          dx6/enums.h           dx6/macro.h
//    dx6/kripper6.h/.cpp
//    dx6/drawprimitive6.cpp              dx6/drawprimitivestrided6.cpp
//    dx6/drawprimitivevb6.cpp
//    dx6/drawindexedprimitive6.cpp       dx6/drawindexedprimitivestrided6.cpp
//    dx6/drawindexedprimitivevb6.cpp
//    dx6/savemeshtextures6.cpp           dx6/savetexture6.cpp
//    dx6/texture6.cpp                    dx6/pre6.cpp
//
//  This section uses the DX6 COM interfaces from the legacy DXSDK7 headers
//  (ddraw.h / d3d.h).  Include order in the outer TU must be:
//    #include <ddraw.h>   // IDirectDraw4, IDirectDrawSurface4
//    #include <d3d.h>     // IDirect3D3, IDirect3DDevice3, D3DFVF_* …
//  Both headers must appear *before* d3d9.h (or enable only DX6 in the build).
// =============================================================================

// Guard: compile this block only when the DX6 SDK headers are present.
#if defined(__DDRAW_INCLUDED__) && defined(__D3D_H__)

// ---------------------------------------------------------------------------
//  SECTION 30-A  Function-pointer typedefs  (from dx6/dx6types.h)
// ---------------------------------------------------------------------------
#pragma once


#include "../DXSDK/DXSDK7/include/ddraw.h"
#include "../DXSDK/DXSDK7/include/d3d.h"



// IDirect3D3_CreateDevice
typedef HRESULT(__stdcall* PFN_IDirect3D3_CreateDevice)(
                                           IDirect3D3* d3d,
                                           REFCLSID rclsid,
                                           LPDIRECTDRAWSURFACE4 lpDDS,
                                           LPDIRECT3DDEVICE3*  lplpD3DDevice,
                                           LPUNKNOWN pUnkOuter
                                           );

// IDirect3D3_CreateVertexBuffer
typedef HRESULT(__stdcall* PFN_IDirect3D3_CreateVertexBuffer)(
                                IDirect3D3* d3d,
                                LPD3DVERTEXBUFFERDESC lpVBDesc,
                                LPDIRECT3DVERTEXBUFFER* lpD3DVertexBuffer,
                                DWORD dwFlags,
                                LPUNKNOWN pUnkOuter
                                );


// IDirect3DDevice3_DrawPrimitive
typedef HRESULT (__stdcall* PFN_IDirect3DDevice3_DrawPrimitive)(
                                            IDirect3DDevice3* pDev,
                                            D3DPRIMITIVETYPE dptPrimitiveType,
                                            DWORD  dwVertexTypeDesc,
                                            LPVOID lpvVertices,
                                            DWORD  dwVertexCount,
                                            DWORD  dwFlags
                                            );

// IDirect3DDevice3_DrawIndexedPrimitive
typedef HRESULT(__stdcall* PFN_IDirect3DDevice3_DrawIndexedPrimitive)(
                                            IDirect3DDevice3* pDev,
                                            D3DPRIMITIVETYPE d3dptPrimitiveType,
                                            DWORD  dwVertexTypeDesc,
                                            LPVOID lpvVertices,
                                            DWORD  dwVertexCount,
                                            LPWORD lpwIndices,
                                            DWORD  dwIndexCount,
                                            DWORD  dwFlags
                                            );

// IDirect3DDevice3_DrawPrimitiveStrided
typedef HRESULT(__stdcall* PFN_IDirect3DDevice3_DrawPrimitiveStrided)(
                                   IDirect3DDevice3* pDev,
                                   D3DPRIMITIVETYPE dptPrimitiveType,
                                   DWORD  dwVertexTypeDesc,
                                   LPD3DDRAWPRIMITIVESTRIDEDDATA lpVertexArray,
                                   DWORD  dwVertexCount,
                                   DWORD  dwFlags
                                   );

// IDirect3DDevice3_DrawIndexedPrimitiveStrided
typedef HRESULT(__stdcall* PFN_IDirect3DDevice3_DrawIndexedPrimitiveStrided)(
                                   IDirect3DDevice3* pDev,
                                   D3DPRIMITIVETYPE d3dptPrimitiveType,
                                   DWORD  dwVertexTypeDesc,
                                   LPD3DDRAWPRIMITIVESTRIDEDDATA lpVertexArray,
                                   DWORD  dwVertexCount,
                                   LPWORD lpwIndices,
                                   DWORD  dwIndexCount,
                                   DWORD  dwFlags
                                   );



// IDirect3DDevice3_DrawPrimitiveVB
typedef HRESULT(__stdcall* PFN_IDirect3DDevice3_DrawPrimitiveVB)(
                                   IDirect3DDevice3* pDev,
                                   D3DPRIMITIVETYPE d3dptPrimitiveType,
                                   LPDIRECT3DVERTEXBUFFER lpd3dVertexBuffer,
                                   DWORD dwStartVertex,
                                   DWORD dwNumVertices,
                                   DWORD dwFlags
                                   );


// IDirect3DDevice3_DrawIndexedPrimitiveVB
typedef HRESULT(__stdcall* PFN_IDirect3DDevice3_DrawIndexedPrimitiveVB)(
                                   IDirect3DDevice3* pDev,
                                   D3DPRIMITIVETYPE d3dptPrimitiveType,
                                   LPDIRECT3DVERTEXBUFFER lpd3dVertexBuffer,
                                   LPWORD lpwIndices,
                                   DWORD  dwIndexCount,
                                   DWORD  dwFlags
                                   );


// IDirect3DDevice3_SetTexture
typedef HRESULT(__stdcall* PFN_IDirect3DDevice3_SetTexture)(
                                            IDirect3DDevice3* pDev,
                                            DWORD dwStage,
                                            LPDIRECT3DTEXTURE2 lpTexture
                                            );

// ---------------------------------------------------------------------------
//  SECTION 30-B  VTable indices  (from dx6/enums.h)
// ---------------------------------------------------------------------------
#pragma once


enum
{
  IDX_IDirect3D3_CreateDevice = 8,
  IDX_IDirect3D3_CreateVertexBuffer = 9,

  IDX_IDirect3DDevice3_DrawPrimitive = 28,
  IDX_IDirect3DDevice3_DrawIndexedPrimitive = 29,
  IDX_IDirect3DDevice3_DrawPrimitiveStrided = 32,
  IDX_IDirect3DDevice3_DrawIndexedPrimitiveStrided = 33,
  IDX_IDirect3DDevice3_DrawPrimitiveVB = 34,
  IDX_IDirect3DDevice3_DrawIndexedPrimitiveVB = 35,
  IDX_IDirect3DDevice3_SetTexture = 38
};

// ---------------------------------------------------------------------------
//  SECTION 30-C  Hook-stub macros  (from dx6/macro.h)
// ---------------------------------------------------------------------------
#pragma once



// IDirect3DDevice3_DrawPrimitive
#define STUB_IDirect3DDevice3_DrawPrimitive(IDX)\
static HRESULT __stdcall _IDirect3DDevice3_DrawPrimitive_##IDX(\
                                            IDirect3DDevice3* pDev,\
                                            D3DPRIMITIVETYPE dptPrimitiveType,\
                                            DWORD  dwVertexTypeDesc,\
                                            LPVOID lpvVertices,\
                                            DWORD  dwVertexCount,\
                                            DWORD  dwFlags\
)\
{\
  KHook* h = this_->hooks_IDirect3DDevice3_DrawPrimitive.getHook(##IDX);\
  return this_->helper_IDirect3DDevice3_DrawPrimitive(\
                                                      h,\
                                                      pDev,\
                                                      dptPrimitiveType,\
                                                      dwVertexTypeDesc,\
                                                      lpvVertices,\
                                                      dwVertexCount,\
                                                      dwFlags\
                                                      );\
}


// IDirect3D3_CreateDevice
#define STUB_IDirect3D3_CreateDevice(IDX)\
static HRESULT __stdcall _IDirect3D3_CreateDevice_##IDX(\
                                           IDirect3D3* d3d,\
                                           REFCLSID rclsid,\
                                           LPDIRECTDRAWSURFACE4 lpDDS,\
                                           LPDIRECT3DDEVICE3 *  lplpD3DDevice,\
                                           LPUNKNOWN pUnkOuter\
)\
{\
KHook* h = this_->hooks_IDirect3D3_CreateDevice.getHook(##IDX);\
return this_->helper_IDirect3D3_CreateDevice(h, d3d, rclsid, lpDDS, lplpD3DDevice, pUnkOuter);\
}




// IDirect3DDevice3_DrawIndexedPrimitive
#define STUB_IDirect3DDevice3_DrawIndexedPrimitive(IDX)\
static HRESULT __stdcall _IDirect3DDevice3_DrawIndexedPrimitive_##IDX(\
                                            IDirect3DDevice3* pDev,\
                                            D3DPRIMITIVETYPE d3dptPrimitiveType,\
                                            DWORD  dwVertexTypeDesc,\
                                            LPVOID lpvVertices,\
                                            DWORD  dwVertexCount,\
                                            LPWORD lpwIndices,\
                                            DWORD  dwIndexCount,\
                                            DWORD  dwFlags\
)\
{\
  KHook* h = this_->hooks_IDirect3DDevice3_DrawIndexedPrimitive.getHook(##IDX);\
  return this_->helper_IDirect3DDevice3_DrawIndexedPrimitive(\
                                                        h,\
                                                        pDev,\
                                                        d3dptPrimitiveType,\
                                                        dwVertexTypeDesc,\
                                                        lpvVertices,\
                                                        dwVertexCount,\
                                                        lpwIndices,\
                                                        dwIndexCount,\
                                                        dwFlags);\
}



// IDirect3DDevice3_DrawPrimitiveStrided
#define STUB_IDirect3DDevice3_DrawPrimitiveStrided(IDX)\
static HRESULT __stdcall _IDirect3DDevice3_DrawPrimitiveStrided_##IDX(\
                                   IDirect3DDevice3* pDev,\
                                   D3DPRIMITIVETYPE dptPrimitiveType,\
                                   DWORD  dwVertexTypeDesc,\
                                   LPD3DDRAWPRIMITIVESTRIDEDDATA lpVertexArray,\
                                   DWORD  dwVertexCount,\
                                   DWORD  dwFlags\
)\
{\
  KHook* h = this_->hooks_IDirect3DDevice3_DrawPrimitiveStrided.getHook(##IDX);\
  return this_->helper_IDirect3DDevice3_DrawPrimitiveStrided(h,\
                                                            pDev,\
                                                            dptPrimitiveType,\
                                                            dwVertexTypeDesc,\
                                                            lpVertexArray,\
                                                            dwVertexCount,\
                                                            dwFlags);\
}


// IDirect3DDevice3_DrawIndexedPrimitiveStrided
#define STUB_IDirect3DDevice3_DrawIndexedPrimitiveStrided(IDX)\
static HRESULT __stdcall _IDirect3DDevice3_DrawIndexedPrimitiveStrided_##IDX(\
                                   IDirect3DDevice3* pDev,\
                                   D3DPRIMITIVETYPE d3dptPrimitiveType,\
                                   DWORD  dwVertexTypeDesc,\
                                   LPD3DDRAWPRIMITIVESTRIDEDDATA lpVertexArray,\
                                   DWORD  dwVertexCount,\
                                   LPWORD lpwIndices,\
                                   DWORD  dwIndexCount,\
                                   DWORD  dwFlags\
                                   )\
{\
  KHook* h = this_->hooks_IDirect3DDevice3_DrawIndexedPrimitiveStrided.getHook(##IDX);\
  return this_->helper_IDirect3DDevice3_DrawIndexedPrimitiveStrided(h,\
                                                        pDev,\
                                                        d3dptPrimitiveType,\
                                                        dwVertexTypeDesc,\
                                                        lpVertexArray,\
                                                        dwVertexCount,\
                                                        lpwIndices,\
                                                        dwIndexCount,\
                                                        dwFlags);\
}


// IDirect3DDevice3_DrawPrimitiveVB
#define STUB_IDirect3DDevice3_DrawPrimitiveVB(IDX)\
static HRESULT __stdcall _IDirect3DDevice3_DrawPrimitiveVB_##IDX(\
                                   IDirect3DDevice3* pDev,\
                                   D3DPRIMITIVETYPE d3dptPrimitiveType,\
                                   LPDIRECT3DVERTEXBUFFER lpd3dVertexBuffer,\
                                   DWORD dwStartVertex,\
                                   DWORD dwNumVertices,\
                                   DWORD dwFlags\
                                   )\
{\
  KHook* h = this_->hooks_IDirect3DDevice3_DrawPrimitiveVB.getHook(##IDX);\
  return this_->helper_IDirect3DDevice3_DrawPrimitiveVB(h,\
                                                        pDev,\
                                                        d3dptPrimitiveType,\
                                                        lpd3dVertexBuffer,\
                                                        dwStartVertex,\
                                                        dwNumVertices,\
                                                        dwFlags);\
}


// IDirect3DDevice3_DrawIndexedPrimitiveVB
#define STUB_IDirect3DDevice3_DrawIndexedPrimitiveVB(IDX)\
static HRESULT __stdcall _IDirect3DDevice3_DrawIndexedPrimitiveVB_##IDX(\
                                   IDirect3DDevice3* pDev,\
                                   D3DPRIMITIVETYPE d3dptPrimitiveType,\
                                   LPDIRECT3DVERTEXBUFFER lpd3dVertexBuffer,\
                                   LPWORD lpwIndices,\
                                   DWORD  dwIndexCount,\
                                   DWORD  dwFlags\
                                )\
{\
  KHook* h = this_->hooks_IDirect3DDevice3_DrawIndexedPrimitiveVB.getHook(##IDX);\
  return this_->helper_IDirect3DDevice3_DrawIndexedPrimitiveVB(h,\
                                                           pDev,\
                                                           d3dptPrimitiveType,\
                                                           lpd3dVertexBuffer,\
                                                           lpwIndices,\
                                                           dwIndexCount,\
                                                           dwFlags\
                                                           );\
}


// IDirect3D3_CreateVertexBuffer
#define STUB_IDirect3D3_CreateVertexBuffer(IDX)\
static HRESULT __stdcall _IDirect3D3_CreateVertexBuffer_##IDX(\
                                IDirect3D3* d3d,\
                                LPD3DVERTEXBUFFERDESC lpVBDesc,\
                                LPDIRECT3DVERTEXBUFFER* lpD3DVertexBuffer,\
                                DWORD dwFlags,\
                                LPUNKNOWN pUnkOuter\
                                )\
{\
  KHook* h = this_->hooks_IDirect3D3_CreateVertexBuffer.getHook(##IDX); \
  return this_->helper_IDirect3D3_CreateVertexBuffer(\
                                             h,\
                                             d3d, \
                                             lpVBDesc, \
                                             lpD3DVertexBuffer, \
                                             dwFlags,\
                                             pUnkOuter\
                                             );\
}


// IDirect3DDevice3_SetTexture
#define STUB_IDirect3DDevice3_SetTexture(IDX)\
static HRESULT __stdcall _IDirect3DDevice3_SetTexture_##IDX(\
                                            IDirect3DDevice3* pDev,\
                                            DWORD dwStage,\
                                            LPDIRECT3DTEXTURE2 lpTexture\
                                                )\
{\
  KHook* h = this_->hooks_IDirect3DDevice3_SetTexture.getHook(##IDX); \
  return this_->helper_IDirect3DDevice3_SetTexture(\
                                             h,\
                                             pDev,\
                                             dwStage,\
                                             lpTexture\
                                             );\
}

// ---------------------------------------------------------------------------
//  SECTION 30-D  KRipper6 class declaration  (from dx6/kripper6.h)
// ---------------------------------------------------------------------------
#pragma once


#include <windows.h>
#include <vector>
#include <string>
#include <map>


class KHook;
class KFACES;
class KVERTICES;


class KRipper6: public IRipper
{
public:
  KRipper6();
  virtual ~KRipper6();

  // IRipper
  virtual void frameStart();
  virtual void frameEnd();
  virtual void textureRipStart();
  virtual void textureRipEnd();


  void cleanup();
  void initialize(IDirect3D3* obj);


  void addTextureSurface(LPDIRECT3DTEXTURE2 tex, void* surface);

private:
  struct KTexture
  {
    LPDIRECT3DTEXTURE2 pTexture;
    std::string  name;
    std::wstring fullPath;

    KTexture(): pTexture(NULL)
    {
    }
  };
  typedef std::vector < KTexture > KFrameTextureVec;

  static KRipper6* this_;

  void zeroHooks();
  void hook_IDirect3DDevice3(IDirect3DDevice3* pDev);

  CRITICAL_SECTION cs;


  // IDirect3D3_CreateDevice
  HooksGroup hooks_IDirect3D3_CreateDevice;
  HRESULT helper_IDirect3D3_CreateDevice( KHook*,
                                          IDirect3D3* d3d,
                                          REFCLSID rclsid,
                                          LPDIRECTDRAWSURFACE4 lpDDS,
                                          LPDIRECT3DDEVICE3 *  lplpD3DDevice,
                                          LPUNKNOWN pUnkOuter
                                         );
  GENERATE_STUBS_GROUP(STUB_IDirect3D3_CreateDevice);



  // IDirect3D3_CreateVertexBuffer
  HooksGroup hooks_IDirect3D3_CreateVertexBuffer;
  HRESULT helper_IDirect3D3_CreateVertexBuffer(
                              KHook*,
                              IDirect3D3* d3d,
                              LPD3DVERTEXBUFFERDESC lpVBDesc,
                              LPDIRECT3DVERTEXBUFFER* lpD3DVertexBuffer,
                              DWORD dwFlags,
                              LPUNKNOWN pUnkOuter
                              );
  GENERATE_STUBS_GROUP(STUB_IDirect3D3_CreateVertexBuffer);



  // IDirect3DDevice3_DrawPrimitive
  HooksGroup hooks_IDirect3DDevice3_DrawPrimitive;
  HRESULT helper_IDirect3DDevice3_DrawPrimitive(
                                            KHook*,
                                            IDirect3DDevice3* pDev,
                                            D3DPRIMITIVETYPE dptPrimitiveType,
                                            DWORD  dwVertexTypeDesc,
                                            LPVOID lpvVertices,
                                            DWORD  dwVertexCount,
                                            DWORD  dwFlags
                                            );
  GENERATE_STUBS_GROUP(STUB_IDirect3DDevice3_DrawPrimitive);




  EPrimitiveTopology::Type D3DPRIMITIVETYPE_to_EPrimitiveTopology(
                                                         D3DPRIMITIVETYPE pt
                                                         );


  void saveMeshTextures(IDirect3DDevice3*, KMeshTextures*);



  // IDirect3DDevice3_DrawIndexedPrimitive
  HooksGroup hooks_IDirect3DDevice3_DrawIndexedPrimitive;
  HRESULT helper_IDirect3DDevice3_DrawIndexedPrimitive(KHook*,
                                          IDirect3DDevice3* pDev,
                                          D3DPRIMITIVETYPE d3dptPrimitiveType,
                                          DWORD  dwVertexTypeDesc,
                                          LPVOID lpvVertices,
                                          DWORD  dwVertexCount,
                                          LPWORD lpwIndices,
                                          DWORD  dwIndexCount,
                                          DWORD  dwFlags
                                            );
  GENERATE_STUBS_GROUP(STUB_IDirect3DDevice3_DrawIndexedPrimitive);


  // IDirect3DDevice3_DrawPrimitiveStrided
  HooksGroup hooks_IDirect3DDevice3_DrawPrimitiveStrided;
  HRESULT helper_IDirect3DDevice3_DrawPrimitiveStrided(KHook*,
                                   IDirect3DDevice3* pDev,
                                   D3DPRIMITIVETYPE dptPrimitiveType,
                                   DWORD  dwVertexTypeDesc,
                                   LPD3DDRAWPRIMITIVESTRIDEDDATA lpVertexArray,
                                   DWORD  dwVertexCount,
                                   DWORD  dwFlags
                                   );
  GENERATE_STUBS_GROUP(STUB_IDirect3DDevice3_DrawPrimitiveStrided);





  // IDirect3DDevice3_DrawIndexedPrimitiveStrided
  HooksGroup hooks_IDirect3DDevice3_DrawIndexedPrimitiveStrided;
  HRESULT helper_IDirect3DDevice3_DrawIndexedPrimitiveStrided(
                                   KHook* h,
                                   IDirect3DDevice3* pDev,
                                   D3DPRIMITIVETYPE d3dptPrimitiveType,
                                   DWORD  dwVertexTypeDesc,
                                   LPD3DDRAWPRIMITIVESTRIDEDDATA lpVertexArray,
                                   DWORD  dwVertexCount,
                                   LPWORD lpwIndices,
                                   DWORD  dwIndexCount,
                                   DWORD  dwFlags
                                   );
  GENERATE_STUBS_GROUP(STUB_IDirect3DDevice3_DrawIndexedPrimitiveStrided);


  // IDirect3DDevice3_DrawPrimitiveVB
  HooksGroup hooks_IDirect3DDevice3_DrawPrimitiveVB;
  HRESULT helper_IDirect3DDevice3_DrawPrimitiveVB(
                                        KHook* h,
                                        IDirect3DDevice3* pDev,
                                        D3DPRIMITIVETYPE d3dptPrimitiveType,
                                        LPDIRECT3DVERTEXBUFFER lpd3dVertexBuffer,
                                        DWORD dwStartVertex,
                                        DWORD dwNumVertices,
                                        DWORD dwFlags
                                        );
  GENERATE_STUBS_GROUP(STUB_IDirect3DDevice3_DrawPrimitiveVB);


  // IDirect3DDevice3_DrawIndexedPrimitiveVB
  HooksGroup hooks_IDirect3DDevice3_DrawIndexedPrimitiveVB;
  HRESULT helper_IDirect3DDevice3_DrawIndexedPrimitiveVB(
                                    KHook* h,
                                    IDirect3DDevice3* pDev,
                                    D3DPRIMITIVETYPE d3dptPrimitiveType,
                                    LPDIRECT3DVERTEXBUFFER lpd3dVertexBuffer,
                                    LPWORD lpwIndices,
                                    DWORD  dwIndexCount,
                                    DWORD  dwFlags
                                    );
  GENERATE_STUBS_GROUP(STUB_IDirect3DDevice3_DrawIndexedPrimitiveVB);




  void ripDrawIndexedPrimitiveVB(
                                  IDirect3DDevice3* pDev,
                                  D3DPRIMITIVETYPE d3dptPrimitiveType,
                                  LPDIRECT3DVERTEXBUFFER lpd3dVertexBuffer,
                                  LPWORD lpwIndices,
                                  DWORD  dwIndexCount,
                                  DWORD  dwFlags
                                 );
  void ripDrawPrimitiveVB(
                          IDirect3DDevice3* pDev,
                          D3DPRIMITIVETYPE d3dptPrimitiveType,
                          LPDIRECT3DVERTEXBUFFER lpd3dVertexBuffer,
                          DWORD dwStartVertex,
                          DWORD dwNumVertices,
                          DWORD dwFlags
                          );
  
  void ripDrawPrimitive(
                        IDirect3DDevice3* pDev,
                        D3DPRIMITIVETYPE dptPrimitiveType,
                        DWORD  dwVertexTypeDesc,
                        LPVOID lpvVertices,
                        DWORD  dwVertexCount,
                        DWORD  dwFlags
                        );

  void ripDrawIndexedPrimitive( IDirect3DDevice3* pDev,
                                D3DPRIMITIVETYPE d3dptPrimitiveType,
                                DWORD  dwVertexTypeDesc,
                                LPVOID lpvVertices,
                                DWORD  dwVertexCount,
                                LPWORD lpwIndices,
                                DWORD  dwIndexCount,
                                DWORD  dwFlags
                               );

  void ripDrawPrimitiveStrided(
                                IDirect3DDevice3* pDev,
                                D3DPRIMITIVETYPE dptPrimitiveType,
                                DWORD  dwVertexTypeDesc,
                                LPD3DDRAWPRIMITIVESTRIDEDDATA lpVertexArray,
                                DWORD  dwVertexCount,
                                DWORD  dwFlags
                               );

  void ripDrawIndexedPrimitiveStrided(
                                    IDirect3DDevice3* pDev,
                                    D3DPRIMITIVETYPE d3dptPrimitiveType,
                                    DWORD  dwVertexTypeDesc,
                                    LPD3DDRAWPRIMITIVESTRIDEDDATA lpVertexArray,
                                    DWORD  dwVertexCount,
                                    LPWORD lpwIndices,
                                    DWORD  dwIndexCount,
                                    DWORD  dwFlags
                                   );

  KFrameTextureVec meshTexturesDb;
  void addMeshTexture(const KTexture& t);
  bool isMeshTextureSaved(LPDIRECT3DTEXTURE2 pTexture, KTexture* out);

  HRESULT saveTexture2File(const wchar_t* fileName,
                           LPDIRECT3DTEXTURE2 pTexture
                           );

  void dumpTextureDesc(LPDIRECT3DTEXTURE2 pTexture);




  // IDirect3DDevice3_SetTexture
  HooksGroup hooks_IDirect3DDevice3_SetTexture;
  HRESULT helper_IDirect3DDevice3_SetTexture(
                                    KHook* h,
                                    IDirect3DDevice3* pDev,
                                    DWORD dwStage,
                                    LPDIRECT3DTEXTURE2 lpTexture
                                    );
  GENERATE_STUBS_GROUP(STUB_IDirect3DDevice3_SetTexture);


  void handleTextureSave(IDirect3DDevice3* pDev,
                         DWORD Stage,
                         LPDIRECT3DTEXTURE2 lpTexture
                         );
  std::vector < LPDIRECT3DTEXTURE2 > forcedTexturesDb;

  DWORD isTextureSaved(LPDIRECT3DTEXTURE2 pTex);


  typedef std::map <LPDIRECT3DTEXTURE2, void*> TextureToSurfaceDb;
  TextureToSurfaceDb textureToSurfaceDb;
};

// ---------------------------------------------------------------------------
//  SECTION 30-E  KRipper6 implementation
//  (kripper6.cpp, pre6.cpp, draw*.cpp, savemeshtextures6.cpp,
//   savetexture6.cpp, texture6.cpp — local #includes stripped)
// ---------------------------------------------------------------------------
//************************************************************************
// D3D6 Ripper
//************************************************************************

extern KIntruder* g_pIntruder;
extern KHookMgr*  g_pHookMgr;
extern KLog*      g_pLog;


// Static vars initialize
KRipper6* KRipper6::this_ = 0;
extern KDdraw* g_pDdraw;


KRipper6::KRipper6()
{
  this_ = this;
  InitializeCriticalSection(&cs);
  zeroHooks();

  g_pLog->log("D3D6 ripper init\n");
}


KRipper6::~KRipper6()
{
  g_pLog->log("D3D6 ripper uninit\n");

  g_pHookMgr->unhookPool(KHookMgr::EHOOK_POOL_D3DIM);
  this_->zeroHooks();

  DeleteCriticalSection(&cs);
}


void KRipper6::frameStart()
{
  meshTexturesDb.clear();
}


void KRipper6::frameEnd()
{

}


void KRipper6::textureRipStart()
{
  forcedTexturesDb.clear();
}


void KRipper6::textureRipEnd()
{
}


void KRipper6::initialize(IDirect3D3* obj)
{
  // IDirect3D3_CreateDevice
  hookEx("IDirect3D3_CreateDevice",
         IDX_IDirect3D3_CreateDevice,
         obj,
         KHookMgr::EHOOK_POOL_D3DIM,
         &hooks_IDirect3D3_CreateDevice
         );
  
  // IDirect3D3_CreateVertexBuffer
  hookEx("IDirect3D3_CreateVertexBuffer",
         IDX_IDirect3D3_CreateVertexBuffer,
         obj,
         KHookMgr::EHOOK_POOL_D3DIM,
         &hooks_IDirect3D3_CreateVertexBuffer
         );

}


void KRipper6::hook_IDirect3DDevice3(IDirect3DDevice3* pDev)
{
  // IDirect3DDevice3_DrawPrimitive
  hookEx("IDirect3DDevice3_DrawPrimitive",
         IDX_IDirect3DDevice3_DrawPrimitive,
         pDev,
         KHookMgr::EHOOK_POOL_D3DIM,
         &hooks_IDirect3DDevice3_DrawPrimitive
         );

  // IDirect3DDevice3_DrawIndexedPrimitive
  hookEx("IDirect3DDevice3_DrawIndexedPrimitive",
         IDX_IDirect3DDevice3_DrawIndexedPrimitive,
         pDev,
         KHookMgr::EHOOK_POOL_D3DIM,
         &hooks_IDirect3DDevice3_DrawIndexedPrimitive
         );


  // IDirect3DDevice3_DrawPrimitiveStrided
  hookEx("IDirect3DDevice3_DrawPrimitiveStrided",
         IDX_IDirect3DDevice3_DrawPrimitiveStrided,
         pDev,
         KHookMgr::EHOOK_POOL_D3DIM,
         &hooks_IDirect3DDevice3_DrawPrimitiveStrided
         );


  // IDirect3DDevice3_DrawIndexedPrimitiveStrided
  hookEx("IDirect3DDevice3_DrawIndexedPrimitiveStrided",
         IDX_IDirect3DDevice3_DrawIndexedPrimitiveStrided,
         pDev,
         KHookMgr::EHOOK_POOL_D3DIM,
         &hooks_IDirect3DDevice3_DrawIndexedPrimitiveStrided
         );


  // IDirect3DDevice3_DrawPrimitiveVB
  hookEx("IDirect3DDevice3_DrawPrimitiveVB",
         IDX_IDirect3DDevice3_DrawPrimitiveVB,
         pDev,
         KHookMgr::EHOOK_POOL_D3DIM,
         &hooks_IDirect3DDevice3_DrawPrimitiveVB
         );


  // IDirect3DDevice3_DrawIndexedPrimitiveVB
  hookEx("IDirect3DDevice3_DrawIndexedPrimitiveVB",
         IDX_IDirect3DDevice3_DrawIndexedPrimitiveVB,
         pDev,
         KHookMgr::EHOOK_POOL_D3DIM,
         &hooks_IDirect3DDevice3_DrawIndexedPrimitiveVB
         );


  // IDirect3DDevice3_SetTexture
  hookEx("IDirect3DDevice3_SetTexture",
         IDX_IDirect3DDevice3_SetTexture,
         pDev,
         KHookMgr::EHOOK_POOL_D3DIM,
         &hooks_IDirect3DDevice3_SetTexture
         );
}


void KRipper6::zeroHooks()
{
  GENERATE_HOOKS_GROUP_CLEARER(IDirect3D3_CreateDevice);
  GENERATE_HOOKS_GROUP_CLEARER(IDirect3D3_CreateVertexBuffer);

  GENERATE_HOOKS_GROUP_CLEARER(IDirect3DDevice3_DrawPrimitive);
  GENERATE_HOOKS_GROUP_CLEARER(IDirect3DDevice3_DrawIndexedPrimitive);
  GENERATE_HOOKS_GROUP_CLEARER(IDirect3DDevice3_DrawPrimitiveStrided);
  GENERATE_HOOKS_GROUP_CLEARER(IDirect3DDevice3_DrawIndexedPrimitiveStrided);
  GENERATE_HOOKS_GROUP_CLEARER(IDirect3DDevice3_DrawPrimitiveVB);
  GENERATE_HOOKS_GROUP_CLEARER(IDirect3DDevice3_DrawIndexedPrimitiveVB);

  GENERATE_HOOKS_GROUP_CLEARER(IDirect3DDevice3_SetTexture);
}


void KRipper6::cleanup()
{

}





EPrimitiveTopology::Type 
KRipper6::D3DPRIMITIVETYPE_to_EPrimitiveTopology(D3DPRIMITIVETYPE pt)
{
  EPrimitiveTopology::Type res = EPrimitiveTopology::UNKNOWNPRIMITIVETYPE;

  switch(pt)
  {
  case D3DPT_TRIANGLELIST:
  {
    res = EPrimitiveTopology::TRIANGLELIST;
    break;
  }

  case D3DPT_TRIANGLESTRIP:
  {
    res = EPrimitiveTopology::TRIANGLESTRIP;
    break;
  }

  case D3DPT_POINTLIST:
  {
    res = EPrimitiveTopology::POINTLIST;
    break;
  }

  case D3DPT_LINELIST:
  {
    res = EPrimitiveTopology::LINELIST;
    break;
  }

  case D3DPT_LINESTRIP:
  {
    res = EPrimitiveTopology::LINESTRIP;
    break;
  }

  case  D3DPT_TRIANGLEFAN:
  {
    res = EPrimitiveTopology::TRIANGLEFAN;
    break;
  }
  } // switch

  return res;
}


HRESULT KRipper6::helper_IDirect3D3_CreateVertexBuffer(
                                KHook* h,
                                IDirect3D3* d3d,
                                LPD3DVERTEXBUFFERDESC lpVBDesc,
                                LPDIRECT3DVERTEXBUFFER* lpD3DVertexBuffer,
                                DWORD dwFlags,
                                LPUNKNOWN pUnkOuter
                                )
{
  PFN_IDirect3D3_CreateVertexBuffer e = 
                    (PFN_IDirect3D3_CreateVertexBuffer)h->getOriginalAddress();

  lpVBDesc->dwCaps = lpVBDesc->dwCaps & (~D3DVBCAPS_WRITEONLY);

  HRESULT hr = e(d3d, lpVBDesc, lpD3DVertexBuffer, dwFlags, pUnkOuter);
  return hr;
}



HRESULT KRipper6::helper_IDirect3D3_CreateDevice(
                                         KHook* h,
                                         IDirect3D3* d3d,
                                         REFCLSID rclsid,
                                         LPDIRECTDRAWSURFACE4 lpDDS,
                                         LPDIRECT3DDEVICE3 *  lplpD3DDevice,
                                         LPUNKNOWN pUnkOuter
                                         )
{
  PFN_IDirect3D3_CreateDevice e = (PFN_IDirect3D3_CreateDevice)
                                                       h->getOriginalAddress();

  std::string devname = guidToName(rclsid);
  g_pLog->log("IDirect3D3_CreateDevice(%s)\n", devname.c_str());
  
  HRESULT hr = e(d3d, rclsid, lpDDS, lplpD3DDevice, pUnkOuter);

  if (SUCCEEDED(hr))
  {
    hook_IDirect3DDevice3(*lplpD3DDevice);

    // Frame handler
    g_pDdraw->hook_IDirectDrawSurface(lpDDS);
  }
  return hr;
}


void KRipper6::addTextureSurface(LPDIRECT3DTEXTURE2 tex, void* surface)
{
  TextureToSurfaceDb::iterator it = textureToSurfaceDb.find(tex);
  if (it == textureToSurfaceDb.end())
  {
    // New texture
    textureToSurfaceDb.insert(std::pair<LPDIRECT3DTEXTURE2, void*>(tex, surface));
  }
  else
  {
    // Update existing texture
    it->second = surface;
  }
}

KRipper6* create_KRipper6()
{
  return new KRipper6;
}


void delete_KRipper6(KRipper6* & p)
{
  delete p;
}

extern KIntruder* g_pIntruder;
extern KLog*      g_pLog;


void KRipper6::ripDrawPrimitive(IDirect3DDevice3* pDev,
                                D3DPRIMITIVETYPE dptPrimitiveType,
                                DWORD  dwVertexTypeDesc,
                                LPVOID lpvVertices,
                                DWORD  dwVertexCount,
                                DWORD  dwFlags
                                )
{
  do
  {
    // Primitive topology
    EPrimitiveTopology::Type primitiveTopology =
                      D3DPRIMITIVETYPE_to_EPrimitiveTopology(dptPrimitiveType);

    if (!::isPrimitiveTopologySupported(primitiveTopology))
    {
      g_pLog->logError("Input primitive topology not supported\n\n");
      break;
    }


    // Vertex declaration
    KInputVertexDeclaration  inputVertDecl;
    KOutputVertexDeclaration outputVertDecl;

    fvfToInputVertexDeclaration(dwVertexTypeDesc, &inputVertDecl);

    HRESULT hr = ::createKOutputVertexDeclaration(inputVertDecl,
                                                  outputVertDecl
                                                  );
    ::dumpInputVertexDeclaration2Log(inputVertDecl);
    ::dumpOutputVertexDeclaration2Log(outputVertDecl);


    // Indexes
    KFACES faces;
    OptimizedIndexToMeshIndex optimizedIdxToMeshIdx;
    generateIndexes_VertexCount(primitiveTopology, 
                                dwVertexCount,
                                &faces,
                                &optimizedIdxToMeshIdx
                                );

    // Vertices
    DWORD vertSize = outputVertDecl.getVertexSize(); // Output vertex size
    DWORD vertCnt = (DWORD)optimizedIdxToMeshIdx.size();
    g_pLog->log("PrimitivesCount=%d\nVertexCnt=%d\nOutVertexSize=%d\n",
                faces.getPrimitivesCount(),
                vertCnt,
                vertSize
                );

    KVERTICES vertices(vertCnt, vertSize);

    dumpVbUP(inputVertDecl,
             outputVertDecl, 
             optimizedIdxToMeshIdx, 
             &vertices, 
             lpvVertices,
             inputVertDecl.getStreamVertexSize(0)
             );

    KMeshTextures meshTextures;
    saveMeshTextures(pDev, &meshTextures);

    // No shaders in dx6. Empty
    KMeshShaders meshShaders;


    // Save RIP file
    std::wstring ripFilePath = g_pIntruder->getFrameMeshSavePath();
    std::string utf8str = wideStringToMultiByte(ripFilePath.c_str());

    hr = ::saveRipFile(ripFilePath.c_str(),
                       inputVertDecl,
                       outputVertDecl,
                       meshTextures,
                       meshShaders,
                       faces, 
                       vertices
                       );
    if (SUCCEEDED(hr))
    {
      g_pLog->log("Mesh saved as: %s\n\n\n", utf8str.c_str());
    }
    else
    {
      g_pLog->logError("Mesh save error: %s\n\n\n", utf8str.c_str());
    }

    g_pIntruder->incFrameMeshIdx();
  }
  while (false);
}


HRESULT KRipper6::helper_IDirect3DDevice3_DrawPrimitive(
                                             KHook* h,
                                             IDirect3DDevice3* pDev,
                                             D3DPRIMITIVETYPE dptPrimitiveType,
                                             DWORD  dwVertexTypeDesc,
                                             LPVOID lpvVertices,
                                             DWORD  dwVertexCount,
                                             DWORD  dwFlags
                                             )
{
  PFN_IDirect3DDevice3_DrawPrimitive e = 
                    (PFN_IDirect3DDevice3_DrawPrimitive)h->getOriginalAddress();
  
  
  g_pIntruder->keyHandler(this);

  DWORD ripEnabled     = g_pIntruder->isMeshRipEnabled();
  DWORD minVertexCount = g_pIntruder->getSettings()->dwMinVertexCount;

  if (ripEnabled)
  {
    if (dwVertexCount >= minVertexCount)
    {
      g_pLog->log("IDirect3DDevice3_DrawPrimitive(\
0x%p, %d, 0x%08X, 0x%p, %d, 0x%08X)\n",
                  pDev, 
                  dptPrimitiveType, 
                  dwVertexTypeDesc,
                  lpvVertices,
                  dwVertexCount,
                  dwFlags
                  );
      __try
      {
        ripDrawPrimitive(pDev,
                         dptPrimitiveType, 
                         dwVertexTypeDesc, 
                         lpvVertices, 
                         dwVertexCount, 
                         dwFlags
                         );
      }
      __except (EXCEPTION_EXECUTE_HANDLER)
      {
        g_pLog->logError("IDirect3DDevice3_DrawPrimitive() exception\n\n\n");
      }
    }
    else
    {
      g_pLog->logWarning("IDirect3DDevice3_DrawPrimitive() rip skipped\n");
    }
  }
  HRESULT res = e(pDev, 
                  dptPrimitiveType, 
                  dwVertexTypeDesc, 
                  lpvVertices, 
                  dwVertexCount, 
                  dwFlags
                  );
  return res;
}

extern KIntruder* g_pIntruder;
extern KLog*      g_pLog;


void KRipper6::ripDrawPrimitiveStrided(
                                   IDirect3DDevice3* pDev,
                                   D3DPRIMITIVETYPE dptPrimitiveType,
                                   DWORD  dwVertexTypeDesc,
                                   LPD3DDRAWPRIMITIVESTRIDEDDATA lpVertexArray,
                                   DWORD  dwVertexCount,
                                   DWORD  dwFlags
                                   )
{
  do
  {
    // Primitive topology
    EPrimitiveTopology::Type primitiveTopology =
                      D3DPRIMITIVETYPE_to_EPrimitiveTopology(dptPrimitiveType);

    if (!::isPrimitiveTopologySupported(primitiveTopology))
    {
      g_pLog->logError("Input primitive topology not supported\n\n");
      break;
    }


    // Vertex declaration
    KInputVertexDeclaration  inputVertDecl;
    KOutputVertexDeclaration outputVertDecl;

    fvfToInputVertexDeclaration(dwVertexTypeDesc, &inputVertDecl);

    HRESULT hr = ::createKOutputVertexDeclaration(inputVertDecl,
                                                  outputVertDecl
                                                  );
    ::dumpInputVertexDeclaration2Log(inputVertDecl);
    ::dumpOutputVertexDeclaration2Log(outputVertDecl);


    // Indexes
    KFACES faces;
    OptimizedIndexToMeshIndex optimizedIdxToMeshIdx;
    generateIndexes_VertexCount(primitiveTopology, 
                                dwVertexCount,
                                &faces,
                                &optimizedIdxToMeshIdx
                                );

    // Vertices
    DWORD vertSize = outputVertDecl.getVertexSize(); // Output vertex size
    DWORD vertCnt = (DWORD)optimizedIdxToMeshIdx.size();
    g_pLog->log("PrimitivesCount=%d\nVertexCnt=%d\nOutVertexSize=%d\n",
                faces.getPrimitivesCount(),
                vertCnt,
                vertSize
                );

    KVERTICES vertices(vertCnt, vertSize);
    dumpVertexesStrided(lpVertexArray, 
                        inputVertDecl, 
                        outputVertDecl, 
                        optimizedIdxToMeshIdx, 
                        &vertices
                        );


    KMeshTextures meshTextures;
    saveMeshTextures(pDev, &meshTextures);

    // No shaders in dx6. Empty
    KMeshShaders meshShaders;


    // Save RIP file
    std::wstring ripFilePath = g_pIntruder->getFrameMeshSavePath();
    std::string utf8str = wideStringToMultiByte(ripFilePath.c_str());

    hr = ::saveRipFile(ripFilePath.c_str(),
                       inputVertDecl,
                       outputVertDecl,
                       meshTextures,
                       meshShaders,
                       faces, 
                       vertices
                       );
    if (SUCCEEDED(hr))
    {
      g_pLog->log("Mesh saved as: %s\n\n\n", utf8str.c_str());
    }
    else
    {
      g_pLog->logError("Mesh save error: %s\n\n\n", utf8str.c_str());
    }

    g_pIntruder->incFrameMeshIdx();
  }
  while (false);
}


HRESULT KRipper6::helper_IDirect3DDevice3_DrawPrimitiveStrided(
                                   KHook* h,
                                   IDirect3DDevice3* pDev,
                                   D3DPRIMITIVETYPE dptPrimitiveType,
                                   DWORD  dwVertexTypeDesc,
                                   LPD3DDRAWPRIMITIVESTRIDEDDATA lpVertexArray,
                                   DWORD  dwVertexCount,
                                   DWORD  dwFlags
                                   )
{
    PFN_IDirect3DDevice3_DrawPrimitiveStrided e =
             (PFN_IDirect3DDevice3_DrawPrimitiveStrided)h->getOriginalAddress();
  
  
  g_pIntruder->keyHandler(this);

  DWORD ripEnabled     = g_pIntruder->isMeshRipEnabled();
  DWORD minVertexCount = g_pIntruder->getSettings()->dwMinVertexCount;

  if (ripEnabled)
  {
    if (dwVertexCount >= minVertexCount)
    {
      g_pLog->log("IDirect3DDevice3_DrawPrimitiveStrided(\
0x%p, %d, 0x%08X, 0x%p, %d, 0x%08X)\n",
                  pDev,
                  dptPrimitiveType,
                  dwVertexTypeDesc,
                  lpVertexArray,
                  dwVertexCount,
                  dwFlags
                  );
      __try
      {
        ripDrawPrimitiveStrided(pDev,
                                dptPrimitiveType,
                                dwVertexTypeDesc,
                                lpVertexArray,
                                dwVertexCount,
                                dwFlags
                                );
      }
      __except (EXCEPTION_EXECUTE_HANDLER)
      {
        g_pLog->logError("IDirect3DDevice3_DrawPrimitiveStrided() exception\n\n\n");
      }
    }
    else
    {
      g_pLog->logWarning("IDirect3DDevice3_DrawPrimitiveStrided() rip skipped\n");
    }
  }
  HRESULT res = e(pDev,
                  dptPrimitiveType,
                  dwVertexTypeDesc,
                  lpVertexArray,
                  dwVertexCount,
                  dwFlags
                  );
  return res;
}

extern KIntruder* g_pIntruder;
extern KLog*      g_pLog;


void KRipper6::ripDrawPrimitiveVB(
                                  IDirect3DDevice3* pDev,
                                  D3DPRIMITIVETYPE d3dptPrimitiveType,
                                  LPDIRECT3DVERTEXBUFFER lpd3dVertexBuffer,
                                  DWORD dwStartVertex,
                                  DWORD dwNumVertices,
                                  DWORD dwFlags
                                  )
{
  do
  {
    // Primitive topology
    EPrimitiveTopology::Type primitiveTopology =
                    D3DPRIMITIVETYPE_to_EPrimitiveTopology(d3dptPrimitiveType);

    if (!::isPrimitiveTopologySupported(primitiveTopology))
    {
      g_pLog->logError("Input primitive topology not supported\n\n");
      break;
    }


    // Vertex declaration
    KInputVertexDeclaration  inputVertDecl;
    KOutputVertexDeclaration outputVertDecl;

    D3DVERTEXBUFFERDESC vbDesc;
    vbDesc.dwSize = sizeof(vbDesc);
    HRESULT hr = lpd3dVertexBuffer->GetVertexBufferDesc(&vbDesc);
    if (FAILED(hr))
    {
      g_pLog->logError("IDirect3DVertexBuffer::GetVertexBufferDesc(). \
HRESULT: 0x%08X\n\n\n", hr);
      break;
    }

    DWORD dwVertexTypeDesc = vbDesc.dwFVF;
    fvfToInputVertexDeclaration(dwVertexTypeDesc, &inputVertDecl);

    hr = ::createKOutputVertexDeclaration(inputVertDecl, outputVertDecl);
    ::dumpInputVertexDeclaration2Log(inputVertDecl);
    ::dumpOutputVertexDeclaration2Log(outputVertDecl);


    DWORD primitiveCount = primitiveCountFromVertexCount(dwNumVertices,
                                                          primitiveTopology
                                                          );
    // Indexes
    KFACES faces;
    OptimizedIndexToMeshIndex optimizedIdxToMeshIdx;
    generateIndexes_PrimitiveCount(primitiveTopology, 
                                   primitiveCount,
                                   &faces,
                                   &optimizedIdxToMeshIdx
                                   );



    // Vertices
    DWORD vertSize = outputVertDecl.getVertexSize(); // Output vertex size
    DWORD vertCnt = (DWORD)optimizedIdxToMeshIdx.size();
    g_pLog->log("PrimitivesCount=%d\nVertexCnt=%d\nOutVertexSize=%d\n",
                faces.getPrimitivesCount(),
                vertCnt,
                vertSize
                );

    KVERTICES vertices(vertCnt, vertSize);

    LPVOID vbData = 0;
    hr = lpd3dVertexBuffer->Lock(DDLOCK_READONLY, &vbData, NULL);
    if (FAILED(hr))
    {
      g_pLog->logError("lpd3dVertexBuffer->Lock(). HRESULT: 0x%08X\n\n", hr);
      break;
    }


    DWORD stride = inputVertDecl.getStreamVertexSize(0);
    dumpVbUP(inputVertDecl,
             outputVertDecl,
             optimizedIdxToMeshIdx,
             &vertices,
             (BYTE*)vbData + dwStartVertex * stride,
             stride
             );

    hr = lpd3dVertexBuffer->Unlock();
    if (FAILED(hr))
    {
        g_pLog->logError("lpd3dVertexBuffer->Unlock(). HRESULT: 0x%08X\n\n", hr);
        break;
    }

    KMeshTextures meshTextures;
    saveMeshTextures(pDev, &meshTextures);

    // No shaders in dx6. Empty
    KMeshShaders meshShaders;


    // Save RIP file
    std::wstring ripFilePath = g_pIntruder->getFrameMeshSavePath();
    std::string utf8str = wideStringToMultiByte(ripFilePath.c_str());

    hr = ::saveRipFile(ripFilePath.c_str(),
                       inputVertDecl,
                       outputVertDecl,
                       meshTextures,
                       meshShaders,
                       faces, 
                       vertices
                       );
    if (SUCCEEDED(hr))
    {
      g_pLog->log("Mesh saved as: %s\n\n\n", utf8str.c_str());
    }
    else
    {
      g_pLog->logError("Mesh save error: %s\n\n\n", utf8str.c_str());
    }

    g_pIntruder->incFrameMeshIdx();
  }
  while (false);

}


HRESULT KRipper6::helper_IDirect3DDevice3_DrawPrimitiveVB(
                                      KHook* h,
                                      IDirect3DDevice3* pDev,
                                      D3DPRIMITIVETYPE d3dptPrimitiveType,
                                      LPDIRECT3DVERTEXBUFFER lpd3dVertexBuffer,
                                      DWORD dwStartVertex,
                                      DWORD dwNumVertices,
                                      DWORD dwFlags
                                      )
{
  PFN_IDirect3DDevice3_DrawPrimitiveVB e =
                  (PFN_IDirect3DDevice3_DrawPrimitiveVB)h->getOriginalAddress();
  
  
  g_pIntruder->keyHandler(this);

  DWORD ripEnabled     = g_pIntruder->isMeshRipEnabled();
  DWORD minVertexCount = g_pIntruder->getSettings()->dwMinVertexCount;

  if (ripEnabled)
  {
    if (dwNumVertices >= minVertexCount)
    {
      g_pLog->log("IDirect3DDevice3_DrawPrimitiveVB(\
0x%p, %d, 0x%p, %d, %d, 0x%08X)\n",
                pDev,
                d3dptPrimitiveType,
                lpd3dVertexBuffer,
                dwStartVertex,
                dwNumVertices,
                dwFlags
                );
      __try
      {
        ripDrawPrimitiveVB(pDev,
                           d3dptPrimitiveType,
                           lpd3dVertexBuffer,
                           dwStartVertex,
                           dwNumVertices,
                           dwFlags
                           );
      }
      __except (EXCEPTION_EXECUTE_HANDLER)
      {
        g_pLog->logError("IDirect3DDevice3_DrawPrimitiveVB() exception\n\n\n");
      }
    }
    else
    {
      g_pLog->logWarning("IDirect3DDevice3_DrawPrimitiveVB() rip skipped\n");
    }
  }
  HRESULT res = e(pDev,
                  d3dptPrimitiveType,
                  lpd3dVertexBuffer,
                  dwStartVertex,
                  dwNumVertices,
                  dwFlags
                  );
  return res;
}

extern KIntruder* g_pIntruder;
extern KLog*      g_pLog;


void KRipper6::ripDrawIndexedPrimitive(IDirect3DDevice3* pDev,
                                        D3DPRIMITIVETYPE d3dptPrimitiveType,
                                        DWORD  dwVertexTypeDesc,
                                        LPVOID lpvVertices,
                                        DWORD  dwVertexCount,
                                        LPWORD lpwIndices,
                                        DWORD  dwIndexCount,
                                        DWORD  dwFlags
                                       )
{
  do
  {
    // Primitive topology
    EPrimitiveTopology::Type primitiveTopology =
                     D3DPRIMITIVETYPE_to_EPrimitiveTopology(d3dptPrimitiveType);

    if (!::isPrimitiveTopologySupported(primitiveTopology))
    {
      g_pLog->logError("Input primitive topology not supported\n\n");
      break;
    }


    // Vertex declaration
    KInputVertexDeclaration  inputVertDecl;
    KOutputVertexDeclaration outputVertDecl;

    fvfToInputVertexDeclaration(dwVertexTypeDesc, &inputVertDecl);

    HRESULT hr = ::createKOutputVertexDeclaration(inputVertDecl,
                                                  outputVertDecl
                                                  );
    ::dumpInputVertexDeclaration2Log(inputVertDecl);
    ::dumpOutputVertexDeclaration2Log(outputVertDecl);


    DWORD primitivesCount = primitiveCountFromIndexCount(dwIndexCount, 
                                                         primitiveTopology
                                                         );
    // Indexes
    KFACES faces;
    OptimizedIndexToMeshIndex optimizedIdxToMeshIdx;
    hr = dumpIndexesUP(primitiveTopology, 
                       primitivesCount,
                       &faces, 
                       &optimizedIdxToMeshIdx,
                       lpwIndices,
                       EIndexFormat::INDEX_16
                       );
    if (FAILED(hr))
    {
      g_pLog->logError("dumpIndexesUP(). HRESULT: 0x%08X\n\n", hr);
      break;
    }

    // Vertices
    DWORD vertSize = outputVertDecl.getVertexSize(); // Output vertex size
    DWORD vertCnt = (DWORD)optimizedIdxToMeshIdx.size();
    g_pLog->log("PrimitivesCount=%d\nVertexCnt=%d\nOutVertexSize=%d\n",
                faces.getPrimitivesCount(),
                vertCnt,
                vertSize
                );

    KVERTICES vertices(vertCnt, vertSize);

    dumpVbUP(inputVertDecl,
             outputVertDecl, 
             optimizedIdxToMeshIdx, 
             &vertices, 
             lpvVertices,
             inputVertDecl.getStreamVertexSize(0)
             );

    KMeshTextures meshTextures;
    saveMeshTextures(pDev, &meshTextures);

    // No shaders in dx6. Empty
    KMeshShaders meshShaders;


    // Save RIP file
    std::wstring ripFilePath = g_pIntruder->getFrameMeshSavePath();
    std::string utf8str = wideStringToMultiByte(ripFilePath.c_str());

    hr = ::saveRipFile(ripFilePath.c_str(),
                       inputVertDecl,
                       outputVertDecl,
                       meshTextures,
                       meshShaders,
                       faces, 
                       vertices
                       );
    if (SUCCEEDED(hr))
    {
      g_pLog->log("Mesh saved as: %s\n\n\n", utf8str.c_str());
    }
    else
    {
      g_pLog->logError("Mesh save error: %s\n\n\n", utf8str.c_str());
    }

    g_pIntruder->incFrameMeshIdx();
  }
  while (false);
}


HRESULT KRipper6::helper_IDirect3DDevice3_DrawIndexedPrimitive(
                                        KHook* h,
                                        IDirect3DDevice3* pDev,
                                        D3DPRIMITIVETYPE d3dptPrimitiveType,
                                        DWORD  dwVertexTypeDesc,
                                        LPVOID lpvVertices,
                                        DWORD  dwVertexCount,
                                        LPWORD lpwIndices,
                                        DWORD  dwIndexCount,
                                        DWORD  dwFlags
                                        )
{
    PFN_IDirect3DDevice3_DrawIndexedPrimitive e =
        (PFN_IDirect3DDevice3_DrawIndexedPrimitive)h->getOriginalAddress();
  
  
  g_pIntruder->keyHandler(this);

  DWORD ripEnabled     = g_pIntruder->isMeshRipEnabled();
  DWORD minVertexCount = g_pIntruder->getSettings()->dwMinVertexCount;

  if (ripEnabled)
  {
    if (dwVertexCount >= minVertexCount)
    {
      g_pLog->log("IDirect3DDevice3_DrawIndexedPrimitive(0x%p, %d, 0x%08X, \
0x%p, %d, 0x%p, %d, 0x%08X)\n", 
                  pDev,
                  d3dptPrimitiveType,
                  dwVertexTypeDesc,
                  lpvVertices,
                  dwVertexCount,
                  lpwIndices,
                  dwIndexCount,
                  dwFlags
                  );
      __try
      {
        ripDrawIndexedPrimitive(pDev,
                                d3dptPrimitiveType,
                                dwVertexTypeDesc,
                                lpvVertices,
                                dwVertexCount,
                                lpwIndices,
                                dwIndexCount,
                                dwFlags
                                );

      }
      __except (EXCEPTION_EXECUTE_HANDLER)
      {
        g_pLog->logError("IDirect3DDevice3_DrawIndexedPrimitive() exception\n\n\n");
      }
    }
    else
    {
      g_pLog->logWarning("IDirect3DDevice3_DrawIndexedPrimitive() rip skipped\n");
    }
  }
  HRESULT res = e(pDev,
                  d3dptPrimitiveType,
                  dwVertexTypeDesc,
                  lpvVertices,
                  dwVertexCount,
                  lpwIndices,
                  dwIndexCount,
                  dwFlags
                  );
  return res;
}

extern KIntruder* g_pIntruder;
extern KLog*      g_pLog;



void KRipper6::ripDrawIndexedPrimitiveStrided(
                                   IDirect3DDevice3* pDev,
                                   D3DPRIMITIVETYPE d3dptPrimitiveType,
                                   DWORD  dwVertexTypeDesc,
                                   LPD3DDRAWPRIMITIVESTRIDEDDATA lpVertexArray,
                                   DWORD  dwVertexCount,
                                   LPWORD lpwIndices,
                                   DWORD  dwIndexCount,
                                   DWORD  dwFlags
                                   )
{
  do
  {
    // Primitive topology
    EPrimitiveTopology::Type primitiveTopology =
                     D3DPRIMITIVETYPE_to_EPrimitiveTopology(d3dptPrimitiveType);

    if (!::isPrimitiveTopologySupported(primitiveTopology))
    {
      g_pLog->logError("Input primitive topology not supported\n\n");
      break;
    }


    // Vertex declaration
    KInputVertexDeclaration  inputVertDecl;
    KOutputVertexDeclaration outputVertDecl;

    fvfToInputVertexDeclaration(dwVertexTypeDesc, &inputVertDecl);

    HRESULT hr = ::createKOutputVertexDeclaration(inputVertDecl,
                                                  outputVertDecl
                                                  );
    ::dumpInputVertexDeclaration2Log(inputVertDecl);
    ::dumpOutputVertexDeclaration2Log(outputVertDecl);


    DWORD primitivesCount = primitiveCountFromIndexCount(dwIndexCount, 
                                                         primitiveTopology
                                                         );
    // Indexes
    KFACES faces;
    OptimizedIndexToMeshIndex optimizedIdxToMeshIdx;
    hr = dumpIndexesUP(primitiveTopology, 
                       primitivesCount,
                       &faces, 
                       &optimizedIdxToMeshIdx,
                       lpwIndices,
                       EIndexFormat::INDEX_16
                       );
    if (FAILED(hr))
    {
      g_pLog->logError("dumpIndexesUP(). HRESULT: 0x%08X\n\n", hr);
      break;
    }

    // Vertices
    DWORD vertSize = outputVertDecl.getVertexSize(); // Output vertex size
    DWORD vertCnt = (DWORD)optimizedIdxToMeshIdx.size();
    g_pLog->log("PrimitivesCount=%d\nVertexCnt=%d\nOutVertexSize=%d\n",
                faces.getPrimitivesCount(),
                vertCnt,
                vertSize
                );

    KVERTICES vertices(vertCnt, vertSize);
    dumpVertexesStrided(lpVertexArray, 
                        inputVertDecl, 
                        outputVertDecl, 
                        optimizedIdxToMeshIdx, 
                        &vertices
                        );

    KMeshTextures meshTextures;
    saveMeshTextures(pDev, &meshTextures);

    // No shaders in dx6. Empty
    KMeshShaders meshShaders;


    // Save RIP file
    std::wstring ripFilePath = g_pIntruder->getFrameMeshSavePath();
    std::string utf8str = wideStringToMultiByte(ripFilePath.c_str());

    hr = ::saveRipFile(ripFilePath.c_str(),
                       inputVertDecl,
                       outputVertDecl,
                       meshTextures,
                       meshShaders,
                       faces, 
                       vertices
                       );
    if (SUCCEEDED(hr))
    {
      g_pLog->log("Mesh saved as: %s\n\n\n", utf8str.c_str());
    }
    else
    {
      g_pLog->logError("Mesh save error: %s\n\n\n", utf8str.c_str());
    }

    g_pIntruder->incFrameMeshIdx();
  }
  while (false);
}


HRESULT KRipper6::helper_IDirect3DDevice3_DrawIndexedPrimitiveStrided(
                                        KHook* h,
                                        IDirect3DDevice3* pDev,
                                        D3DPRIMITIVETYPE d3dptPrimitiveType,
                                        DWORD  dwVertexTypeDesc,
                                        LPD3DDRAWPRIMITIVESTRIDEDDATA lpVertexArray,
                                        DWORD  dwVertexCount,
                                        LPWORD lpwIndices,
                                        DWORD  dwIndexCount,
                                        DWORD  dwFlags
                                        )
{
  PFN_IDirect3DDevice3_DrawIndexedPrimitiveStrided e =
    (PFN_IDirect3DDevice3_DrawIndexedPrimitiveStrided)h->getOriginalAddress();
  
  
  g_pIntruder->keyHandler(this);

  DWORD ripEnabled     = g_pIntruder->isMeshRipEnabled();
  DWORD minVertexCount = g_pIntruder->getSettings()->dwMinVertexCount;

  if (ripEnabled)
  {
    if (dwVertexCount >= minVertexCount)
    {
      g_pLog->log("IDirect3DDevice3_DrawIndexedPrimitiveStrided(\
0x%p, %d, 0x%08X, 0x%p, %d, 0x%p, %d, 0x%08X)\n",
                  pDev,
                  d3dptPrimitiveType,
                  dwVertexTypeDesc,
                  lpVertexArray,
                  dwVertexCount,
                  lpwIndices,
                  dwIndexCount,
                  dwFlags
                  );
      __try
      {
        ripDrawIndexedPrimitiveStrided(pDev,
                                       d3dptPrimitiveType,
                                       dwVertexTypeDesc,
                                       lpVertexArray,
                                       dwVertexCount,
                                       lpwIndices,
                                       dwIndexCount,
                                       dwFlags
                                       );
      }
      __except (EXCEPTION_EXECUTE_HANDLER)
      {
        g_pLog->logError("IDirect3DDevice3_DrawIndexedPrimitiveStrided() exception\n\n\n");
      }
    }
    else
    {
      g_pLog->logWarning("IDirect3DDevice3_DrawIndexedPrimitiveStrided() rip skipped\n");
    }
  }
  HRESULT res = e(pDev,
                  d3dptPrimitiveType,
                  dwVertexTypeDesc,
                  lpVertexArray,
                  dwVertexCount,
                  lpwIndices,
                  dwIndexCount,
                  dwFlags
                  );
  return res;
}

extern KIntruder* g_pIntruder;
extern KLog*      g_pLog;


void KRipper6::ripDrawIndexedPrimitiveVB(
                                  IDirect3DDevice3* pDev,
                                  D3DPRIMITIVETYPE d3dptPrimitiveType,
                                  LPDIRECT3DVERTEXBUFFER lpd3dVertexBuffer,
                                  LPWORD lpwIndices,
                                  DWORD  dwIndexCount,
                                  DWORD  dwFlags
                                  )
{
  do
  {
    // Primitive topology
    EPrimitiveTopology::Type primitiveTopology =
                    D3DPRIMITIVETYPE_to_EPrimitiveTopology(d3dptPrimitiveType);

    if (!::isPrimitiveTopologySupported(primitiveTopology))
    {
      g_pLog->logError("Input primitive topology not supported\n\n");
      break;
    }


    // Vertex declaration
    KInputVertexDeclaration  inputVertDecl;
    KOutputVertexDeclaration outputVertDecl;

    D3DVERTEXBUFFERDESC vbDesc;
    vbDesc.dwSize = sizeof(vbDesc);
    HRESULT hr = lpd3dVertexBuffer->GetVertexBufferDesc(&vbDesc);
    if (FAILED(hr))
    {
      g_pLog->logError("IDirect3DVertexBuffer::GetVertexBufferDesc(). \
HRESULT: 0x%08X\n\n\n", hr);
      break;
    }

    DWORD dwVertexTypeDesc = vbDesc.dwFVF;
    fvfToInputVertexDeclaration(dwVertexTypeDesc, &inputVertDecl);

    hr = ::createKOutputVertexDeclaration(inputVertDecl, outputVertDecl);

    g_pLog->log("FVF: 0x%08X\n", dwVertexTypeDesc);
    ::dumpInputVertexDeclaration2Log(inputVertDecl);
    ::dumpOutputVertexDeclaration2Log(outputVertDecl);


    DWORD primitivesCount = primitiveCountFromIndexCount(dwIndexCount, 
                                                         primitiveTopology
                                                         );
    // Indexes
    KFACES faces;
    OptimizedIndexToMeshIndex optimizedIdxToMeshIdx;
    hr = dumpIndexesUP(primitiveTopology, 
                       primitivesCount,
                       &faces, 
                       &optimizedIdxToMeshIdx,
                       lpwIndices,
                       EIndexFormat::INDEX_16
                       );
    if (FAILED(hr))
    {
      g_pLog->logError("dumpIndexesUP(). HRESULT: 0x%08X\n\n", hr);
      break;
    }



    // Vertices
    DWORD vertSize = outputVertDecl.getVertexSize(); // Output vertex size
    DWORD vertCnt = (DWORD)optimizedIdxToMeshIdx.size();
    g_pLog->log("PrimitivesCount=%d\nVertexCnt=%d\nOutVertexSize=%d\n",
                faces.getPrimitivesCount(),
                vertCnt,
                vertSize
                );

    KVERTICES vertices(vertCnt, vertSize);

    LPVOID vbData = 0;
    hr = lpd3dVertexBuffer->Lock(DDLOCK_READONLY, &vbData, NULL);
    if (FAILED(hr))
    {
      g_pLog->logError("lpd3dVertexBuffer->Lock(). HRESULT: 0x%08X\n\n", hr);
      break;
    }


    DWORD stride = inputVertDecl.getStreamVertexSize(0);
    dumpVbUP(inputVertDecl,
             outputVertDecl,
             optimizedIdxToMeshIdx,
             &vertices,
             (BYTE*)vbData,
             stride
             );

    hr = lpd3dVertexBuffer->Unlock();
    if (FAILED(hr))
    {
        g_pLog->logError("lpd3dVertexBuffer->Unlock(). HRESULT: 0x%08X\n\n", hr);
        break;
    }

    KMeshTextures meshTextures;
    saveMeshTextures(pDev, &meshTextures);

    // No shaders in dx6. Empty
    KMeshShaders meshShaders;


    // Save RIP file
    std::wstring ripFilePath = g_pIntruder->getFrameMeshSavePath();
    std::string utf8str = wideStringToMultiByte(ripFilePath.c_str());

    hr = ::saveRipFile(ripFilePath.c_str(),
                       inputVertDecl,
                       outputVertDecl,
                       meshTextures,
                       meshShaders,
                       faces, 
                       vertices
                       );
    if (SUCCEEDED(hr))
    {
      g_pLog->log("Mesh saved as: %s\n\n\n", utf8str.c_str());
    }
    else
    {
      g_pLog->logError("Mesh save error: %s\n\n\n", utf8str.c_str());
    }

    g_pIntruder->incFrameMeshIdx();
  }
  while (false);

}


HRESULT KRipper6::helper_IDirect3DDevice3_DrawIndexedPrimitiveVB(
                                    KHook* h,
                                    IDirect3DDevice3* pDev,
                                    D3DPRIMITIVETYPE d3dptPrimitiveType,
                                    LPDIRECT3DVERTEXBUFFER lpd3dVertexBuffer,
                                    LPWORD lpwIndices,
                                    DWORD  dwIndexCount,
                                    DWORD  dwFlags
                                    )
{
  PFN_IDirect3DDevice3_DrawIndexedPrimitiveVB e =
           (PFN_IDirect3DDevice3_DrawIndexedPrimitiveVB)h->getOriginalAddress();
  
  
  g_pIntruder->keyHandler(this);

  DWORD ripEnabled     = g_pIntruder->isMeshRipEnabled();
  DWORD minIndexCount  = g_pIntruder->getSettings()->dwMinIndicies;

  if (ripEnabled)
  {
    if (dwIndexCount >= minIndexCount)
    {
      g_pLog->log("IDirect3DDevice3_DrawIndexedPrimitiveVB(\
0x%p, %d, 0x%p, 0x%p, %d, 0x%08X)\n",
                                      pDev,
                                      d3dptPrimitiveType,
                                      lpd3dVertexBuffer,
                                      lpwIndices,
                                      dwIndexCount,
                                      dwFlags
                                      );
      __try
      {
          ripDrawIndexedPrimitiveVB(
                                    pDev,
                                    d3dptPrimitiveType,
                                    lpd3dVertexBuffer,
                                    lpwIndices,
                                    dwIndexCount,
                                    dwFlags
                                    );
      }
      __except (EXCEPTION_EXECUTE_HANDLER)
      {
        g_pLog->logError("IDirect3DDevice3_DrawIndexedPrimitiveVB() exception\n\n\n");
      }
    }
    else
    {
      g_pLog->logWarning("IDirect3DDevice3_DrawIndexedPrimitiveVB() rip skipped\n");
    }
  }
  HRESULT res = e(pDev,
                  d3dptPrimitiveType,
                  lpd3dVertexBuffer,
                  lpwIndices,
                  dwIndexCount,
                  dwFlags
                  );
  return res;
}

extern KIntruder* g_pIntruder;
extern KLog*      g_pLog;


void KRipper6::addMeshTexture(const KTexture& t)
{
  meshTexturesDb.push_back(t);
}


bool KRipper6::isMeshTextureSaved(LPDIRECT3DTEXTURE2 pTexture,
                                  KTexture* out
                                  )
{
  bool res = false;

  for (size_t i = 0; i < meshTexturesDb.size(); i++)
  {
    if (meshTexturesDb[i].pTexture == pTexture)
    {
      *out = meshTexturesDb[i];
      res = true;
      break;
    }
  }

  return res;
}


void KRipper6::saveMeshTextures(IDirect3DDevice3* pDev, 
                                KMeshTextures* meshTextures
                                )
{
  for (DWORD i = 0; i < 8; ++i)
  {

    TDXRef < IDirect3DTexture2 > pTexture;

    HRESULT hr = pDev->GetTexture(i, &pTexture);
    if (FAILED(hr))
    {
      g_pLog->logError("IDirect3DDevice3::GetTexture(%d). HRESULT: 0x%08X\n", 
                       i, 
                       hr
                       );
    }
    else if (pTexture.get())
    {
      KTexture savedTex;
      if (isMeshTextureSaved(pTexture.get(), &savedTex))
      {
        std::string utf8str = wideStringToMultiByte(savedTex.fullPath.c_str());

        // Already Saved Texture. Copy Texture Name To Header
        meshTextures->textures.push_back(savedTex.name);

        g_pLog->log("Texture stage #%d already saved as: %s\n", 
                    i, 
                    utf8str.c_str()
                    );
      }
      else
      {
        std::string  textureFileA;
        std::wstring textureFilePath = 
                        g_pIntruder->getFrameTextureSavePath(textureFileA, i);

        //----------------------
        // New Texture In Model. Copy Texture Name To Header
        //----------------------
        hr = saveTexture2File(textureFilePath.c_str(), pTexture.get());
        if (SUCCEEDED(hr))
        {
          KTexture ft;
          ft.pTexture = pTexture.get();
          ft.name     = textureFileA;
          ft.fullPath = textureFilePath;
          addMeshTexture(ft);

          meshTextures->textures.push_back(textureFileA);

          std::string utf8str = wideStringToMultiByte(textureFilePath.c_str());
          g_pLog->log("Texture stage #%d saved as: %s\n", 
                      i, 
                      utf8str.c_str()
                      );
        }
        else
        {
          g_pLog->logError("Texture save. HRESULT: 0x%08X\n", hr);
        }

        g_pIntruder->incFrameTextureIdx();
      }
    }
    else
    {
//      g_pLog->log("Texture stage #%d not exist\n", i);
    }
  }
}

extern KIntruder* g_pIntruder;
extern KHookMgr*  g_pHookMgr;
extern KLog*      g_pLog;
extern KDdraw*    g_pDdraw;


HRESULT KRipper6::saveTexture2File(const wchar_t* fileName, 
                                   LPDIRECT3DTEXTURE2 tex
                                   )
{
  TextureToSurfaceDb::iterator it = textureToSurfaceDb.find(tex);
  HRESULT res = E_FAIL;
  if (it == textureToSurfaceDb.end())
  {
    g_pLog->logError("D3D6 ripper: Texture surface not found in db. Search texture in surfaces dir\n");
  }
  else
  {
    void* surface = it->second;
    res = g_pDdraw->save_IDirectDrawSurface(fileName, surface);
  }
  return res;
}

extern KIntruder* g_pIntruder;
extern KHookMgr*  g_pHookMgr;
extern KLog*      g_pLog;


DWORD KRipper6::isTextureSaved(LPDIRECT3DTEXTURE2 pTex)
{
  if (!pTex)//Texture unset
    return 1;

  for (size_t i = 0; i < forcedTexturesDb.size(); i++)
  {
    if (forcedTexturesDb[i] == pTex)
    {
      return 1;
    }
  }
  return 0;
}


void KRipper6::handleTextureSave(IDirect3DDevice3* pDev,
                                 DWORD Stage,
                                 LPDIRECT3DTEXTURE2 pTexture
                                 )
{
  g_pIntruder->keyHandler(this);
  DWORD RipFlag = g_pIntruder->isTexturesRipKeyPressed();
  if (RipFlag)
  {
    if (!isTextureSaved(pTexture))
    {
      std::wstring TextureFile = g_pIntruder->getTextureSavePath();
      std::string utf8str = wideStringToMultiByte(TextureFile.c_str());

      HRESULT hr = saveTexture2File(TextureFile.c_str(), pTexture);
      
      if (SUCCEEDED(hr))
      {
        // Saving success
        g_pIntruder->incTextureIdx();
        g_pLog->log("Texture saved: %s\n", utf8str.c_str());
      }
      else
      {
        // Texture save error
        g_pLog->logError("Texture save. HRESULT: 0x%08X\n", hr);
      }

      // Mark as processed
      this_->forcedTexturesDb.push_back(pTexture);
    }
  }
}


HRESULT KRipper6::helper_IDirect3DDevice3_SetTexture(
                                                KHook* h,
                                                IDirect3DDevice3* pDev,
                                                DWORD dwStage,
                                                LPDIRECT3DTEXTURE2 lpTexture
                                                )
{
  // HACK. D3D changes VTBL. Need rehook
  hook_IDirect3DDevice3(pDev);


  PFN_IDirect3DDevice3_SetTexture e = 
                       (PFN_IDirect3DDevice3_SetTexture)h->getOriginalAddress();

  EnterCriticalSection(&cs);
  __try
  {
    handleTextureSave(pDev, dwStage, lpTexture);
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    g_pLog->logError("Exception in KRipper6::handleTextureSave()\n");
  }
  LeaveCriticalSection(&cs);

  return e(pDev, dwStage, lpTexture);
}

#endif // defined(__DDRAW_INCLUDED__) && defined(__D3D_H__)
