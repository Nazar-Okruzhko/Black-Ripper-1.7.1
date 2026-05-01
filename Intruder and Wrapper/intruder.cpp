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
 
// Ripper factories — filled when dx*/ddraw/dxgi files arrive:
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
//  SECTION 1 — intruder.h  (types and declarations)
// =============================================================================
 
// KUNICODE_STRING — NT internal Unicode string (used for LdrLoadDll hook)
#pragma pack(push,1)
struct KUNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
};
#pragma pack(pop)
 
// LdrLoadDll / LdrUnloadDll — NT loader functions we hook to watch DX DLL loads
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
 
// NtMapViewOfSection — not currently hooked but declared for completeness
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
//  SECTION 2 — process.h  (child-process injection hook declarations)
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
//  SECTION 3 — Global state
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
//  SECTION 4 — intruder.cpp  (DllMain, install, uninstall, LdrLoad hooks)
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
 
 
// Check all DX DLLs on startup — some may already be loaded before our hook.
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
    g_pLog->log("\xc2\xa9 black_ninja, 2017\n\n");  // © black_ninja (UTF-8)
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
    // These fire for EVERY DLL load in the process — we watch for DX DLLs.
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
 
 
// ---- LdrLoadDll hook — fires on EVERY DLL load in the target process --------
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
 
 
// ---- LdrUnloadDll hook — fires when a DLL is freed --------------------------
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
        g_pLog->logError("\n\nPSAPI error — cannot enumerate modules\n\n");
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
//  SECTION 5 — process.cpp  (child-process injection hooks)
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
            g_pLog->logError("Inject to child skipped — wrapper dll found (delete manually): %s\n", utf8.c_str());
        else
            g_pLog->logError("Inject to child skipped — arch mismatch 32<->64, wrapper: %s\n", utf8.c_str());
 
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
 
    // Strip flags that require elevated token — fall back to plain CreateProcessW
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
 
    // Block integrity-level downgrades — they prevent injection into children
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
 
    // SetInformationJobObject hook is commented out in original source —
    // preserved as-is (some games use job objects to prevent external injection)
    /*
    hookEx("SetInformationJobObject", GetProcAddress(hK32, "SetInformationJobObject"),
           _SetInformationJobObject,  KHookMgr::EHOOK_KERNEL32, &pHook_SetInformationJobObject);
    */
}
 
 
// =============================================================================
//  SECTION 6 — IRipper interface + ERIP_ERR  (iripper.h)
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
//  SECTION 7 — commontypes.h  (IUnknown helper)
// =============================================================================
 
#include <Unknwn.h>
 
enum { IDX_IUnknown_QueryInterface = 0 };
 
typedef HRESULT(__stdcall* PFN_IUnk_QueryInterface)(
    IUnknown* p, REFIID refiid, void** obj);
 
 
// =============================================================================
//  SECTION 8 — datatypes.h  (vertex element type system)
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
//  SECTION 9 — KLog  (klog.h — thread-safe timestamped logger)
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
//  SECTION 10 — KHook + HooksGroup  (khook.h/cpp)
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
//  SECTION 11 — KHookMgr  (khookmgr.h/cpp)
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
//  SECTION 12 — tools.h stubs + hookEx()
//  Full implementation arrives in intruder/common/tools.h (part 2).
//  hookEx() is used by every hook-install call site throughout the DLL.
// =============================================================================
 
// String utilities — implemented in tools.cpp (part 2)
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
//  SECTION 13 — KIntruder  (kintruder.h/cpp)
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
 
// Uses SHCreateDirectoryExW — needs shlobj.h (already included above)
int createDirectoryRecursively(const wchar_t* path)
{
    return SHCreateDirectoryExW(nullptr, path, nullptr);
}
 
 
// =============================================================================
//  SECTION 14 — macro.h
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
//  SECTION 15 — tools.h / tools.cpp  (string utils, vtable hooks, dir helpers)
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
 
// Load a DLL from System32 — try GetModuleHandle first to avoid double-load
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
 
// Fix up Section 12 stub — replace the inline hookEx() there with a call here
// (Re-define the inline so it dispatches to hookEx_full)
// This must appear after the definition above.
#define hookEx(name,targ,detour,pool,outHook) \
    hookEx_full((name),(targ),(detour),(pool),(outHook))
 
 
// =============================================================================
//  SECTION 16 — topology.h / topology.cpp
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
//  SECTION 17 — vertexprocess.h / vertexprocess.cpp  (vertex buffer engine)
// =============================================================================
 
const DWORD SEMANTIC_LEN     = 64;
const DWORD MAX_TYPEMAP_SIZE = 8;
 
// Vertex buffer container — owns a flat byte array of (vertexCount × vertexSize)
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
//  SECTION 18 — indexprocess  (face/index processing engine)
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
 
// These implementations live in dx*/ddraw files — forward-declared here:
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
//  SECTION 19 — EIndexFormat + vert_indx_dump  (UP draw-path helpers)
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
//  SECTION 20 — ripout.h / ripout.cpp  (.rip file format and writer)
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
//   [vertexAttributesCnt × attribute records]  (semantic string + metadata)
//   [textureFilesCnt × null-terminated strings]
//   [shaderFilesCnt  × null-terminated strings]
//   [dwFacesCnt × KFace]
//   [dwVertexesCnt × vertexSize bytes]
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
//  SECTION 21 — TDXRef / TDXRefVec  (RAII COM pointer wrappers)
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
//  SECTION 22 — TInitedVal  (lazy initialisation wrapper)
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
//  SECTION 23 — outtypes__.h  (legacy .rip v2 structs — kept for reference)
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
//  SECTION 24 — shadercompile.h / shadercompile.cpp
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
//  SECTION 25 — ddraw/  (DirectDraw DX1-DX7 ripper)
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
    // (full enum in surfacesave.h — abbreviated here, add values as needed)
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
 
// saveImg uses DirectXTex — forward declared; implemented when DirectXTex
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
// Requires DXSDK7 ddraw.h — include path set in project
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
 
// SurfaceData — tracks which surfaces we've already saved (CRC dedup)
struct SurfaceData { SurfaceData():dataCrc32(0){} DWORD dataCrc32; };
 
// ---- ddraw/macro.h — stub generators ---------------------------------------
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
 
    // HooksGroups — public so STUB macros can access them
    HooksGroup hooks_IUnk_QueryInterface;
    HooksGroup hooks_IDirectDraw_CreateSurface;
    HooksGroup hooks_IDirectDrawSurface_Blt;
    HooksGroup hooks_IDirectDrawSurface_Flip;
    HooksGroup hooks_IDirectDrawSurface_Unlock;
    HooksGroup hooks_IDirectDrawSurface_SetPalette;
    HooksGroup hooks_IDirectDrawSurface_ReleaseDC;
 
    // Helpers — public so STUB macros can call them
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
    // Placeholder — returns S_OK to keep flow intact until DXSDK7 is linked.
    (void)fileName; (void)pSurface;
    return S_OK;
}
 
// ---- Factory functions (from preddraw.h/cpp) --------------------------------
KDdraw* create_KDdraw(HINSTANCE hDll){ return KDdraw::create(hDll); }
void    delete_KDdraw(KDdraw*& p)    { KDdraw::destroy(p); }
 
 
// =============================================================================
//  SECTION 26 — dxgi/  (DXGI swap-chain ripper)
//
//  Hooks: CreateDXGIFactory, CreateDXGIFactory1,
//         IDXGIFactory::CreateSwapChain (and Factory2 variants),
//         IDXGISwapChain::Present, IDXGISwapChain1::Present1,
//         IDXGIFactory::QueryInterface  (detects Factory2 upgrades)
//  Frame trigger: IDXGISwapChain::Present ? g_pIntruder->frameHandler(ripper)
//  The 'ripper' pointer is set externally via setIRipper(g_pDxgi, g_pRipper11)
//  once D3D11 initialises — decouples DXGI from D3D11 at startup.
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
//  SECTION 27 — dx9/  (Direct3D 9 ripper — KRipper9)
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
 
// ---- dx9/macro.h — stub generators -----------------------------------------
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
 
    // Pixel shader / depth stencil / gamma — tracked for texture render restore
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
//  SECTIONS 28+ — filled as dx8 / dx11 / dx7 / dx6 / MinHook arrive
//
//  intruder/dx8/    ? KRipper8
//  intruder/dx11/   ? KRipper11
//  intruder/dx7/    ? KRipper7
//  intruder/dx6/    ? KRipper6
//  intruder/MinHook/? MH_Initialize, MH_CreateHook, MH_EnableHook
//  intruder/common/ ? dataconvert.cpp, fvf.cpp, guidtoname.cpp,
//                     indexprocess.cpp, datatypes.cpp
// =============================================================================
 