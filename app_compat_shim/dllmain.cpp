// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"

#include "FunctionFinder.hpp"

#pragma comment(lib, "detours.lib")
#pragma comment(lib, "shlwapi.lib")


bool copying_file = false;
bool debug = false;

//decltype(&CreateProcessW) RealCreateProcessW = CreateProcessW;
//HMODULE kernelBase = GetModuleHandle(L"kernelbase.dll");
decltype(&CreateProcessW) RealCreateProcessW = reinterpret_cast<decltype(&CreateProcessW)>(DetourFindFunction("kernelBase.dll", "CreateProcessW"));
decltype(&LoadLibraryExW) RealLoadLibraryExW = LoadLibraryExW;
decltype(&CreateFileW) RealCreateFileW = CreateFileW;
decltype(&CreateActCtxW) RealCreateActCtxW = CreateActCtxW;

std::wstring redir_file;
dumbnose::event_log event_log(L"CentennialAppCompatShim");


void parse_cmdline_file()
{
    try {
        //
        // Read the cmdline from the text file and parse it
        //
        std::wifstream ifs("cmdline.txt");
        std::wstring cmdline((std::istreambuf_iterator<wchar_t>(ifs)), (std::istreambuf_iterator<wchar_t>()));

        int argc = 0;
        wchar_t** argv = CommandLineToArgvW(cmdline.c_str(), &argc);
        dumbnose::cmdline_options parsed_cmdline(argc, argv);
        LocalFree(argv);

        debug = parsed_cmdline.exists(L"debug");

        if (parsed_cmdline.exists(L"redirfile")) {
            redir_file = parsed_cmdline.option(L"redirfile");
        }

    } catch (dumbnose::windows_exception& ex) {
        event_log.add_error(ex.num(), ex.what());
        if (debug) {
            MessageBoxA(nullptr, ex.what(), "Error", MB_ICONERROR);
        }
    } catch (std::exception& ex) {
        event_log.add_error(-1, ex.what());
        if (debug) {
            MessageBoxA(nullptr, ex.what(), "Error", MB_ICONERROR);
        }
    }
}

std::wstring get_new_path(LPCWSTR original_path)
{
    PWSTR appdata = nullptr;

    HRESULT hr = SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_DEFAULT, nullptr, &appdata);
    if (FAILED(hr)) throw dumbnose::windows_exception("SHGetKnownFolderPath failed", hr);
    ON_BLOCK_EXIT([&appdata] {CoTaskMemFree(appdata); });

    std::wstring new_path(appdata);
    new_path += L'\\';
    new_path += PathFindFileName(original_path);

    return new_path;
}

std::wstring copy_file_to_appdata(PCWSTR original_path)
{
    std::wstring new_path;

    try {

        new_path = get_new_path(original_path);
        if (_wcsicmp(original_path, new_path.c_str()) == 0) return new_path;  // We're accessing the new path already
        if (PathFileExists(new_path.c_str())) return new_path;  // We've already copied

        copying_file = true;
        if (!CopyFile(original_path, new_path.c_str(), false)) throw dumbnose::windows_exception("CopyFile failed");
        copying_file = false;

    } catch (dumbnose::windows_exception& ex) {
        event_log.add_error(ex.num(), ex.what());
        if (debug) {
            MessageBoxA(nullptr, ex.what(), "Error", MB_ICONERROR);
        }
        return original_path;
    } catch (std::exception& ex) {
        event_log.add_error(-1, ex.what());
        if (debug) {
            MessageBoxA(nullptr, ex.what(), "Error", MB_ICONERROR);
        }
        return original_path;
    }

    return new_path;
}

HANDLE
WINAPI
InterceptedCreateFileW(
    _In_ LPCWSTR lpFileName,
    _In_ DWORD dwDesiredAccess,
    _In_ DWORD dwShareMode,
    _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _In_ DWORD dwCreationDisposition,
    _In_ DWORD dwFlagsAndAttributes,
    _In_opt_ HANDLE hTemplateFile
    )
{
    if (!copying_file && (redir_file.length()>0) && (_wcsicmp(PathFindFileName(lpFileName), redir_file.c_str()) == 0)) {
        std::wstring new_path = copy_file_to_appdata(lpFileName);
        return RealCreateFileW(new_path.c_str(), dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    }

    return RealCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}


BOOL
WINAPI
InterceptedCreateProcessW(
    _In_opt_ LPCWSTR lpApplicationName,
    _Inout_opt_ LPWSTR lpCommandLine,
    _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
    _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
    _In_ BOOL bInheritHandles,
    _In_ DWORD dwCreationFlags,
    _In_opt_ LPVOID lpEnvironment,
    _In_opt_ LPCWSTR lpCurrentDirectory,
    _In_ LPSTARTUPINFOW lpStartupInfo,
    _Out_ LPPROCESS_INFORMATION lpProcessInformation
    )
{
    //MessageBox(nullptr, L"Intercepted CreateProcessW", L"Intercetped", MB_OK);

    return DetourCreateProcessWithDll(
        lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation,
        "app_compat_shim.dll",
        RealCreateProcessW
            );

}

_Ret_maybenull_
HMODULE
WINAPI
InterceptedLoadLibraryExW(
    _In_ LPCWSTR lpLibFileName,
    _Reserved_ HANDLE hFile,
    _In_ DWORD dwFlags
    )
{
    //MessageBox(nullptr, L"Intercepted LoadLibraryExW", L"Intercetped", MB_OK);

    return RealLoadLibraryExW(lpLibFileName, hFile,dwFlags);
}


HANDLE
WINAPI
InterceptedCreateActCtxW(
    _In_ PCACTCTXW pActCtx
)
{
    try {
        if (_wcsicmp(L"plugin.X.manifest", pActCtx->lpSource) == 0) {
            std::wstring assembly_path = pActCtx->lpAssemblyDirectory;
            assembly_path += L"\\";
            assembly_path += pActCtx->lpSource;

            HANDLE dir = CreateFile(assembly_path.c_str(), GENERIC_READ, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
            if (dir == INVALID_HANDLE_VALUE) throw dumbnose::windows_exception("CreateFile for assembly failed.");

            wchar_t real_path[MAX_PATH] = L"";
            DWORD result = GetFinalPathNameByHandle(dir, real_path, MAX_PATH, 0);
            if (result == 0) throw dumbnose::windows_exception("GetFinalPathNameByHandle for assembly failed.", result);

            if(!PathRemoveFileSpec(real_path)) throw dumbnose::windows_exception("PathRemoveFileSpec failed.");

            ACTCTXW act_ctx = *pActCtx;
            act_ctx.lpAssemblyDirectory = real_path;

            HANDLE act_ctx_handle = RealCreateActCtxW(&act_ctx);
            if (act_ctx_handle == INVALID_HANDLE_VALUE) throw dumbnose::windows_exception("RealCreateActCtxW for assembly failed.");

            return act_ctx_handle;
        }
    } catch (dumbnose::windows_exception& ex) {
        event_log.add_error(ex.num(), ex.what());
        if (debug) {
            MessageBoxA(nullptr, ex.what(), "Error", MB_ICONERROR);
        }
    } catch (std::exception& ex) {
        event_log.add_error(-1, ex.what());
        if (debug) {
            MessageBoxA(nullptr, ex.what(), "Error", MB_ICONERROR);
        }
    }

    return RealCreateActCtxW(pActCtx);
}

void hook_functions()
{
    FunctionFinder finder;
    auto OtherRealCreateProcessW = reinterpret_cast<decltype(&CreateProcessW)>(finder.FindFunction("kernelbase.dll", "CreateProcessW"));

    LONG rc = DetourTransactionBegin();
    rc = DetourUpdateThread(GetCurrentThread());

    //rc = DetourAttach(&(PVOID&)RealCreateProcessW, InterceptedCreateProcessW);
    rc = DetourAttach(&(PVOID&)OtherRealCreateProcessW, InterceptedCreateProcessW);
    std::wstringstream message; 
    
    message << (L"DetourAttach returned: ") << rc << " RealCreateProcessW=" << RealCreateProcessW << " OtherRealCreateProcessW=" << OtherRealCreateProcessW;
    
    MessageBox(NULL, message.str().c_str(), L"Result", MB_OK);

    rc = DetourAttach(&(PVOID&)RealLoadLibraryExW, InterceptedLoadLibraryExW);
    rc = DetourAttach(&(PVOID&)RealCreateFileW, InterceptedCreateFileW);
    rc = DetourAttach(&(PVOID&)RealCreateActCtxW, InterceptedCreateActCtxW);
    rc = DetourTransactionCommit();
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
        parse_cmdline_file();
        hook_functions();
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
