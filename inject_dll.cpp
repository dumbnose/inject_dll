// inject_dll.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"


#pragma comment(lib, "detours.lib")
#pragma comment(lib, "shlwapi.lib")


bool debug = false;
dumbnose::event_log event_log(L"CentennialAppCompatShim");


int usage()
{
    std::cout << "USAGE:\n\n"
              << "\tinject_dll.exe -cmd:<command to execute> [-dll:<name of dll to inject>] [-setcwd:<directory to make current working directory>] [-redirfile:<filename to redirect>] [-debug]\n\n"
              << "\t\tcmd:        The command you want to execute.\n"
              << "\t\tdll:        The dll you want to inject into the resulting process.\n"
              << "\t\tsetcwd:     Set the current working directory to the one specified.\n"
              << "\t\tredirfile:  Redirect writes to this file to the appdata folder.\n"
              << "\t\tdebug:      Enables debug messages.\n"
        ;

    return -1;
}

bool is_cmdline_valid(dumbnose::cmdline_options& options)
{
    if (!options.exists(L"cmd")) return false;

    return true;
}

int wmain()
{
    try {
        //
        // Read the cmdline from the text file and parse it
        //
        if (!PathFileExists(L"cmdline.txt")) {
            wchar_t package_root[256] = L"\0";
            UINT32 package_root_length = ARRAYSIZE(package_root);
            LONG err = GetCurrentPackagePath(&package_root_length, package_root);
            if (err != 0) throw dumbnose::windows_exception("GetCurrentPackagePath() failed", err);

            if (!SetCurrentDirectory(package_root)) throw dumbnose::windows_exception("SetCurrentDirectory() failed");
        }

        std::wifstream ifs("cmdline.txt");
        std::wstring cmdline((std::istreambuf_iterator<wchar_t>(ifs)), (std::istreambuf_iterator<wchar_t>()));

        int argc = 0;
        wchar_t** argv = CommandLineToArgvW(cmdline.c_str(), &argc);
        dumbnose::cmdline_options parsed_cmdline(argc, argv);
        LocalFree(argv);

        if (!is_cmdline_valid(parsed_cmdline)) return usage();

        debug = parsed_cmdline.exists(L"debug");

        //
        // Change working directory, if required
        //
        if (parsed_cmdline.exists(L"setcwd")) {
            std::wstring cwd = parsed_cmdline.option(L"setcwd");
            if (!SetCurrentDirectory(cwd.c_str())) throw dumbnose::windows_exception("SetCurrentDirectory failed.");
        }

        //
        // Extract the cmdline args and execute it
        //
        std::wstring cmd = parsed_cmdline.option(L"cmd");
        std::string dll;
        if (parsed_cmdline.exists(L"dll")) {
            dll = dumbnose::string_utils::convert(parsed_cmdline.option(L"dll"));
        }

        LPWSTR cmd_cstr = const_cast<LPWSTR>(cmd.data());
        LPCSTR dll_cstr = dll.data();

        STARTUPINFO si{ 0 };
        PROCESS_INFORMATION pi;

        if (dll.length() > 0) {
            LoadLibrary(L"app_compat_shim");
            if (!DetourCreateProcessWithDll(nullptr, cmd_cstr, nullptr, nullptr, false, 0, nullptr, nullptr, &si, &pi, dll_cstr, nullptr)) throw dumbnose::windows_exception("DetourCreateProcessWithDll failed.");
        } else {
            if (!CreateProcess(nullptr, cmd_cstr, nullptr, nullptr, false, 0, nullptr, nullptr, &si, &pi)) throw dumbnose::windows_exception("CreateProcess failed.");
        }

    } catch (dumbnose::windows_exception& ex) {
        event_log.add_error(ex.num(), ex.what());
        if (debug) {
            MessageBoxA(nullptr, ex.what(), "Error", MB_ICONERROR);
        }
        return usage();
    } catch (std::exception& ex) {
        event_log.add_error(-1, ex.what());
        if (debug) {
            MessageBoxA(nullptr, ex.what(), "Error", MB_ICONERROR);
        }
        return usage();
    }

    return 0;
}

