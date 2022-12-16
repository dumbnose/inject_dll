#pragma once

#include <string>

extern const __declspec(selectany) char API_MS_WIN_CORE_PROCESSTHREADS_DLL[] = "API-MS-WIN-CORE-PROCESSTHREADS-L1-1-0.DLL";
extern const __declspec(selectany) char API_MS_WIN_CORE_REGISTRY_DLL[] = "API-MS-WIN-CORE-REGISTRY-L1-1-0.DLL";
extern const __declspec(selectany) char API_MS_WIN_SERVICE_CORE_DLL[] = "API-MS-WIN-SERVICE-CORE-L1-1-1.DLL";
extern const __declspec(selectany) char API_MS_WIN_SERVICE_WINSVC_DLL[] = "API-MS-WIN-SERVICE-WINSVC-L1-1-0.DLL";
extern const __declspec(selectany) char API_MS_WIN_SERVICE_MANAGEMENT_DLL[] = "API-MS-WIN-SERVICE-MANAGEMENT-L1-1-0.DLL";
extern const __declspec(selectany) char API_MS_WIN_SERVICE_MANAGEMENT_L2_DLL[] = "API-MS-WIN-SERVICE-MANAGEMENT-L2-1-0.DLL";
//if additional dll names are added, API_SET_KNOWN_DLLS must be updated

extern const __declspec(selectany) char* API_SET_KNOWN_DLLS[] = {
	API_MS_WIN_CORE_PROCESSTHREADS_DLL,
	API_MS_WIN_CORE_REGISTRY_DLL,
	API_MS_WIN_SERVICE_CORE_DLL,
	API_MS_WIN_SERVICE_WINSVC_DLL,
	API_MS_WIN_SERVICE_MANAGEMENT_DLL,
	API_MS_WIN_SERVICE_MANAGEMENT_L2_DLL };


HMODULE LoadSystemLibrary(const std::wstring& dllName);
// Maps file device path to drive letter path.
// e.g. '\Device\HarddiskVolume1\Windows' to 'C:\Windows'
bool device_path_to_dos_path(const std::wstring& device_path, std::wstring& path);
std::wstring get_module_path_from_address(void* module_addr);

//note that like the 4-component version of splitpath, dir contains a trailing slash
inline void splitpath(const std::wstring& fullPath, std::wstring& dir, std::wstring& name)
{
    size_t pos = fullPath.find_last_of(L'\\');
    if (pos != std::wstring::npos)
    {
        dir = fullPath.substr(0, pos + 1);
        name = fullPath.substr(pos + 1, std::wstring::npos);
    }
    else
    {
        dir = L"";
        name = fullPath;
    }
}

//Note: the returned directory has a trailing slash
inline std::wstring path_dir_portion(const std::wstring& path)
{
    std::wstring dir;
    std::wstring name;
    splitpath(path, dir, name);
    return dir;
}

inline std::wstring path_name_portion(const std::wstring& path)
{
    std::wstring dir;
    std::wstring name;
    splitpath(path, dir, name);
    return name;
}

struct iless
{
    bool operator()(const std::wstring& left, const std::wstring& right) const;
    bool operator()(const std::string& left, const std::string& right) const;
};