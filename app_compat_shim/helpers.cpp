#include "stdafx.h"
#include "helpers.hpp"

inline
bool lexicographical_compare(const std::wstring& left, const std::wstring& right)
{
	int result = wcscmp(left.c_str(), right.c_str());
	return (0 > result);
}


inline
bool ilexicographical_compare(const std::wstring& left, const std::wstring& right)
{
	int result = _wcsicmp(left.c_str(), right.c_str());
	return (0 > result);
}

inline
bool lexicographical_compare(const std::string& left, const std::string& right)
{
	int result = strcmp(left.c_str(), right.c_str());
	return (0 > result);
}


inline
bool ilexicographical_compare(const std::string& left, const std::string& right)
{
	int result = _stricmp(left.c_str(), right.c_str());
	return (0 > result);
}

bool iless::operator()(const std::wstring& left, const std::wstring& right) const
{
	return ilexicographical_compare(left, right);
}

bool iless::operator()(const std::string& left, const std::string& right) const
{
	return ilexicographical_compare(left, right);
}


std::wstring path_combine(const std::wstring& dir, const std::wstring& relativePath)
{
	if (dir.empty())
		return relativePath;

	if (relativePath.empty())
		return dir;

	std::wstring result;
	if (dir[dir.length() - 1] != L'\\' && relativePath[0] != L'\\')
		result = dir + std::wstring(L"\\") + relativePath;
	else if (dir[dir.length() - 1] == L'\\' && relativePath[0] == L'\\')
		result = dir + relativePath.substr(1);
	else
		result = dir + relativePath;

	return result;
}

template <typename string_type>
inline string_type append_path_copy(const string_type& parent, const string_type& sub_folder)
{
	bool parent_ends_with_slash = parent.length() > 0 && '\\' == parent[parent.length() - 1];
	bool sub_folder_starts_with_slash = sub_folder.length() > 0 && '\\' == sub_folder[0];

	if (parent_ends_with_slash)
	{
		if (sub_folder_starts_with_slash)
			return parent + sub_folder.substr(1);
		else
			return parent + sub_folder;
	}
	else
	{
		if (sub_folder_starts_with_slash)
			return parent + sub_folder;
		else if (parent.empty())
			return sub_folder;
		else if (sub_folder.empty())
			return parent;
		else
		{
			string_type temp(parent);
			temp.append(1, '\\');
			temp.append(sub_folder);
			return temp;
		}
	}
}


HMODULE LoadSystemLibrary(const std::wstring& dllName)
{
	if (boost::algorithm::istarts_with(dllName, L"API-MS-WIN"))
	{
		//This looks like an API-set dll. Interestingly, if we prefix it
		//with the system32 path, it will report that it loaded correctly,
		//but the loader table will be populated differently than if we just
		//load it by name and GetProcAddress returns only stub addresses,
		//whereas GetProcAddress will return the implementation address if
		//it is loaded by name without the path.
		std::string dllNameA = boost::nowide::narrow(dllName.c_str());
		if (dllNameA.empty()) return NULL;

		for (size_t i = 0; i < sizeof(API_SET_KNOWN_DLLS) / sizeof(char*); ++i)
		{
			if (!_stricmp(dllNameA.c_str(), API_SET_KNOWN_DLLS[i]))
			{
				//The API-set dll names are handled directly by ntdll, currently
				//implemented in ntdll!ApiSetResolveToHost, so there is no
				//possibility of an unsafe load.
				return LoadLibraryA(dllNameA.c_str());
			}
		}
		assert(false && "Unknown API-set dll encountered.");
	}

	wchar_t sysdir[MAX_PATH];
	UINT cnt = GetSystemDirectory(sysdir, MAX_PATH);
	if (cnt == 0 || cnt > MAX_PATH)
	{
		return NULL;
	}
	return LoadLibrary(path_combine(sysdir, dllName).c_str());
}

// Maps file device path to drive letter path.
// e.g. '\Device\HarddiskVolume1\Windows' to 'C:\Windows'
bool device_path_to_dos_path(const std::wstring& device_path, std::wstring& path)
{
	std::vector<wchar_t> drive_letters(1024);
	DWORD size = GetLogicalDriveStrings(msl::utilities::SafeInt<DWORD>(drive_letters.size()), &drive_letters[0]);
	if (size > drive_letters.size())
	{
		drive_letters.resize(size);
		size = GetLogicalDriveStrings(msl::utilities::SafeInt<DWORD>(drive_letters.size()), &drive_letters[0]);
	}

	if (size == 0)
		return false;

	wchar_t drive[3] = L" :";
	const wchar_t* current_drive_letter = &drive_letters[0];
	std::vector<wchar_t> dos_device_buffer(1024);

	while (*current_drive_letter)
	{
		drive[0] = *current_drive_letter;
		if (QueryDosDevice(drive, &dos_device_buffer[0], msl::utilities::SafeInt<DWORD>(dos_device_buffer.size())))
		{
			std::wstring dos_device = &dos_device_buffer[0];
			if (boost::algorithm::istarts_with(device_path, dos_device))
			{
				path = append_path_copy(std::wstring(drive), device_path.substr(dos_device.length()));
				return true;
			}
		}

		while (*(++current_drive_letter));
		++current_drive_letter;
	}

	return false;
}


std::wstring get_module_path_from_address(void* module_addr)
{
	std::wstring module_path;

	size_t size = 0;
	std::vector<wchar_t> buffer(1024);
	size_t max_size = (1024 * 32) + 1;
	while ((size = GetMappedFileName(GetCurrentProcess(), module_addr, &buffer[0], static_cast<DWORD>(buffer.size()))) && size == buffer.size() && size <= max_size)
		buffer.resize(buffer.size() * 2);

	if (!size || size > max_size)
		return std::wstring();

	module_path = &buffer[0];

	// GetMappedFileName() can return paths in the form '/Device/HarddiskVolumeNN/path' where path is in 
	// short path format. Convert the path returned by GetMappedFileName() to a DOS name format.
	std::wstring path;
	if (device_path_to_dos_path(module_path, path))
		module_path = path;

	return module_path;
}
