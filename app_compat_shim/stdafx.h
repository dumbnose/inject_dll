// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files:
#include <windows.h>
#include <psapi.h>
#include <safeint.h>

#include <string>
#include <map>
#include <iostream>
#include <shlwapi.h>
#include <shellapi.h>
#include <shlobj.h>
#include <fstream>
#include <detours\include\detours.h>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/algorithm.hpp>
#include <boost/nowide/convert.hpp>
#include <dumbnose/scope_guard.hpp>
#include <dumbnose\cmdline_options.hpp>
#include <dumbnose\windows_exception.hpp>
#include <dumbnose\event_log.hpp>
