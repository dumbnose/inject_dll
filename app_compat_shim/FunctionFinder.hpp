/*  -------------------------------------------------------  *\
	
	Copyright (c) Microsoft Corporation.  All rights reserved.

    File: FunctionFinder.hpp

    Author: Nick Dalalelis, Joseph Rovine

    Description: A class encapsulating the work to find
    	the pointers to the functions we intend to hook.

\*  -------------------------------------------------------  */


#pragma once

//#include <os.h>
#include "stdafx.h"
#include "helpers.hpp"


using GETPROCADDRESS = decltype(&GetProcAddress);

class FunctionFinder
{
public:
	FunctionFinder();
	~FunctionFinder();

	PVOID	FindFunction(PCSTR module_name, PCSTR function_name,bool hook_first_jump_on_x64_win8 = false);

	struct EnumMatchData
	{
		EnumMatchData(PVOID pointer, PCSTR name)
			: function_pointer(pointer), expected_name(name), match_found(false)
		{}

		PVOID function_pointer;
		PCSTR expected_name;
		bool match_found;
	};

	// support for enumerating imports to find a particular function by name
	static BOOL __stdcall EnumeratorCallbackFunctionByName(PVOID pContext, ULONG nOrdinal,
													const char* pszName, PVOID pCode);

	// the known module list is an optimization for looking up modules
	// loaded into the process.  Since the set of loaded modules changes
	// with time, the list should be built before extensive use of the 
	// FunctionFinder (e.g., while hooking fuctions from DLL main of the 
	// subsystems DLL), and then reset afterwards.  Any later use of the
	// FunctionFinder will execute in a correct but unoptimized manner.
	static void BuildKnownModuleList();
	static void ResetKnownModuleList();
    static GETPROCADDRESS real_GetProcAddress;


private:
	PVOID	ResolveWinStubFunction	(PVOID stub_function,	PCSTR function_name);
	
	PVOID	ResolveImportFunction		(PVOID import_stub, 	PVOID stub_function, PCSTR function_name);

	PVOID	GetDelayLoadedFunction	(PVOID delay_load_stub,		PCSTR function_name);

	PVOID	GetFirstJumpTarget			(PVOID function_pointer);

	PVOID	GetImportStub					(_In_ ULONG_PTR function_pointer, unsigned int cb);

	PVOID	GetImportDescriptorAddress(
#ifdef _WIN64
		_In_bytecount_c_( 55 )		// based on inspection of x64 implemenation of this method
#else
		_In_bytecount_c_( 5 )		// based on inspection of x86 implementation of this method
#endif
		const PVOID tail_merge_function);

	bool	InstructionIsReturn			(PVOID instruction_pointer);
	bool	ValidateForwardedFunction	(PVOID function_pointer, PCSTR expected_name);

	// support for enumerating imports to find out if the forwarded
	// function has the expected name
	static BOOL __stdcall EnumeratorCallback(PVOID pContext, ULONG nOrdinal,
											 		const char* pszName, PVOID pCode);

	PVOID AppvFindFunction(PCSTR module_name, PCSTR function_name);
	HMODULE FindModuleAlreadyLoadedInProcess(PCSTR target_module_name_a);


	static std::map<std::wstring, HMODULE, iless> s_known_modules;
};

// RAII object for building and cleaning the
// known module list in a given scope.
// NOTE: currently only used under the loader lock. If you
// want to use this elsewhere, you'll probably need to protect
// the known modules map with a lock.
struct FunctionFinderKnownModuleHolder
{
	FunctionFinderKnownModuleHolder()
	{
		FunctionFinder::BuildKnownModuleList();
	}

	~FunctionFinderKnownModuleHolder()
	{
		FunctionFinder::ResetKnownModuleList();
	}
};
