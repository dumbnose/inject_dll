/*  -------------------------------------------------------  *\
	
	Copyright (c) Microsoft Corporation.  All rights reserved.

    File: FunctionFinder.cpp

    Author: Nick Dalalelis, Joseph Rovine

    Description: A class encapsulating the work to find
    	the pointers to the functions we intend to hook.

\*  -------------------------------------------------------  */

#include "stdafx.h"
#include "FunctionFinder.hpp"

#include <windows.h>

#pragma warning(push)
#pragma warning(disable : 4005) // warning C4005: 'FACILITY_VISUALCPP' : macro redefinition.  Universally it's 0x6d (109)
#include <delayimp.h>
#pragma warning(pop)

#include <detours/include/detours.h>
//#include "oacr.h"
//#include "stringutils.hpp"
//#include "swfileutil.h"
//#include "file_utils.h"
//#include "safe_load_library.h"
//#include "mrdata.h"
//
//using namespace AppV::shared::OS;

/*	--------------------------------------------------------------	*\
	convenience definitions of symbolic names for opcodes that
	we may be interested in
\*	--------------------------------------------------------------	*/
const enum OPCODE
{
	JMP_NEAR_ABSOLUTE	= 0xff,
	JMP_NEAR_RELATIVE	= 0xe9,
	JMPF				= 0xea,
	JMP_SHORT			= 0xeb,
	MOV_REG				= 0x8b,
	MOV					= 0xb8,
	PUSH_EBP			= 0x55,
	PUSH_ECX			= 0x51,
	PUSH_EDX			= 0x52,
	PUSH_EAX			= 0x50,
	PUSH_MEM			= 0x68,
	POP_EBP				= 0x5d,
	LEA					= 0x8d,
	RET_DW				= 0xc2,
	RET					= 0xc3,
	RETF_DW				= 0xca,
	RETF				= 0xcb
};

const enum MOD
{
	IMPORT_ALIAS		= 0x25,
	REGISTER_EDI_EDI	= 0xff,
	REGISTER_EBP_ESP	= 0xec,
	REX_W				= 0x48
};

/*	--------------------------------------------------------------	*\
	Finds the address of the real GetProcAddress by enumerating the exports
	of kernel32.dll and matching the name.

	Note: This is necessary to circumvent any app that tries to rewrite our
	import table to replace a function address with the address of a shim. 
	If we were to hook the shim and not the real function, we could miss 
	calls to the real function that we were supposed to wrap and virtualize.
\*	--------------------------------------------------------------	*/
static GETPROCADDRESS InitializeGetProcAddress()
{
	// get the module where GetProcAddress resides
	HMODULE hModule = LoadSystemLibrary(L"kernel32.dll");
	if (hModule == NULL) {
		return NULL;
	}

	// call EnumeratorCallbackFunctionByName until we find GetProcAddress, which will be stored in md.function_pointer
	FunctionFinder::EnumMatchData md(NULL, "GetProcAddress");
	BOOL bEnumOK = DetourEnumerateExports(hModule, &md, 
		reinterpret_cast<PF_DETOUR_ENUMERATE_EXPORT_CALLBACK>(FunctionFinder::EnumeratorCallbackFunctionByName));

    //if (NO_ERROR != MakeMrdataReadOnly(true))
    //{
    //    return NULL;
    //}
    
	if (bEnumOK==TRUE)
		return static_cast<GETPROCADDRESS>(md.function_pointer);
	else
		return NULL;
}


// This indirect call has CFG checks suppressed as GetProcAddress is not
// considered a valid call target.  This is safe because the global that
// stores the function pointer called through is in a read-only section.
//
// Note: use SAL1 to the parameters to keep it exactly same prototype as 
//       GetProcAddress
static DECLSPEC_GUARDNOCF FARPROC CallRealGetProcAddress(
    __in HMODULE hModule, 
    __in LPCSTR lpProcName)
{
    return FunctionFinder::real_GetProcAddress(hModule, lpProcName);
}

// maximum number of instructions to consider when looking for
// the first jump or call instruction
const ULONG kMaxInstructions = 64;

// static WINAPI* to the real GetProcAddress
/*MRDATA_ALLOC */GETPROCADDRESS FunctionFinder::real_GetProcAddress = InitializeGetProcAddress();

std::map<std::wstring, HMODULE, iless> FunctionFinder::s_known_modules;

FunctionFinder::FunctionFinder() {};
FunctionFinder::~FunctionFinder() {};

void FunctionFinder::BuildKnownModuleList()
{
	HMODULE hModule = NULL;
	while (hModule = DetourEnumerateModules(hModule))
	{
		std::wstring module_path = get_module_path_from_address(hModule);
		std::wstring module_name = path_name_portion(module_path);
		if ( !module_name.empty() )
		{
			s_known_modules.insert(std::make_pair(module_name, hModule));
		}
	}
}


void FunctionFinder::ResetKnownModuleList()
{
	s_known_modules.clear();
}


//finds a module already loaded in the process by name
//Unlike LoadLibrary, it will not invoke SxS processesing.
//Even if a module with a given name is already loaded, LoadLibrary
//can cause a different version of it to be loaded due to sxs processing.
//We don't want to be hooking a different version of a dll than the process
//is using
HMODULE FunctionFinder::FindModuleAlreadyLoadedInProcess(PCSTR target_module_name_a)
{
	std::wstring target_module_name = boost::nowide::widen(target_module_name_a);
	
	auto found = s_known_modules.find(target_module_name);
	if ( found != s_known_modules.end() )
		return found->second;

    return GetModuleHandle(target_module_name.c_str());
}

/*	--------------------------------------------------------------	*\
	Given a module name (e.g., "kernel32.dll") and a function
	name (e.g., "CreateProcessW"), this method will return the
	pointer to that function if it can be found by directly calling a
	pointer to the real GetProcAddress which is statically initialized
	earlier in this file. If the module is not already loaded in the current
	process, then only system modules (i.e. from the system32 directory)
	can be found by this function.
\*	--------------------------------------------------------------	*/

PVOID FunctionFinder::AppvFindFunction(PCSTR module_name, PCSTR function_name)
{
	if (real_GetProcAddress == NULL)
		return NULL;

	HMODULE hModule = FindModuleAlreadyLoadedInProcess(module_name);

	if(!hModule)
	{
		// fish out the module handle like DetourFindFunction does, then
		// pass that into real_GProcAddress.
		hModule = LoadSystemLibrary(boost::nowide::widen(module_name));
		if (hModule == NULL)
			return NULL;
	}

	PVOID pbCode = CallRealGetProcAddress(hModule, function_name);

	return pbCode;
}

/*	--------------------------------------------------------------	*\
	Given a module name (e.g., "kernel32.dll") and a function
	name (e.g., "CreateProcessW"), this method will return the
	pointer to that function if it can be found, which is where
	we will apply our hook.
	On Win7, some functions are stubs that forward elsewhere, and
	we would like to apply our hook at the target (e.g., kernel32's
	CreateProcessW function really ends up calling CreateProcessW
	exported by kernelbase.dll).  In this case, we need to do extra
	work to find the actual function.
\*	--------------------------------------------------------------	*/
PVOID FunctionFinder::FindFunction(PCSTR module_name, PCSTR function_name,bool hook_first_jump_on_x64_win8)
{
	// Find the function using the real GetProcAddress that we've statically initialized
	PVOID function_pointer = AppvFindFunction(module_name, function_name);

	if (function_pointer == NULL) // ask Detours to find the function
		function_pointer = ::DetourFindFunction(module_name, function_name);

	if ( !function_pointer )
	{
		// TODO: Convert to ETW logging
		/*DoTraceLevelMessage(TRACE_LEVEL_ERROR, HOOK_INIT,
			"FunctionFinder::FindFunction: DetourFindFunction failed for function %s, module %s",
			module_name, function_name);*/
		return NULL;
	}

    // if we are on x64 win8, AddVectoredException handler is implemented as a call through a function pointer
    // this generates a function that is too short for detours to hook.
    // for this function, and only this function, we will look at the original,
    // and if we see a jmp target, we will return the jump target and hook that instead, 
    // since that should be long enough to hook.
#ifdef _WIN64
    if (true == hook_first_jump_on_x64_win8) 
    {
        return GetFirstJumpTarget(function_pointer);
    }
#endif

	PVOID forwarded_function = ResolveWinStubFunction(function_pointer, function_name);
	if ( forwarded_function != NULL )
		return forwarded_function;

	// Note: if we didn't find a forwarded function, that's ok,
	// it just means that there wasn't one, and we return the
	// original function pointer given to us by Detours

	return function_pointer;
}


/***********************************************************
 One of the MinWin goals is to isolate core Win32 APIs.  This 
 goal is achieved is by refactoring functions out of various 
 dlls, like kernel32.dll.  

 In order to provide backwards compatibility, Win7 added stub 
 functions that simply forwarded the Win32 API call to the real function.
 The real functions are just imports.

 Example:

 VOID SleepStub (__in DWORD dwMilliseconds)
 {
	 Sleep( dwMilliseconds );
 }

 The assembly for SleepStub looks like the following
	768b5146 8bff			 mov	 edi,edi
	768b5148 55 			 push	 ebp
	768b5149 8bec			 mov	 ebp,esp
	768b514b 5d 			 pop	 ebp
	768b514c e9bbcefaff 	 jmp	 kernel32!Sleep (7686200c)

 The assembly at kernel32!Sleep (7686200c) looks like the following
	7686200c ff25281b8676	 jmp	 dword ptr [kernel32!_imp__Sleep (76861b28)]

 The purpose of the ResolveWin7StubFunction is to determine if
 the return value from a GetProcAddress or DetourFindFunction call is in 
 fact a stub function that forwards the call to an imported function.  If 
 that is the case, the ResolveWin7StubFunction will return the address 
 of the forwarded function.
**************************************************************/

PVOID FunctionFinder::ResolveWinStubFunction(PVOID stub_function, PCSTR function_name)
{
	// the stub either jumps or calls to the wrapped function
	PVOID wrapped_function = GetFirstJumpTarget(stub_function);
	if ( wrapped_function == DETOUR_INSTRUCTION_TARGET_NONE )
		return NULL;

	// the wrapped function has an immediate jump to the import
	// stub function (_imp_XXX)
	PVOID import_stub = GetImportStub(reinterpret_cast<ULONG_PTR>(wrapped_function), sizeof(wrapped_function));
	if ( import_stub == NULL )
		return NULL;
	
	return ResolveImportFunction(import_stub, stub_function, function_name);
}


/***********************************************************
 Validates and resolves _imp__* imports for Win7+ stubs.
**************************************************************/
PVOID FunctionFinder::ResolveImportFunction(PVOID import_stub, PVOID stub_function, PCSTR function_name)
{
	PVOID imported_function = NULL;
	
	// If the target is in the import table, the return that function
	if ( ::DetourIsFunctionImported(static_cast<PBYTE>(stub_function), static_cast<PBYTE>(import_stub)) ) 
	{
		imported_function = *static_cast<PBYTE*>(import_stub);
	}
	else
	{
		// The function may be delay loaded.  It is not in the import table,
		// but the import stub points at a delay load stub that loads a
		// dll and calls the function
		PVOID delay_load_stub = *static_cast<PBYTE*>(import_stub);
		imported_function = GetDelayLoadedFunction(delay_load_stub, function_name);
	}

	// if we found an imported function, make sure it is correct by
	// matching its exported name with the original function's name
	if ( imported_function && ValidateForwardedFunction(imported_function, function_name) )
	{
		return imported_function;
	}

	return NULL;
}


/*********************************************************************
Function:		GetFirstJumpTarget 

Scan through the opcodes one by one looking for a jump or call
instruction, and if found, return the target (that the jump or 
call points to).  Detours code is used to step through the
instructions and return the target.

ReturnValues: if a jump or call is found, return the target,
				otherwise, returns DETOUR_INSTRUCTION_TARGET_NONE

Win8 also has stub functions that forward to imports. Unlike on Win7, the stubs
jmp directly to the imports instead of an intermediate.
 
  For example, advapi32!OpenSCManager on Win7 is implemented like this:
 	advapi32!OpenSCManagerWStub:
 	74e9d1f5 8bff            mov     edi,edi
 	74e9d1f7 55              push    ebp
 	74e9d1f8 8bec            mov     ebp,esp
 	74e9d1fa 5d              pop     ebp
 	74e9d1fb eb05            jmp     advapi32!OpenSCManagerW (74e9d202)
 
 	advapi32!OpenSCManagerW:
 	74e9d202 ff252814e974    jmp     dword ptr [advapi32!_imp__OpenSCManagerW (74e91428)]
 
  The Win8 implementation jumps straight to the import:
    advapi32!OpenSCManagerWStub:
 	755690d6 8bff            mov     edi,edi
 	755690d8 55              push    ebp
 	755690d9 5d              pop     ebp
 	755690da ff25d8145675    jmp     dword ptr [advapi32!_imp__OpenSCManagerW (755614d8)]

We verify for Win8 if the jump target is an import table. If it is then we pass
the current instruction because GetImportStub(called after GetFirstJumpTarget) will return the import table for us.
ResolveImportFunction will then pass the targeted import function.
***********************************************************************/


PVOID FunctionFinder::GetFirstJumpTarget(PVOID function_pointer)
{
	PVOID curr_instruction = function_pointer;
	PVOID jump_target = DETOUR_INSTRUCTION_TARGET_NONE;

	__try
	{
		for ( ULONG instr_count=0; instr_count < kMaxInstructions; instr_count++ )
		{
			// if we find a return, there's no need to look further
			if ( curr_instruction == NULL || InstructionIsReturn(curr_instruction) )
			{
				break;
			}

			// DetourCopyInstruction returns a pointer to the next instruction
			// after the one passed in, and if curr_instruction is a jmp or call,
			// returns the target of the jmp or call in jump_target
			PVOID next_instruction = DetourCopyInstruction(NULL, NULL, curr_instruction, &jump_target, NULL);

			if ( jump_target != DETOUR_INSTRUCTION_TARGET_NONE )
			{
				if ( jump_target == DETOUR_INSTRUCTION_TARGET_DYNAMIC )
				{
					// This case is where the target is calculated at
					// runtime, for example, relative to a register.
					// We can't know from examining the disassembly
					// what the actual target will be.
					// We don't care about this case, since we are
					// looking for jumps or calls that are known
					// at compile time or have been fixed up by the
					// loader, so the address is present.  It is 
					// safe to bail out at this point if we find
					// a dynamic jump target.
					jump_target = DETOUR_INSTRUCTION_TARGET_NONE;
				}

				//Win8 specific handling for cases where there are not intermediate jmps.
				//Most of the code that calls this function will call GetImportStub on the result from
				//this function. That second call to GetImportStub will fail if there is only one level of stubs.
				//So if we detect a stub here, we return the current instruction, essentially
				//doing nothing and allowing the later call to GetImportStub to actually resolve the jmp
				if (DETOUR_INSTRUCTION_TARGET_NONE != jump_target)
				{
					PVOID import_stub = GetImportStub(reinterpret_cast<ULONG_PTR>(curr_instruction), sizeof(curr_instruction));
					if (DETOUR_INSTRUCTION_TARGET_NONE != import_stub)
					{
						jump_target = curr_instruction;
					}
				}
				break;
			}

			// advance to the next instruction
			curr_instruction = next_instruction;
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		// a harmless access violation occurs when the Detours code tries
		// to dereference the illegal instruction used as a jump target
		// that triggers the Wow64 thunk in ntdll32.dll.  We just catch
		// it and go on hooking the original function correctly
		return false;
	}

	return jump_target;
}


/*********************************************************************
Function:		InstructionIsReturn 

Test whether instruction_pointer points to a return opcode that
	exits the current function

ReturnValues: true if the instruction pointed to is a return

***********************************************************************/
bool FunctionFinder::InstructionIsReturn(PVOID instruction_pointer)
{
	const BYTE opcode = static_cast<PBYTE>(instruction_pointer)[0];

	if ( opcode == RET ||
			opcode == RETF ||
			opcode == RET_DW ||
			opcode == RETF_DW )
	{
		return true;
	}

	return false;
}


/*********************************************************************
Function:		GetImportStub 

Test whether the provided pointer is a jump or a call instruction and if so
returns the target address.

Candidates are of this format:
	0x48 0xFF 0x25 -> REX.W JMP
	As seen in ADVAPI32!OpenSCManagerWStub on Win8 x64.

	0xFF 0x25 -> JMP import alias
	As seen in ADVAPI32!StartServiceWStub.

ReturnValues: Target address if points to JMP;  NULL otherwise.

***********************************************************************/
PVOID FunctionFinder::GetImportStub(_In_ ULONG_PTR function_pointer, unsigned int cb)
{
	PVOID pbTarget = NULL;
	PBYTE pCode = reinterpret_cast<PBYTE>(function_pointer);

	if (NULL == pCode || cb < 4)
		return NULL;
	
	char addressOffset = 0;

	// (JMP) address
	if (JMP_NEAR_ABSOLUTE == pCode[0] && IMPORT_ALIAS == pCode[1])

	{
		addressOffset = 2;
	}
	// REX.W (JMP) address
	else if (REX_W == pCode[0] && JMP_NEAR_ABSOLUTE == pCode[1] && IMPORT_ALIAS == pCode[2])

	{
		addressOffset = 3;
	}
	else
	{
		// Not a JMP of interest.
		return DETOUR_INSTRUCTION_TARGET_NONE;
	}

	// Now to figure out where it is.
#ifdef _WIN64
	pbTarget = &pCode[addressOffset] + *(INT32 *)&pCode[addressOffset] + 4;
#else
	pbTarget = *(PBYTE *)&pCode[addressOffset];
#endif
	
	return pbTarget;
}

/*********************************************************************
Function:		GetImportDescriptorAddress 

If pCode points to the _tailMerge_XXX function, then we know that it
sets up the stack and eventually calls advapi32!__delayLoadHelper2.
We exploit our knowledge of the parameters to extract the pointer to
the import descriptor from the parameters as they are pushed on the stack.

ReturnValues: if expected push instructions are found, returns a pointer
 				to the import descriptor, otherwise, returns NULL

***********************************************************************/
PVOID FunctionFinder::GetImportDescriptorAddress(const PVOID tail_merge_function)
{
	PVOID pbDescriptor = NULL;
	PBYTE pCode = static_cast<PBYTE>(tail_merge_function);
	if (!pCode)
		return NULL;

	// Note: If you update the following code to read different offsets from pCode then
	//	     update the _In_bytecount_c_ SAL annotations in header as appropriate
#ifdef _WIN64
	if (REX_W == pCode[51] &&
			LEA == pCode[52])	// 64bit LEA
	{
		// pCode[53] specifies the register, usually 0x0D for rcx.
		// The address of the descriptor to be loaded is a
		// 32bit offset from the next instruction
		pbDescriptor = &(pCode[54]) + *(INT32 *)&pCode[54] + 4;
	}
#else
	if (PUSH_ECX == pCode[0] && PUSH_EDX == pCode[1] &&
			PUSH_EAX == pCode[2] && PUSH_MEM == pCode[3])
	{
		// absolute address of descriptor to be pushed
		// on the stack
		pbDescriptor = *(PBYTE *)&pCode[4];
	}
#endif
	
	return pbDescriptor;
}


/*********************************************************************
Function:		GetDelayLoadedFunction 

In a delay loaded module, the address of the function does not appear 
in the Import Address Table.

An example of the jump statement to the location of the delay loaded
module for a function is as follows.

	ADVAPI32!OpenSCManagerW:
	7648e8c1 ff25f4304f76	 jmp	 dword ptr [ADVAPI32!_imp__OpenSCManagerW (764f30f4)]

Under a debugger, we get the memory at 764f30f4 to equal 7648e82f.	Below is the 
disassembly at 7648e82f. (delay load stub)

	ADVAPI32!_imp_load_OpenSCManagerW:
	7648e82f b8f4304f76 	 mov	 eax,offset ADVAPI32!_imp__OpenSCManagerW (764f30f4)
	7648e834 e960620000 	 jmp	 ADVAPI32!_tailMerge_Microsoft_Windows_System_Services_L1_1_0_dll (76494a99)

If we follow the jump statement to 76494a99, we get the following.

	ADVAPI32!_tailMerge_Microsoft_Windows_System_Services_L1_1_0_dll:
	76494a99 51 			 push	 ecx
	76494a9a 52 			 push	 edx
	76494a9b 50 			 push	 eax
	76494a9c 68d0e54e76 	 push	 offset ADVAPI32!_DELAY_IMPORT_DESCRIPTOR_Microsoft_Windows_System_Services_L1_1_0_dll (764ee5d0)
	76494aa1 e868830000 	 call	 ADVAPI32!__delayLoadHelper2 (7649ce0e)

As you can see, the above will eventually call the __delayLoadHelper2 function.


Return Values:	If pszFunction is found within the delay loaded module, then the
				address of the function within the delay loaded module is returned.

				If the function is not found in the delay loaded module,
				then NULL is returned.
***********************************************************************/
PVOID FunctionFinder::GetDelayLoadedFunction(PVOID delay_load_stub, PCSTR function_name)
{
	__try
	{
		// get the module handle so we can find the allocation base
		// for the relative offset to the imported dll name
		HMODULE target_module = DetourGetContainingModule(delay_load_stub);
		if ( target_module == NULL )
			return NULL;
		
		const unsigned char *module_base = reinterpret_cast<const unsigned char *>(target_module);		

		// the first jump is to the _tailMerge_XXX function
		PVOID tail_merge_function = GetFirstJumpTarget(delay_load_stub);

		if ( tail_merge_function != DETOUR_INSTRUCTION_TARGET_NONE )
		{
			// extract the import descriptor from the _tailMerge_XXX code
			PVOID descriptor_address = GetImportDescriptorAddress(tail_merge_function);
			if ( descriptor_address != NULL )
			{
				// extract the dll name from the import descriptor
				PCImgDelayDescr delay_descriptor = static_cast<PCImgDelayDescr>(descriptor_address);
				LPCSTR dll_name = reinterpret_cast<LPCSTR>(module_base + delay_descriptor->rvaDLLName);

				// ask detours to find the function in the given dll
				PVOID imported_function = ::DetourFindFunction(dll_name, function_name);

				if ( imported_function == NULL )
				{
					// TODO: Convert to ETW logging
					/*DoTraceLevelMessage(TRACE_LEVEL_ERROR, HOOK_INIT,
						"FunctionFinder::GetDelayLoadedFunction: DetourFindFunction failed for function %s module %s",
						function_name, dll_name);*/
				}

				return imported_function;
			}
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		// TODO: Convert to ETW logging
		/*DoTraceLevelMessage(TRACE_LEVEL_ERROR, HOOK_INIT,
			"FunctionFinder::GetDelayLoadedFunction: Exception caught looking up function %s.",
			function_name);*/
	}

	return NULL;
}


/*********************************************************************
Function:		ValidateForwardedFunction 

Given a pointer to the target function and the name of the
	method being forwarded, determine if the pointer points to
	a method having the expected name.

ReturnValues: if function_pointer points to a method with the expected name,
	return true, otherwise false.

***********************************************************************/
bool FunctionFinder::ValidateForwardedFunction(PVOID function_pointer, PCSTR expected_name)
{
	// get the module where the function resides
	HMODULE target_module = DetourGetContainingModule(function_pointer);
	if ( target_module != NULL )
	{
		// enumerate the exports of the module with our callback to
		// determine if the exported name is what we expect
		EnumMatchData md(function_pointer, expected_name);

		BOOL bEnumOK = DetourEnumerateExports(target_module, &md, reinterpret_cast<PF_DETOUR_ENUMERATE_EXPORT_CALLBACK>(EnumeratorCallback));
		if ( !bEnumOK )
		{
			// this only fails if the module is not valid, so it's
			// very unlikely to happen
			// TODO: Convert to ETW logging
			/*DoTraceLevelMessage(TRACE_LEVEL_INFORMATION, HOOK_INIT,
				"FunctionFinder::ValidateForwardedFunction: Failed to enumerate exports for module %p while validating %s",
				target_module, expected_name);*/
		}

		return ((bEnumOK==TRUE) && md.match_found);
	}
	else
	{
		// the module was not loaded -- how is this possible
		// if we retrieved the function pointer?
		// TODO: Convert to ETW logging
		/*DoTraceLevelMessage(TRACE_LEVEL_ERROR, HOOK_INIT,
			"FunctionFinder::ValidateForwardedFunction: Failed to find containing module for forwarded %s.", expected_name);*/
	}

	return false;
}


/*********************************************************************
Function:		EnumeratorCallback 

A callback used with the DetourEnumerateExports() function to find
	out if the function exported from the given module has the
	name we expect it to have.  This is called once for each
	entry in the module's exports table.

ReturnValues: if a match is found, return FALSE to end the enumeration,
	otherwise return TRUE to continue

***********************************************************************/
BOOL __stdcall FunctionFinder::EnumeratorCallback(PVOID pContext,
												 ULONG nOrdinal,
												 const char* pszName,
												 PVOID pCode)
{
	EnumMatchData* md = (EnumMatchData*)pContext;
	// if we find the function pointer we're looking
	// for, make sure the name is what we expect
	if ( (pCode == md->function_pointer) &&
			pszName &&
			(strcmp(pszName, md->expected_name) == 0) )
	{
		md->match_found = true;
		return FALSE;
	}

	return TRUE;
}


/*********************************************************************
Function:		EnumeratorCallbackFunctionByName 

A callback used with the DetourEnumerateExports() function to find
	a specific function in the given module. This is called once for each
	entry in the module's exports table.

ReturnValues: if a match is found, return FALSE to end the enumeration,
	otherwise return TRUE to continue

***********************************************************************/
BOOL __stdcall FunctionFinder::EnumeratorCallbackFunctionByName(PVOID pContext,
												 ULONG nOrdinal,
												 const char* pszName,
												 PVOID pCode)
{
	EnumMatchData* md = (EnumMatchData*)pContext;
	// test if the function we found matches the name we expect
	if (pszName && strcmp(pszName, md->expected_name) == 0)
	{
		md->match_found = true;
		md->function_pointer = pCode;
		return FALSE;
	}

	return TRUE;
}
