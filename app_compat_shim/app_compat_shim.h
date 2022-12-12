// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the APP_COMPAT_SHIM_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// APP_COMPAT_SHIM_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef APP_COMPAT_SHIM_EXPORTS
#define APP_COMPAT_SHIM_API __declspec(dllexport)
#else
#define APP_COMPAT_SHIM_API __declspec(dllimport)
#endif

// This class is exported from the app_compat_shim.dll
class APP_COMPAT_SHIM_API Capp_compat_shim {
public:
	Capp_compat_shim(void);
	// TODO: add your methods here.
};

extern APP_COMPAT_SHIM_API int napp_compat_shim;

APP_COMPAT_SHIM_API int fnapp_compat_shim(void);
