<#
.Synopsis
   MCTBuilder injects drivers into boot.wim (WinPE and Windows Setup) and install.wim (Windows 11 Pro) of a USB-drive created with the Media Creation Tool.

.DESCRIPTION
    Instructions:
    1. Create a USB-drive using the Media Creation Tool
    2. Construct the CSV-file with driver information
    3. Generate a Windows Answer File (autounattend.xml) and copy the contents in variable $AnswerFile (optional).
    4. Run Invoke-MCTBuilder.ps1 with administrative permissions

    Example CSV-file (values must be seperated by semicolon):

    Manufacturer;    Model;              URL;                                                                                                                              Drivers
    Microsoft;       Surface Laptop 5;   https://download.microsoft.com/download/d/2/6/d26c7d69-ec2f-4dd6-95ab-7e1d2b5ee7ae/SurfaceLaptop5_Win11_22621_22.102.17243.0.msi; adlserial,alderlakepchpsystem, gna, heci, intelprecisetouch, msu53cx22x64sta, msump64x64sta, surfaceacpiplatformextensiondriver, surfacebattery, surfacebutton, surfacedockintegration, surfaceethernetadapter, surfacehidminidriver, surfacehotplug, surfaceintegration, surfaceserialhubdriver, surfacetimealarmacpifilter, tbtslimhostcontroller, wifi08
    Dell;            Generic;            https://downloads.dell.com/FOLDER09651035M/1/WinPE11.0-Drivers-A00-5DWN3.CAB;
    HP;              Generic;            https://ftp.hp.com/pub/softpaq/sp145001-145500/sp145240.exe;
    Lenovo;          ThinkPad E14 Gen 5; https://download.lenovo.com/pccbbs/mobiles/tp_e14_r14-g-5_e16-g-1_mt21jk-21jl_21jm_21jn-21jq_winpe_202304.exe;

    The drivers are downloaded, extracted and selected based on the content of the CSV-file.
    The Drivers-column contains drivers that will be injected. All others will be removed. All drivers will be kept if no drivers are specified in the Drivers-column.
    
    Vendors of supported driver packages: Microsoft, HP, Dell and Lenovo

.PARAMETER CSVFile
    Specify the path to the CSV-file that contains the driver information.

.PARAMETER LogDir
    Specify the folder to the log directory.

.PARAMETER WorkingDir
    Specify the folder to the working directory. MCTBuilder will use this folder to download and extract drivers, mounting and dismounting the WIM-files.

.PARAMETER AnswerFile
    Specify whether the Windows Answer File (autounattend.xml) must be copied to the root of the USB-drive.

.EXAMPLE
    Invoke-MCTBuilder.ps1 -CSVFile 'C:\MCTBrun\Drivers.csv' -LogDir 'C:\MCTBrun\' -WorkingDir 'C:\MCTBrun\' -AnswerFile:$true" 

.NOTES
    Version                 : 1.0.1
    FileName                : Invoke-MCTBuilder.ps1
    Author                  : Rory Vossepoel
    Contact                 : @roryvossepoel
    Created                 : 23-05-2023
    Modified                : 23-05-2023
    Contributors            : Please reach out! :)

    Version History
    1.0.1 (23-05-2023)      : Log mounted WIM-information after conversion from install.esd to install.wim.
                              Copy log-file to the root of the USB-Drive after completion.
                              Semantic improvements.
    1.0.0 (23-05-2023)      : Initial version

.CREDITS
    Function Write-LogEntry : MSEndpointMgr - https://msendpointmgr.com

.LINKS
    Media Creation Tool for Windows 11 : https://go.microsoft.com/fwlink/?linkid=2156295
    CMtrace                            : https://learn.microsoft.com/en-us/mem/configmgr/core/support/cmtrace
    HP Drivers for WinPE               : https://ftp.hp.com/pub/caps-softpaq/cmit/softpaq/WinPE10.html
    Dell Drivers for WinPE             : https://www.dell.com/support/kbdoc/nl-nl/000108642/winpe-10-driverpakket
    Microsoft Drivers for WinPE        : https://learn.microsoft.com/en-us/surface/deploy-windows-10-to-surface-devices-with-mdt
    Lenovo Drivers for WinPE           : https://support.lenovo.com/nl/nl/solutions/ht074984-microsoft-system-center-configuration-manager-sccm-and-microsoft-deployment-toolkit-mdt-package-index
    Windows Anser File Generator 1     : https://www.windowsafg.com
    Windows Anser File Generator 2     : https://schneegans.de/windows/unattend-generator
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory = $True, HelpMessage = 'Enter the path to the CSV-file.')]    
    [string]$CSVFile,
    [Parameter(Mandatory = $True, HelpMessage = 'Enter the path to the Log-directory.')]    
    [string]$LogDir,
    [Parameter(Mandatory = $True, HelpMessage = 'Enter the path to the Working-directory.')]    
    [string]$WorkingDir,
    [Parameter(Mandatory = $True, HelpMessage = 'Enable or disable adding the Windows Answer File (autounattend.xml) to the root of the USB-drive.')]    
    [boolean]$AnswerFile
)

# Write data to a CMTrace compatible log file. (Credit to MSEndpointMgr - https://msendpointmgr.com)
Function Write-LogEntry
{
	param(
		[parameter(Mandatory = $true, HelpMessage = "Value added to the log file.")]
		[ValidateNotNullOrEmpty()]
		[string]$Value,
		[parameter(Mandatory = $true, HelpMessage = "Severity for the log entry. 1 for Informational, 2 for Warning and 3 for Error.")]
		[ValidateNotNullOrEmpty()]
		[ValidateSet("1", "2", "3")]
		[string]$Severity,
		[parameter(Mandatory = $false, HelpMessage = "Name of the log file that the entry will written to.")]
		[ValidateNotNullOrEmpty()]
		[string]$FileName = "MCTBuilder.log"
	)

    # Determine log file location
    $global:LogFilePath = Join-Path -Path $LogDir -ChildPath $FileName

    # Construct time stamp for log entry
    if(-not(Test-Path -Path 'variable:global:TimezoneBias'))
    {
        [string]$global:TimezoneBias = [System.TimeZoneInfo]::Local.GetUtcOffset((Get-Date)).TotalMinutes
        if($TimezoneBias -match "^-")
        {
            $TimezoneBias = $TimezoneBias.Replace('-', '+')
        }
        else
        {
            $TimezoneBias = '-' + $TimezoneBias
        }
    }
    $Time = -join @((Get-Date -Format "HH:mm:ss.fff"), $TimezoneBias)
		
    # Construct date for log entry
    $Date = (Get-Date -Format "MM-dd-yyyy")
		
    # Construct context for log entry
    $Context = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
		
    # Construct final log entry
    $LogText = "<![LOG[$($Value)]LOG]!><time=""$($Time)"" date=""$($Date)"" component=""MCTBuilder"" context=""$($Context)"" type=""$($Severity)"" thread=""$($PID)"" file="""">"
		
    # Add value to log file
    try
    {
        Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $LogFilePath -ErrorAction Stop
    }
    catch [System.Exception]
    {
        Write-Warning -Message "Unable to append log entry to $FileName file. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
    }
}

function Test-Administrator  
{  
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    $isadmin = (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

    if(-not($isadmin)) {
        $LogMessage = "MCTBuilder must run with administrative permissions."
        Write-LogEntry -Value $LogMessage -Severity 3
        throw $LogMessage
    }
    else {
        $LogMessage = "MCTBuilder is running with administrative permissions."
        Write-LogEntry -Value $LogMessage -Severity 1
    }
}

function Create-WorkingFolder {

    if(!(Test-Path -PathType Container $LogDir))
    {
        New-Item -Path $LogDir -ItemType "Directory" -Force | Out-Null
    }

    if(!(Test-Path -PathType Container $WorkingDir))
    {
        New-Item -Path $WorkingDir -ItemType "Directory" -Force | Out-Null
    }

    # Create mount folder
    New-Item -Path "$WorkingDir\Mount" -ItemType Directory -Force -ErrorAction SilentlyContinue -Verbose

    # Create wim folder
    New-Item -Path "$WorkingDir\Wim" -ItemType Directory -Force -ErrorAction SilentlyContinue -Verbose
}

function Invoke-MCTBuilder {
    
    ######################################################
    ##              Import CSV-file content.            ##
    ######################################################

    try {
        Write-LogEntry -Value "Importing the CSV-file." -Severity 1
        $Drivers = Import-Csv $CSVFile -Delimiter ";" -Verbose -ErrorAction Stop
        $LogMessage = "Successfully imported the CSV-file."
        Write-LogEntry -Value $LogMessage -Severity 1
    }
    catch  [System.Management.Automation.RuntimeException] {
        $LogMessage = "Unable to open CSV-file with driver information: $_"
        Write-LogEntry -Value $LogMessage -Severity 3
        throw $LogMessage
    }

    ######################################################
    ##        Verify CSV-file content validity.         ##
    ######################################################

    Write-LogEntry -Value "Checking if the CSV-file contains any data." -Severity 1

    # Check if CSV-file contains more than 1 line
    if (($Drivers | Measure-Object | Select-Object Count).Count -ge 1) {

        # Check if the rows in the CSV-file contains required data. The Drivers-column is not required.
        foreach ($item in $Drivers) {

            foreach ($property in ($item.psobject.Properties | Where-Object { $_.Name -ne "Drivers" })) {

                if ([string]::IsNullOrEmpty($property.Value)) {
                    $validrows = $false
                }
                else {
                    $validrows = $true
                } 

                if($validrows -eq $false) {
                    break
                }
            }
        }

        if($validrows) {
                  
            # Check if the CSV-file contains the required headers.
            [string]$ExpectedHeaders = "Drivers","Manufacturer","Model","URL"
            [string]$ActualHeaders = ($Drivers | Get-Member -MemberType NoteProperty).Name

            if ($ExpectedHeaders -eq $ActualHeaders) {

                foreach ($Item in $Drivers.manufacturer) {

                    if($Item -in "Microsoft", "Dell", "HP", "Lenovo") {
                        $ValidManufacturers = $true
                    }
                    else {
                        $ValidManufacturers = $false
                    }

                    if($ValidManufacturers -eq $false) {
                        break
                    }
                }

                if($ValidManufacturers) {
        
                    Write-LogEntry -Value "The manufacturers in the CSV-file are supported." -Severity 1

                    # Check if the CSV-file contains valid URL's.
                    foreach ($Item in $Drivers) {

                        $url = $Item.URL
                        if($url -match "^https?://") {

                            $request = [System.Net.WebRequest]::Create($url)
                            $request.Method = "HEAD"                       

                            try {
                                $response = $request.GetResponse()

                                if ($response.StatusCode -ne "OK") {
                                    $LogMessage = "The CSV-file contains an inaccessible URL: " + $($Item).Manufacturer + " " + $($Item).Model + ":" + $($Item).URL
                                    Write-LogEntry -Value $LogMessage -Severity 3
                                    throw $LogMessage
                                }
                                $response.Close()
                            }
                            catch {
                                $LogMessage = "Error checking URL for " + $($Item).Manufacturer + " " + $($Item).Model + ": " + $($Item).URL
                                Write-LogEntry -Value $LogMessage -Severity 3
                                throw $LogMessage
                            }
                        }
                        else  {
                            $LogMessage = "The CSV-file contains an invalid URL: " + $($Item).Manufacturer + " " + $($Item).Model + ":" + $($Item).URL
                            Write-LogEntry -Value $LogMessage -Severity 3
                            throw $LogMessage
                        }
                    }
                    $LogMessage = "The URL's in the CSV-file are accessible."
                    Write-LogEntry -Value $LogMessage -Severity 1
                }
                else {
                    $LogMessage = "The CSV-file contains invalid manufacturers."
                    Write-LogEntry -Value $LogMessage -Severity 3
                    throw $LogMessage
                }
            }
            else {
                $LogMessage = "The CSV-file contains invalid headers."
                Write-LogEntry -Value $LogMessage -Severity 3
                throw $LogMessage
            }
        }
        else {
            $LogMessage = "The CSV-file contains empty required rows."
            Write-LogEntry -Value $LogMessage -Severity 3
            throw $LogMessage
        }
    }
    else {
        $LogMessage = "The CSV-file does not contain enough content."
        Write-LogEntry -Value $LogMessage -Severity 3
        throw $LogMessage
    }

    Write-LogEntry -Value "CSV-file successfully verified" -Severity 1

    ######################################################
    ##  Download, extract and remove non-WinPE drivers  ##
    ######################################################
    
    foreach ($Driver in $Drivers)
    {
        ######################################################
        ##                Download drivers                  ##
        ######################################################

        # Create driver folder
        New-Item -Path "$WorkingDir\Drivers\$($Driver.Manufacturer)\$($Driver.Model)" -ItemType Directory -Force -Verbose

        Write-LogEntry -Value ("Downloading driver for " + $($Driver).Manufacturer + " " + $($Driver).Model + ": " + $($Driver).URL) -Severity 1
        
        try {
            Invoke-WebRequest -Uri $($Driver.URL) -OutFile "$WorkingDir\Drivers\$($Driver.Manufacturer)\$($Driver.Model)\$((($Driver.URL).Split("/"))[-1])" -Verbose
            Write-LogEntry -Value ("Successfully downloaded and saved driver for " + $($Driver).Manufacturer + " " + $($Driver).Model + ":" + $($Driver).URL) -Severity 1
        }
        catch [System.Net.WebException] {
            $LogMessage = "Unable to download driver for " + $($Driver).Manufacturer + " " + $($Driver).Model + ": " + $($Driver).URL
            Write-LogEntry -Value $LogMessage -Severity 3
            throw $LogMessage
        }
        catch [System.IO.IOException] {
            $LogMessage = "Unable to save driver for " + $($Driver).Manufacturer + " " + $($Driver).Model + ": " + $($Driver).URL
            Write-LogEntry -Value $LogMessage -Severity 3
            throw $LogMessage
        }
        catch {
            $LogMessage = "Unspecified error"
            Write-LogEntry -Value $LogMessage -Severity 3
            throw $LogMessage
        }

        ######################################################
        ##    Extracting and removing unwanted drivers.     ##
        ######################################################

        Switch ($Driver.Manufacturer) {
                    
            # Extract Microsoft drivers
            "Microsoft" {
                Write-LogEntry -Value ("Extracting driver for: " + $($Driver).Manufacturer + " " + $($Driver).Model) -Severity 1
                Start-Process msiexec.exe -ArgumentList "/a ""$WorkingDir\Drivers\$($Driver.Manufacturer)\$($Driver.Model)\$((($Driver.URL).Split("/"))[-1])"" targetdir=""$WorkingDir\Drivers\$($Driver.Manufacturer)\$($Driver.Model)\Extracted"" /qn" -Wait -Verbose

                Write-LogEntry -Value ("Removing unwanted drivers for: " + $($Driver).Manufacturer + " " + $($Driver).Model) -Severity 1

                # Remove non-WinPE drivers based on provided list: https://learn.microsoft.com/en-us/surface/enable-surface-keyboard-for-windows-pe-deployment#import-drivers-for-surface-devices
                foreach ($WinPEDriver in (Get-ChildItem "$WorkingDir\Drivers\$($Driver.Manufacturer)\$($Driver.Model)\Extracted\SurfaceUpdate\" -Directory)) {

                    if($WinPEDriver.name -notin ($Driver.Drivers).split(",").Trim()) {
                        Write-LogEntry -Value ("Removing unwanted drivers for " + $($Driver).Manufacturer + " " + $($Driver).Model + ": " + $($WinPEDriver).name) -Severity 1
                        Remove-Item -Path "$WorkingDir\Drivers\$($Driver.Manufacturer)\$($Driver.Model)\Extracted\SurfaceUpdate\$($WinPEDriver.name)\" -Recurse -Force
                    }
                }
                Write-LogEntry -Value ("Done extracting drivers for: " + $($Driver).Manufacturer + " " + $($Driver).Model) -Severity 1
            }

            # Extract HP Drivers
            "HP" {
                Write-LogEntry -Value ("Extracting drivers for: " + $($Driver).Manufacturer + " " + $($Driver).Model) -Severity 1
                Start-Process "$WorkingDir\Drivers\$($Driver.Manufacturer)\$($Driver.Model)\$((($Driver.URL).Split("/"))[-1])" -ArgumentList "/s /e /f ""$WorkingDir\Drivers\$($Driver.Manufacturer)\$($Driver.Model)\Extracted""" -Wait -Verbose
                Write-LogEntry -Value ("Done extracting drivers for: " + $($Driver).Manufacturer + " " + $($Driver).Model) -Severity 1
            }

            # Extract Lenovo Drivers
            "Lenovo" {
                Write-LogEntry -Value ("Extracting drivers for: " + $($Driver).Manufacturer + " " + $($Driver).Model) -Severity 1
                Start-Process "$WorkingDir\Drivers\$($Driver.Manufacturer)\$($Driver.Model)\$((($Driver.URL).Split("/"))[-1])" -ArgumentList "/sp- /verysilent /dir=""$WorkingDir\Drivers\$($Driver.Manufacturer)\$($Driver.Model)""" -Wait -Verbose
                Write-LogEntry -Value ("Done extracting drivers for: " + $($Driver).Manufacturer + " " + $($Driver).Model) -Severity 1
             }

            # Extract Dell Drivers
            "Dell" {
                Write-LogEntry -Value ("Extracting drivers for: " + $($Driver).Manufacturer + " " + $($Driver).Model) -Severity 1
                Start-Process "C:\Windows\System32\expand.exe" -ArgumentList "-F:*.* ""$WorkingDir\Drivers\$($Driver.Manufacturer)\$($Driver.Model)\$((($Driver.URL).Split("/"))[-1])"" ""$WorkingDir\Drivers\$($Driver.Manufacturer)\$($Driver.Model)""" -NoNewWindow -Verbose 
                Write-LogEntry -Value ("Done extracting drivers for: " + $($Driver).Manufacturer + " " + $($Driver).Model) -Severity 1
            }
        }
    }

    ######################################################
    ##               Getting USB-drive                  ##
    ######################################################

    # Get boot.wim from connected USB Drive
    $USBDrive = Get-CimInstance -Class Win32_logicaldisk | Where-Object VolumeName -eq "ESD-USB"

    if($USBDrive) {
        $GetBootWim = ($USBDrive | Select-Object DeviceID -Verbose).DeviceID + "\sources\boot.wim"
        $GetInstallESD = ($USBDrive | Select-Object DeviceID -Verbose).DeviceID + "\sources\install.esd"
    }
    else {
        $LogMessage = "No USB-drive named ""ESD-USB"" connected!"
        Write-LogEntry -Value $LogMessage -Severity 3
        throw $LogMessage
    }

    #########################################################
    ## Injecting drivers into Microsoft Windows PE (amd64) ##
    #########################################################

    # Mount boot.wim index 1: Microsoft Windows PE (amd64)
    Write-LogEntry -Value "Mounting boot.wim index 1: Microsoft Windows PE (amd64)" -Severity 1

    try {
        Mount-WindowsImage -ImagePath "$GetBootWim" -Index 1 -Path "$WorkingDir\Mount" -Verbose
        Write-LogEntry -Value "Successfully mounted boot.wim index 1: Microsoft Windows PE (amd64)" -Severity 1
    }
    catch {
        $LogMessage = "Error mounting boot.wim: Microsoft Windows PE (amd64): $_"
        Write-LogEntry -Value $LogMessage -Severity 3
        throw $LogMessage
    }

    # Inject drivers into Microsoft Windows PE (amd64)
    Write-LogEntry -Value "Injecting drivers into boot.wim index 1: Microsoft Windows PE (amd64)" -Severity 1

    try {
        Add-WindowsDriver -Path "$WorkingDir\Mount" -Driver "$WorkingDir\Drivers\" -Recurse -Verbose
        Write-LogEntry -Value "Successfully injected drivers into boot.wim index 1: Microsoft Windows PE (amd64)" -Severity 1
    }
    catch {
        $LogMessage = "Error injecting drivers into boot.wim index 1: Microsoft Windows PE (amd64): $_"
        Write-LogEntry -Value $LogMessage -Severity 3
        throw $LogMessage
    }

    # Dismount boot.wim index 1: Microsoft Windows PE (amd64)
    Write-LogEntry -Value "Dismounting boot.wim index 1: Microsoft Windows PE (amd64)" -Severity 1

    try {
        Dismount-WindowsImage -Path "$WorkingDir\Mount" -Save -Verbose
        Write-LogEntry -Value "Successfully dismounted boot.wim index 1: Microsoft Windows PE (amd64)" -Severity 1
    }
    catch {
        $LogMessage = "Error dismounting boot.wim index 1: Microsoft Windows PE (amd64): $_"
        Write-LogEntry -Value $LogMessage -Severity 3
        throw $LogMessage
    }

    ############################################################
    ## Injecting drivers into Microsoft Windows Setup (amd64) ##
    ############################################################

    # Mount boot.wim index 2: Microsoft Windows Setup (amd64)
    Write-LogEntry -Value "Mounting boot.wim index 2: Microsoft Windows Setup (amd64)" -Severity 1

    try {
        Mount-WindowsImage -ImagePath "$GetBootWim" -Index 2 -Path "$WorkingDir\Mount" -Verbose
        Write-LogEntry -Value "Successfully mounted boot.wim index 2: Microsoft Windows Setup (amd64)" -Severity 1
    }
    catch {
        $LogMessage = "Error mounting boot.wim index 2: Microsoft Windows Setup (amd64): $_"
        Write-LogEntry -Value $LogMessage -Severity 3
        throw $LogMessage
    }

    # Add drivers to Microsoft Windows PE (amd64)
    Write-LogEntry -Value "Injecting drivers into boot.wim index 2: Microsoft Windows Setup (amd64)" -Severity 1

    try {
        Add-WindowsDriver -Path "$WorkingDir\Mount" -Driver "$WorkingDir\Drivers\" -Recurse -Verbose
        Write-LogEntry -Value "Successfully injected drivers into boot.wim index 2: Microsoft Windows Setup (amd64)" -Severity 1
    }
    catch {
        $LogMessage = "Error mounting boot.wim index 2: Microsoft Windows Setup (amd64): $_"
        Write-LogEntry -Value $LogMessage -Severity 3
        throw $LogMessage
    }
    
    # Dismount boot.wim index 2: Microsoft Windows Setup (amd64)
    Write-LogEntry -Value "Dismounting boot.wim index 2: Microsoft Windows Setup (amd64)" -Severity 1

    try {
        Dismount-WindowsImage -Path "$WorkingDir\Mount" -Save -Verbose
        Write-LogEntry -Value "Successfully dismounted boot.wim index 2: Microsoft Windows Setup (amd64)" -Severity 1
    }
    catch {
        $LogMessage = "Error mounting boot.wim index 2: Microsoft Windows Setup (amd64): $_"
        Write-LogEntry -Value $LogMessage -Severity 3
        throw $LogMessage
    }

    ############################################################
    ##         Injecting drivers into Windows 11 Pro          ##
    ############################################################

    # Export install.esd to install.wim
    Write-LogEntry -Value "Exporting install.esd to install.wim" -Severity 1

    try {
        Export-WindowsImage -SourceImagePath "$GetInstallESD" -SourceName "Windows 11 Pro" -DestinationImagePath "$WorkingDir\Wim\install.wim" -CompressionType Max -CheckIntegrity -Verbose

        $WimInfo = Get-WindowsImage -ImagePath "$WorkingDir\Wim\install.wim" -Index 1 | Select-Object ImageName, Version, Languages, @{Name="Size"; Expression={[math]::round($_.ImageSize/1MB, 2)}}
        
        Write-LogEntry -Value ("Exported install.esd to install.wim: " + $WorkingDir + "\Wim\install.wim") -Severity 1

        Write-LogEntry -Value "############## OS Information ##############" -Severity 1
        Write-LogEntry -Value ("OS Name: " + $($WimInfo).ImageName) -Severity 1
        Write-LogEntry -Value ("OS Version: " + $($WimInfo).Version) -Severity 1
        Write-LogEntry -Value ("OS Language: " + $($WimInfo).Languages) -Severity 1
        Write-LogEntry -Value ("OS Size: " + $($WimInfo).Size + " MB") -Severity 1
        Write-LogEntry -Value "############################################" -Severity 1
    }
    catch {
        $LogMessage = "Error exporting install.esd to install.wim: $_"
        Write-LogEntry -Value $LogMessage -Severity 3
        throw $LogMessage
    }

    # Mount install.wim: Windows 11 Pro"
    Write-LogEntry -Value "Mounting install.wim: Windows 11 Pro" -Severity 1

    try {
        Mount-WindowsImage -ImagePath "$WorkingDir\Wim\install.wim" -Name "Windows 11 Pro" -Path "$WorkingDir\Mount" -Verbose
        Write-LogEntry -Value "Mounted install.wim: Windows 11 Pro" -Severity 1
    }
    catch {
        $LogMessage = "Error mounting install.wim: Windows 11 Pro: $_"
        Write-LogEntry -Value $LogMessage -Severity 3
        throw $LogMessage
    }

    # Add drivers to Windows 11 Pro
    Write-LogEntry -Value "Injecting drivers into install.wim: Windows 11 Pro" -Severity 1

    try {
        Add-WindowsDriver -Path "$WorkingDir\Mount" -Driver "$WorkingDir\Drivers\" -Recurse -Verbose
        Write-LogEntry -Value "Injected drivers into install.wim: Windows 11 Pro" -Severity 1
    }
    catch {
        $LogMessage = "Error injecting trivers into install.wim: Windows 11 Pro: $_"
        Write-LogEntry -Value $LogMessage -Severity 3
        throw $LogMessage
    }
    
    # Dismount install.wim: Windows 11 Pro
    Write-LogEntry -Value "Dismounting install.wim: Windows 11 Pro" -Severity 1

    try {
        Dismount-WindowsImage -Path "$WorkingDir\Mount" -Save -Verbose
        Write-LogEntry -Value "Dismounted install.wim: Windows 11 Pro" -Severity 1
    }
    catch {
        $LogMessage = "Error dismounting install.wim: Windows 11 Pro: $_"
        Write-LogEntry -Value $LogMessage -Severity 3
        throw $LogMessage
    }

    ############################################################
    ##    Spitting install.wim and removing install.esd       ##
    ############################################################

    # Remove original install.esd from USB-drive
    Write-LogEntry -Value "Removing original install.esd" -Severity 1

    try {
        Remove-item $GetInstallESD -Force -Verbose
        Write-LogEntry -Value "Removed original install.esd" -Severity 1
    }
    catch {
        $LogMessage = "Error removing original install.esd: Windows 11 Pro: $_"
        Write-LogEntry -Value $LogMessage -Severity 3
        throw $LogMessage
    }

    # Split install.wim into files of maximum 4000Mb
    Write-LogEntry -Value "Splitting install.wim into multiple install.swm-files of maximum 4000Mb due to FAT32 limitation." -Severity 1

    try {
        Split-WindowsImage -ImagePath "$WorkingDir\Wim\install.wim" -SplitImagePath ($($USBDrive).DeviceID + "\sources\install.swm") -FileSize 4000 -Verbose
        Write-LogEntry -Value "Splitted install.wim" -Severity 1
    }
    catch {
        $LogMessage = "Error splitting install.wim: Windows 11 Pro: $_"
        Write-LogEntry -Value $LogMessage -Severity 3
        throw $LogMessage
    }

    ######################################################
    ##            Copy Windows Answer File              ##
    ######################################################

    if($AnswerFile) {

$autounattend = @"
<?xml version="1.0" encoding="UTF-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
   <settings pass="offlineServicing" />
   <settings pass="windowsPE">
      <component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
         <SetupUILanguage>
            <UILanguage>nl-NL</UILanguage>
         </SetupUILanguage>
         <InputLocale>0413:00020409</InputLocale>
         <SystemLocale>nl-NL</SystemLocale>
         <UILanguage>nl-NL</UILanguage>
         <UserLocale>nl-NL</UserLocale>
      </component>
      <component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
         <DiskConfiguration>
            <WillShowUI>OnError</WillShowUI>
            <Disk wcm:action="add">
               <CreatePartitions>
                  <!-- EFI system partition -->
                  <CreatePartition wcm:action="add">
                     <Order>1</Order>
                     <Type>EFI</Type>
                     <Size>100</Size>
                  </CreatePartition>
                  <!-- Microsoft reserved partition (MSR) -->
                  <CreatePartition wcm:action="add">
                     <Order>2</Order>
                     <Type>MSR</Type>
                     <Size>16</Size>
                  </CreatePartition>
                  <!-- Windows partition -->
                  <CreatePartition wcm:action="add">
                     <Order>3</Order>
                     <Type>Primary</Type>
                     <Extend>true</Extend>
                  </CreatePartition>
               </CreatePartitions>
               <ModifyPartitions>
                  <!-- EFI system partition -->
                  <ModifyPartition wcm:action="add">
                     <Order>1</Order>
                     <PartitionID>1</PartitionID>
                     <Label>System</Label>
                     <Format>FAT32</Format>
                  </ModifyPartition>
                  <!-- Microsoft reserved partition (MSR) -->
                  <ModifyPartition wcm:action="add">
                     <Order>2</Order>
                     <PartitionID>2</PartitionID>
                  </ModifyPartition>
                  <!-- Windows partition -->
                  <ModifyPartition wcm:action="add">
                     <Order>3</Order>
                     <PartitionID>3</PartitionID>
                     <Label>Windows</Label>
                     <Format>NTFS</Format>
                     <Letter>C</Letter>
                  </ModifyPartition>
               </ModifyPartitions>
               <DiskID>0</DiskID>
               <WillWipeDisk>true</WillWipeDisk>
            </Disk>
         </DiskConfiguration>
         <ImageInstall>
            <OSImage>
               <InstallTo>
                  <DiskID>0</DiskID>
                  <PartitionID>3</PartitionID>
               </InstallTo>
            </OSImage>
         </ImageInstall>
         <UserData>
            <ProductKey>
               <Key>VK7JG-NPHTM-C97JM-9MPGT-3V66T</Key>
            </ProductKey>
            <AcceptEula>true</AcceptEula>
         </UserData>
      </component>
   </settings>
   <settings pass="generalize" />
   <settings pass="specialize" />
   <settings pass="auditSystem" />
   <settings pass="auditUser" />
   <settings pass="oobeSystem">
      <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
         <OOBE>
            <ProtectYourPC>1</ProtectYourPC>
            <HideEULAPage>true</HideEULAPage>
            <HideLocalAccountScreen>true</HideLocalAccountScreen>
            <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
            <HideWirelessSetupInOOBE>false</HideWirelessSetupInOOBE>
         </OOBE>
      </component>
   </settings>
</unattend>
"@

        # Copy Windows Answer File (autounattend.xml) to the root of the USB-drive.
        Write-LogEntry -Value "Copying Windows Answer File (autounattend.xml) to the root of the USB-drive." -Severity 1

        try {
            New-Item -Path ($($USBDrive).DeviceID) -Name autounattend.xml -ItemType File -Value $autounattend -Force -Verbose
            Write-LogEntry -Value "Copied Windows Answer File (autounattend.xml) to the root of the USB-drive." -Severity 1
        }
        catch {
            $LogMessage = "Error copying Windows Answer File (autounattend.xml) to the root of the USB-drive: $_"
            Write-LogEntry -Value $LogMessage -Severity 3
            throw $LogMessage
        }
    }
    
    # Copy Log File (MCTBuilder.log) to the root of the USB-drive.
    Write-LogEntry -Value "Copying Log File (MCTBuilder.log) to the root of the USB-drive." -Severity 1

    try {
        Copy-Item $LogFilePath ($($USBDrive).DeviceID) -Force -Verbose
        Write-LogEntry -Value "Copied Log File (MCTBuilder.log) to the root of the USB-drive." -Severity 1
    }
    catch {
        $LogMessage = "Error copying Log File (MCTBuilder.log) to the root of the USB-drive: $_"
        Write-LogEntry -Value $LogMessage -Severity 3
        throw $LogMessage
    }
}

Write-LogEntry -Value "Begin MCTBuilder" -Severity 1

# Check if invoke-MCTBuilder.ps1 is running with Administrative permissions
Test-Administrator

# Create required working folders
Create-WorkingFolder

# Run MCTBuilder
Invoke-MCTBuilder

Write-LogEntry -Value "End MCTBuilder" -Severity 1
