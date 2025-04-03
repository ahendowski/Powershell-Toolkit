write-host " Common " -nonewline -BackgroundColor darkred
write-host " Command " -ForegroundColor Black -backgroundcolor Gray -nonewline
write-host " Reference: " -BackgroundColor darkred -nonewline
Write-Host $($PSStyle.Reset)
write-host "`tADSync" -foregroundcolor Cyan
write-host "`tFind-PC" -foregroundcolor Green -nonewline; write-host " [-c / -a]" -foregroundcolor Yellow
write-host "`tGet-UninstallString" -foregroundcolor Cyan -nonewline; write-host " [`$Program]" -foregroundcolor Yellow
write-host "`tGet-DeletedADObjects" -foregroundcolor Green -nonewline; write-host " [`$Computer]" -foregroundcolor Yellow
write-host "`tRemove-ADEI" -ForegroundColor Red -NoNewline; write-host " [-update]`n`t   " -foregroundcolor Yellow -nonewline
write-host "WARNING: Must have Windows Terminal or Powershell Session pinned to taskbar in slot 7." -BackgroundColor DarkRed -ForegroundColor White -nonewline
Write-Host $($PSStyle.Reset)
write-host "`t   " -nonewline
write-host "If you do not want this, go to Remove-ADEI and comment out Get-PSFocus function." -BackgroundColor DarkRed -ForegroundColor White -nonewline
Write-Host $($PSStyle.Reset)

write-host ""
write-host "Update-Hendo" -foregroundcolor Green -NoNewline
write-host " to update all Hendo Functions."
write-host "HenCmd "-foregroundcolor Green -NoNewline
write-host "for all other commands."

function Update-Hendo {
    copy-item "c:\github\Powershell-Toolkit\Hendowski.PS.Toolkit.psm1" "C:\Program Files\PowerShell\7\Modules\Hendowski.PS.Toolkit"
    copy-item "c:\github\Powershell-Toolkit\Hendowski.PS.Toolkit.psd1" "C:\Program Files\PowerShell\7\Modules\Hendowski.PS.Toolkit"
    write-host "Hendo Module has been updated." -foregroundcolor Green
}

function Get-PSFocus {
    Add-Type -TypeDefinition @"
    using System;
    using System.Runtime.InteropServices;

    public class Keyboard {
        [DllImport("user32.dll", SetLastError = true)]
        public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);

        public const int KEYEVENTF_KEYDOWN = 0x0000;
        public const int KEYEVENTF_KEYUP = 0x0002;
        public const byte VK_LWIN = 0x5B; // Left Windows key
        public const byte VK_7 = 0x37;    // Number key 7
    }
"@ -PassThru | Out-Null

# Press and hold Windows key
[Keyboard]::keybd_event([Keyboard]::VK_LWIN, 0, [Keyboard]::KEYEVENTF_KEYDOWN, [UIntPtr]::Zero)
Start-Sleep -Milliseconds 50

# Press and release '7'
[Keyboard]::keybd_event([Keyboard]::VK_7, 0, [Keyboard]::KEYEVENTF_KEYDOWN, [UIntPtr]::Zero)
Start-Sleep -Milliseconds 50
[Keyboard]::keybd_event([Keyboard]::VK_7, 0, [Keyboard]::KEYEVENTF_KEYUP, [UIntPtr]::Zero)

Start-Sleep -Milliseconds 50

# Release Windows key
[Keyboard]::keybd_event([Keyboard]::VK_LWIN, 0, [Keyboard]::KEYEVENTF_KEYUP, [UIntPtr]::Zero)
}

function HenCmd {
    Get-Command -Module Hendowski.PS.Toolkit
    }    

function Connect-MSGraphHendo {
    connect-MGGraph  -ClientId "b2193728-d737-4a9c-9b07-58d96c154a7a" -TenantId "e9ab118a-9355-41a6-aaad-633046c798b9" -CertificateThumbprint "94099B58C83D043FFAC756E2453A12529F6DAD83" -nowelcome
}

function Set-Array {
    [cmdletbinding()]
    Param (
        [Alias("c")]
        [switch]$Clipboard
    )

    $script:Array = @()
    
    if ($Clipboard) {
        $script:Array = (Get-Clipboard) -replace "(\r?\n){2,}", "`r`n" -split '[,\|\r\n]' -match '\S+'

    } else {
        write-host "Enter a blank space to submit." -ForegroundColor yellow
        while (1) {
            read-host | Set-Variable r
            if (!$r) {break}
            $script:Array += $r
            }

        if ($script:Array.count -eq 0) {
            write-host "ERROR: Nothing entered. Exiting" -foregroundcolor red -BackgroundColor black
            exit 1
        }
    } 
}

function Set-ExportPath {
    # Checks to see if the export filepath has a '\' at the end of it.  If it does not, add it.
    # C:\folder = C:\folder\
    param (
        [Parameter(mandatory=$true,ValueFromPipeline=$true)]
        [String]$export
    )
    $ErrorActionPreference = 'SilentlyContinue'

    try {
        get-childitem -path $export -erroraction stop | out-null
    } catch {
        write-host "The path [$export] does not exist.  Please enter a correct path." -ForegroundColor red
        break
    }

    if ($export[-1] -ne '\') { 
        $export = "$export\" 
    } 

    $script:export = $export
    
}

# Single Functions
function Find-PC {
    <#
    .SYNOPSIS
        This will take input and check each input in AD if the computer exists.
        
    .DESCRIPTION
        When running Find-PC, it will by default ask you to input parts of whatever name you're looking for.
        For example, if the computer is PC123456, and you enter 345, it will search for *345* and find any in AD that matches that.
    
        You must have a line break, comma, or pipe between each entry.  When you are done, enter a blank space to run the command.
    
        When you are done entering the list, entering a blank space 

        You may use Clipboard or Auto 
    
    .PARAMETER Clipboard
        This will just run whatever is in your clipboard.  Copy your data before running this.

    .PARAMETER Auto
        This will automatically run -c and also copy all output into your clipboard.

    .EXAMPLE
        Find-PC
        Find-PC -Autof
        Find-PC -a
        Find-PC -Clipboard
        Find-PC -c
    
    .NOTES
        This script is useful when you have something like an asset tag or some kind of identifier for any computer name, or if you have only a partial name.  It will get the entire list.
    #>
    
    [CmdletBinding()]
    param (
        [Alias("c")]
        [switch]$Clipboard,
        [Alias("a")]
        [switch]$auto,
        [Alias("CN")]
        [switch]$CopyNames
    )

    $script:successText = ""
    $script:failText = ""
    $script:TaniumText = ""

    $OutputSuccess = {
        if ($successfulComputers) {
            # Output successful computers
            Write-Host "Computers Exist in AD:"
            $script:successText += "Computers Exist in AD:`n"
            foreach ($success in $successfulComputers) {
                Write-Host "$($success.ComputerName)" -ForegroundColor Green
                $script:successText += "$($success.ComputerName)`n"
            }  
            write-Host ""
            $script:successText += "`n"
        } else {
            Write-Host "Computers Exist in AD:"
            Write-Host "N/A" -ForegroundColor Green
            write-host ""
            $script:successText +=  "Computers Exist in AD:`nN/A`n"
        }
    }

    $OutputFailed = {
        # Output failed attempts
        if ($failedComputers) {
            # Output failed attempts
            Write-Host "Computers NOT Existing in AD:"
            $script:failText += "Computers NOT Existing in AD:`n"
            foreach ($failure in $failedComputers) {
                Write-Host "$($failure.ComputerName)" -ForegroundColor Red
                $script:failText += "$($failure.ComputerName)`n"
            } write-Host ""
            $script:failText += "`n"
        }
    }

    $OutputTanium = {
        if ($successfulComputers) {
            #Tanium Friendly naming convention
            Write-Host "Tanium Friendly List:"
            $script:TaniumText += "Tanium Friendly List:`n"
                $taniumCopyPaste = $successfulComputers.Hostname -join ', '
                write-host "$taniumCopyPaste" -ForegroundColor Magenta
                $script:TaniumText += "$taniumCopyPaste"
            }
        }
    

    # Arrays to store results
    $successfulComputers = @()
    $failedComputers = @()
    $script:Array = @()

    if ($clipboard -or $auto -or $CopyNames) {
        set-array -Clipboard
    } else {
        set-array
    }


    $totalComputers = $Array.Count

    # If $Array has 1 entry, run the syntax, instead of the foreach loop.  Else if there is >=2, run foreach loop.
    if ($totalComputers -eq 1) {         
            $computer = Get-ADComputer -Filter "SamAccountName -like '*$($Array)*'" -Properties dnshostname -ErrorAction Stop
            if ($computer) {
                $successfulComputers += [PSCustomObject]@{
                    ComputerName = $Array
                    HostName = $computer.dnshostname
                    Name = $computer.SamAccountName.trim('$')
                }
            } else {
                $failedComputers += [PSCustomObject]@{
                    ComputerName = $Array
                }
            }
        }
        else {
        # Use foreach loop to process each computer name
        foreach ($index in 0..($totalComputers - 1)) {
            $computerName = $Array[$index]

            # Write progress status
            Write-Progress -Activity "Processing computers" -Status "Checking $computerName - $index/$totalComputers" -PercentComplete (($index / $totalComputers) * 100)

            try {
                $computer = Get-ADComputer -Filter "SamAccountName -like '*$($computerName)*'" -Properties dnshostname -ErrorAction Stop
                if ($computer) {
                    $successfulComputers += [PSCustomObject]@{
                        ComputerName = $computer.SamAccountName.trim('$')
                        HostName = $computer.dnshostname
                    }
                } else {
                    $failedComputers += [PSCustomObject]@{
                        ComputerName = $computerName
                    }
                }
            }
            catch {
                $failedComputers += [PSCustomObject]@{
                    ComputerName = $computerName
                }
            }
        }
    }

    # Clear progress once done
    Write-Progress -Activity "Processing computers" -Completed


    if ($Auto -or $a) {
        & $OutputSuccess
        & $OutputFailed
        & $OutputTanium
        $combinedOutput = $script:successText + $script:failText + $script:TaniumText
        Set-Clipboard $combinedOutput
    } elseif ($CopyNames -or $CN) {
        $successfulComputers.Name | Set-Clipboard

    } else {
        & $OutputSuccess
        & $OutputFailed
        & $OutputTanium
    }
}

function Move-ComputerOUAuto {
    <#
    .SYNOPSIS
        Automatically moves Computer to their correct OU based off a hash map.
        
    .DESCRIPTION
        This script can be run on demand, or set in a scheduled task to constantly run.

        It uses a hash table to match the beginning pre-fix of a computer, or anything that designates where it needs to be, and places it in the appropriate OU.

        It has a built in hashtable mapper, so you can run Move-ComputerOUAuto -map, to create an entire map.  Once this is created, edit the data and set it into the $departmentOUmap variable underneath the functions.
    
    .PARAMETER OU
        Enter the OU that you want to run this on.

    .PARAMETER map
        Creates a hashtable to copy and paste into $departmentOUmap.  Requires manual editing to ensure it's accurate and looks good.

    .EXAMPLE
        Move-ComputerOUAuto -map
        Move-ComputerOUAuto -OU "OU=OUHere,DC=domain,DC=com"
    
    .NOTES
        The script is handy as a one time setup.  Run a test to make sure it works in the right OU after creating the hash table.

        Once you do this, create a service account on a server and have it run as a scheduled task, to ensure cleanup.
    #>
    param(
        [string]$OU = $null,
        [Alias("getmap","OUmap")]
        [switch]$map
    )
    function Get-DepartmentOUMap {
        param(
            [string]$OU = $null
        )
    
        if (-not $OU) {
            $script:GetAD = get-adcomputer -filter * -Property Name
        } else {
            try {
                [adsi]::Exists("LDAP://$OU") | Out-Null
            } catch {
                Write-Host "Error: OU does not exist.  Exiting" -ForegroundColor Red
                break
            }
            $script:GetAD = get-adcomputer -filter * -searchbase $OU -Property Name
        }
        # Gets computer filtering and outputs the key needed
    
        $GetAD | select-object @{Name='name'; Expression={ if ($_.Name -match '^[^\d]+') { $matches[0] } }},@{Name='OU'; Expression={$_.DistinguishedName -replace '^.+?(?<!\\),',''} } | 
        sort-object name -Unique | foreach-object { 
            if ($_.name.length -le 4) {
                write-host "`'$($_.name)`' `t`t= `'$($_.OU)`'"
            } elseif ($_.name.length -lt 13) {
                write-host "`'$($_.name)`' `t= `'$($_.OU)`'" 
            }
    
        }
        Write-Host "Please go through and verify list, remove any entries, then copy and paste your results into this script under the variable " -nonewline -ForegroundColor Yellow
        write-host "`$departmentOUMap" -ForegroundColor Cyan
    }

    function Get-DepartmentCode {
        param (
            [string]$computerName
        )

        $deptCode = $computerName -replace '\d.*$', ''
        return $deptCode
    }

    function Move-ComputerOUAuto {
        $IncorrectDevices = @()

        foreach ($computer in $GetAD) {
            $computerName = $computer.Name
            $deptCode = Get-DepartmentCode -computerName $computerName

            # Find the OU based on the department code
            $targetOU = $null
            $currentOU = $computer.DistinguishedName -Replace '^.+?(?<!\\),', ''

            foreach ($key in $departmentOUMap.Keys) {
                if ($deptCode -like "$key*") {
                    $targetOU = $departmentOUMap[$key]
                
                    if ($currentOU -notlike $targetOU) {
                        $IncorrectDevices += $computerName
                        write-host "$computerName"
                        write-host "Current OU: $currentOU" -ForegroundColor red
                        write-host "Target OU: $targetOU" -ForegroundColor green
                        write-host ""
                        move-ADobject -Identity $computer.DistinguishedName -TargetPath $targetOU -verbose
                        break
                    }
                }
            }
        }
    }

    $departmentOUMap = @{
        # Set computer Prefix name and the OU
        # Example: 
        # 'Prefix'      = 'OU=Computers,OU=Your,DC=domain,DC=location'
    }

    if ($map) {
        Get-DepartmentOUMap
        break
    }

    if ($departmentOUMap.count -eq 0) {
        write-host "ERROR: [" -NoNewline -ForegroundColor red
        write-host "`$departmentOUMap" -nonewline -foregroundcolor cyan
        write-host "] is empty.  Please run [" -NoNewline -ForegroundColor red
        write-host "Move-ComputerOUAuto -map" -nonewline
        write-host "] and edit the [" -nonewline -ForegroundColor Red
        write-host "`$departmentOUMap" -nonewline -foregroundcolor cyan
        write-host "] variable and try again" -ForegroundColor red
        break
    }

    Move-ComputerOUAuto

}

function Get-EntraBitlockerKeys {
    <#
    .SYNOPSIS
        Grabs all bitlocker keys from Entra.
        
    .DESCRIPTION
        This will display the bitlocker keys in a .csv format.
    
    .PARAMETER Export
        Mandatory, set filepath you want to export.

    .EXAMPLE
        Get-EntraBitlockerKeys C:\folder\to\export
        Get-EntraBitlockerKeys C:\folder\to\export\
    
    .NOTES
        You do not need to designate a \ at the end, the script has a built in function to either remove or append a \ at the end of the file path.
    #>
    Param (
        [cmdletbinding()]
        [Parameter(Mandatory=$true,Position=0)]
        [string]$export
    )

    $export | Set-ExportPath

    Connect-MSGraphHendo

    Write-Host "Grabbing all encrypted devices from Intune" -ForegroundColor Gray
    $Devices = get-mgdevicemanagementManagedDevice -Filter "OperatingSystem eq 'Windows'" -all

    # Grabs the total device count to use later on in the Progress
    $totalDevices = $Devices.Count
    $allDeviceEncryption = @()

    Write-Host "Success." -ForegroundColor Green
    Write-Host "Checking Bitlocker information for all devices" -ForegroundColor Gray

    # Use foreach loop to cycle through each computer grabbed from $Devices
        foreach ($index in 0..($totalDevices - 1)) {
            $Device = $Devices[$index]
            
            Write-Progress -Activity "Processing computers, Started $($startTime.ToString("MM/dd @ hh:mm tt"))" -Status "Checking $index/$totalDevices - $($Device.DeviceName)" -PercentComplete (($index / $totalDevices) * 100)

            $getBitlock = Get-MgInformationProtectionBitlockerRecoveryKey -Filter "DeviceID eq '$($Device.AzureADDeviceID)'" | select-object Id,CreatedDateTime,DeviceId,@{n="Key";e={(Get-MgInformationProtectionBitlockerRecoveryKey -BitlockerRecoveryKeyId $_.Id -Property key).key}},VolumeType

            if (-not $getBitlock) {
                $allDeviceEncryption += [PSCustomObject]@{
                    Name = $Device.DeviceName
                    Encrypted = $Device.IsEncrypted
                    User = $Device.UserDisplayName
                    DeviceID = $Device.Id
                    CreatedDate = $null
                    Key = $null
                    VolumeType = $null
                }
            } else {
            foreach ($BitlockerDevice in $getBitlock) {
                $BitlockerDevices = Get-MgInformationProtectionBitlockerRecoveryKey -BitlockerRecoveryKeyId "$($BitlockerDevice.ID)" -Property "Key"
                $allDeviceEncryption += [PSCustomObject]@{
                    Name = $Device.DeviceName
                    Encrypted = $Device.IsEncrypted
                    User = $Device.UserDisplayName
                    DeviceID = $Device.Id
                    CreatedDate = $BitlockerDevices.CreatedDateTime
                    Key = $BitlockerDevices.Key
                    VolumeType = $BitlockerDevices.VolumeType
                }
            }
        }
    }

    Write-Progress -Activity "Processing computers, Started $($startTime.ToString("MM/dd @ hh:mm tt"))" -Completed

    $endTime = Get-Date
    $elapsedTime = [datetime]$endTime - [datetime]$startTime
    $elapsedTime = '{0:hh\:mm\:ss}' -f $elapsedTime

    Write-Host "Success!" -ForegroundColor green
    Write-Host "Completed time: $($endTime.ToString("MM/dd @ hh:mm tt"))" -ForegroundColor Green
    Write-Host "Total Time elapsed: $elapsedTime" -ForegroundColor Green
    $allDeviceEncryption | Export-csv -Path "$export\BitlockerKeys.csv"
}

# Need to add Set-Array
function Add-EntraDevicetoGroup {
    <#
        .SYNOPSIS
            Add multiple devices into an Entra group.
            
        .DESCRIPTION
            Allows you to input a list and grab all devices, then input the Entra group you want, and add all devices to that Entra group.
        
        .NOTES
            This script currently uses input.  Might edit it later to add a parameter to do like -EntraGroup ""
        #>

    function Get-PCInfo {
        param (
            [string]$computerName,
            [Microsoft.ActiveDirectory.Management.ADComputer]$computer
        )

        return [PSCustomObject]@{
            ComputerName = $computerName
            HostName = $computer.dnshostname
            Name = $computer.SamAccountName.trim('$')
            # Add more properties if needed, e.g.:
            # SamAccountName = $computer.SamAccountName
        }
    }

    Connect-MSGraphHendo

    write-host "Please enter all computers to add to Entra:" -ForegroundColor Cyan
    Set-Array
    write-host "Please enter the Entra group name:" -ForegroundColor Cyan
    $Entragroup = Read-Host

    $successfulComputers = @()
    $failedComputers = @()
    $totalComputers = $Array.Count

    # If $Array has 1 entry, run the syntax, instead of the foreach loop. Else if there are >=2, run foreach loop.
    if ($totalComputers -eq 1) {
        $computerName = $Array[0]
        try {
            $computer = Get-ADComputer -Filter "SamAccountName -like '*$($computerName)*'" -Properties dnshostname -ErrorAction Stop
            if ($computer) {
                $successfulComputers += Get-PCInfo -computerName $computerName -computer $computer
            } else {
                $failedComputers += [PSCustomObject]@{
                    ComputerName = $computerName
                }
            }
        } catch {
            $failedComputers += [PSCustomObject]@{
                ComputerName = $computerName
            }
        }
    } else {
        # Use foreach loop to process each computer name in $Array
        foreach ($index in 0..($totalComputers - 1)) {
            $computerName = $Array[$index]

            Write-Progress -Activity "Processing computers" -Status "Checking $computerName - $index/$totalComputers" -PercentComplete (($index / $totalComputers) * 100)

            try {
                $computer = Get-ADComputer -Filter "SamAccountName -like '*$($computerName)*'" -Properties dnshostname -ErrorAction Stop
                if ($computer) {
                    $successfulComputers += Get-PCInfo -computerName $computerName -computer $computer
                } else {
                    $failedComputers += [PSCustomObject]@{
                        ComputerName = $computerName
                    }
                }
            } catch {
                $failedComputers += [PSCustomObject]@{
                    ComputerName = $computerName
                }
            }
        }
    }

    # Clear progress once done
    Write-Progress -Activity "Processing computers" -Completed

    # Set Entra group to get ID (need to change wehre this goes to organize better)
    $group = get-mggroup -filter "displayname eq '$($EntraGroup)'" -consistencylevel eventual


    # Cycle through each computer and add it to $group using the device ID for Entra.

    foreach ($success in $successfulComputers) {
        $pcname = $success.Name
        $userID = get-mgdevice -filter "displayname eq '$pcname'"

        new-mggroupmember -groupid $group.id -DirectoryObjectId $userID.id


    }

}

function Get-UninstallString {
    <#
    .SYNOPSIS
        Scans two basic registry keys to quickly get an uninstall string for all devices that match a naming convention.
        
    .DESCRIPTION
        Software typically is installed under the reg key CurrentVersion\Uninstall.  This will scan 64-bit and 32-bit registry and grab the devices name + registry key for uninstalling.

        It's a good quick lookup tool.
    
    .PARAMETER Program
        Enter the name of the program you would like to look up

    .EXAMPLE
        Get-UninstallString Microsoft

    .NOTES
        If you do not enter anything, you will be prompted to enter a list of computers.
    #>

    param(
        [Parameter(Position=0)]
        [string]$Program = $null
    )

    if ($Program) {
        Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | where-object Displayname -match $Program | select-object Displayname,displayversion,QuietUninstallString,uninstallstring
        Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | where-object DisplayName -match $Program | select-object Displayname,displayversion,QuietUninstallString,uninstallstring
        return
    } 

    if ($null -eq $Program) {
        write-host "Please enter name of all software to check:" -ForegroundColor Cyan
        Set-Array
        foreach ($Software in $Array) {
            Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | where-object DisplayName -match $Software | select-object Displayname,displayversion,uninstallstring,QuietUninstallString
            Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | where-object DisplayName -match $Software | select-object Displayname,displayversion,uninstallstring,QuietUninstallString
        }
    }
}
function Get-DeletedADObjects {
    <#
    .SYNOPSIS
        Searches for a computer if it is in the Recycle Bin
        
    .DESCRIPTION
        Checks AD to see if the computer is in the AD Recycle Bin.
    
    .PARAMETER computer
        Enter the computer you want to search

    .EXAMPLE
        Get-DeletedADObjects
        Get-DeletedADObjects PC12345
    
    .NOTES
        The AD component is so slow, I wrote this as a way to speed up searching for computers in the recycle bin.
        
    #>
    param(
        [parameter(position=0)]
        [string]$computer
    )

    
    if($computer) {
        write-host "Checking AD Recycle Bin for [" -ForegroundColor Yellow -nonewline
        write-host "$computer" -ForegroundColor Cyan -NoNewline
        write-host "]" -ForegroundColor yellow
        get-adobject -ldapFilter:"(msDS-LastKnownRDN=*)" -IncludeDeletedObjects | where-object {$_.Name -match $computer} | select-object -expandproperty Name | ft -AutoSize

    }

    if (-not $computer) {
        $Deletedobjects = @()
        Write-Host "Please enter all computers to search:" -ForegroundColor Cyan
        Set-Array
        write-host "Checking AD Recycle Bin..." -ForegroundColor Yellow
        foreach ($object in $array) {
            $Deletedobjects += get-adobject -ldapFilter:"(msDS-LastKnownRDN=*)" -IncludeDeletedObjects | where-object {$_.Name -match "$object"} 
        } 
    } 
}

function ADSync {
    Invoke-Command -ComputerName TCM1017 -ScriptBlock {
        Start-ADSyncSyncCycle -PolicyType Delta
    }
}

function Remove-ADEI {
    [cmdletbinding()]
    Param (
        [Alias("u")]
        [switch]$Update
    )

    # Use Set-Array to create $script:Array from clipboard.
    Set-Array -Clipboard

    # Checks variable $removeadeidate to compare if ran in 24 hours.
    # If it has not been run in 24 hours, it will connect to MGGraph and grab all devices.
    if ($global:removeadeidate) {
        write-host "Last run time: "-nonewline
        write-host "$($global:removeadeidate)`n" -ForegroundColor DarkGreen
    } else {
        write-host "Running first time.`n" -ForegroundColor DarkGreen
    }

    # Sleep for 5 to verify quickly if the clipboard contained the correct machines.
    write-host "All devices to be deleted:" -ForegroundColor Yellow
    foreach ($item in $script:Array) {
        write-host "$item" -ForegroundColor Magenta
    }
    start-sleep -seconds 5
    write-host ""

    # Connect to MSGraph and query global variables for Entra and Intune.
    if ($null -eq $global:removeadeidate -or $global:removeadeidate -lt (Get-Date).AddHours((-10)) -or $update) {
    write-host "Connecting to MGGraph"
    Connect-MSGraphHendo
    write-host "Getting Entra devices" -ForegroundColor Cyan
    $global:AllEntra = Get-MgDevice -All
    write-host "Getting Intune devices" -ForegroundColor Green
    $global:AllIntune = Get-MgDeviceManagementManagedDevice -All
    $global:removeadeidate = Get-Date
    }
    
    # List out all devices found to be deleted.

    Write-host "To Be Deleted: " -ForegroundColor Red -nonewline
    write-host "AD" -ForegroundColor Yellow -nonewline
    write-host " / " -nonewline
    write-host "Entra" -ForegroundColor Cyan -nonewline
    write-host " / " -nonewline
    write-host "Intune`n`n" -ForegroundColor Green -nonewline
    $confirmcheck = $false

    # Cycle through each device in AD / Entra / Intune and check if it matches Asset tag.
    foreach ($device in $script:Array) {
        $ADDelete = $null
        $EntraDelete = $null
        $IntuneDelete = $null

        write-host "$device" -ForegroundColor magenta
        $ADDelete = Get-ADComputer -filter "SamAccountName -like '*$($device)*'"
        $EntraDelete = $global:AllEntra | Where-Object {$_.DisplayName -like "*$($device)*"}
        $IntuneDelete = $global:AllIntune | Where-Object {$_.DeviceName -like "*$($device)*"}


        foreach ($item in $ADDelete) {
            #Split OU to exclude the CN=PCNAME
            $OUpath = ($item.distinguishedname -split ',' | Where-Object { $_ -notmatch '^CN='}) -join ','
            write-host "  $($item.Name) `($OUPath`)" -foregroundcolor Yellow            
        }

        foreach ($item in $EntraDelete) {
            write-host "  $($item.DisplayName) `($($item.ID)`)" -ForegroundColor Cyan
        }

        foreach ($item in $IntuneDelete) {
            write-host "  $($item.DeviceName) `($($item.ID)`)" -ForegroundColor Green
        }

        # IF there are more than 1 device matching Asset Tag, set $confirmcheck to true.
        # This will prompt the user to confirm deletion.
        if ($ADDelete.Count -gt 1 -or $EntraDelete.Count -gt 1 -or $IntuneDelete.Count -gt 1) {
            $confirmcheck = $true
        }
    }

    # If a duplicate is detected, prompt the user to confirm deletion.
    # Also bring forward the Terminal by pressing Windows Key + 7.
    # This is a workaround for the console not being in focus when running this script, so the user can see the prompt.
    # This is a custom solution, for this to be used please make sure you set the Taskbar icon 7 to the Windows Terminal you are running this on.
    # If the screen is in focus and a confirmation pops up, it will minimize - I don't know how to check for active window.

    if ($confirmcheck -eq $true) {
        # IF YOU DO NOT WANT TO FOREGROUND POWERSHELL, COMMENT OUT GET-PSFOCUS
        Get-PSFocus
    
        $UserInput = Read-Host "`nDo you want to delete the above items? (Y/N)"
    
        if ($UserInput -ne "Y") {
            Write-Host "Exiting" -ForegroundColor Red
            return
        }
    }

    write-host ""

    foreach ($device in $script:Array) {
        $ADDelete = $null
        $EntraDelete = $null
        $IntuneDelete = $null

        $ADDelete = Get-ADComputer -filter "SamAccountName -like '*$($device)*'"
        $EntraDelete = $global:AllEntra | Where-Object {$_.DisplayName -like "*$($device)*"}
        $IntuneDelete = $global:AllIntune | Where-Object {$_.DeviceName -like "*$($device)*"}


        # Delete in order of Intune --> Entra --> AD
        # If it does not exist, it will write 'No [Device]' in the console.

        write-host "Deleting $device" -ForegroundColor Red
        if ($null -eq $IntuneDelete) {
            write-host "  No Intune Device" -foregroundcolor DarkRed
        } else {
            foreach ($item in $IntuneDelete) {
                write-host "  $($item.DeviceName) `($($item.ID)`)" -ForegroundColor DarkGreen
                Remove-MgDeviceManagementManagedDevice -ManagedDeviceID $IntuneDelete.Id
            }
        }

        if ($null -eq $EntraDelete) {
            write-host "  No Entra Device." -foregroundcolor DarkRed
        } else {
            foreach ($item in $EntraDelete) {
                write-host "  $($item.DisplayName) `($($item.ID)`)" -ForegroundColor DarkCyan
                Remove-MgDevice -DeviceId $item.Id
                
            }
        }

        if ($null -eq $ADDelete) {
            write-host "  No AD Device." -foregroundcolor DarkRed
        } else {
            foreach ($item in $ADDelete) {
                $OUpath = ($item.distinguishedname -split ',' | Where-Object { $_ -notmatch '^CN='}) -join ','
                write-host "  $($item.Name) `($OUPath`)" -foregroundcolor darkyellow
                Remove-ADObject -identity $item -Recursive -confirm:$false
            }
        }
        
    }
    write-host "`nAll devices have been deleted." -ForegroundColor Green

}