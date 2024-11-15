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

function Find-PC {
    <#
    .SYNOPSIS
        This will take input and check each input in AD if the computer exists.
        
    .DESCRIPTION
        When running Find-PC, it will by default ask you to input parts of whatever name you're looking for.
        For example, if the computer is PC123456, and you enter 345, it will search for *345* and find any in AD that matches that.
    
        You must have a line break between each entry, comma's are not currently supported.
    
        When you are done entering the list, entering a blank space 
    
    .PARAMETER variable
        [-Clipboard, -c] = This will just run whatever is in your clipboard.
        [-Auto, -a] = This will automatically run -c and also copy everything in the clipboard.
    
    .EXAMPLE
        Find-PC -a
        Find-PC -c
        Find-PC
    
    
    .NOTES
        Author: Alex Hendowski
        Last Updated: 10/9/2024
        Notes: This is useful if you have a naming convention that has something like "DEPT-[Asset]" so for example, if you have 2 departments, Math and English
        Math = MATH
        English = ENG
    
        If you get a list of computer asset tags such as "12345" and "98765" and they ask you to find them, you can load this script and find them without needing to know their department.
    
    #>
    
    [CmdletBinding()]
    param (
        [Alias("c")]
        [switch]$Clipboard,
        [Alias("a")]
        [switch]$auto
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

    if ($clipboard -or $auto) {
        set-array -Clipboard
    } else {
        set-array
    }


    $totalComputers = $Array.Count

    # If $computerList has 1 entry, run the syntax, instead of the foreach loop.  Else if there is >=2, run foreach loop.
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
    } else {
        & $OutputSuccess
        & $OutputFailed
        & $OutputTanium
    }
}

function Move-ComputerOUAuto {
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
    Param (
        [cmdletbinding()]
        [Parameter(Mandatory=$true,Position=0)]
        [string]$export
    )

    $export | Set-ExportPath

    connect-mgGraph -Scopes "User.Read.All","Device.Read.All" -NoWelcome
    
    Write-Host "Grabbing all encrypted devices from Intune" -ForegroundColor Gray
    $Devices = get-mgdevicemanagementManagedDevice -Filter "OperatingSystem eq 'Windows'" -all | where-object Isencrypted -eq true

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

function Set-Array {
    [cmdletbinding()]
    Param (
        [Alias("c")]
        [switch]$Clipboard
    )

    $script:Array = @()

    if ($Clipboard) {
        $script:Array = (Get-Clipboard).split("\n").split(",").split("|")
    } else {
        write-host "Enter a blank space to continue." -ForegroundColor Blue
        write-host "Copy and paste asset tags:" -ForegroundColor Cyan
        while (1) {
            read-host | Set-Variable r
            if (!$r) {break}
            $script:Array += $r
            }

        if ($script:Array.count -eq 0) {
            write-host "ERROR: Nothing entered." -foregroundcolor red -BackgroundColor black
            exit 1
        }
        write-Host "********************`n" -ForegroundColor Cyan
    } 
}