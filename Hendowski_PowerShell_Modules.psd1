function Invoke-IntuneFix {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false, Position=1, HelpMessage="The name of the computer")]
        [Alias("Name", "Computer", "PC")]
        [string]$computerName = $null
    )

    if ($computerName -and $computerName -notin "localhost", $env:COMPUTERNAME) {
        if (! ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            throw "You don't have administrator rights"
        }
    }

    #script
    $scriptblock = {
        Write-Host "Stopping Intune Service" -ForegroundColor Magenta
        Get-Service *intune* | Stop-Service
        
        Write-Host "Checking if device is Entra joined" -ForegroundColor Magenta
        $DSREGCMD = dsregcmd /status
        $AzureADJoined = $null
        $AzureADJoined = $DSREGCMD | Select-String -Pattern 'AzureAdJoined : YES'
        if ($null -eq $AzureADJoined) {
            Write-Host "ERROR: Device is not Entra Joined. Exiting" -ForegroundColor Red
            Break
        } else {
            Write-Host "Device is Entra Joined!" -ForegroundColor Green
        }

        Write-Host "Searching for enrollment ID" -ForegroundColor Magenta
        $Tasks = Get-ScheduledTask | Where-Object { $_.TaskPath -like "\Microsoft\Windows\EnterpriseMgmt\*" }

        $EnrollId = $Tasks[0].TaskPath.Split('\')[-2].Trim()
        if ($EnrollID -notmatch '\w{8}-\w{4}-\w{4}-\w{4}-\w{12}') {
            write-host "No Enrollment ID found with \ filter.  Creating throwaway scheduled task." -ForegroundColor Yellow
            Register-ScheduledTask -TaskName "ThrowAwayTask" -TaskPath "\Microsoft\Windows\EnterpriseMgmt\1234ABCD-1234-1234-1234-1234ABCD1234" -Action (New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c exit") -RunLevel Highest -Force
            $Tasks = Get-ScheduledTask | Where-Object { $_.TaskPath -like "\Microsoft\Windows\EnterpriseMgmt\*" }
            $EnrollId = $($Tasks | where taskName -eq "ThrowAwayTask").taskpath.split('\')[-2]
        }

        if ($EnrollID -match "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}") {
            Write-Host "Found EnrollmentID: " -nonewline -ForegroundColor Green
            write-host "$EnrollID" -ForegroundColor cyan
        } else {
            Write-Host "ERROR: Cannot find Enrollment ID. Cannot rejoin without Enrollment ID. Exiting." -ForegroundColor Red
            Break
        }

        Write-Host "Removing Scheduled Tasks" -ForegroundColor Magenta
        Try {
            $Tasks | ForEach-Object { Unregister-ScheduledTask -InputObject $_ -Verbose -Confirm:$false }
        } catch {
            Throw $_.Exception.Message
        }
        Write-Host "Removed Scheduled Tasks Successfully" -ForegroundColor Green


        Write-Host "Removing Tasks folder - [" -nonewline -ForegroundColor Magenta
        Write-host "C:\Windows\System32\Tasks\Microsoft\Windows\EnterpriseMgmt\$EnrollID" -ForegroundColor Cyan -NoNewline
        write-host "]" -ForegroundColor Magenta

        $TaskFolder = Test-Path "C:\Windows\System32\Tasks\Microsoft\Windows\EnterpriseMgmt\$EnrollID"
        try {
            if ($TaskFolder) {
                Remove-Item -Path "C:\Windows\System32\Tasks\Microsoft\Windows\EnterpriseMgmt\$EnrollID" -Force -Verbose 
            }
        } catch {
            Throw $_.Exception.Message
        }
        write-host "Task folder successfully removed!" -ForegroundColor Green

        Write-Host "Removing Registry Keys" -ForegroundColor Magenta


        $RegistryPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Enrollments\$EnrollID"
            "HKLM:\SOFTWARE\Microsoft\Enrollments\Status\$EnrollID"
            "HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked\$EnrollID"
            "HKLM:\SOFTWARE\Microsoft\PolicyManager\AdmxInstalled\$EnrollID"
            "HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers\$EnrollID"
            "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\$EnrollID"
            "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Logger\$EnrollID"
            "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Sessions\$EnrollID"
        )


        foreach ($path in $RegistryPaths) {
            $Registrycheck = Test-Path -Path $path

            if ($Registrycheck) {
                Remove-Item -path $path -recurse -Force -verbose
            }
        }

        Write-Host "Removed Registry Keys Successfully" -ForegroundColor Green


        Write-Host "Checking for Intune MDM cert" -ForegroundColor Magenta
        $MDMCert = $null
        $MDMCert = Get-ChildItem -Path cert:\LocalMachine\My | Where-Object { $_.issuer -like '*Intune*' }
        if ($null -ne $MDMCert) {
            $(Get-Item ($MDMCert).PSPath) | Remove-Item -Force -Verbose 
            Write-Host "Removed MDM Certificate Successfully" -ForegroundColor Green
        } else {
            Write-Host "No MDM Certs found." -ForegroundColor Yellow
        }

        Write-Host "Downloading PSExec" -ForegroundColor Magenta
        Invoke-RestMethod -Uri 'https://download.sysinternals.com/files/PSTools.zip' -OutFile $env:TEMP\PSTools.zip
        Write-Host "Unzipping PSExec" -ForegroundColor Magenta
        Expand-Archive -Path $env:TEMP\PSTools.zip -DestinationPath $env:TEMP\PSTools -Force
        Write-Host "Starting PSExec with AutoEnrollMDM" -ForegroundColor Magenta
        $Process = Start-Process -FilePath $env:TEMP\PSTools\psexec.exe -ArgumentList "-i -s -accepteula cmd  /c `"deviceenroller.exe /c /AutoEnrollMDM`"" -Wait -NoNewWindow -PassThru
        if ($process.ExitCode -eq 0) {
            Write-Host "Started AutoEnrollMDM" -ForegroundColor Green
        } else {
            Write-Host "Exit code 1. Something went wrong.  Please verify manually." -ForegroundColor Red
        }
        if ((Get-Service *intune*).Status -ne 'Running') {
            Get-Service *intune* | Start-Service
        }
    }

    # If no computer is given, run on the local computer.
    if ($computerName) {
        invoke-command -computername $computerName -scriptblock $scriptblock
    } else {
        & $scriptblock
    }

}

function Get-ADEI {
    <#
	.SYNOPSIS
		Script to help determine broken machines in a Hybrid Environment.

	.DESCRIPTION
		ADEI stands for Active Directory Entra Intune.

        This script helps break up all objects and does different comparisons to figure out what devices are actually broken and where.

        If you are struggling on knowing which devices are in Entra but not Intune, or what devices are somehow in Intune, but not Entra, or even Intune but not AD, this tool will lay it out and allow you to filter through and find every different instance.

        The devices are added into locally stored Variables with time stamps, so when you're working out the logic on filtering, it's quick to do queries and parsing, and it helps with not having to call MSGraph and load all objects.

        When you're troubleshooting different small variations, speed is key!

	.PARAMETER  Update
		Runs the update.  Grabs all AD / Entra / Intune devices and puts them into their own

	.PARAMETER  OU
		OU allows you to set what OU you want to run the Get-ADComputer portion of the script.  If this is left blank, it'll just grab the base default, which you probably don't want.  
        Setting OU to whatever the top level folder of all your user devices, as opposed to servers, is highly recommended.
        
	.PARAMETER  Computer
		Checks a single computer if it exists in AD, Entra, and Intune.  Quick way to test a single PC without filtering.

	.PARAMETER  help
		A built in helper to find out how to use the program.  Nicely color coded!

	.EXAMPLE
        Get-ADEI -Update
        Get-ADEI -Update -OU "OU=UserAccounts,DC=your,DC=Domain"
        Get-ADEI
        Get-ADEI -Export "C:\Folder"
        Get-ADEI -help
        Get-ADEI -Computer "PC12345"
        $ADDevices | where-object {$_.Entra -eq $false -and $_.Intune -eq False}
        $EntraDevices | where-object {$_.Intune -eq $false} | select-object Displayname, DeviceID

		
	.NOTES
		Please run [Get-ADEI -Update -OU "OUPATHHERE"] before running any of the queries below.
        Note: The [-OU "OUPATHHERE"] parameter is optional, but recommended.

        Please take time to go into the powershell script and edit the [$ADFilter / $Entrafilter / $Intunefilter] before starting.
        The filter has instructions in the array as a comment to help you filter properly.

        To get more data, such as Names, Devices, Dates, TrustType, and more, please use one of the following variables:
        $ADDevices
        $EntraDevices
        $EntraDevicesBroken
        $IntuneDevices

        Each object has a property of AD, Entra, and Intune, each set to $true or $false.
        You can filter each of them out to see which object is in what category. For example:

        This will show you all Active Directory devices not in Entra AND Intune:
        $ADDevices | where-object {$_.Entra -eq $false -and $_.Intune -eq False}

        Incase there are 2 Entra objects, one working, one stale, this premade variable will showcase only objects that don't have a working duplicate:
        $EntraDevicesBroken

        For example if PC123 is in Entra twice, one working, one not working, it won't be in $EntraDevicesBroken, to prevent accidently working on a working Intune object.

#>
    [CmdletBinding()]
    param (
        # Gathering Information
        [switch]$Update,
        [String]$OU = $null,
        [switch]$help,
        [string]$export,
        [Alias("Name", "Computer", "PC")]
        [String]$Computer = $null


    )

    # Set filtering variables

    <# EXAMPLES FOR FILTERING: 
    
    Use Regular expression (regex) to be able to filter out specific naming conventions.

    AD, Entra, and Intune all use different property names for their name:

        AD = name
        Entra = Displayname
        Intune = Devicename

    I set this up because if you have a broken environment, you might have personal devices mixing in with the results.  With this, you can be sure you're filtering anything that matches your company's naming convention.

    Look up how to write Regex if you're not sure - it's not terribly complicated once you figure it out.  A very valuable resource I used as of this writing is www.regex101.com (no affiliate)

    Here's an example for Entra:
    Filtering computer names that start with a prefix followed by numbers 4 numbers, and then anything else. 
    For example: [MATH12345, ENG55933, SCI22223W, SCI334344L]

    $intunefilter = {
        (
            $_.displayname -match "^(?:MATH[A-Z]*)\d{4,}.*$" -or
            $_.displayname -match "^(?:ENG[A-Z]*)\d{4,}.*$" -or
            $_.displayname -match "^(?:SCI[A-Z]*)\d{4,}.*$"
        )
    }

    Filtering only computers that have "TrustType" ServerAD, and operating system is Windows:
        (
            $_.TrustType -eq "ServerAD" -and `
            $_.OperatingSystem -eq "Windows" `
        )

    Common troubleshooting filter properties:
        TrustType
        IsCompliant
        DisplayName
        ApproximateLastSignInDateTime
    #>

    $global:ADfilter = {
        $_.name -match "^(?:A)\d{4,}.*$" -or
        $_.name -match "^(?:AG[A-Z]*)\d{4,}.*$" -or
        $_.name -match "^(?:ASSR[A-Z]*)\d{4,}.*$" -or
        $_.name -match "^(?:AUD[A-Z]*)\d{4,}.*$" -or
        $_.name -match "^(?:BOS[A-Z]*)\d{4,}.*$" -or
        $_.name -match "^(?:CAO[A-Z]*)\d{4,}.*$" -or
        $_.name -match "^(?:CC[A-Z]*)\d{4,}.*$" -or
        $_.name -match "^(?:COOP[A-Z]*).*$" -or
        $_.name -match "^(?:CWS[A-Z]*)\d{4,}.*$" -or
        $_.name -match "^(?:DA[A-Z]*)\d{4,}.*$" -or
        $_.name -match "^(?:DCSS).*$" -or
        $_.name -match "^(?:EH[A-Z]*)\d{4,}.*$" -or
        $_.name -match "^(?:ELEC[A-Z]*)\d{4,}.*$" -or
        $_.name -match "^(?:FIRE[A-Z]*)\d{4,}.*$" -or
        $_.name -match "^(?:FIS[A-Z]*)\d{4,}.*$" -or
        $_.name -match "^(?:GS[A-Z]*)\d{4,}.*$" -or
        $_.name -match "^(?:GJ[A-Z]*)\d{4,}.*$" -or
        $_.name -match "^(?:HLTH).*$" -or
        $_.name -match "^(?:HR[A-Z]*)\d{4,}.*$" -or
        $_.name -match "^(?:HS[A-Z]*)\d{4,}.*$" -or
        $_.name -match "^(?:HHS[A-Z]*)\d{4,}.*$" -or
        $_.name -match "^(?:LAWLIB[A-Z]*)\d{4,}.*$" -or
        $_.name -match "^(?:LIB[A-Z]*)\d{4,}.*$" -or
        $_.name -match "^(?:LL[A-Z]*)\d{4,}.*$" -or
        $_.name -match "^(?:LCSA[A-Z]*)\d{4,}.*$" -or
        $_.name -match "^(?:MH[A-Z]*)\d{4,}.*$" -or
        $_.name -match "^(?:PD[A-Z]*)\d{4,}.*$" -or
        $_.name -match "^(?:PG[A-Z]*)\d{4,}.*$" -or
        $_.name -match "^(?:PROB[A-Z]*)\d{4,}.*$" -or
        $_.name -match "^(?:PROPTAX[A-Z]*)\d{4,}.*$" -or
        $_.name -match "^(?:PURCH[A-Z]*)\d{4,}.*$" -or
        $_.name -match "^(?:REC[A-Z]*)\d{4,}.*$" -or
        $_.name -match "^(?:RET[A-Z]*)\d{4,}.*$" -or
        $_.name -match "^(?:RMA[A-Z]*)\d{4,}.*$" -or
        $_.name -match "^(?:SW[A-Z]*)\d{4,}.*$" -or
        $_.name -match "^(?:TAX[A-Z]*)\d{4,}.*$" -or
        $_.name -match "^(?:TCAG[A-Z]*)\d{4,}.*$" -or
        $_.name -match "^(?:TCICT[A-Z]*)\d{4,}.*$" -or
        $_.name -match "^(?:TCRTA[A-Z]*)\d{4,}.*$" -or
        $_.name -match "^(?:TREAS[A-Z]*)\d{4,}.*$" -or
        $_.name -match "^(?:TW[A-Z]*)\d{4,}.*$" -or
        $_.name -match "^(?:VET[A-Z]*)\d{4,}.*$" -or
        $_.name -match "^(?:WIB[A-Z]*)\d{4,}.*$"
        
    }

    $global:entrafilter = {
        $_.displayname -match "^(?:A)\d{4,}.*$" -or
        $_.displayname -match "^(?:AG[A-Z]*)\d{4,}.*$" -or
        $_.displayname -match "^(?:ASSR[A-Z]*)\d{4,}.*$" -or
        $_.displayname -match "^(?:AUD[A-Z]*)\d{4,}.*$" -or
        $_.displayname -match "^(?:BOS[A-Z]*)\d{4,}.*$" -or
        $_.displayname -match "^(?:CAO[A-Z]*)\d{4,}.*$" -or
        $_.displayname -match "^(?:CC[A-Z]*)\d{4,}.*$" -or
        $_.displayname -match "^(?:COOP[A-Z]*).*$" -or
        $_.displayname -match "^(?:CWS[A-Z]*)\d{4,}.*$" -or
        $_.displayname -match "^(?:DA[A-Z]*)\d{4,}.*$" -or
        $_.displayname -match "^(?:DCSS).*$" -or
        $_.displayname -match "^(?:EH[A-Z]*)\d{4,}.*$" -or
        $_.displayname -match "^(?:ELEC[A-Z]*)\d{4,}.*$" -or
        $_.displayname -match "^(?:FIRE[A-Z]*)\d{4,}.*$" -or
        $_.displayname -match "^(?:FIS[A-Z]*)\d{4,}.*$" -or
        $_.displayname -match "^(?:GS[A-Z]*)\d{4,}.*$" -or
        $_.displayname -match "^(?:GJ[A-Z]*)\d{4,}.*$" -or
        $_.displayname -match "^(?:HLTH).*$" -or
        $_.displayname -match "^(?:HR[A-Z]*)\d{4,}.*$" -or
        $_.displayname -match "^(?:HS[A-Z]*)\d{4,}.*$" -or
        $_.displayname -match "^(?:HHS[A-Z]*)\d{4,}.*$" -or
        $_.displayname -match "^(?:LAWLIB[A-Z]*)\d{4,}.*$" -or
        $_.displayname -match "^(?:LIB[A-Z]*)\d{4,}.*$" -or
        $_.displayname -match "^(?:LL[A-Z]*)\d{4,}.*$" -or
        $_.displayname -match "^(?:LCSA[A-Z]*)\d{4,}.*$" -or
        $_.displayname -match "^(?:MH[A-Z]*)\d{4,}.*$" -or
        $_.displayname -match "^(?:PD[A-Z]*)\d{4,}.*$" -or
        $_.displayname -match "^(?:PG[A-Z]*)\d{4,}.*$" -or
        $_.displayname -match "^(?:PROB[A-Z]*)\d{4,}.*$" -or
        $_.displayname -match "^(?:PROPTAX[A-Z]*)\d{4,}.*$" -or
        $_.displayname -match "^(?:PURCH[A-Z]*)\d{4,}.*$" -or
        $_.displayname -match "^(?:REC[A-Z]*)\d{4,}.*$" -or
        $_.displayname -match "^(?:RET[A-Z]*)\d{4,}.*$" -or
        $_.displayname -match "^(?:RMA[A-Z]*)\d{4,}.*$" -or
        $_.displayname -match "^(?:SW[A-Z]*)\d{4,}.*$" -or
        $_.displayname -match "^(?:TAX[A-Z]*)\d{4,}.*$" -or
        $_.displayname -match "^(?:TCAG[A-Z]*)\d{4,}.*$" -or
        $_.displayname -match "^(?:TCICT[A-Z]*)\d{4,}.*$" -or
        $_.displayname -match "^(?:TCRTA[A-Z]*)\d{4,}.*$" -or
        $_.displayname -match "^(?:TREAS[A-Z]*)\d{4,}.*$" -or
        $_.displayname -match "^(?:TW[A-Z]*)\d{4,}.*$" -or
        $_.displayname -match "^(?:VET[A-Z]*)\d{4,}.*$" -or
        $_.displayname -match "^(?:WIB[A-Z]*)\d{4,}.*$" 
    }

    $global:intunefilter = {
        $_.devicename -match "^(?:A)\d{4,}.*$" -or
        $_.devicename -match "^(?:AG[A-Z]*)\d{4,}.*$" -or
        $_.devicename -match "^(?:ASSR[A-Z]*)\d{4,}.*$" -or
        $_.devicename -match "^(?:AUD[A-Z]*)\d{4,}.*$" -or
        $_.devicename -match "^(?:BOS[A-Z]*)\d{4,}.*$" -or
        $_.devicename -match "^(?:CAO[A-Z]*)\d{4,}.*$" -or
        $_.devicename -match "^(?:CC[A-Z]*)\d{4,}.*$" -or
        $_.devicename -match "^(?:COOP[A-Z]*).*$" -or
        $_.devicename -match "^(?:CWS[A-Z]*)\d{4,}.*$" -or
        $_.devicename -match "^(?:DA[A-Z]*)\d{4,}.*$" -or
        $_.devicename -match "^(?:DCSS).*$" -or
        $_.devicename -match "^(?:EH[A-Z]*)\d{4,}.*$" -or
        $_.devicename -match "^(?:ELEC[A-Z]*)\d{4,}.*$" -or
        $_.devicename -match "^(?:FIRE[A-Z]*)\d{4,}.*$" -or
        $_.devicename -match "^(?:FIS[A-Z]*)\d{4,}.*$" -or
        $_.devicename -match "^(?:GS[A-Z]*)\d{4,}.*$" -or
        $_.devicename -match "^(?:GJ[A-Z]*)\d{4,}.*$" -or
        $_.devicename -match "^(?:HLTH).*$" -or
        $_.devicename -match "^(?:HR[A-Z]*)\d{4,}.*$" -or
        $_.devicename -match "^(?:HS[A-Z]*)\d{4,}.*$" -or
        $_.devicename -match "^(?:HHS[A-Z]*)\d{4,}.*$" -or
        $_.devicename -match "^(?:LAWLIB[A-Z]*)\d{4,}.*$" -or
        $_.devicename -match "^(?:LIB[A-Z]*)\d{4,}.*$" -or
        $_.devicename -match "^(?:LL[A-Z]*)\d{4,}.*$" -or
        $_.devicename -match "^(?:LCSA[A-Z]*)\d{4,}.*$" -or
        $_.devicename -match "^(?:MH[A-Z]*)\d{4,}.*$" -or
        $_.devicename -match "^(?:PD[A-Z]*)\d{4,}.*$" -or
        $_.devicename -match "^(?:PG[A-Z]*)\d{4,}.*$" -or
        $_.devicename -match "^(?:PROB[A-Z]*)\d{4,}.*$" -or
        $_.devicename -match "^(?:PROPTAX[A-Z]*)\d{4,}.*$" -or
        $_.devicename -match "^(?:PURCH[A-Z]*)\d{4,}.*$" -or
        $_.devicename -match "^(?:REC[A-Z]*)\d{4,}.*$" -or
        $_.devicename -match "^(?:RET[A-Z]*)\d{4,}.*$" -or
        $_.devicename -match "^(?:RMA[A-Z]*)\d{4,}.*$" -or
        $_.devicename -match "^(?:SW[A-Z]*)\d{4,}.*$" -or
        $_.devicename -match "^(?:TAX[A-Z]*)\d{4,}.*$" -or
        $_.devicename -match "^(?:TCAG[A-Z]*)\d{4,}.*$" -or
        $_.devicename -match "^(?:TCICT[A-Z]*)\d{4,}.*$" -or
        $_.devicename -match "^(?:TCRTA[A-Z]*)\d{4,}.*$" -or
        $_.devicename -match "^(?:TREAS[A-Z]*)\d{4,}.*$" -or
        $_.devicename -match "^(?:TW[A-Z]*)\d{4,}.*$" -or
        $_.devicename -match "^(?:VET[A-Z]*)\d{4,}.*$" -or
        $_.devicename -match "^(?:WIB[A-Z]*)\d{4,}.*$" 
    }


    # Checks for MS Graph Connection, if none, starts the authorization.
    function Set-MSGraphConnection {
        try {
            $context = Get-MgContext -ErrorAction Stop
            if ($null -eq $context -or $null -eq $context.Account) {
                Write-Host "Not connected to MGGraph." -ForegroundColor Yellow
                Write-Host "Connecting to MGGraph..." -foregroundcolor Cyan
                Connect-MgGraph -Scopes "Device.Read.All" -NoWelcome
                $context = Get-MgContext -ErrorAction Stop

                if ($null -eq $context -or $null -eq $context.Account) {
                    throw "Could not connect to Microsoft Graph."                }
            }

            # Successful MS Graph Connection
            Write-Host "Connected to Microsoft Graph as: " -foregroundcolor Green -nonewline
            Write-Host "$($context.Account)" -ForegroundColor Magenta
        }
        catch {
            Write-Host "Error: $_" -ForegroundColor Red
            Write-Host "Please run the following command:`nConnect-MgGraph -Scopes `"Device.Read.All`"" -ForegroundColor Yellow
            return
        }
    }

    # Sets $ADDevices / $EntraDevices / $IntuneDevices
    function Update-Devices {
        Write-host "Retrieving Active Directory Computer Objects..." -ForegroundColor Cyan
        if (!$OU) {
            Write-host "-OU not set.  Searching entire Active Directory." -ForegroundColor Yellow
            $Global:ADDevices = Get-ADComputer -Filter * -Properties *
        } else {
            Write-host "TargetOU: " -NoNewline -ForegroundColor Cyan
            Write-host "$OU" -ForegroundColor Yellow
            $Global:ADDevices = Get-ADComputer -Filter * -Properties * -SearchBase $OU
        }
        Write-Host "`$ADDevices" -foregroundcolor white -BackgroundColor DarkBlue -nonewline
        write-host " updated!" -ForegroundColor Green

        Write-Host "Retrieving Entra devices..." -ForegroundColor Cyan
        $Global:EntraDevices = Get-MGDevice -All | Where-Object { $_.OperatingSystem -eq "Windows" }
        Write-Host "`$EntraDevices" -foregroundcolor white -BackgroundColor DarkBlue -nonewline
        Write-host " updated!" -ForegroundColor Green

        Write-Host "Retrieving Intune Objects..." -ForegroundColor Cyan
        $Global:IntuneDevices = Get-MGDeviceManagementManagedDevice -All
        Write-Host "`$IntuneDevices" -foregroundcolor white -BackgroundColor DarkBlue -nonewline
        Write-host " updated!" -ForegroundColor Green

        $Global:SyncTime = Get-Date

    }
        

    # 1. Main function that creates properties [AD, Entra, Intune] for [$ADDevices, $EntraDevices, $IntuneDevices]
        # The reason for the local variable is to be able to call $ADDevices easily without having to constantly connect to MSGraph / call AD.  This is good for troubleshooting speed as it's all loaded in memory.
    # 2. Checks what matches between all variables, and if it matches sets the flag to $true, otherwise by default it's set to $false
    # 3. Creates $EntraDevicesBroken to remove any duplicates to avoid listing machines that are working.  More explained in the help file.
    # 4. Lists out how many machines are broken so you know what kind of situation you're in.
    function Compare-ADEI {
        $global:EntraDevicesBroken = @()

        $ADDevices | add-member -notepropertyname "AD" -notepropertyvalue $true -force
        $ADDevices | add-member -notepropertyname "Entra" -notepropertyvalue $false -force
        $ADDevices | add-member -notepropertyname "Intune" -notepropertyvalue $false -force

        $EntraDevices | add-member -notepropertyname "AD" -notepropertyvalue $false -force
        $EntraDevices | add-member -notepropertyname "Entra" -notepropertyvalue $true -force
        $EntraDevices | add-member -notepropertyname "Intune" -notepropertyvalue $false -force

        $IntuneDevices | add-member -notepropertyname "AD" -notepropertyvalue $false -force
        $IntuneDevices | add-member -notepropertyname "Entra" -notepropertyvalue $false -force
        $IntuneDevices | add-member -notepropertyname "Intune" -notepropertyvalue $true -force

        
            # Initialize progress bar
        $totalCount = $ADDevices.Count
        $counter = 0

        # Check AD for Entra
        foreach ($ADDevice in $ADDevices) {
            $EntraDeviceMatchAD = $EntraDevices | where-object $entrafilter | Where-Object { $_.DisplayName -eq $ADDevice.Name }

            # Check Entra Device ID for matching Intune Device ID
            if ($EntraDeviceMatchAD) {
                $ADDevice.Entra = $true
                
                # If $ADMatchEntra has 2 objects (duplicates in Entra), then check for each of them
                foreach ($EntraMatch in $EntraDeviceMatchAD) {
                    
                    $EntraMatch.AD = $true
                    $IntuneDeviceMatchEntra = $IntuneDevices | where-object { $_.AzureADDeviceID -eq $EntraMatch.DeviceID }

                    if ($IntuneDeviceMatchEntra) {
                        $ADDevice.Intune = $true
                        $EntraMatch.Intune = $true
                        $IntuneDeviceMatchEntra.Entra = $true
                        $IntuneDeviceMatchEntra.AD = $true
                        break
                    }
                }
                
        }

                # Update progress bar
                $counter++
                Write-Progress -Activity "Getting data for AD, Entra, Intune" `
                -Status "Processing device $counter of $totalCount" `
                -PercentComplete (($counter / $totalCount) * 100)

    }


    $entraDevicesByDisplayName = $EntraDevices | Group-Object -Property DisplayName

    foreach ($group in $entraDevicesByDisplayName) {
        # Check if there's any Intune = $true within this group
        $hasIntuneEntry = $group.Group | Where-Object { $_.Intune -eq $true }

        # If no entry in the group has Intune = $true, add all entries with Intune = $false to the result list
        if (-not $hasIntuneEntry) {
            $global:EntraDevicesBroken += $group.Group | Where-Object { $_.Intune -eq $false }
        }
    }
        
            Write-Progress -PercentComplete 100 -Activity "Comparison Complete" -Status "All devices processed"

    }

    # Checks each computer if it exists or is missing from AD, Entra, or Intune to quickly see where something is broken.
    function Get-ADEISingle {
        Param ([String]$ComputerName
        )

        $ADComputerGet = $null
        $EntraComputerGet = $null
        $IntuneComputerGet = $null

        $ADComputerGet = ($ADDevices | Where-Object name -eq "$ComputerName")
        $EntraComputerGet = ($EntraDevices | Where-Object DisplayName -eq "$ComputerName")
        $IntuneComputerGet = ($IntuneDevices | Where-Object DeviceName -eq "$ComputerName")

        if ($null -eq $ADComputerGet -and $null -eq $EntraComputerGet -and $null -eq $IntuneComputerGet) {
            write-host "Error: No computer exists by the name of $ComputerName." -ForegroundColor Red
            return
        }

        Write-host "Checking for $ComputerName`:" -ForegroundColor Magenta
        if ($null -eq $ADComputerGet) {
            Write-Host "AD:`t" -NoNewline -ForegroundColor Yellow
            Write-Host "NO" -ForegroundColor Red
        } else {
            Write-Host "AD:`t" -NoNewline -ForegroundColor Yellow
            Write-Host "YES" -ForegroundColor Green
        }

        if ($null -eq $EntraComputerget) {
            Write-Host "Entra:`t" -NoNewline -ForegroundColor Cyan
            Write-Host "NO" -ForegroundColor Red
        } else {
            Write-Host "Entra:`t" -NoNewline -ForegroundColor Cyan
            Write-Host "YES" -ForegroundColor Green
        }

        if ($null -eq $IntuneComputerGet) {
            Write-Host "Intune:`t" -NoNewline -ForegroundColor Gray
            Write-Host "NO" -ForegroundColor Red
        } else {
            Write-Host "Intune:`t" -NoNewline -ForegroundColor Gray
            Write-Host "YES" -ForegroundColor Green
        }
        
    }

    function Get-ADEIHelp {
        write-host "******`n******" -ForegroundColor Magenta
        write-host "Please run [" -NoNewline
        write-host "Get-ADEI -Update -OU `"OUPATHHERE`"" -NoNewline -ForegroundColor Yellow
        write-host "] before running any of the queries below.`nNote: The [" -nonewline 
        write-host "-OU `"OUPATHHERE`"" -nonewline -ForegroundColor Yellow
        write-host "] parameter is optional, but highly recommended.`n" 

        write-host "Please take time to go into the powershell script and edit the [" -nonewline 
        write-host "`$ADFilter / `$Entrafilter / `$Intunefilter" -NoNewline -ForegroundColor Yellow
        write-host "] before starting." 
        write-host "The filter has instructions (in the comment above it at the top of all the code) to help you filter properly.`n" 

        write-host "To get more data, such as Names, Devices, Dates, Trust Type, and more, please use one of the following variables:" 
        write-host "`$ADDevices" -ForegroundColor Yellow
        write-host "`$EntraDevices`n`$EntraDevicesBroken" -ForegroundColor Cyan
        write-host "`$IntuneDevices" -ForegroundColor Green
        write-host ""
        write-host "Each object has a property of AD, Entra, and Intune, each set to " -nonewline 
        write-host "`$true" -ForegroundColor Green -nonewline
        write-host " or " -nonewline 
        write-host "`$false." -nonewline -ForegroundColor red
        write-host "`nYou can filter each of them out to see which object is in what category. For example:`n" 
        write-host "This will show you all Active Directory devices not in Entra AND Intune:" 
        write-host "`$ADDevices | where-object {`$_.Entra -eq `$false -and `$_.Intune -eq False}`n" -ForegroundColor Yellow

        write-host "Incase there are 2 Entra objects, one working in Intune, one stale, this premade variable will showcase only objects that don't have a working Intune duplicate:" 
        write-host "`$EntraDevicesBroken`n" -ForegroundColor Cyan
        write-host "For example if PC123 is in Entra twice, one connected to Intune, and one stale, it won't be in `$EntraDevicesBroken, to prevent accidently working on a working Intune object."
        write-host "`$EntraDevicesBroken is probably your best bet to get a big list of all computers that are in Entra, but not working properly in Intune." 
        write-host "******`n******" -ForegroundColor Magenta
    }

    function Export-ADEIReport {
        # Checks to see if the export filepath has a '\' at the end of it.  If it does not, add it.
        # C:\folder = C:\folder\

        try {
            get-childitem -path $export -erroraction stop | out-null
        } catch {
            write-host "The path [$export] does not exist.  Please enter a correct path." -ForegroundColor red
            return
            }
        
        if ($export[-1] -ne '\') { 
            $export = "$export\" 
        }
        

        $ADDevices | export-csv -path "${export}ADDevices.csv" -Verbose -notypeinformation
        $EntraDevices | export-csv -path "${export}EntraDevices.csv" -Verbose -NoTypeInformation
        $EntraDevicesBroken | export-csv -path "${export}EntraDevicesBroken.csv" -Verbose -NoTypeInformation
        $IntuneDevices | export-csv -path "${export}IntuneDevices.csv" -Verbose -NoTypeInformation
        return

    }

    function Get-ADEIReport {
        Write-host "************************" -ForegroundColor yellow
        write-host "Broken devices report:"
        Write-host "************************" -ForegroundColor Yellow

        Write-host "Last Sync Time: " -foregroundcolor Green -NoNewline
        Write-Host "$($Global:ADDate.tostring("MM/dd/yy hh:mm tt"))" -foregroundcolor Magenta
        Write-Host ""

        write-host "Total " -nonewline -ForegroundColor Magenta
        write-host "AD " -nonewline -ForegroundColor yellow
        write-host "Devices: " -ForegroundColor Magenta -nonewline
        write-host "$($ADDevices.count)" 

        write-host "Total " -nonewline -ForegroundColor Magenta
        write-host "Entra " -nonewline -ForegroundColor Cyan
        write-host "Devices: " -ForegroundColor Magenta -nonewline
        write-host "$($EntraDevices.count)" 

        write-host "Total " -nonewline -ForegroundColor Magenta
        write-host "Intune " -nonewline -ForegroundColor Green
        write-host "Devices: " -ForegroundColor Magenta -nonewline
        write-host "$($IntuneDevices.count)" 

        write-host ""
        
        Write-Host "In " -nonewline
        write-host "AD" -ForegroundColor Yellow -nonewline
        write-host " | NOT " -nonewline 
        write-host "Entra" -nonewline -ForegroundColor Cyan
        write-host ": " -nonewline
        write-host "$($ADDevices | where-object $adfilter | where-object {$_.Entra -eq $false} | measure-object | select-object -ExpandProperty Count)" -ForegroundColor Red

        Write-Host "In " -nonewline
        write-host "AD" -ForegroundColor Yellow -nonewline
        write-host " | NOT " -nonewline 
        write-host "Intune" -nonewline -ForegroundColor Green
        write-host ": " -nonewline
        write-host "$($ADDevices | where-object $adfilter | where-object {$_.Intune -eq $false} | measure-object | select-object -ExpandProperty Count)" -ForegroundColor red
        write-host ""

        Write-Host "In " -nonewline
        write-host "Entra" -ForegroundColor Cyan -nonewline
        write-host " | NOT " -nonewline 
        write-host "AD" -nonewline -ForegroundColor Yellow
        write-host ": " -nonewline
        write-host "$($EntraDevices | where-object $entrafilter | where-object {$_.AD -eq $false} | measure-object | select-object -ExpandProperty Count)" -ForegroundColor red

        Write-Host "In " -nonewline
        write-host "Entra" -ForegroundColor cyan -nonewline
        write-host " | NOT " -nonewline 
        write-host "Intune" -nonewline -ForegroundColor Green
        write-host ": " -nonewline
        write-host "$($EntraDevicesBroken | where-object $entrafilter | measure-object | select-object -ExpandProperty Count)" -ForegroundColor red
        write-host ""

        Write-Host "In " -nonewline
        write-host "Intune" -ForegroundColor Green -nonewline
        write-host " | NOT " -nonewline 
        write-host "AD" -nonewline -ForegroundColor Yellow
        write-host ": " -nonewline
        write-host "$($IntuneDevices | where-object $intunefilter | where-object {$_.AD -eq $false} | measure-object | select-object -ExpandProperty Count)" -ForegroundColor red

        Write-Host "In " -nonewline
        write-host "Intune" -ForegroundColor Green -nonewline
        write-host " | NOT " -nonewline 
        write-host "Entra" -nonewline -ForegroundColor Cyan
        write-host ": " -nonewline
        write-host "$($IntuneDevices | where-object $intunefilter | where-object {$_.Entra -eq $false} | measure-object | select-object -ExpandProperty Count)" -ForegroundColor red
        write-host ""
    }


    if ($help) {
        Get-ADEIHelp
        return
    }


    if ($Update) {
        $measuredtime = measure-command {
            write-host "Start time:"$(Get-Date -format "MM/dd/yyyy @ hh:mm:ss tt") -foregroundcolor Yellow
            Set-MSGraphConnection
            Update-Devices
            Compare-ADEI
            Get-ADEIReport
            write-host "End time:"$(Get-Date -format "MM/dd/yyyy @ hh:mm:ss tt") -foregroundcolor Yellow
    }
    write-host ("Total time ran: {0:D2}:{1:D2}:{2:D2}" -f $measuredtime.Hours, $measuredtime.Minutes, $measuredtime.Seconds) -foregroundcolor yellow
        return
    }


    # If Sync Time never ran, then error out.
    if ($null -eq $SyncTime) {
        write-host "Error: No data. Please run [" -ForegroundColor red -nonewline
        write-host "Get-ADEI -Update -OU `"OUPATHHERE`"" -nonewline
        write-host "] first." -ForegroundColor red
        return
    }

    if ($export) {
        Export-ADEIReport
        return
    }

    if ($Computer) {
        Get-ADEISingle -ComputerName $Computer
        return 
        }

    Get-ADEIReport
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
        $computerList = @()
    
        if ($Clipboard -or $auto) {
            $computerList = (Get-Clipboard).split("\n").split(",").split("|")
        } else {
            write-host "Enter a blank space to continue." -ForegroundColor Blue
            write-host "Copy and paste asset tags:" -ForegroundColor Cyan
    
            while (1) {
                read-host | Set-Variable r
                if (!$r) {break}
                $computerList += $r
                }
    
            if ($computerList.count -eq 0) {
                write-host "ERROR: No computers entered." -foregroundcolor red -BackgroundColor black
                exit 1
            }
            write-Host "********************`n" -ForegroundColor Cyan
        } 
    
        
        $computerList = $computerList.split("\n").split(",").split("|").trim()
        $totalComputers = $computerList.Count  # Total number of computers
    
        # If $computerList has 1 entry, run the syntax, instead of the foreach loop.  Else if there is >=2, run foreach loop.
        if ($totalComputers -eq 1) {         
                $computer = Get-ADComputer -Filter "SamAccountName -like '*$($computerList)*'" -Properties dnshostname -ErrorAction Stop
                if ($computer) {
                    $successfulComputers += [PSCustomObject]@{
                        ComputerName = $computerList
                        HostName = $computer.dnshostname
                        Name = $computer.SamAccountName.trim('$')
                    }
                } else {
                    $failedComputers += [PSCustomObject]@{
                        ComputerName = $computerList
                    }
                }
            }
            else {
            # Use foreach loop to process each computer name
            foreach ($index in 0..($totalComputers - 1)) {
                $computerName = $computerList[$index]
    
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