<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
.NOTES
    CreateUpdateDownloader() and CreateUpdateInstaller() methods can't be called from a remote computer - E_ACCESSDENIED.
    prooflink https://msdn.microsoft.com/en-us/library/windows/desktop/aa387288(v=vs.85).aspx
#>
function Install-WindowsUpdates {
    [CmdletBinding()]
    Param (
        # you'll never guess what it can be
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [string]$computerName,

        # modify post-install behavior
        [Parameter(Mandatory = $true)]
        [ValidateSet('Reboot', 'InstallOnly')]
        $installOption
    )

    Begin {
	    $Script = 
@'
<# listing required updates #>
$updateSession = New-Object -ComObject 'Microsoft.Update.Session'
$updateSearcher = $updateSession.CreateUpdateSearcher()
$updatePending = $updateSearcher.Search('IsInstalled = 0')
$updatePending.Updates | foreach {$_.AcceptEula()}

<# downloading #>
$updateDownloader = $updateSession.CreateUpdateDownloader()
$updateDownloader.Updates = $updatePending.Updates
$donwloadResult = $updateDownloader.Download()

<# installing #>
$updateInstaller = $updateSession.CreateUpdateInstaller()
$updateInstaller.Updates = $updatePending.Updates
$InstallResult = $updateInstaller.Install()

<# reboot now #>

'@

        if ($installOption -eq 'Reboot') {
            $Script += 'if ($InstallResult.RebootRequired -eq "True") { Shutdown -r -t 0 }'
        }
	    $User = [Security.Principal.WindowsIdentity]::GetCurrent()
        <#
        $computername = 'altdevadfs01'
        #>
    }
    Process {
        $computerHash = [ordered]@{ ComputerName = $computerName}
        try {
            $session = New-PSSession -ComputerName $computerName -ErrorAction Stop
            $computerHash.State = 'Online'
        }
        catch [System.Management.Automation.Remoting.PSRemotingTransportException] {
            $computerHash.State = 'Kerberos auth error'
            $computerObject =  New-Object -TypeName psobject -Property $computerHash
            return $computerObject
        }
        catch {
            $computerHash.ComputerState = 'General connection error'
            $computerObject =  New-Object -TypeName psobject -Property $computerHash
            return $computerObject
        }

        #region Get WU state
        $computerHash.PedingUpdates = Invoke-Command -Session $session -ScriptBlock {
            $updateSession = New-Object -ComObject 'Microsoft.Update.Session'
            $updateSearcher = $updateSession.CreateUpdateSearcher()
            $updatePending = $updateSearcher.Search('IsInstalled = 0')
            $updatePending.Updates.count
        }
        $computerHash.PedingReboot = Invoke-Command -Session $session -ScriptBlock {
            Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
        }        

        $installTask = Invoke-Command -Session $session -ScriptBlock {
            $TaskName = "WUinstallWorkaround"
		    $Scheduler = New-Object -ComObject Schedule.Service
		    $Scheduler.Connect()
            $RootFolder = $Scheduler.GetFolder("\")
            $task = $RootFolder.GetTasks(1)  | Where-Object {$_.Name -eq $TaskName}
            $task.State
        }
        if ($installTask -eq 3) {$computerHash.TaskState = 'Already Running'}
        else {$computerHash.TaskState = 'Idle'}
		#endregion
		
		$rebootFlag = ($computerHash.PedingReboot -eq $true) -and ($installOption -eq 'Reboot')
		if ($rebootFlag) {
			Restart-Computer -ComputerName $computerName -AsJob | Out-Null
		}

		$updatesFlag = ($computerHash.PedingUpdates -ne 0) -and ($computerHash.PedingReboot -eq $false) -and ($computerHash.TaskState -eq 'Idle')
        if ($updatesFlag) {
            $computerHash.TaskState = 'Started'
	        Invoke-Command -Session $session -ArgumentList ($Script,$User) -AsJob -ScriptBlock {
		        param ($Script,$User)
		        $ScriptFile = $env:LocalAppData + "\Install-Updates.ps1"
		        $Script | Out-File $ScriptFile
		        if (-Not(Test-Path $ScriptFile)) {
			        Write-Error "$("Failed to create file:" + $ScriptFile)"
			        return 
		        }

		        #Create a scheduled task
		        $TaskName = "WUinstallWorkaround"
		        $arg = "-NoProfile -NoLogo -NonInteractive -ExecutionPolicy Bypass -File $ScriptFile"

		        $Scheduler = New-Object -ComObject Schedule.Service
		        $Scheduler.Connect()

		        $RootFolder = $Scheduler.GetFolder("\")
		        #Delete existing task
		        if ($RootFolder.GetTasks(1) | Where-Object {$_.Name -eq $TaskName}) {
			        Write-Debug("Deleting existing task" + $TaskName)
			        $RootFolder.DeleteTask($TaskName, 0)
		        }

		        $Task = $Scheduler.NewTask(0)
		        $RegistrationInfo = $Task.RegistrationInfo
		        $RegistrationInfo.Description = $TaskName
		        $RegistrationInfo.Author = $User.Name

		        $Triggers = $Task.Triggers
		        $Trigger = $Triggers.Create(7) #TASK_TRIGGER_REGISTRATION: Starts the task when the task is registered.
		        $Trigger.Enabled = $true

		        $Settings = $Task.Settings
		        $Settings.Enabled = $True
		        $Settings.StartWhenAvailable = $True
		        $Settings.Hidden = $False

		        $Action = $Task.Actions.Create(0)
		        $Action.Path = "powershell"
		        $Action.Arguments = $arg

		        #Tasks will be run with the highest privileges
		        $Task.Principal.RunLevel = 1

		        #Start the task to run in Local System account. 6: TASK_CREATE_OR_UPDATE
		        $RootFolder.RegisterTaskDefinition($TaskName, $Task, 6, "SYSTEM", $Null, 1) | Out-Null
		        #Wait for running task finished
		        $RootFolder.GetTask($TaskName).Run(0) | Out-Null
		        while ($Scheduler.GetRunningTasks(0) | Where-Object {$_.Name -eq $TaskName}) {
			        Start-Sleep -s 1
		        }

		        #Clean up
		        $RootFolder.DeleteTask($TaskName, 0)
		        Remove-Item $ScriptFile
	        } | Out-Null

        }

        
        $computerObject =  New-Object -TypeName psobject -Property $computerHash
        return $computerObject 
    }
    End {

    }
}