$DOWNLOADPATH = (New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path + "\wsl_setup.ps1"
$DOWNLOADPATHF = (New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
Invoke-WebRequest -Headers @{"Cache-Control"="no-cache"} -Uri "https://raw.githubusercontent.com/cschanot/windows-scripts/main/setup_wsl.ps1" -OutFile $DOWNLOADPATH

Function Check-RunAsAdministrator()
{
  #Get current user context
  $CurrentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
  
  #Check user is running the script is member of Administrator Group
  if($CurrentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator))
  {
       Write-host "Script is running with Administrator privileges!"
  }
  else
    {
       #Create a new Elevated process to Start PowerShell
       $ElevatedProcess = New-Object System.Diagnostics.ProcessStartInfo "PowerShell";
 
       # Specify the current script path and name as a parameter
       $ElevatedProcess.Arguments = "& '" + $DOWNLOADPATH + "'"
 
       #Set the Process to elevated
       $ElevatedProcess.Verb = "runas"
 
       #Start the new elevated process
       [System.Diagnostics.Process]::Start($ElevatedProcess)
 
       #Exit from the current, unelevated, process
       Exit
 
    }
}
 
#Check Script is running with Elevated Privileges
Check-RunAsAdministrator

#Set-ExecutionPolicy RemoteSigned -Force
## GET RID OF THAT PESKY UAC PROMPT
Set-ItemProperty -Path REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -Value 0
### PROBABLY SHOULD CHECK BEFORE WE DO BELOW ALSO CHANGE TO Set-ItemProperty
reg add HKCU\Software\Microsoft\Powershell\1\ShellIds\Microsoft.PowerShell /v ExecutionPolicy /t REG_SZ /d RemoteSigned /f



# Enable Virtual Machine Platform feature
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
# Enable WSL feature
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
# To set the WSL default version to 2.
# Any distribution installed after this, would run on WSL 2
wsl --set-default-version 2
wsl --install
$URL = "https://raw.githubusercontent.com/cschanot/windows-scripts/main/wslfinal.ps1"
Invoke-WebRequest -URI $URL -OutFile $DOWNLOADPATHF\wslfinal.ps1

# Download second script, this will run every reboot

New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
    -Name "Application" `
    -Value "c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe $DOWNLOADPATHF\wslfinal.ps1"
$wshell = New-Object -ComObject Wscript.Shell
  $answer = $wshell.Popup("OK TO RESTART?",0,"RESTART WARNING",0x4)

if($answer -eq 7){exit}
Restart-Computer -Force
