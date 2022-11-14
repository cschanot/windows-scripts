function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if ((Test-Admin) -eq $false)  {
    if ($elevated) {
        # tried to elevate, did not work, aborting
    } else {
        Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition))
    }
    exit
}

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
$DOWNLOADPATH = (New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path

# Download second script, this will run every reboot

New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
    -Name "Application" `
    -Value "c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe $DOWNLOADPATH\wslfinal.ps1"
$wshell = New-Object -ComObject Wscript.Shell
  $answer = $wshell.Popup("OK TO RESTART?",0,"RESTART WARNING",0x4)

if($answer -eq 7){exit}
Restart-Computer -Force
