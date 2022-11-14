$Loc = Get-Location
"Security.Principal.Windows" | % { IEX "( [ $_`Principal ] [$_`Identity ]::GetCurrent() ).IsInRole( 'Administrator' )" } | ? {
    $True | % { $Arguments =  @('-NoProfile','-ExecutionPolicy Bypass','-NoExit','-File',"`"$($MyInvocation.MyCommand.Path)`"","\`"$Loc\`"");
    Start-Process -FilePath PowerShell.exe -Verb RunAs -ArgumentList $Arguments; } }

(Get-Location).ToString()

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
