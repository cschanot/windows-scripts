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

Set-ItemProperty -Path REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -Value 0


$isRunning = wsl.exe -u root service docker status
# WILL BE UNRECOGNIZED IF NOT INSTALLED
if ($isRunning -like "*unrecognized*") {
### INSTALL AND RUN DOCKER
wsl  curl -s https://get.docker.com/ `| bash
wsl -u root service docker start

}

## IF DOCKER ALREADY INSTALLED BUT NOT RUNNING RUN IT
if ($isRunning -like "*not*") {
wsl -u root service docker start
# wsl docker run --detach --name watchtower --volume /var/run/docker.sock:/var/run/docker.sock containrrr/watchtower
}
else {
wsl docker ps
wsl -u root docker run --detach --name watchtower --volume /var/run/docker.sock:/var/run/docker.sock containrrr/watchtower
}
exit
