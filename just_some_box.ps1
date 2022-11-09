
##1
#God mode
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
     $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
     Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
     Exit
    }
   }
#shoutout = expta

#####var begins
$ScriptName = 'W10GenericBox.ps1'
$ScriptPath = $MyInvocation.MyCommand.Path
$CurrentUser = ($env:UserName)
$CurrentHostname = ($env:ComputerName)
$UserDirs = 'c:\apps', 'c:\tools\scripts', 'c:\tmp','c:\hyperv','c:\wsl'
$DefenderExcludeDirs = 'c:\tmp','c:\hyperv','c:\wsl'

#$ScriptLocation = Split-Path $ScriptPath
#$PSScriptRoot # - NOTUSED // the directory where the script exists, not the target directory the script is running in
#$PSCommandPath #- NOTUSED // the full path of the script

#####var ends

 #Start transcript and log
 Start-Transcript -Path .\$ScriptName.txt -NoClobber

 #Start install by splash etc
  Write-Host "`n"
  Write-Host " ____________________________________________________________________________ " -ForegroundColor White 
  Write-Host "| "  -ForegroundColor White -NoNewline; Write-Host "  " -ForegroundColor Green -NoNewline; Write-Host "                                                                         |" -ForegroundColor White   
  Write-Host "| "  -ForegroundColor White -NoNewline; Write-Host "A " -ForegroundColor Green -NoNewline; Write-Host "                                                                         |" -ForegroundColor White  
  Write-Host "| "  -ForegroundColor White -NoNewline; Write-Host "          ██ ▄█▀▄▄▄     ▓██   ██▓ █     █░ ▒█████  ▒███████▒ " -ForegroundColor Red -NoNewline; Write-Host "              |" -ForegroundColor White  
  Write-Host "| "  -ForegroundColor White -NoNewline; Write-Host "          ██▄█▒▒████▄    ▒██  ██▒▓█░ █ ░█░▒██▒  ██▒▒ ▒ ▒ ▄▀░ " -ForegroundColor Red -NoNewline; Write-Host "              |" -ForegroundColor White  
  Write-Host "| "  -ForegroundColor White -NoNewline; Write-Host "          ▓███▄░▒██  ▀█▄   ▒██ ██░▒█░ █ ░█ ▒██░  ██▒░ ▒ ▄▀▒░  " -ForegroundColor Red -NoNewline; Write-Host "             |" -ForegroundColor White  
  Write-Host "| "  -ForegroundColor White -NoNewline; Write-Host "          ▓██ █▄░██▄▄▄▄██  ░ ▐██▓░░█░ █ ░█ ▒██   ██░  ▄▀▒   ░ " -ForegroundColor Red -NoNewline; Write-Host "             |" -ForegroundColor White  
  Write-Host "| "  -ForegroundColor White -NoNewline; Write-Host "          ▒██▒ █▄▓█   ▓██▒ ░ ██▒▓░░░██▒██▓ ░ ████▓▒░▒███████▒ " -ForegroundColor Red -NoNewline; Write-Host "             |" -ForegroundColor White
  Write-Host "| "  -ForegroundColor White -NoNewline; Write-Host "          ▒██▒ █▄▓█   ▓██▒ ░ ██▒▓░░░██▒██▓ ░ ████▓▒░▒███████▒ " -ForegroundColor Red -NoNewline; Write-Host "             |" -ForegroundColor White   
  Write-Host "| "  -ForegroundColor White -NoNewline; Write-Host "          ▒ ▒▒ ▓▒▒▒   ▓▒█░  ██▒▒▒ ░ ▓░▒ ▒  ░ ▒░▒░▒░ ░▒▒ ▓░▒░▒ " -ForegroundColor Red -NoNewline; Write-Host "             |" -ForegroundColor White   
  Write-Host "| "  -ForegroundColor White -NoNewline; Write-Host "          ░ ░▒ ▒░ ▒   ▒▒ ░▓██ ░▒░   ▒ ░ ░    ░ ▒ ▒░ ░░▒ ▒ ░ ▒ " -ForegroundColor Red -NoNewline; Write-Host "             |" -ForegroundColor White   
  Write-Host "| "  -ForegroundColor White -NoNewline; Write-Host "          ░ ░░ ░  ░   ▒   ▒ ▒ ░░    ░   ░  ░ ░ ░ ▒  ░ ░ ░ ░ ░ " -ForegroundColor Red -NoNewline; Write-Host "             |" -ForegroundColor White   
  Write-Host "| "  -ForegroundColor White -NoNewline; Write-Host "          ░  ░        ░  ░░ ░         ░        ░ ░    ░ ░     " -ForegroundColor Red -NoNewline; Write-Host "             |" -ForegroundColor White   
  Write-Host "| "  -ForegroundColor White -NoNewline; Write-Host "          ░ ░                       ░         " -ForegroundColor Red -NoNewline; Write-Host "                             |" -ForegroundColor White
  Write-Host "|                                                                   "  -ForegroundColor White -NoNewline; Write-Host " PR0j3ct" -ForegroundColor Green -NoNewline; Write-Host " |" -ForegroundColor White   
  Write-Host "|                                                                            |" -ForegroundColor White 
  Write-Host "|____________________________________________________________________________|" -ForegroundColor White 
  Write-Host "|                                                                            |" -ForegroundColor White 
  Write-Host "| "  -ForegroundColor White -NoNewline; Write-Host "                               W10GenericBox" -ForegroundColor Green -NoNewline; Write-Host "                               |" -ForegroundColor White   
  Write-Host "|                                                                            |" -ForegroundColor White 
  Write-Host "|                                  Version 2k22.1                            |" -ForegroundColor White 
  Write-Host "|                                  Created by                                |" -ForegroundColor White 
  Write-Host "|                              github.com/kaywoz                             |" -ForegroundColor White 
  Write-Host "|                                                                            |" -ForegroundColor White 
  Write-Host "|____________________________________________________________________________|" -ForegroundColor White 
  Write-Host ""
  
   
##2 Base stuff
$NewHostname = Read-Host 'Hostname ?'

Write-Host "***Changing hostname from"$CurrentHostname" to: "$NewHostname  -ForegroundColor Green
Rename-Computer -NewName $NewHostname | Out-Null  

$thisPCIconRegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
$thisPCRegValname = "{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
$item = Get-ItemProperty -Path $thisPCIconRegPath -Name $thisPCRegValname -ErrorAction SilentlyContinue

if ($item) {
Set-ItemProperty  -Path $thisPCIconRegPath -name $thisPCRegValname -Value 0  | Out-Null  
}

else {
New-ItemProperty -Path $thisPCIconRegPath -Name $thisPCRegValname -Value 0 -PropertyType DWORD  | Out-Null  
}

Write-Host "***Creating standard DIR's..."  -ForegroundColor Green
try {
    New-Item -Path $UserDirs -ItemType "Directory" -ErrorAction Stop | Out-Null
        }
catch {
    Write-Warning -Message "ERROR: Directories already exist ----> Skipping.";
    }





##3 install and configure features
Enable-WindowsOptionalFeature -Online -FeatureName containers -All -NoRestart | Out-Null
Write-Host "***installed containers..."  -ForegroundColor Green

Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -NoRestart | Out-Null
Write-Host "***installed hyper-v..."  -ForegroundColor Green

Enable-WindowsOptionalFeature -FeatureName "Containers-DisposableClientVM" -All -Online -NoRestart | Out-Null
Write-Host "***installed sandbox..."  -ForegroundColor Green

##4 install and configure packagemanagers

Write-Host "***installed winget..."  -ForegroundColor Green
Install-PackageProvider -Name NuGet -Force | Out-Null

. { Invoke-WebRequest -useb https://boxstarter.org/bootstrapper.ps1 } | Invoke-Expression; Get-Boxstarter -Force | Out-Null 
Write-Host "***installed BoxStarter..."  -ForegroundColor Green

Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1')) | Out-Null 
Write-Host "***re-checking chocolatey..."  -ForegroundColor Green

iex "& {$(irm get.scoop.sh)} -RunAsAdmin" | Out-Null 
Write-Host "***installed scoop..."  -ForegroundColor Green


##5.1 install and configure choco packages
Write-Host "***installing choco packages..."  -ForegroundColor Yellow

choco install 7zip.install -y | Out-Null
Write-Host "*** 7zip installed..."  -ForegroundColor Green

choco install vlc -y | Out-Null 
Write-Host "*** vlc installed..."  -ForegroundColor Green

choco install notepadplusplus.install -y | Out-Null 
Write-Host "*** notepadplusplus installed..."  -ForegroundColor Green

choco install powershell -y | Out-Null 
Write-Host "*** powershell installed..."  -ForegroundColor Green

choco install powershell-core -y | Out-Null 
Write-Host "*** powershell-core installed..."  -ForegroundColor Green

choco install curl -y | Out-Null 
Write-Host "*** curl installed..."  -ForegroundColor Green

choco install wget -y | Out-Null 
Write-Host "*** wget installed..."  -ForegroundColor Green

choco install python3 -y | Out-Null 
Write-Host "*** python3 installed..."  -ForegroundColor Green

choco install adobereader -y | Out-Null 
Write-Host "*** adobereader installed..."  -ForegroundColor Green

choco install chromium -y | Out-Null 
Write-Host "*** chromium installed..."  -ForegroundColor Green


choco install treesizefree -y | Out-Null 
Write-Host "*** treesizefree installed..."  -ForegroundColor Green

choco install microsoft-windows-terminal -y | Out-Null
Write-Host "*** microsoft-windows-terminal installed..."  -ForegroundColor Green

choco install docker-desktop -y | Out-Null
Write-Host "*** docker desktop installed..."  -ForegroundColor Green

choco install vagrant -y | Out-Null
Write-Host "*** vagrant installed..."  -ForegroundColor Green

choco install packer -y | Out-Null
Write-Host "*** packer installed..."  -ForegroundColor Green

choco install windows-admin-center -y | Out-Null
Write-Host "*** windows-admin-center installed..."  -ForegroundColor Green

choco install cyberduck -y | Out-Null
Write-Host "*** cyberduck installed..."  -ForegroundColor Green

choco install veeam-agent -y | Out-Null
Write-Host "*** veeam-agent installed..."  -ForegroundColor Green

choco install zoom -y | Out-Null
Write-Host "*** zoom installed..."  -ForegroundColor Green

choco install visualstudio2019buildtools -y | Out-Null
Write-Host "*** visualstudio2019buildtools installed..."  -ForegroundColor Green

choco install vscode -y | Out-Null
Write-Host "*** vscode installed..."  -ForegroundColor Green

choco install git -y | Out-Null
Write-Host "*** git installed..."  -ForegroundColor Green

choco install slack -y | Out-Null
Write-Host "*** slack installed..."  -ForegroundColor Green

choco install spotify -y | Out-Null
Write-Host "*** spotify installed..."  -ForegroundColor Green

choco install telegraf -y | Out-Null
Write-Host "*** telegraf installed..."  -ForegroundColor Green

choco install office365proplus -y | Out-Null
Write-Host "*** office365proplus installed..."  -ForegroundColor Green

choco install powertoys -y | Out-Null
Write-Host "*** powertoys installed..."  -ForegroundColor Green

choco install terraform -y | Out-Null
Write-Host "*** terraform installed..."  -ForegroundColor Green

choco install signal -y | Out-Null
Write-Host "*** signal installed..."  -ForegroundColor Green

choco install onenote -y | Out-Null
Write-Host "*** onenote installed..."  -ForegroundColor Green

choco install 1password -y | Out-Null
Write-Host "*** 1password installed..."  -ForegroundColor Green

choco install etcher -y | Out-Null
Write-Host "*** etcher installed..."  -ForegroundColor Green

choco install hwinfo -y | Out-Null
Write-Host "*** hwinfo installed..."  -ForegroundColor Green

choco install discord -y | Out-Null
Write-Host "*** discord installed..."  -ForegroundColor Green

choco install telegram -y | Out-Null
Write-Host "*** telegram installed..."  -ForegroundColor Green

choco install tailscale -y | Out-Null
Write-Host "*** tailscale installed..."  -ForegroundColor Green

choco install nirlauncher -y | Out-Null
Write-Host "*** nirlauncher installed..."  -ForegroundColor Green

choco install ericzimmermantools -y | Out-Null
Write-Host "*** ericzimmermantools installed..."  -ForegroundColor Green

choco install wireshark -y | Out-Null
Write-Host "*** wireshark installed..."  -ForegroundColor Green

choco install authy-desktop -y | Out-Null
Write-Host "*** authy-desktop installed..."  -ForegroundColor Green

choco install dupeguru -y | Out-Null
Write-Host "*** dupeguru installed..."  -ForegroundColor Green

choco install geekbench -y | Out-Null
Write-Host "*** geekbench installed..."  -ForegroundColor Green

choco install mousewithoutborders -y | Out-Null
Write-Host "*** mousewithoutborders installed..."  -ForegroundColor Green

choco install mullvad-app -y | Out-Null 
Write-Host "*** mullvad-app installed..."  -ForegroundColor Green

choco install universal-adb-drivers -y | Out-Null
Write-Host "*** universal-adb-drivers installed..."  -ForegroundColor Green

choco install remote-desktop-client  -y | Out-Null
Write-Host "*** remote-desktop-client installed..."  -ForegroundColor Green

choco install lenovo-thinkvantage-system-update  -y | Out-Null
Write-Host "*** lenovo-thinkvantage-system-update installed..."  -ForegroundColor Green

choco install qemu-img  -y | Out-Null
Write-Host "*** qemu-img installed..."  -ForegroundColor Green

choco install dotnetfx  -y | Out-Null
Write-Host "*** dotnetfx installed..."  -ForegroundColor Green

##5.2 install and configure winget packages
Write-Host "*** Microsoft Defender installed..."  -ForegroundColor Green
winget install "Microsoft Defender" --source msstore --accept-package-agreements

Write-Host "*** Phone Link installed..."  -ForegroundColor Green
winget install "Phone Link" --source msstore --accept-package-agreements

Write-Host "*** Dell Display Manager installed..."  -ForegroundColor Green
winget install "Dell Display Manager" --source winget --accept-package-agreements

#________________

Write-Host "***Changing Explorer behaviour"  -ForegroundColor Green
# will expand explorer to the actual folder you're in
Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name NavPaneExpandToCurrentFolder -Value 1
#adds things back in your left pane like recycle bin
Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name NavPaneShowAllFolders -Value 1
#opens PC to This PC, not quick access
Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -Value 1

Write-Host "***Changing Taskbar behaviour"  -ForegroundColor Green
# will expand explorer to the actual folder you're in
Set-TaskbarOptions -Size Small -Lock -Dock Bottom -Combine Always

#Cleanup
Write-Host "***Removing stuff..."  -ForegroundColor Green
Get-ChildItem C:\Users\Public\Desktop | Remove-Item
Get-ChildItem C:\Users\$CurrentUser\Desktop | Remove-item
Clear-RecycleBin -Force

##6 windows options and tweaks

Write-Host "***Setting wallpaper...." -ForegroundColor Green
(New-Object System.Net.WebClient).DownloadFile('https://git.io/JfYWM','c:\tools\scripts\Set-Wallpaper.ps1')
Write-Host "***Scheduling wallpaper refresh task...." -ForegroundColor Green
$action = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument "-nologo -noninteractive -WindowStyle Hidden c:\tools\scripts\Set-Wallpaper.ps1 Colour Black"
$trigger =  New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "WallpaperRefresh" -Description "Refreshes wallpaper" | Out-Null

Write-Host "***Enabling W10 DevMode..."  -ForegroundColor Green
#Enable developer mode on the system
Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\AppModelUnlock -Name AllowDevelopmentWithoutDevLicense -Value 1

Write-Host "***Showing hidden files and such..."  -ForegroundColor Green
# Show hidden files, Show protected OS files, Show file extensions
Set-WindowsExplorerOptions -EnableShowHiddenFilesFoldersDrives -EnableShowProtectedOSFiles -EnableShowFileExtensions

Write-Host "***Excluding dirs from WinDefender..."  -ForegroundColor Green
Add-MpPreference -ExclusionPath $DefenderExcludeDirs

Write-Host "***Setting Networks to Private"  -ForegroundColor Green
try {
Get-NetConnectionProfile | Where-Object {$_.NetworkCategory -eq "Public"} | Set-NetConnectionProfile -NetworkCategory Private
}
catch {
    Write-Warning -Message "WARNING: No need to set adapters ----> Skipping.";
}

Write-Host "***Enabling PSremoting..."  -ForegroundColor Green
Enable-PSRemoting -Force | Out-Null

Write-Host "***Enabling RDP and Firewall ports for RDP..."  -ForegroundColor Green
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"


Write-Host "***Installing OpenSSH Server..."  -ForegroundColor Green
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'
Get-NetFirewallRule -Name *ssh*
New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22

Write-Host "***Disabling visual animations and effects..."  -ForegroundColor Green
$path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects'
try {
    $s = (Get-ItemProperty -ErrorAction stop -Name visualfxsetting -Path $path).visualfxsetting 
    if ($s -ne 2) {
        Set-ItemProperty -Path $path -Name 'VisualFXSetting' -Value 2  
        }
    }
catch {
    New-ItemProperty -Path $path -Name 'VisualFXSetting' -Value 2 -PropertyType 'DWORD'
    }

Write-Host "***Prepping for WSL..."  -ForegroundColor Green
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
Invoke-WebRequest -Uri https://wslstorestorage.blob.core.windows.net/wslblob/wsl_update_x64.msi -OutFile wsl_update_x64.msi -UseBasicParsing
RefreshEnv
wsl --set-default-version 2
Write-Host "***Downloading WSL distros..."  -ForegroundColor Green
cd d:\wsl
Invoke-WebRequest -Uri https://aka.ms/wslubuntu2004 -OutFile Ubuntu2004.appx -UseBasicParsing
move .\Ubuntu2004.appx .\Ubuntu2004.zip
Expand-Archive .\Ubuntu2004.zip
d:\wsl\Ubuntu2004\ubuntu2004.exe


Write-Host "***Setting a High Performance power plan...."  -ForegroundColor Green
Try {
    $HighPerf = powercfg -l | %{if($_.contains("High performance")) {$_.split()[3]}}
    $CurrPlan = $(powercfg -getactivescheme).split()[3]
    if ($CurrPlan -ne $HighPerf) {powercfg -setactive $HighPerf}
} Catch {
    Write-Warning -Message "***Unable to set power plan to high performance"
}

Write-Host "***Resetting System Install base..."  -ForegroundColor Green
DISM.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase




Write-Host "***Compacting non-essential and duplicate OS-files..."  -ForegroundColor Green
Compact.exe /CompactOS:always

Install-Module -Name PSWindowsUpdate -Force | Out-Null
Write-Host "***installed PSWindowsUpdate..."  -ForegroundColor Green
Install-Module -Name Az -Repository PSGallery -Force  | Out-Null
Write-Host "***installed Azure PSModule..."  -ForegroundColor Green

Write-Host "***Updating PS help...."  -ForegroundColor Green
Update-Help -ErrorAction SilentlyContinue | Out-Null 

Import-Module PSWindowsUpdate
Install-WindowsUpdate -AcceptAll -ForceInstall  | Out-Null
Write-Host "***installed Windows Updates..."  -ForegroundColor Green

Write-Host "***Pulling and prepping for debloat...."  -ForegroundColor Green
Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/Sycnex/Windows10Debloater/master/Windows10SysPrepDebloater.ps1'))
#shoutout = Sycnex

Write-Host "***Restarting..."  -ForegroundColor Green
restart-computer -Force






