Import-Module -DisableNameChecking $PSScriptRoot\utils.psm1

# Elevate priviledges for process.
Write-Output "Elevating priviledges for this process"
do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)

# List of Window's services to disable.
$_services = @(
  "diagnosticshub.standardcollector.service" # Microsoft (R) Diagnostics Hub Standard Collector Service
  "DiagTrack"                                # Diagnostics Tracking Service
  "dmwappushservice"                         # WAP Push Message Routing Service (see known issues)
  "HomeGroupListener"                        # HomeGroup Listener
  "HomeGroupProvider"                        # HomeGroup Provider
  "lfsvc"                                    # Geolocation Service
  "MapsBroker"                               # Downloaded Maps Manager
  "NetTcpPortSharing"                        # Net.Tcp Port Sharing Service
  "RemoteAccess"                             # Routing and Remote Access
  "RemoteRegistry"                           # Remote Registry
  "SharedAccess"                             # Internet Connection Sharing (ICS)
  "TrkWks"                                   # Distributed Link Tracking Client
  "WbioSrvc"                                 # Windows Biometric Service (required for Fingerprint reader / facial detection)
  "WMPNetworkSvc"                            # Windows Media Player Network Sharing Service
  "wscsvc"                                   # Windows Security Center Service
  "XblAuthManager"                           # Xbox Live Auth Manager
  "XblGameSave"                              # Xbox Live Game Save Service
  "XboxNetApiSvc"                            # Xbox Live Networking Service
  "ndu"                                      # Windows Network Data Usage Monitor
)

# List of Window's Defender tasks to disable.
$_defTasks = @(
  "Windows Defender Cache Maintenance"
  "Windows Defender Cleanup"
  "Windows Defender Scheduled Scan"
  "Windows Defender Verification"
)

# List of default Window's apps to remove.
$_winApps = @(
  "Microsoft.3DBuilder"
  "Microsoft.Appconnector"
  "Microsoft.BingFinance"
  "Microsoft.BingNews"
  "Microsoft.BingSports"
  "Microsoft.BingTranslator"
  "Microsoft.BingWeather"
  "Microsoft.Microsoft3DViewer"
  "Microsoft.MicrosoftOfficeHub"
  "Microsoft.MicrosoftSolitaireCollection"
  "Microsoft.MicrosoftPowerBIForWindows"
  "Microsoft.MinecraftUWP"
  "Microsoft.NetworkSpeedTest"
  "Microsoft.Office.OneNote"
  "Microsoft.People"
  "Microsoft.Print3D"
  "Microsoft.SkypeApp"
  "Microsoft.Wallet"
  "Microsoft.WindowsAlarms"
  "Microsoft.WindowsCamera"
  "microsoft.windowscommunicationsapps"
  "Microsoft.WindowsMaps"
  "Microsoft.WindowsPhone"
  "Microsoft.WindowsSoundRecorder"
  #"Microsoft.WindowsStore"
  #"Microsoft.XboxApp"
  #"Microsoft.XboxGameOverlay"
  #"Microsoft.XboxGamingOverlay"
  #"Microsoft.XboxSpeechToTextOverlay"
  #"Microsoft.Xbox.TCUI"
  "Microsoft.ZuneMusic"
  "Microsoft.ZuneVideo"
  "Microsoft.Advertising.Xaml"

  # Threshold 2 apps
  "Microsoft.CommsPhone"
  "Microsoft.ConnectivityStore"
  "Microsoft.GetHelp"
  "Microsoft.Getstarted"
  "Microsoft.Messaging"
  "Microsoft.Office.Sway"
  "Microsoft.OneConnect"
  "Microsoft.WindowsFeedbackHub"

  # Creators Update apps
  "Microsoft.Microsoft3DViewer"

  #Redstone apps
  "Microsoft.BingFoodAndDrink"
  "Microsoft.BingTravel"
  "Microsoft.BingHealthAndFitness"
  "Microsoft.WindowsReadingList"

  # Redstone 5 apps
  "Microsoft.MixedReality.Portal"
  "Microsoft.ScreenSketch"
  "Microsoft.XboxGamingOverlay"
  "Microsoft.YourPhone"
)

# List of non-default apps to remove.
$_apps = @(
  "9E2F88E3.Twitter"
  "PandoraMediaInc.29680B314EFC2"
  "Flipboard.Flipboard"
  "ShazamEntertainmentLtd.Shazam"
  "king.com.CandyCrushSaga"
  "king.com.CandyCrushSodaSaga"
  "king.com.BubbleWitch3Saga"
  "king.com.*"
  "ClearChannelRadioDigital.iHeartRadio"
  "4DF9E0F8.Netflix"
  "6Wunderkinder.Wunderlist"
  "Drawboard.DrawboardPDF"
  "2FE3CB00.PicsArt-PhotoStudio"
  "D52A8D61.FarmVille2CountryEscape"
  "TuneIn.TuneInRadio"
  "GAMELOFTSA.Asphalt8Airborne"
  "DB6EA5DB.CyberLinkMediaSuiteEssentials"
  "Facebook.Facebook"
  "flaregamesGmbH.RoyalRevolt2"
  "Playtika.CaesarsSlotsFreeCasino"
  "A278AB0D.MarchofEmpires"
  "KeeperSecurityInc.Keeper"
  "ThumbmunkeysLtd.PhototasticCollage"
  "XINGAG.XING"
  "89006A2E.AutodeskSketchBook"
  "D5EA27B7.Duolingo-LearnLanguagesforFree"
  "46928bounde.EclipseManager"
  "ActiproSoftwareLLC.562882FEEB491" # this one is for the Code Writer from Actipro Software LLC
  "DolbyLaboratories.DolbyAccess"
  "SpotifyAB.SpotifyMusic"
  "A278AB0D.DisneyMagicKingdoms"
  "WinZipComputing.WinZipUniversal"
  "CAF9E577.Plex"
  "7EE7776C.LinkedInforWindows"
  "613EBCEA.PolarrPhotoEditorAcademicEdition"
  "Fitbit.FitbitCoach"
  "DolbyLaboratories.DolbyAccess"
  "Microsoft.BingNews"
  "NORDCURRENT.COOKINGFEVER"
)

$_cdm = @(
  "ContentDeliveryAllowed"
  "FeatureManagementEnabled"
  "OemPreInstalledAppsEnabled"
  "PreInstalledAppsEnabled"
  "PreInstalledAppsEverEnabled"
  "SilentInstalledAppsEnabled"
  "SubscribedContent-314559Enabled"
  "SubscribedContent-338387Enabled"
  "SubscribedContent-338388Enabled"
  "SubscribedContent-338389Enabled"
  "SubscribedContent-338393Enabled"
  "SubscribedContentEnabled"
  "SystemPaneSuggestionsEnabled"
)

foreach($service in $_services)
{
  Write-Output "Disabling $service"
  Get-Service -Name $service | Set-Service -StartupType Disabled
}

foreach($task in $_defTasks)
{
  Write-Output "Disabling $task"
  Disable-ScheduledTask -TaskName $task -TaskPath "\Microsoft\Windows\Windows Defender"
}

Write-Output "Disabling Windows Defender via Group Policies..."
force-mkdir "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender"
Set-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender" "DisableAntiSpyware" 1
Set-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender" "DisableRoutinelyTakingAction" 1
force-mkdir "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender\Real-Time Protection"
Set-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableRealtimeMonitoring" 1

Write-Output "Disabling Windows Defender Services..."
Takeown-Registry("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend")
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" "Start" 4
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" "AutorunsDisabled" 3
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WdNisSvc" "Start" 4
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WdNisSvc" "AutorunsDisabled" 3
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Sense" "Start" 4
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Sense" "AutorunsDisabled" 3

#Write-Output "Removing Windows Defender GUI / tray from autorun"
#Remove-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" "WindowsDefender" -ea 0

Write-Output "Disabling Game DVR and Game Bar..."
force-mkdir "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" "AllowgameDVR" 0

Write-Output "Disabling sticky keys..."
Set-ItemProperty "HKCU:\Control Panel\Accessibility\StickyKeys" "Flags" "506"

Write-Output "Setting folder view option...s"
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "Hidden" 1
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "HideFileExt" 0
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "HideDrivesWithNoMedia" 0
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ShowSyncProviderNotifications" 0

Write-Output "Disabling seeding of updates to other computers via Group Policies..."
force-mkdir "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" "DODownloadMode" 0

Write-Output "Disabling automatic download and installation of Windows updates..."
force-mkdir "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU"
Set-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoUpdate" 0
Set-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" "AUOptions" 2
Set-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" "ScheduledInstallDay" 0
Set-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" "ScheduledInstallTime" 3

Write-Output "Removing non-critical Window's default apps..."
foreach ($app in $_winApps) {
  Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -AllUsers
  Get-AppXProvisionedPackage -Online | Where-Object DisplayName -EQ $app | Remove-AppxProvisionedPackage -Online
}

Write-Output "Disabling default apps from reinstalling..."
force-mkdir "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
foreach ($key in $_cdm) {
  Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" $key 0
}

Write-Output "Disabling Windows optional features..."
# Uninstall Windows Media Player
Function UninstallMediaPlayer {
	Write-Output "Uninstalling Windows Media Player..."
	Disable-WindowsOptionalFeature -Online -FeatureName "WindowsMediaPlayer" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

Function DisableAdobeFlash {
	Write-Output "Disabling built-in Adobe Flash in IE and Edge..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" -Name "DisableFlashInIE" -Type DWord -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons" -Name "FlashPlayerEnabled" -Type DWord -Value 0
}

Write-Output "Disabling Suggested Applications window..."
force-mkdir "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" 1
