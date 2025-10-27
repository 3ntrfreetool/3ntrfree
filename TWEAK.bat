@echo off

REM Disables synchronization of application settings, app sync settings, web browser settings, desktop theme settings, and all settings in Windows.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /F /V "DisableApplicationSettingSync" /T REG_DWORD /d 2 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /F /V "DisableAppSyncSettingSync" /T REG_DWORD /d 2 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /F /V "DisableWebBrowserSettingSync" /T REG_DWORD /d 2 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /F /V "DisableDesktopThemeSettingSync" /T REG_DWORD /d 2 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /F /V "DisableSettingSync" /T REG_DWORD /d 2 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /F /V "DisableSyncOnPaidNetwork" /T REG_DWORD /d 1 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /F /V "DisableWindowsSettingSync" /T REG_DWORD /d 2 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /F /V "DisableCredentialsSettingSync" /T REG_DWORD /d 2 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /F /V "DisablePersonalizationSettingSync" /T REG_DWORD /d 2 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /F /V "DisableStartLayoutSettingSync" /T REG_DWORD /d 2  
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /f /d 0 
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-314563Enabled" /t REG_DWORD /f /d 0 
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /f /d 0 
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353698Enabled" /t REG_DWORD /f /d 0 
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /f /d 0 
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /f /d 0 
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /f /d 0 
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /f /d 0 
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t REG_DWORD /f /d 0 
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /f /d 0 
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /f /d 0 
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /f /d 0 
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /f /d 0 
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /f /d 0 
reg add "HKLM\SOFTWARE\Policies\Microsoft\TabletPC" /F /V "TurnOffTouchInput" /T REG_DWORD /d 1 
reg add "HKLM\SOFTWARE\Policies\Microsoft\TabletPC" /F /V "TurnOffPanning" /T REG_DWORD /d 1 
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" /F /V "AllowLinguisticDataCollection" /T REG_DWORD /d 0 

REM Disable pretty paths in the Windows Explorer.
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DontPrettyPath" /t REG_DWORD /d "1" /f 

REM Disable tagged energy logging.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "DisableTaggedEnergyLogging" /t REG_DWORD /d "1" /f 

REM Set the maximum number of applications and tags for tagged energy logging to 0.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "TelemetryMaxApplication" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "TelemetryMaxTagPerApplication" /t REG_DWORD /d "0" /f 

REM Set the power plan settings for the current user.
reg add "HKCU\Control Panel\PowerCfg\GlobalPowerPolicy" /v "Policies" /t REG_BINARY /d "01000000020000000100000000000000020000000000000000000000000000002c0100003232030304000000040000000000000000000000840300002c01000000000000840300000001646464640000" /f 

REM Disable Program Compatibility Assistant Service (PcaSvc)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PcaSvc" /v "Start" /t REG_DWORD /d 4 /f 

REM Disable Windows Event Collector Service (Wecsvc)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Wecsvc" /v "Start" /t REG_DWORD /d 4 /f 

REM Disable Windows Biometric Service (WbioSrvc)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WbioSrvc" /v "Start" /t REG_DWORD /d 4 /f 

REM Disable Windows Image Acquisition (stisvc)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stisvc" /v "Start" /t REG_DWORD /d 4 /f 

REM Disable GameDVR and its settings
reg add "HKCU\System\GameConfigStore" /F /V "GameDVR_Enabled" /T REG_DWORD /d 0 
reg add "HKCU\System\GameConfigStore" /F /V "GameDVR_FSEBehaviorMode" /T REG_DWORD /d 2 
reg add "HKCU\System\GameConfigStore" /F /V "GameDVR_HonorUserFSEBehaviorMode" /T REG_DWORD /d 0 
reg add "HKCU\System\GameConfigStore" /F /V "GameDVR_DXGIHonorFSEWindowsCompatible" /T REG_DWORD /d 0 
reg add "HKCU\System\GameConfigStore" /F /V "GameDVR_EFSEFeatureFlags" /T REG_DWORD /d 0 

REM Mouse Keys
reg add "HKCU\Control Panel\Accessibility\MouseKeys" /v "Flags" /t REG_SZ /d "0" /f 
reg add "HKCU\Control Panel\Accessibility\MouseKeys" /v "MaximumSpeed" /t REG_SZ /d "80" /f 
reg add "HKCU\Control Panel\Accessibility\MouseKeys" /v "TimeToMaximumSpeed" /t REG_SZ /d "3000" /f 

REM Keyboard Delay And Repeat Rate
reg add "HKCU\Control Panel\Keyboard" /v "KeyboardSpeed" /t REG_SZ /d "31" /f 
reg add "HKCU\Control Panel\Keyboard" /v "KeyboardDelay" /t REG_SZ /d "0" /f 

REM Keyboard Response
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "AutoRepeatDelay" /t REG_SZ /d "0" /f 
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "AutoRepeatRate" /t REG_SZ /d "0" /f 
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "BounceTime" /t REG_SZ /d "0" /f 
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "DelayBeforeAcceptance" /t REG_SZ /d "0" /f 
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "0" /f 
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Last BounceKey Setting" /t REG_DWORD /d "0" /f 
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Last Valid Delay" /t REG_DWORD /d "0" /f 
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Last Valid Repeat" /t REG_DWORD /d "0" /f 
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Last Valid Wait" /t REG_DWORD /d "1000" /f 

REM Disable Data Collection and Telemetry
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "AllowCommercialDataPipeline" /T REG_DWORD /d 0 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "AllowDesktopAnalyticsProcessing" /T REG_DWORD /d 0 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "AllowDeviceNameInTelemetry" /T REG_DWORD /d 0 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "AllowTelemetry" /T REG_DWORD /d 0 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "AllowUpdateComplianceProcessing" /T REG_DWORD /d 0 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "AllowWUfBCloudProcessing" /T REG_DWORD /d 0 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "DisableEnterpriseAuthProxy" /T REG_DWORD /d 1 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "MicrosoftEdgeDataOptIn" /T REG_DWORD /d 0 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "DisableTelemetryOptInChangeNotification" /T REG_DWORD /d 1 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "DisableTelemetryOptInSettingsUx" /T REG_DWORD /d 1 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "DisableDiagnosticDataViewer" /T REG_DWORD /d 1 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "EnableConfigFlighting" /T REG_DWORD /d 0 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "DoNotShowFeedbackNotifications" /T REG_DWORD /d 1 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "LimitEnhancedDiagnosticDataWindowsAnalytics" /T REG_DWORD /d 0 

REM Disable SmartScreen
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /F /V "EnableSmartScreen" /T REG_DWORD /d 0 

REM Disable File History
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\FileHistory" /F /V "Disabled" /T REG_DWORD /d 1 

REM Disable Find My Device
reg add "HKLM\SOFTWARE\Policies\Microsoft\FindMyDevice" /F /V "AllowFindMyDevice" /T REG_DWORD /d 0 

REM Disable Location Sync
reg add "HKLM\SOFTWARE\Microsoft\Settings\FindMyDevice" /F /V "LocationSyncEnabled" /T REG_DWORD /d 0 

REM Deny location access
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /F /V "Value" /T REG_SZ /d "Deny" 

REM Disable Location and Sensors
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /F /V "DisableLocation" /T REG_DWORD /d 1 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /F /V "DisableLocationScripting" /T REG_DWORD /d 1 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /F /V "DisableSensors" /T REG_DWORD /d 1 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /F /V "DisableWindowsLocationProvider" /T REG_DWORD /d 1 


REM Disable Anti Malware
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Sense" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\wscsvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" /v "DisableNotifications" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoToastApplicationNotification" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoToastApplicationNotificationOnLockScreen" /t REG_DWORD /d "1" /f

REM Set Mouse Data Size Queue To 50
reg add "HKLM\SYSTEM\CurrentControlSet\services\mouclass\Parameters" /v "MouseDataQueueSize" /t REG_DWORD /d "50" /f

REM Disable Mouse Acceleration
reg add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_DWORD /d "0" /f 
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_DWORD /d "0" /f  
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_DWORD /d "0" /f

REM Disable Auto Download and Update Map Data
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Maps" /F /V "AutoDownloadAndUpdateMapData" /T REG_DWORD /d 0

REM Disable Untriggered Network Traffic on Settings Page for Maps
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Maps" /F /V "AllowUntriggeredNetworkTrafficOnSettingsPage" /T REG_DWORD /d 0

REM Deny App Diagnostics access
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /F /V "Value" /T REG_SZ /d "Deny"

REM Deny access to Appointments
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /F /V "Value" /T REG_SZ /d "Deny"

REM Deny access to Email
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /F /V "Value" /T REG_SZ /d "Deny"

REM Deny access to Phone Calls
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" /F /V "Value" /T REG_SZ /d "Deny"

REM Deny access to User Data Tasks
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" /F /V "Value" /T REG_SZ /d "Deny"

REM Deny access to Chat
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /F /V "Value" /T REG_SZ /d "Deny"

REM Deny access to Contacts
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /F /V "Value" /T REG_SZ /d "Deny"

REM Disable Messaging Data Collection
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Messaging" /F /V "AllowMessageSync" /T REG_DWORD /d 0

REM Delete directory and suppress output
rmdir C:\Windows\system32\adminrightstest 

REM Set the startup type and start services, suppressing output for each
SC CONFIG Winmgmt start= auto 
SC CONFIG TrustedInstaller start= demand 
SC CONFIG AppInfo start= demand 
SC CONFIG DeviceInstall start= demand 

SC START Winmgmt 
SC START TrustedInstaller 
SC START AppInfo 
SC START DeviceInstall 
SC START Dhcp 

REM Set the priority of processes and processor affinity, suppressing output for each
wmic process where name="javaw.exe" CALL setpriority "realtime" 
wmic process where name="svchost.exe" CALL setpriority "realtime" 

PowerShell "get-process svchost | foreach { $_.ProcessorAffinity=2 }" >nul 2>&1
PowerShell "get-process winlogon | foreach { $_.ProcessorAffinity=2 }" >nul 2>&1
PowerShell "get-process dwm | foreach { $_.ProcessorAffinity=2 }" >nul 2>&1

REM Set various TCP/IP settings, suppressing output for each
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "16" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxConnectionsPerServer" /t REG_DWORD /d "16" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableTaskOffload" /t REG_DWORD /d "00000000" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableConnectionRateLimiting" /t REG_DWORD /d "00000000" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUBHDetect" /t REG_DWORD /d "00000000" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUDiscovery" /t REG_DWORD /d "00000001" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableRSS" /t REG_DWORD /d "00000001" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableTCPA" /t REG_DWORD /d "00000001" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableWsd" /t REG_DWORD /d "00000000" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxFreeTcbs" /t REG_DWORD /d "65535" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxHashTableSize" /t REG_DWORD /d "00010000" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "65534" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SackOpts" /t REG_DWORD /d "00000001" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SizReqBuf" /t REG_DWORD /d "51319" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SynAttackProtect" /t REG_DWORD /d "00000001" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "00000001" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "00000001" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDataRetransmissions" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpAckFrequency" /t REG_DWORD /d "00000005" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "StrictTimeWaitSeqCheck" /t REG_DWORD /d "00000001" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableIPSourceRouting" /t REG_DWORD /d "00000008" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpCreateAndConnectTcbRateLimitDepth" /t REG_DWORD /d "00000000" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPInitalRtt" /t REG_DWORD /d "00046325" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDupAcks" /t REG_DWORD /d "00000002" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPDelAckTicks" /t REG_DWORD /d "00000001" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "IPAutoconfigurationEnabled" /t REG_DWORD /d "0" /f

REM Memory Managment Tweaks
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "ClearPageFileAtShutdown" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "NonPagedPoolQuota" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "NonPagedPoolSize" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PagedPoolQuota" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PagedPoolSize" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PagingFiles" /t REG_MULTI_SZ /d "c:\pagefile.sys 8000 8000" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "SecondLevelDataCache" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "SessionPoolSize" /t REG_DWORD /d "48" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "SessionViewSize" /t REG_DWORD /d "96" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "SystemPages" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PhysicalAddressExtension" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableCfg" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePageCombining" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "MoveImages" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "IoPageLockLimit" /t REG_DWORD /d "134217728" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PagefileUsage" /t REG_BINARY /d "0400000051270000d0340000276a0000b65700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "ExistingPageFiles" /t REG_MULTI_SZ /d "\??\C:\pagefile.sys" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "BootId" /t REG_DWORD /d "92" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "BaseTime" /t REG_DWORD /d "672778600" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "SfTracingState" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableBootTrace" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\StoreParameters" /f

REM Enable large system cache
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "1" /f

REM Set the cache hash table bucket size
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "CacheHashTableBucketSize" /t REG_DWORD /d "00000001" /f

REM Set the negative cache time
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NegativeCacheTime" /t REG_DWORD /d "00000000" /f

REM Set the net failure cache time
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NetFailureCacheTime" /t REG_DWORD /d "00000000" /f

REM Set the TCP no delay option
reg add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f

REM Enable OCM setup
reg add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters\OCMsetup" /f

REM Disable secure DS communication
reg add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters\Security" /v "SecureDSCommunication" /t REG_DWORD /d "0" /f

REM Enable setup
reg add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters\setup" /f

REM Enable MSMQ setup
reg add "HKLM\SOFTWARE\Microsoft\MSMQ\Setup" /f

REM Increase IRPStackSize to 80
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "80" /f

REM Enable hibernation
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "HiberbootEnabled" /t REG_DWORD /d "1" /f

REM Increase MaxOutstandingSends
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "MaxOutstandingSends" /t REG_DWORD /d "1073741824" /f

REM Set NonBestEffortLimit to 0
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f

REM Increase TimerResolution
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "TimerResolution" /t REG_DWORD /d "4294967295" /f

REM Map ServiceTypeNonConforming to 7
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched\UserPriorityMapping" /v "ServiceTypeNonConforming" /t REG_DWORD /d "7" /f

REM Map ServiceTypeBestEffort to 7
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched\UserPriorityMapping" /v "ServiceTypeBestEffort" /t REG_DWORD /d "7" /f

REM Map ServiceTypeControlledLoad to 7
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched\UserPriorityMapping" /v "ServiceTypeControlledLoad" /t REG_DWORD /d "7" /f

REM Map ServiceTypeGuaranteed to 7
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched\UserPriorityMapping" /v "ServiceTypeGuaranteed" /t REG_DWORD /d "7" /f

REM Map ServiceTypeNetworkControl to 7
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched\UserPriorityMapping" /v "ServiceTypeNetworkControl" /t REG_DWORD /d "7" /f

REM Map ServiceTypeQualitative to 7
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched\UserPriorityMapping" /v "ServiceTypeQualitative" /t REG_DWORD /d "7" /f

REM Enable BITS Max Bandwidth
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\BITS" /v "EnableBITSMaxBandwidth" /t REG_DWORD /d "0" /f

REM Increase PeerCachingLatencyThreshold
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetCache" /v "PeerCachingLatencyThreshold" /t REG_DWORD /d "268435456" /f

REM Enable Peerdist service
reg add "HKLM\SOFTWARE\Policies\Microsoft\PeerDist\Service" /v "Enable" /t REG_DWORD /d "1" /f

REM Increase UpdateSecurityLevel
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v "UpdateSecurityLevel" /t REG_DWORD /d "598" /f

REM Increase RegistrationTtl
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v "RegistrationTtl" /t REG_DWORD /d "1117034098" /f

REM Disable NetBridge NLA
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections" /v "NC_AllowNetBridge_NLA" /t REG_DWORD /d "0" /f

REM Allow Advanced TCP/IP Configuration
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections" /v "NC_AllowAdvancedTCPIPConfig" /t REG_DWORD /d "1" /f

REM Set NvTelemetryContainer Start value to 4
reg add "HKLM\SYSTEM\CurrentControlSet\services\NvTelemetryContainer" /v "Start" /t REG_DWORD /d 4 /f

REM Enable VidMem Virtual Buffers in Direct3D
reg add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "DisableVidMemVBs" /t REG_DWORD /d 0 /f

REM Enable FlipNoVsync in Direct3D
reg add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "FlipNoVsync" /t REG_DWORD /d 1 /f

REM Enable hardware acceleration in Direct3D drivers
reg add "HKLM\SOFTWARE\Microsoft\Direct3DDrivers" /v "SoftwareOnly" /t REG_DWORD /d 0 /f

REM Enable MMX Fast Path in Direct3D
reg add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "MMX Fast Path" /t REG_DWORD /d 1 /f

REM Disable Timeout Detection and Recovery (TDR) in Graphics Drivers
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrLevel" /t REG_DWORD /d 0 /f

REM Disable TDR Debug Mode in Graphics Drivers
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrDebugMode" /t REG_DWORD /d 0 /f

REM Disable Energy Estimation in Power settings
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EnergyEstimationEnabled" /t REG_DWORD /d 0 /f

REM Disable Connected Standby in Power settings
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CsEnabled" /t REG_DWORD /d 0 /f

REM Disable actual utilization calculation in Power settings
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "PerfCalculateActualUtilization" /t REG_DWORD /d 0 /f

REM Disable detailed diagnostics for sleep reliability in Power settings
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "SleepReliabilityDetailedDiagnostics" /t REG_DWORD /d 0 /f

REM Disable event processor in Power settings
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EventProcessorEnabled" /t REG_DWORD /d 0 /f

REM Disable QoS management of idle processors in Power settings
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "QosManagesIdleProcessors" /t REG_DWORD /d 0 /f

REM Enable Vsync latency update in Power settings
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DisableVsyncLatencyUpdate" /t REG_DWORD /d 1 /f

REM Disable sensor watchdog in Power settings
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DisableSensorWatchdog" /t REG_DWORD /d 1 /f

REM Disable exit latency check in Power settings
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatencyCheckEnabled" /t REG_DWORD /d 0 /f

REM Enable Power Throttling Off in Power settings
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d 1 /f

REM Set Magnetism Update Interval to 1 millisecond in Controller Processor settings
reg add "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v "MagnetismUpdateIntervalInMilliseconds" /t REG_DWORD /d 1 /f

REM Set Cursor Update Interval to 1 millisecond in Controller Processor settings
reg add "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed" /v "CursorUpdateInterval" /t REG_DWORD /d 1 /f

REM Set Time Stamp Interval to 0 in Reliability settings
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" /v "TimeStampInterval" /t REG_DWORD /d 0 /f

REM Set Composition Policy to 0 in DWM (Desktop Window Manager) settings
reg add "HKCU\Software\Microsoft\Windows\DWM" /v "CompositionPolicy" /t REG_DWORD /d 0 /f

REM Set amdlog Start value to 4 in Services
reg add "HKLM\SYSTEM\CurrentControlSet\Services\amdlog" /v "Start" /t REG_DWORD /d 4 /f

REM Enable DisableDMACopy in Graphics Drivers Class settings
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableDMACopy" /t REG_DWORD /d 1 /f

REM Set StutterMode value to 0 in Graphics Drivers Class settings
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "StutterMode" /t REG_DWORD /d 0 /f

REM Disable Ulps (Ultra Low Power State) in Graphics Drivers Class settings
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableUlps" /t REG_DWORD /d 0 /f

REM Enable PP_SclkDeepSleepDisable in Graphics Drivers Class settings
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_SclkDeepSleepDisable" /t REG_DWORD /d 1 /f

REM Disable PP_ThermalAutoThrottlingEnable in Graphics Drivers Class settings
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_ThermalAutoThrottlingEnable" /t REG_DWORD /d 0 /f

REM Disable DrmdmaPowerGating in Graphics Drivers Class settings
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableDrmdmaPowerGating" /t REG_DWORD /d 1 /f

REM Set GPU Priority to 8 for Games in Multimedia System Profile
reg add "HKLM\SOFTWARE\Microsoft\Windows Nt\CurrentVersion\Multimedia\SystemProfilE\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 8 /f

REM Set Priority to 6 for Games in Multimedia System Profile
reg add "HKLM\SOFTWARE\Microsoft\Windows Nt\CurrentVersion\Multimedia\SystemProfilE\Tasks\Games" /v "Priority" /t REG_DWORD /d 6 /f

REM Set Scheduling Category to High for Games in Multimedia System Profile
reg add "HKLM\SOFTWARE\Microsoft\Windows Nt\CurrentVersion\Multimedia\SystemProfilE\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d High /f

REM Restrict Implicit Ink Collection in InputPersonalization settings
reg add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f

REM Restrict Implicit Text Collection in InputPersonalization settings
reg add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f

REM Disable Harvesting of Contacts in TrainedDataStore settings
reg add "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 0 /f

REM Disable Metrics Reporting in Google Chrome policies
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "MetricsReportingEnabled" /t REG_DWORD /d 0 /f

REM Prevent Handwriting Error Reports in HandwritingErrorReports policies
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d 1 /f

REM Opt-out HttpAcceptLanguage in User Profile International settings
reg add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d 1 /f

REM Disables service
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc" /v "Start" /t REG_DWORD /d 4 /f

REM Disables service configuration
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" /v "Status" /t REG_DWORD /d 0 /f

REM Disables sensor permissions
reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions" /v "SensorPermissionState" /t REG_DWORD /d 0 /f

REM Disables sensor overrides
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides" /v "SensorPermissionState" /t REG_DWORD /d 0 /f

REM Disables dmwappushservice
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d 4 /f

REM Disable AIT (Application Impact Telemetry) in AppCompat policies
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f

REM Disable Advertising Info in CurrentVersion settings
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 0 /f

REM Disable Advertising Info for Current User
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 0 /f

REM Disable Advertising Info by Group Policy
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d 1 /f

REM Disable Inventory in AppCompat policies
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d 1 /f

REM Disable CEIP (Customer Experience Improvement Program) in SQMClient policies
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f

REM Set CorporateSQMURL to 0.0.0.0 in SQMClient policies
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient" /v "CorporateSQMURL" /t REG_SZ /d 0.0.0.0 /f

REM Disable Soft Landing in CloudContent policies
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableSoftLanding" /t REG_DWORD /d 1 /f

REM Disable Active Help in Assistance Client policies
reg add "HKLM\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" /v "NoActiveHelp" /t REG_DWORD /d 1 /f

REM Disable AutoLogger-Diagtrack-Listener
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f

REM Disable AutoLogger-Diagtrack-Listener in CurrentControlSet WMI
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f

REM Disable SQMLogger
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "Start" /t REG_DWORD /d 0 /f

REM Set NumberOfSIUFInPeriod value to 0 in Siuf Rules for Current User
reg add "HKCU\Software\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f

REM Set PeriodInNanoSeconds value to 0 in Siuf Rules for Current User
reg add "HKCU\Software\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d 0 /f

REM Disable Feedback Notifications in DataCollection policies
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d 1 /f

REM Disable Explicit Feedback in Assistance Client policies for Current User
reg add "HKCU\Software\Policies\Microsoft\Assistance\Client\1.0" /v "NoExplicitFeedback" /t REG_DWORD /d 1 /f

REM Disable Usage Tracking in Windows Media Player Preferences for Current User
reg add "HKCU\Software\Microsoft\MediaPlayer\Preferences" /v "UsageTracking" /t REG_DWORD /d 0 /f

REM Disable Store Open With in Explorer policies
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoUseStoreOpenWith" /t REG_DWORD /d 1 /f

REM Disable ConsentUxUserSvc service
reg add "HKLM\SYSTEM\CurrentControlSet\Services\ConsentUxUserSvc" /v "Start" /t REG_DWORD /d 3 /f

REM Disable DevicePickerUserSvc service
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DevicePickerUserSvc" /v "Start" /t REG_DWORD /d 3 /f

REM Disable UnistoreSvc service
reg add "HKLM\SYSTEM\CurrentControlSet\Services\UnistoreSvc" /v "Start" /t REG_DWORD /d 3 /f

REM Disable DevicesFlowUserSvc service
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvc" /v "Start" /t REG_DWORD /d 3 /f

REM Disable lfsvc service
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc" /v "Start" /t REG_DWORD /d 3 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" /v "Status" /t REG_DWORD /d 1 /f

REM Modify sensor permissions
reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions" /v "SensorPermissionState" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides" /v "SensorPermissionState" /t REG_DWORD /d 1 /f

REM Disable DiagTrack, diagsvc, dmwappushsvc, and other related services
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d 3 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\diagsvc" /v "Start" /t REG_DWORD /d 3 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushsvc" /v "Start" /t REG_DWORD /d 3 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /v "Start" /t REG_DWORD /d 3 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\TroubleshootingSvc" /v "Start" /t REG_DWORD /d 3 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DsSvc" /v "Start" /t REG_DWORD /d 3 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d 3 /f

REM Modify system performance settings
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVt\Channels\Microsoft-Windows-Superfetch/Main" /v "Enabled" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVt\Channels\Microsoft-Windows-Superfetch/PfApLog" /v "Enabled" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVt\Channels\Microsoft-Windows-Superfetch/StoreLog" /v "Enabled" /t REG_DWORD /d 1 /f

REM Modify mouse and keyboard settings
reg add "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "MouseDataQueueSize" /t REG_DWORD /d 100 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d 100 /f

REM Modify memory management settings
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d 2 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d 2 /f

REM Modify power and file system settings
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NTFSDisableLastAccessUpdate" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "ContigFileAllocSize" /t REG_DWORD /d "64" /f

REM Modify desktop and user settings
reg add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
reg add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "5000" /f
reg add "HKCU\Control Panel\Desktop" /v "WaitToKillServiceTimeout" /t REG_SZ /d "1000" /f
reg add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "4000" /f
reg add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f
reg add "HKCU\Control Panel\Desktop" /v "ForegroundLockTimeout" /t REG_SZ /d "150000" /f

REM Modify game-related settings
reg add "HKCU\Software\Microsoft\Games" /v "FpsAll" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Games" /v "GameFluidity" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Games" /v "FpsStatusGames" /t REG_DWORD /d "16" /f
reg add "HKCU\Software\Microsoft\Games" /v "FpsStatusGamesAll" /t REG_DWORD /d "4" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d "10000" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "2" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Latency Sensitive" /t REG_SZ /d "True" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Affinity" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Background Only" /t REG_SZ /d "False" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Clock Rate" /t REG_DWORD /d "10000" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "GPU Priority" /t REG_DWORD /d "8" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Priority" /t REG_DWORD /d "2" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Scheduling Category" /t REG_SZ /d "High" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "SFIO Priority" /t REG_SZ /d "High" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Latency Sensitive" /t REG_SZ /d "True" /f

REM Set CPU Priority for VxD BIOS
reg add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "CPUPriority" /t REG_DWORD /d "1" /f

REM Configure QoS settings
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS" /v "Tcp Autotuning Level" /t REG_SZ /d "Off" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS" /v "Tcp Autotuning Level" /t REG_SZ /d "Highly Restricted" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS" /v "Tcp Autotuning Level" /t REG_SZ /d "Restricted" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS" /v "Tcp Autotuning Level" /t REG_SZ /d "Normal" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS" /v "Application DSCP Marking Request" /t REG_SZ /d "Ignored" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS" /v "Application DSCP Marking Request" /t REG_SZ /d "Allowed" /f

REM Enables Icons Only in Explorer
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconsOnly" /t REG_DWORD /d "1" /f

REM Disables ListviewAlphaSelect in Explorer
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewAlphaSelect" /t REG_DWORD /d "0" /f

REM Disables ListviewShadow in Explorer
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /d "0" /f

REM Disables Taskbar Animations
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d "0" /f

REM Disables Windows Consumer Features in CloudContent
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f

REM Disables Subscribed Content in ContentDeliveryManager
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d "0" /f

REM Disables AutoLogger-Diagtrack-Listener in WMI AutoLogger
reg add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f

REM Disables SQMLogger in WMI AutoLogger
reg add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "Start" /t REG_DWORD /d "0" /f

REM Disables CEIP (Customer Experience Improvement Program) in SQMClient
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f

REM Sets DownloadMode to 0 in DeliveryOptimization\Settings
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings" /v "DownloadMode" /t REG_DWORD /d "0" /f
cls  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d 3 /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverrideMask /t REG_DWORD /d 3 /f

REM Disable DmaRemappingCompatible 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\rt640x64\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\USBXHCI\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d "0" /f
      
REM Terminate OneDrive processes and uninstall OneDrive
taskkill /f /im OneDrive.exe >nul
%SystemRoot%\SysWOW64\OneDriveSetup.exe /uninstall
%SystemRoot%\System32\OneDriveSetup.exe /uninstall

REM Grant administrators full control over the Microsoft Edge folder
icacls "C:\Program Files (x86)\Microsoft\Edge" /t /c /q /grant administrators:F

REM Take ownership of the Microsoft Edge folder
takeown /f "C:\Program Files (x86)\Microsoft\Edge" /r /d y

REM Terminate Microsoft Edge processes
taskkill /f /im msedge.exe

REM Uninstall Microsoft Edge using the setup tool
cd "%PROGRAMFILES(X86)%\Microsoft\Edge\Application"
for /d %%I in (*) do (
    cd "%%I\Installer"
    setup --uninstall --force-uninstall --system-level
    cd ..
)

REM Remove Microsoft Edge folders
cd "%PROGRAMFILES(X86)%\Microsoft\Edge"
rmdir /s /q "C:\Program Files (x86)\Microsoft\Edge"

REM disables Wi-Fi hotspot reporting
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v "value" /t REG_DWORD /d "0" /f 

REM disables Action Center experience
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v "UseActionCenterExperience" /t REG_DWORD /d "0" /f 

REM disables Windows Telemetry
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f 

REM disables additional Windows Telemetry
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f 

REM disables Clipboard History
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowClipboardHistory" /t REG_DWORD /d "0" /f 

REM disables Cross-device Clipboard
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowCrossDeviceClipboard" /t REG_DWORD /d "0" /f 

REM enables Trusted Computing Group (TCG) security activation
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EnhancedStorageDevices" /v "TCGSecurityActivationDisabled" /t REG_DWORD /d "0" /f 

REM disables Authenticode verification for scripts
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers" /v "authenticodeenabled" /t REG_DWORD /d "0" /f 

REM disables additional Windows Telemetry for 32-bit applications
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f 

REM disable WUDF logging
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogEnable" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogLevel" /t REG_DWORD /d "0" /f 

REM disables debug logging for CredSSP
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Credssp" /v "DebugLogLevel" /t REG_DWORD /d "0" /f 

REM disable Application Compatibility Toolkit (ACT) features
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d "1" /f 

REM disables GameDVR (game recording)
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /v "value" /t REG_SZ /d "00000000" /f

REM disable toast notifications and the Notification Center
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableNotificationCenter" /t REG_DWORD /d "1" /f

REM disables tile notifications for applications
reg add "HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoTileApplicationNotification" /t REG_DWORD /d "1" /f

REM disable Windows SmartScreen
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 0 /f

REM disables web content evaluation
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d 0 /f
  
taskkill -F -FI "IMAGENAME eq SystemSettings.exe"   
REM disables IPv6 components (disables IPv6)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v "DisabledComponents" /t REG_DWORD /d "32" /f

rd s q "C:\Windows\SoftwareDistribution"  
md "C:\Windows\SoftwareDistribution"        

REM disables the DiagTrack service
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d 4 /f

REM disables the dmwappushservice service
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d 4 /f

REM disables DMA remapping for the intelppm service
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d 0 /f

REM disables DMA remapping for the pci service
reg add "HKLM\SYSTEM\CurrentControlSet\Services\pci\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d 0 /f

REM disables Bluetooth advertising in the device's current policy
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth" /v "AllowAdvertising" /t REG_DWORD /d 0 /f 

REM Disables Windows Remote Assistance and related settings
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /F /V "fAllowUnsolicited" /T REG_DWORD /d 0
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /F /V "fAllowToGetHelp" /T REG_DWORD /d 0
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /F /V "UseBandwidthOptimization" /T REG_DWORD /d 0
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /F /V "LoggingEnabled" /T REG_DWORD /d 0

REM Disables some unnecessary services
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "4" /f

REM Disables DMA remapping compatibility for various hardware devices
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\pci\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\kbdhid\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NdisWan\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\EhStorClass\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\HDAudBus\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\partmgr\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\ACPI\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\acpipagr\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BasicDisplay\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BasicRender\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dc1-controller\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelpep\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\MEIx64\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\monitor\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\mouhid\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\msisadrv\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NdisVirtualBus\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NvModuleTracker\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\storahci\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\umbus\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\USBHUB3\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\USBXHCI\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\vdrvroot\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WUDFWpdFsParameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\xinputhid\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f

REM Disables Cortana and related settings
taskkill /f /im Cortana.exe
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CanCortanaBeEnabled" /t REG_DWORD /d 0 /f
rd /s /q "%WinDir%\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy" 
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d "0" /f

REM Disable paging combining
reg add "HKLM\SYSTEM\currentcontrolset\control\session manager\Memory Management" /v "DisablePagingCombining" /t REG_DWORD /d "1" /f

REM Disable Biometrics
reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics" /v "Enabled" /t REG_DWORD /d "0" /f

REM Disable Power Throttling
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f

REM Set Smooth Mouse X Curve
reg add "HKCU\Control Panel\Mouse" /v "SmoothMouseXCurve" /t REG_BINARY /d "000000000000000000a0000000000000004001000000000000800200000000000000050000000000" /f

REM Set Smooth Mouse Y Curve
reg add "HKCU\Control Panel\Mouse" /v "SmoothMouseYCurve" /t REG_BINARY /d "000000000000000066a6020000000000cd4c050000000000a0990a00000000003833150000000000" /f

REM Change permissions and delete Microsoft.XboxGameCallableUI_cw5n1h2txyewy
cd C:\Windows\SystemApps
timeout 1 >nul /nobreak
icacls "C:\Windows\SystemApps\Microsoft.XboxGameCallableUI_cw5n1h2txyewy" /t /c /q /grant administrators:F
takeown /F C:\Windows\SystemApps\Microsoft.XboxGameCallableUI_cw5n1h2txyewy /R /D Y
rmdir /S /Q C:\Windows\SystemApps\Microsoft.XboxGameCallableUI_cw5n1h2txyewy

REM Change permissions and delete Microsoft.XboxApp_48.49.31001.0_x64__8wekyb3d8bbwe
icacls "C:\Windows\SystemApps\Microsoft.XboxApp_48.49.31001.0_x64__8wekyb3d8bbwe" /t /c /q /grant administrators:F
takeown /F C:\Windows\SystemApps\Microsoft.XboxApp_48.49.31001.0_x64__8wekyb3d8bbwe /R /D Y
rmdir /S /Q C:\Windows\SystemApps\Microsoft.XboxApp_48.49.31001.0_x64__8wekyb3d8bbwe

REM Disable MFU Tracking for Edge
reg add "HKCU\Software\Policies\Microsoft\Windows\EdgeUI" /F /V "DisableMFUTracking" /T REG_DWORD /d 1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EdgeUI" /F /V "DisableMFUTracking" /T REG_DWORD /d 1

REM Adjust Explorer Advanced Settings
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /F /V "Start_TrackProgs" /T REG_DWORD /d 0

REM Disable HttpAcceptLanguageOptOut
reg add "HKCU\Control Panel\International\User Profile" /F /V "HttpAcceptLanguageOptOut" /T REG_DWORD /d 1

REM Deny permissions for certain capabilities
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" /F /V "Value" /T REG_SZ /d "Deny"
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" /F /V "Value" /T REG_SZ /d "Deny"
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" /F /V "Value" /T REG_SZ /d "Deny"
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" /F /V "Value" /T REG_SZ /d "Deny"

REM Disable Accessibility Options
reg add "HKCU\Control Panel\Accessibility\MouseKeys" /F /V "Flags" /T REG_SZ /d "0"
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /F /V "Flags" /T REG_SZ /d "0"
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /F /V "Flags" /T REG_SZ /d "0"
reg add "HKCU\Control Panel\Accessibility\ToggleKeys" /F /V "Flags" /T REG_SZ /d "0"

REM Disable Driver Searching
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /F /V "SearchOrderConfig" /T REG_DWORD /d 0

REM Disable Automatic Restart Sign-On
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /F /V "DisableAutomaticRestartSignOn" /T REG_DWORD /d 1

REM Restrict Implicit Text Collection
reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /F /V "RestrictImplicitTextCollection" /T REG_DWORD /d 1

REM Restrict Implicit Ink Collection
reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /F /V "RestrictImplicitInkCollection" /T REG_DWORD /d 1

REM Disable Harvesting Contacts for Personalization
reg add "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /F /V "HarvestContacts" /T REG_DWORD /d 0

REM Set Accepted Privacy Policy to 0
reg add "HKCU\Software\Microsoft\Personalization\Settings" /F /V "AcceptedPrivacyPolicy" /T REG_DWORD /d 0

REM Disable Input Personalization
reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /F /V "AllowInputPersonalization" /T REG_DWORD /d 0

REM Disable Voice Activation for All Apps
reg add "HKCU\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps" /v "AgentActivationEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps" /v "AgentActivationOnLockScreenEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps" /v "AgentActivationLastUsed" /t REG_DWORD /d "0" /f

REM Disable Online Tips
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /F /V "AllowOnlineTips" /T REG_DWORD /d 0

REM Disable Window Minimizing Shortcuts
reg add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /F /V "NoWindowMinimizingShortcuts" /T REG_DWORD /d 1

REM Disable Instrumentation
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /F /V "NoInstrumentation" /T REG_DWORD /d 1

REM Disable Balloon Feature Advertisements
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /F /V "NoBalloonFeatureAdvertisements" /T REG_DWORD /d 1

REM Disable Taskbar Notification
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /F /V "TaskbarNoNotification" /T REG_DWORD /d 1

REM Disable Quiet Hours
reg add "HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\QuietHours" /F /V "Enable" /T REG_DWORD /d 0

REM Disable Tile Application Notifications
reg add "HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /F /V "NoTileApplicationNotification" /T REG_DWORD /d 1

REM Set CdpSessionUserAuthzPolicy to 0
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CDP" /F /V "CdpSessionUserAuthzPolicy" /T REG_DWORD /d 0

REM Set NearShareChannelUserAuthzPolicy to 0
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CDP" /F /V "NearShareChannelUserAuthzPolicy" /T REG_DWORD /d 0

REM Set RomeSdkChannelUserAuthzPolicy to 0
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CDP" /F /V "RomeSdkChannelUserAuthzPolicy" /T REG_DWORD /d 0

REM Enable Database Migration Completed
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /F /V "DatabaseMigrationCompleted" /T REG_DWORD /d 1

REM Disable Toast Notifications
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /F /V "ToastEnabled" /T REG_DWORD /d 0

REM Disable Lock Screen Toast Notifications
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /F /V "LockScreenToastEnabled" /T REG_DWORD /d 0
  
REM Disable AutoUpdateEnabled for Maps
reg add "HKLM\SYSTEM\Maps" /F /V "AutoUpdateEnabled" /T REG_DWORD /d 0

REM Disable Toast Application Notifications on Lock Screen (both current user and all users)
reg add "HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /F /V "NoToastApplicationNotificationOnLockScreen" /T REG_DWORD /d 1

REM Disable Tailored Experiences with Diagnostic Data for the current user
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /F /V "TailoredExperiencesWithDiagnosticDataEnabled" /T REG_DWORD /d 0

REM Disable Tailored Experiences with Diagnostic Data using Group Policy
reg add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /F /V "disabletailoredexperiencesWithDiagnosticData" /T REG_DWORD /d 1

REM Disable Cloud Application Notifications
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /F /V "NoCloudApplicationNotification" /T REG_DWORD /d 1

REM Prevent Handwriting Data Sharing
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /F /V "PreventHandwritingDataSharing" /T REG_DWORD /d 1

REM Prevent Handwriting Error Reports
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /F /V "PreventHandwritingErrorReports" /T REG_DWORD /d 1

REM Disable Windows Error Reporting
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /F /V "Disabled" /T REG_DWORD /d 1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f 

REM Prevent Searching Windows Update for Drivers
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" /F /V "DontSearchWindowsUpdate" /T REG_DWORD /d 1

REM Disable First Logon Animation
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /F /V "EnableFirstLogonAnimation" /T REG_DWORD /d 0

REM Disable Lock Screen App Notifications
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /F /V "DisableLockScreenAppNotifications" /T REG_DWORD /d 1

REM Disable User and System Activity Upload
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /F /V "UploadUserActivities" /T REG_DWORD /d 0
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /F /V "PublishUserActivities" /T REG_DWORD /d 0

REM Disable Cross-Device Clipboard and Clipboard History
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /F /V "AllowCrossDeviceClipboard" /T REG_DWORD /d 0
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /F /V "AllowClipboardHistory" /T REG_DWORD /d 0

REM Disable Activity Feed
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /F /V "EnableActivityFeed" /T REG_DWORD /d 0

REM Disable Hiberboot (Hybrid Boot)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /F /V "HiberbootEnabled" /T REG_DWORD /d 0

REM Disable Storage Sense Global
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\StorageSense" /F /V "AllowStorageSenseGlobal" /T REG_DWORD /d 0

REM Disable Storage Sense Temporary Files Cleanup
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\StorageSense" /F /V "AllowStorageSenseTemporaryFilesCleanup" /T REG_DWORD /d 0

REM Disable Scheduled Diagnostics
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\ScheduledDiagnostics" /F /V "EnabledExecution" /T REG_DWORD /d 0

REM Disable Advertising Info Collection
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f

REM Disable Advertising Info Collection using Group Policy
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /F /V "DisabledByGroupPolicy" /T REG_DWORD /d 1

REM Restrict App Privacy Settings
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /F /V "LetAppsAccessAccountInfo" /T REG_DWORD /d 2
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /F /V "LetAppsAccessGazeInput" /T REG_DWORD /d 2
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /F /V "LetAppsAccessCallHistory" /T REG_DWORD /d 2
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /F /V "LetAppsAccessContacts" /T REG_DWORD /d 2
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /F /V "LetAppsGetDiagnosticInfo" /T REG_DWORD /d 2
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /F /V "LetAppsAccessEmail" /T REG_DWORD /d 2
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /F /V "LetAppsAccessLocation" /T REG_DWORD /d 2
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /F /V "LetAppsAccessMessaging" /T REG_DWORD /d 2
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /F /V "LetAppsAccessMotion" /T REG_DWORD /d 2
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /F /V "LetAppsAccessNotifications" /T REG_DWORD /d 2
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /F /V "LetAppsAccessTasks" /T REG_DWORD /d 2
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /F /V "LetAppsAccessCalendar" /T REG_DWORD /d 2
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /F /V "LetAppsAccessTrustedDevices" /T REG_DWORD /d 2
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /F /V "LetAppsAccessBackgroundSpatialPerception" /T REG_DWORD /d 2
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /F /V "LetAppsActivateWithVoice" /T REG_DWORD /d 2
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /F /V "LetAppsActivateWithVoiceAboveLock" /T REG_DWORD /d 2
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /F /V "LetAppsSyncWithDevices" /T REG_DWORD /d 2
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /F /V "LetAppsAccessRadios" /T REG_DWORD /d 2
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /F /V "LetAppsAccessPhone" /T REG_DWORD /d 2
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /F /V "LetAppsRunInBackground" /T REG_DWORD /d 2

REM Disable Soft Landing for Cloud Content
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /F /V "DisableSoftLanding" /T REG_DWORD /d 1

REM Disable Cloud-Optimized Content
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /F /V "DisableCloudOptimizedContent" /T REG_DWORD /d 1

REM Disable Windows Consumer Features
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /F /V "DisableWindowsConsumerFeatures" /T REG_DWORD /d 1

REM Disable Visuals
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d "3" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\AnimateMinMax" /v "DefaultApplied" /t REG_SZ /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ComboBoxAnimation" /v "DefaultApplied" /t REG_SZ /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ControlAnimations" /v "DefaultApplied" /t REG_SZ /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\CursorShadow" /v "DefaultApplied" /t REG_SZ /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DragFullWindows" /v "DefaultApplied" /t REG_SZ /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DropShadow" /v "DefaultApplied" /t REG_SZ /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMAeroPeekEnabled" /v "DefaultApplied" /t REG_SZ /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMEnabled" /v "DefaultApplied" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMSaveThumbnailEnabled" /v "DefaultApplied" /t REG_SZ /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\FontSmoothing" /v "DefaultApplied" /t REG_SZ /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListBoxSmoothScrolling" /v "DefaultApplied" /t REG_SZ /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListviewAlphaSelect" /v "DefaultApplied" /t REG_SZ /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListviewShadow" /v "DefaultApplied" /t REG_SZ /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\MenuAnimation" /v "DefaultApplied" /t REG_SZ /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\SelectionFade" /v "DefaultApplied" /t REG_SZ /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TaskbarAnimations" /v "DefaultApplied" /t REG_SZ /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ThumbnailsOrIcon" /v "DefaultApplied" /t REG_SZ /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TooltipAnimation" /v "DefaultApplied" /t REG_SZ /d "0" /f

REM Disable Scheduled Maintenance
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /F /V "MaintenanceDisabled" /T REG_DWORD /d 1

REM Disable Use Nexus for Game Bar
reg add "HKCU\Software\Microsoft\GameBar" /F /V "UseNexusForGameBarEnabled" /T REG_DWORD /d 0

REM Allow Webcam access for the consent store (global setting)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v "Value" /t REG_SZ /d "Allow" /f

REM Deny Webcam access for specific apps in the consent store
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\Microsoft.Microsoft3DViewer_8wekyb3d8bbwe" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\Microsoft.MicrosoftEdge_8wekyb3d8bbwe" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\Microsoft.Office.OneNote_8wekyb3d8bbwe" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\Microsoft.SkypeApp_kzf8qxf38zg5c" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\Microsoft.Win32WebViewHost_cw5n1h2txyewy" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\Microsoft.Windows.Photos_8wekyb3d8bbwe" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\Microsoft.WindowsCamera_8wekyb3d8bbwe" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\Microsoft.WindowsFeedbackHub_8wekyb3d8bbwe" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\NonPackaged" /v "Value" /t REG_SZ /d "Allow" /f

REM Allow Microphone access for the consent store (global setting)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" /v "Value" /t REG_SZ /d "Allow" /f

REM Deny Microphone access for specific apps in the consent store
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\Microsoft.549981C3F5F10_8wekyb3d8bbwe" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\Microsoft.Microsoft3DViewer_8wekyb3d8bbwe" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\Microsoft.MicrosoftEdge_8wekyb3d8bbwe" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\Microsoft.MixedReality.Portal_8wekyb3d8bbwe" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\Microsoft.Office.OneNote_8wekyb3d8bbwe" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\Microsoft.SkypeApp_kzf8qxf38zg5c" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\Microsoft.Win32WebViewHost_cw5n1h2txyewy" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\Microsoft.Windows.Photos_8wekyb3d8bbwe" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\Microsoft.Windows.SecureAssessmentBrowser_cw5n1h2txyewy" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\Microsoft.WindowsCamera_8wekyb3d8bbwe" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\Microsoft.WindowsFeedbackHub_8wekyb3d8bbwe" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\Microsoft.WindowsSoundRecorder_8wekyb3d8bbwe" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\Microsoft.XboxApp_8wekyb3d8bbwe" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe" /v "Value" /t REG_SZ /d "Deny" /f

REM GameDVR Tweaks
reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "2" /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehavior" /t REG_DWORD /d "2" /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "1" /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "1" /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /t REG_DWORD /d "0" /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_DSEBehavior" /t REG_DWORD /d "2" /f
reg add "HKCU\Software\Microsoft\GameBar" /v "ShowStartupPanel" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\GameBar" /v "GamePanelStartupTipIndex" /t REG_DWORD /d "3" /f
reg add "HKCU\Software\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\GameBar" /v "UseNexusForGameBarEnabled" /t REG_DWORD /d "0" /f
     
REM Disable SmartScreen
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /F /V "EnableSmartScreen" /T "REG_DWORD" /d "0"

REM Disable Message Sync
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Messaging" /F /V "AllowMessageSync" /T "REG_DWORD" /d "0"

REM Disable Active Help
reg add "HKLM\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" /F /V "NoActiveHelp" /T "REG_DWORD" /d "1"

REM Disable Indexing for Removable Drives
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /F /V "DisableRemovableDriveIndexing" /T "REG_DWORD" /d "1"

REM Disable Cortana Above Lock Screen
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /F /V "AllowCortanaAboveLock" /T "REG_DWORD" /d "0"

REM Disable Cloud Search
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /F /V "AllowCloudSearch" /T "REG_DWORD" /d "0"

REM Disable Location-Based Search
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /F /V "AllowSearchToUseLocation" /T "REG_DWORD" /d "0"

REM Disable Web Search Results in Search
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /F /V "ConnectedSearchUseWeb" /T "REG_DWORD" /d "0"

REM Disable Windows Defender
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t "REG_DWORD" /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableRoutinelyTakingAction" /t "REG_DWORD" /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t "REG_DWORD" /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t "REG_DWORD" /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t "REG_DWORD" /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t "REG_DWORD" /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t "REG_DWORD" /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t "REG_DWORD" /d "1" /f

REM Disable SafeSearch Mode
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /F /V "SafeSearchMode" /T REG_DWORD /d "0"

REM Disable Device Search History
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /F /V "IsDeviceSearchHistoryEnabled" /T REG_DWORD /d "0"

REM Disable Narrator Temporarily
reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\AccessibilityTemp" /v "narrator" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Narrator\NoRoam" /v "RunningState" /t REG_DWORD /d "0" /f

REM Disable Language Sync
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "SettingsVersion" /t REG_DWORD /d "3" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d "0" /f

REM Disable Tablet Input Features
reg add "HKCU\Software\Microsoft\TabletTip\1.7" /v "EnableAutocorrection" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\TabletTip\1.7" /v "EnableSpellchecking" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\TabletTip\1.7" /v "EnableTextPrediction" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\TabletTip\1.7" /v "EnablePredictionSpaceInsertion" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\TabletTip\1.7" /v "EnableDoubleTapSpace" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\TabletTip\1.7" /v "EnableInkingWithTouch" /t REG_DWORD /d "0" /f

REM Disable Input Insights
reg add "HKCU\Software\Microsoft\Input\Settings" /v "InsightsEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Input\Settings" /v "Insights" /t REG_BINARY /d "01000000071de8c131cc8360a3d6d9c1330a686b165aba2e235f5a5c" /f

REM Disable Pen Workspace App Suggestions
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\PenWorkspace" /v "PenWorkspaceAppSuggestionsEnabled" /t REG_DWORD /d "0" /f

REM Disable Autoplay Handlers
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /v "DisableAutoplay" /t REG_DWORD /d "1" /f

REM Restrict Implicit Ink and Text Collection
reg add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f

REM Disable Tablet Mode, Enable Sign-in Mode Prompt, and Reset Shell Cache
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v "TabletMode" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v "SignInMode" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v "ConvertibleSlateModePromptPreference" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell\StateStore" /v "ResetCacheCount" /t REG_DWORD /d "1" /f

REM Device Metadata Configuration
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "BackOffInterval" /t REG_DWORD /d "5" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "CheckBackMDNotRetrieved" /t REG_DWORD /d "5" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "CheckBackMDRetrieved" /t REG_DWORD /d "8" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "DeviceMetadataServiceURL" /t REG_SZ /d "http://go.microsoft.com/fwlink/?LinkID=252669&clcid=0x409" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "MaxRetryLimit" /t REG_DWORD /d "5" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "RequestBatchSize" /t REG_DWORD /d "25" /f
 
REM Disable Remote Assistance features
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "CreateEncryptedOnlyTickets" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowFullControl" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fEnableChatControl" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "MaxTicketExpiry" /t REG_DWORD /d "6" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "MaxTicketExpiryUnits" /t REG_DWORD /d "1" /f

REM Modify Windows Search settings
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "InstalledWin32AppsRevision" /t REG_SZ /d "{E00F4E01-A5F6-488E-A733-D341606BBD99}" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "InstalledPackagedAppsRevision" /t REG_SZ /d "{EE5761AF-9340-40EE-AFFB-D3F7ECEC59BD}" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaMUID" /t REG_SZ /d "MUID=62b4e7c3c0a24010b4c5abdfe4f2b796" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaStateLastRun" /t REG_BINARY /d "3247f55f00000000" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "IsAssignedAccess" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "NamespaceSettingsRevision" /t REG_SZ /d "{EBDF1464-A4D5-443C-ACE8-21C7FCDF002F}" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "AnyAboveLockAppsActive" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaConsent" /t REG_DWORD /d "0" /f

REM Modify Input Personalization settings
reg add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f

REM Disable Content Delivery Manager
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338394Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338396Enabled" /t REG_DWORD /d "0" /f

REM Adjust Telemetry and FindMyDevice settings
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "MaxTelemetryAllowed" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Settings\FindMyDevice" /v "LocationSyncEnabled" /t REG_DWORD /d "0" /f

REM Disable Input Personalization TrainedDataStore
reg add "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f

REM Modify DiagTrack and Privacy settings
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "DiagTrackAuthorization" /t REG_DWORD /d "775" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "DiagTrackStatus" /t REG_DWORD /d "2" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "UploadPermissionReceived" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\TraceManager" /v "MiniTraceSlotContentPermitted" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\TraceManager" /v "MiniTraceSlotEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "PrivacyConsentPresentationVersion" /t REG_DWORD /d "2" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "PrivacyConsentSettingsVersion" /t REG_DWORD /d "3" /f
 
REM Modify Siuf\Rules settings
reg add "HKCU\Software\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d "0" /f

REM Modify BackgroundAccessApplications settings
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "Migrated" /t REG_DWORD /d "4" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f

REM Deny access for specific capabilities
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" /v "Value" /t REG_SZ /d "Allow" /f

REM Modify Shell and Desktop settings
reg add "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d "0" /f
reg add "HKCR\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d "0" /f

REM Modify USB and Control Panel settings
reg add "HKCU\Software\Microsoft\Shell\USB" /v "NotifyOnWeakCharger" /t REG_DWORD /d "0" /f
reg add "HKCU\Control Panel\Desktop" /v "WindowArrangementActive" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Desktop" /v "DragFullWindows" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Desktop" /v "MouseWheelRouting" /t REG_DWORD /d "0" /f
reg add "HKCU\Control Panel\Desktop" /v "Pattern" /t REG_DWORD /d "0" /f
reg add "HKCU\Control Panel\Desktop" /v "WindowArrangementActive" /t REG_DWORD /d "0" /f
reg add "HKCU\Control Panel\Desktop" /v "ScreenSaverIsSecure" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Desktop" /v "ActiveWndTrackTimeout" /t REG_DWORD /d "0" /f
reg add "HKCU\Control Panel\Desktop" /v "BlockSendInputResets" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Desktop" /v "EnablePerProcessSystemDPI" /t REG_DWORD /d "0" /f
reg add "HKCU\Control Panel\Desktop" /v "Beep" /t REG_SZ /d "No" /f
reg add "HKCU\Control Panel\Desktop" /v "ExtendedSounds" /t REG_SZ /d "No" /f
reg add "HKCU\Control Panel\Desktop" /v "KeyboardDelay" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Desktop" /v "MouseSensitivity" /t REG_SZ /d "10" /f
reg add "HKCU\Control Panel\Desktop" /v "MouseSpeed" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Desktop" /v "MouseThreshold1" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Desktop" /v "MouseThreshold2" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Desktop" /v "Win8DpiScaling" /t REG_DWORD /d "0" /f
reg add "HKCU\Control Panel\Desktop" /v "DpiScalingVer" /t REG_DWORD /d "4096" /f
reg add "HKCU\Control Panel\Desktop" /v "ScreenSaverIsSecure" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Desktop" /v "PaintDesktopVersion" /t REG_DWORD /d "0" /f
reg add "HKCU\Control Panel\Desktop" /v "WallpaperOriginX" /t REG_DWORD /d "0" /f
reg add "HKCU\Control Panel\Desktop" /v "WallpaperOriginY" /t REG_DWORD /d "0" /f
reg add "HKCU\Control Panel\Desktop" /v "ForegroundLockTimeout" /t REG_DWORD /d "0" /f
reg add "HKCU\Control Panel\Desktop" /v "LastUpdated" /t REG_DWORD /d "4294967295" /f
reg add "HKCU\Control Panel\Mouse" /v "ActiveWindowTracking" /t REG_DWORD /d "0" /f
reg add "HKCU\Control Panel\Mouse" /v "Beep" /t REG_SZ /d "No" /f
reg add "HKCU\Control Panel\Mouse" /v "ExtendedSounds" /t REG_SZ /d "No" /f
reg add "HKCU\Control Panel\Mouse" /v "MouseSensitivity" /t REG_SZ /d "10" /f
reg add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Mouse" /v "MouseTrails" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Mouse" /v "SmoothMouseXCurve" /t REG_BINARY /d "0000000000000000c0cc0c0000000000809919000000000040662600000000000033330000000000" /f
reg add "HKCU\Control Panel\Mouse" /v "SmoothMouseYCurve" /t REG_BINARY /d "0000000000000000000038000000000000007000000000000000a800000000000000e00000000000" /f
reg add "HKCU\Control Panel\Mouse" /v "SnapToDefaultButton" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Mouse" /v "SwapMouseButtons" /t REG_SZ /d "0" /f

REM Modify WindowMetrics settings
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d "0" /f

REM Modify Explorer settings
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "TelemetrySalt" /t REG_DWORD /d "2" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "FirstRunTelemetryComplete" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "AppReadinessLogonComplete" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "EdgeDesktopShortcutCreated" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "PostAppInstallTasksCompleted" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowFrequent" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "DesktopProcess" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "EnableAutoTray" /t REG_DWORD /d "0" /f

REM Modify Advanced Explorer settings
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ServerAdminUI" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d "2" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCompColor" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DontPrettyPath" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowInfoTip" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideIcons" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "SeparateProcess" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconsOnly" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTypeOverlay" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowStatusBar" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "StoreAppsOnTaskbar" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewAlphaSelect" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "StartMenuInit" /t REG_DWORD /d "13" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCortanaButton" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarStateLastRun" /t REG_BINARY /d "465df45f00000000" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ReindexedProfile" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarSmallIcons" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ExtendedUIHoverTime" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DesktopLivePreviewHoverTime" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "nonetcrawling" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarSizeMove" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisallowShaking" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d "2" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d "0" /f

REM Modify Policies
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" /F /V "AllowWindowsInkWorkspace" /T REG_DWORD /d 0
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowFullControl" /t REG_DWORD /f /d 0
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /f /d 0
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableBoottrace" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableCfg" /t REG_DWORD /d "0" /f

REM disable FTH  
reg add "HKLM\SOFTWARE\Microsoft\FTH" /F /V "Enabled" /T REG_DWORD /d 0 
              
REM Disable a scheduled task
schtasks /change /TN "Microsoft\Windows\Device Information\Device" /DISABLE

REM Modify registry settings
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "LazyModeTimeout" /t REG_DWORD /d "150000" /f 
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /v "ShowSleepOption" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /v "ShowLockOption" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\MediaPlayer\Preferences" /v "UsageTracking" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v "NoGenTicket" /t "REG_DWORD" /d "1" /f
reg add "HKLM\SYSTEM\currentcontrolset\control\session manager\Power" /v "SleepStudyDisabled" /t REG_DWORD /d "1" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CanCortanaBeEnabled" /t REG_DWORD /d 0 /f

REM Set the owner of "Device Parameters" registry key and grant full permissions to Administrators for all USB devices using SetACL and Reg commands
for /f %%a in ('wmic PATH Win32_PnPEntity GET DeviceID ^| findstr /l "USB\VID_"') do (
    C:\Windows\SetACL.exe -on "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters" -ot reg -actn setowner -ownr "n:Administrators"
    C:\Windows\SetACL.exe -on "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters" -ot reg -actn ace -ace "n:Administrators;p:full"
    reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters" /v SelectiveSuspendOn /t REG_DWORD /d 00000000 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters" /v SelectiveSuspendEnabled /t REG_BINARY /d 00 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters" /v EnhancedPowerManagementEnabled /t REG_DWORD /d 00000000 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters" /v AllowIdleIrpInD3 /t REG_DWORD /d 00000000 /f
)

REM Set the owner of "Device Parameters\WDF" registry key and set the "IdleInWorkingState" value to 0 for all USB root hubs using SetACL
for /f %%a in ('wmic PATH Win32_USBHub GET DeviceID ^| findstr /l "USB\ROOT_HUB"') do (
    C:\Windows\SetACL.exe -on "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters\WDF" -ot reg -actn setowner -ownr "n:Administrators"
    reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters\WDF" /v IdleInWorkingState /t REG_DWORD /d 00000000 /f
)
 
REM Disable HttpAcceptLanguageOptOut
reg add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f 

REM Disable EnableWebContentEvaluation
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f 

REM Set Delivery Optimization Download Mode to 0 (Bypass mode)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DownloadMode" /t REG_DWORD /d "0" /f 

REM Hide SCA Health in File Explorer
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAHealth" /t REG_DWORD /d "1" /f 

REM Enable Enhanced Storage Devices TCG Security Activation
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EnhancedStorageDevices" /v "TCGSecurityActivationDisabled" /t REG_DWORD /d "0" /f 

REM Disable OneDrive File Sync
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d "1" /f 

REM Disable Authenticode Checking
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers" /v "authenticodeenabled" /t REG_DWORD /d "0" /f 

REM Disable Telemetry (32-bit Applications on 64-bit Systems)
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f 

REM Disable Lock Screen Toast Notifications
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v "LockScreenToastEnabled" /t REG_DWORD /d "0" /f

REM Disable All Toast Notifications
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d "0" /f

REM Set Quiet Hours Telemetry Last Run (timestamp)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "QuietHoursTelemetryLastRun" /t REG_BINARY /d "2d41e95f00000000" /f

REM Disable Notifications Above Lock Screen
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK" /t REG_DWORD /d "0" /f

REM Disable Critical Notifications Above Lock Screen
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_CRITICAL_TOASTS_ABOVE_LOCK" /t REG_DWORD /d "0" /f

REM Disable Notification Sounds
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_NOTIFICATION_SOUND" /t REG_DWORD /d "0" /f

REM Disable DPC Watchdog Profile Offset
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DpcWatchdogProfileOffset" /t REG_DWORD /d "0" /f

REM Set DPC Timeout to 0 (infinite)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DpcTimeout" /t REG_DWORD /d "0" /f

REM Set DPC Watchdog Period to 0 (infinite)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DpcWatchdogPeriod" /t REG_DWORD /d "0" /f

REM Disable Exception Chain Validation
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d "1" /f

REM Disable Kernel SEHOP (Structured Exception Handling Overwrite Protection)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "KernelSEHOPEnabled" /t REG_DWORD /d "0" /f

REM Disable Exception Chain Validation (CurrentControlSet)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d "1" /f

REM Disable Kernel SEHOP (CurrentControlSet)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "KernelSEHOPEnabled" /t REG_DWORD /d "0" /f
              
REM Disable Hibernate in CurrentControlSet Power settings
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d 0 /f

REM Disable Hibernate in CurrentControlSet Power settings
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d 0 /f

REM Disable Superfetch in WINEVt Channels (Main)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVt\Channels\Microsoft-Windows-Superfetch/Main" /v "Enabled" /t REG_DWORD /d 0 /f

REM Disable Superfetch in WINEVt Channels (PfApLog)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVt\Channels\Microsoft-Windows-Superfetch/PfApLog" /v "Enabled" /t REG_DWORD /d 0 /f

REM Disable Superfetch in WINEVt Channels (StoreLog)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVt\Channels\Microsoft-Windows-Superfetch/StoreLog" /v "Enabled" /t REG_DWORD /d 0 /f

REM Disable ClearPageFileAtShutdown in Memory Management of Session Manager
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "ClearPageFileAtShutdown" /t REG_DWORD /d 0 /f

REM Set Value to Deny in DeviceAccess Global LooselyCoupled for Current User
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" /v "Value" /t REG_SZ /d "Deny" /f

REM Disable amdlog service
reg add "HKLM\SYSTEM\CurrentControlSet\Services\amdlog" /v "Start" /t REG_DWORD /d 3 /f

REM Disable TapiSrv service
reg add "HKLM\SYSTEM\CurrentControlSet\Services\TapiSrv" /v "Start" /t REG_DWORD /d 3 /f

REM Disable FontCache3.0.0.0 service
reg add "HKLM\SYSTEM\CurrentControlSet\Services\FontCache3.0.0.0" /v "Start" /t REG_DWORD /d 3 /f

REM Disable WpcMonSvc service
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WpcMonSvc" /v "Start" /t REG_DWORD /d 3 /f

REM Disable SEMgrSvc service
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SEMgrSvc" /v "Start" /t REG_DWORD /d 2 /f

REM Disable PNRPsvc service
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PNRPsvc" /v "Start" /t REG_DWORD /d 3 /f

REM Disable WEPHOSTSVC service
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WEPHOSTSVC" /v "Start" /t REG_DWORD /d 3 /f

REM Disable p2psvc service
reg add "HKLM\SYSTEM\CurrentControlSet\Services\p2psvc" /v "Start" /t REG_DWORD /d 3 /f

REM Disable p2pimsvc service
reg add "HKLM\SYSTEM\CurrentControlSet\Services\p2pimsvc" /v "Start" /t REG_DWORD /d 3 /f

REM Disable PhoneSvc service
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PhoneSvc" /v "Start" /t REG_DWORD /d 3 /f

REM Disable Wecsvc service
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Wecsvc" /v "Start" /t REG_DWORD /d 3 /f

REM Old AltTab
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "AltTabSettings" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "HoverSelectDesktops" /t REG_DWORD /d "0" /f

REM Disable RmSvc service
reg add "HKLM\SYSTEM\CurrentControlSet\Services\RmSvc" /v "Start" /t REG_DWORD /d 3 /f

REM Disable SensorDataService service
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SensorDataService" /v "Start" /t REG_DWORD /d 3 /f

REM Disable SensrSvc service
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SensrSvc" /v "Start" /t REG_DWORD /d 3 /f

REM Disable perceptionsimulation service
reg add "HKLM\SYSTEM\CurrentControlSet\Services\perceptionsimulation" /v "Start" /t REG_DWORD /d 3 /f

REM Disable StiSvc service
reg add "HKLM\SYSTEM\CurrentControlSet\Services\StiSvc" /v "Start" /t REG_DWORD /d 3 /f

REM Disable OneSyncSvc service
reg add "HKLM\SYSTEM\CurrentControlSet\Services\OneSyncSvc" /v "Start" /t REG_DWORD /d 2 /f
cls
REM Disables the Active Help feature in Windows
reg add "HKLM\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" /F /V "NoActiveHelp" /T REG_DWORD /d 1

REM Disables web search in Windows Search
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /F /V "DisableWebSearch" /T REG_DWORD /d 1

REM Disables automatic speech model updates
reg add "HKLM\SOFTWARE\Policies\Microsoft\Speech" /F /V "AllowSpeechModelUpdate" /T REG_DWORD /d 0

REM Disable Telementry
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f

REM Lower Latency for Power Saving Modes
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v ExitLatency /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v ExitLatencyCheckEnabled /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v Latency /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1" /v "Attributes" /t REG_SZ /d "2" /f

REM Set Csrsss.exe Realtime Priority
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "4" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f

REM Disable Automatic Drivers Update
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d "0" /f

REM Disable background apps
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BackgroundAppGlobalToggle" /t REG_DWORD /d "0" /f

REM Disable DVR1
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /v "value" /t REG_DWORD /d "0" /f

REM Disable Edge Prelaunch
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" /v "AllowPrelaunch" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" /v "AllowTabPreloading" /t REG_DWORD /d "0" /f

REM Disable Hibernate
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabledDefault" /t REG_DWORD /d "0" /f

REM Disable Transparent
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "0" /f

REM Disable Xbox Services
reg add "HKLM\SYSTEM\CurrentControlSet\Services\XblGameSave" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\XboxGipSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\XblAuthManager" /v "Start" /t REG_DWORD /d "4" /f

REM Disable DMA
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d "0" /f

REM Disable Maintance
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f

REM Disable MMCSS
reg add "HKLM\SYSTEM\CurrentControlSet\Services\MMCSS" /v "Start" /t REG_DWORD /d "4" /f

REM Disable DVR2
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f

REM Services Tweaks
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AarSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AJRouter" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\ALG" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AppIDSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Appinfo" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AppMgmt" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AppReadiness" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AppVClient" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AssignedAccessManagerSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AudioEndpointBuilder" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Audiosrv" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\autotimesvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AxInstSV" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BcastDVRUserService" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BFE" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BITS" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BluetoothUserService" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BrokerInfrastructure" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BTAGService" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BthAvctpSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\bthserv" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\camsvc" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CaptureService" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\cbdhsvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CDPSvc" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CDPUserSvc" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CertPropSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\ClipSVC" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\COMSysApp" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\ConsentUxUserSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CoreMessagingRegistrar" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CredentialEnrollmentManagerUserSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CryptSvc" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CscService" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DcomLaunch" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\defragsvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DeviceAssociationBrokerSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DeviceAssociationService" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DeviceInstall" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DevicePickerUserSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvc" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DevQueryBroker" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dhcp" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\diagsvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DispBrokerDesktopSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DisplayEnhancementService" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DmEnrollmentSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DoSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dot3svc" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DPS" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DsmSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DsSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DusmSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Eaphost" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\EFS" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\embeddedmode" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\EntAppSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\EventLog" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\EventSystem" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\fdPHost" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\FDResPub" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\fhsvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\FontCache" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\FontCache3.0.0.0" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\FrameServer" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\gpsvc" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\hidserv" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\HvHost" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\icssvc" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\IKEEXT" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\InstallService" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\iphlpsvc" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\IpxlatCfgSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\KeyIso" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\KtmRm" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LicenseManager" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lltdsvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lmhosts" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LSM" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LxpSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\MapsBroker" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\MessagingService" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\mpssvc" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\MSDTC" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\MSiSCSI" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\msiserver" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NaturalAuthentication" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NcaSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NcbService" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NcdAutoSetup" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netman" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\netprofm" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NetSetupSvc" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NetTcpPortSharing" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\wuauserv" /v "Start" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\W32Time" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WinRM" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SDRSVC" /v "Start" /t REG_DWORD /d "4" /f   
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WbioSrvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Wecsvc" /v "Start" /t REG_DWORD /d "4" /f
net pause DiagTrack >nul 2>&1
net pause DialogBlockingService
net pause MsKeyboardFilter
net pause NetMsmqActivator 
net pause PcaSvc 
net pause SEMgrSvc 
net pause ShellHWDetection
net pause shpamsvc 
net pause SysMain
net pause Themes 
net pause TrkWks 
net pause tzautoupdate 
net pause uhssvc
net pause W3SVC
net pause OneSyncSvc
net pause WdiSystemHost 
net pause WdiServiceHost 
net pause SCardSvr 
net pause ScDeviceEnum 
net pause SCPolicySvc
net pause SensorDataService 
net pause SensrSvc 
net pause Beep
net pause cdfs 
net pause cdrom 
net pause cnghwassist 
net pause GpuEnergyDrv 
net pause Telemetry 
net pause VerifierExt
sc config "DiagTrack" start= disabled >nul 2>&1
sc config "DialogBlockingService" start= disabled >nul 2>&1
sc config "MsKeyboardFilter" start= disabled >nul 2>&1
sc config "NetMsmqActivator" start= disabled >nul 2>&1
sc config "PcaSvc" start= disabled >nul 2>&1
sc config "SEMgrSvc" start= disabled >nul 2>&1
sc config "ShellHWDetection" start= disabled >nul 2>&1
sc config "shpamsvc" start= disabled >nul 2>&1
sc config "SysMain" start= disabled >nul 2>&1
sc config "Themes" start= disabled >nul 2>&1
sc config "TrkWks" start= disabled >nul 2>&1
sc config "tzautoupdate" start= disabled >nul 2>&1
sc config "uhssvc" start= disabled >nul 2>&1
sc config "W3SVC" start= disabled >nul 2>&1
sc config "OneSyncSvc" start= disabled >nul 2>&1
sc config "WdiSystemHost" start= disabled >nul 2>&1
sc config "WdiServiceHost" start= disabled >nul 2>&1
sc config "SCardSvr" start= disabled >nul 2>&1
sc config "ScDeviceEnum" start= disabled >nul 2>&1
sc config "SensorDataService" start= disabled >nul 2>&1
sc config "SensrSvc" start= disabled >nul 2>&1
sc config "Beep" start= disabled >nul 2>&1
sc config "cdfs" start= disabled >nul 2>&1
sc config "cdrom" start= disabled >nul 2>&1
sc config "cnghwassist" start= disabled >nul 2>&1
sc config "GpuEnergyDrv" start= disabled >nul 2>&1
sc config "Telemetry" start= disabled >nul 2>&1
sc config "VerifierExt" start= disabled >nul 2>&1

REM Lower Ram Usage
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "67108864" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Affinity" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Background Only" /t REG_SZ /d "True" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Clock Rate" /t REG_DWORD /d "10000" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "GPU Priority" /t REG_DWORD /d "8" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Priority" /t REG_DWORD /d "6" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Affinity" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Background Only" /t REG_SZ /d "True" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Clock Rate" /t REG_DWORD /d "10000" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "GPU Priority" /t REG_DWORD /d "8" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Priority" /t REG_DWORD /d "5" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Affinity" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Background Only" /t REG_SZ /d "True" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "BackgroundPriority" /t REG_DWORD /d "8" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Clock Rate" /t REG_DWORD /d "10000" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "GPU Priority" /t REG_DWORD /d "8" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Priority" /t REG_DWORD /d "8" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Scheduling Category" /t REG_SZ /d "High" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Affinity" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Background Only" /t REG_SZ /d "True" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Clock Rate" /t REG_DWORD /d "10000" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "GPU Priority" /t REG_DWORD /d "8" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Priority" /t REG_DWORD /d "4" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Affinity" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Background Only" /t REG_SZ /d "False" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "BackgroundPriority" /t REG_DWORD /d "4" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Clock Rate" /t REG_DWORD /d "10000" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "GPU Priority" /t REG_DWORD /d "8" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Priority" /t REG_DWORD /d "3" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Affinity" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Background Only" /t REG_SZ /d "False" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Clock Rate" /t REG_DWORD /d "10000" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "GPU Priority" /t REG_DWORD /d "8" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Priority" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Scheduling Category" /t REG_SZ /d "High" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Affinity" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Background Only" /t REG_SZ /d "True" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Clock Rate" /t REG_DWORD /d "10000" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "GPU Priority" /t REG_DWORD /d "8" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Priority" /t REG_DWORD /d "5" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\System\GameConfigStore" /v "Win32_AutoGameModeDefaultProfile" /t REG_BINARY /d "01000100000000000000000000000000000000000000000000000000000000000000000000000000" /f
reg add "HKCU\System\GameConfigStore" /v "Win32_GameModeRelatedProcesses" /t REG_BINARY /d "010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "0" /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1" /v "Attributes" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "0" /f

REM Disable Tracking
reg add "HKLM\SYSTEM\CurrentControlSet\services\NDIS\Parameters" /v "TrackNblOwner" /t REG_DWORD /d "0" /f

REM set Win32 to 26hex
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "38" /f

REM Set TscSyncPolicy to Enhanced
bcdedit /set tscsyncpolicy enhanced

REM Disable Screen Savers
reg add "HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop" /v "ScreenSaveActive" /t REG_SZ /d "0" /f

REM Disable Windows 10 Most of Ads
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d "0" /f

REM Low Latency mode
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NoLazyMode" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "AlwaysOn" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Latency Sensitive" /t REG_SZ /d "True" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Latency Sensitive" /t REG_SZ /d "True" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Latency Sensitive" /t REG_SZ /d "True" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Latency Sensitive" /t REG_SZ /d "True" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Latency Sensitive" /t REG_SZ /d "True" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Latency Sensitive" /t REG_SZ /d "True" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Latency" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighPerformance" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatency" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatencyCheckEnabled" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LowLatency" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighestPerformance" /t REG_DWORD /d "1" /f

REM Set SVCSplitThreshold to your Memory Size
for /f "tokens=2 delims==" %%i in ('wmic os get TotalVisibleMemorySize /format:value') do set "mem=%%i"

set /a ram=mem + 1024000
call :SetRegistryValue "HKLM\System\CurrentControlSet\Control" "SvcHostSplitThresholdInKB" REG_DWORD %ram%

:SetRegistryValue
reg add "%~1" /v "%~2" /t %~3 /d %~4 /f

REM Disable Settings Synchronization
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSync" /t REG_DWORD /d "2" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSyncUserOverride" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSyncOnPaidNetwork" /t REG_DWORD /d "1" /f 

REM Disable Advertising ID
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f 
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f 

REM Disable Location Tracking
reg add "HKLM\SOFTWARE\Policies\Microsoft\FindMyDevice" /v "AllowFindMyDevice" /t REG_DWORD /d "0" /f

REM Wallpaper Quality 100%
reg add "HKCU\Control Panel\Desktop" /v "JPEGImportQuality" /t REG_DWORD /d "100" /f

REM Disable scheduled tasks using PowerShell
Powershell -Command "Get-ScheduledTask -TaskName XblGameSaveTask | Disable-ScheduledTask"
Powershell -Command "Get-ScheduledTask -TaskName Consolidator | Disable-ScheduledTask"
Powershell -Command "Get-ScheduledTask -TaskName UsbCeip | Disable-ScheduledTask"
Powershell -Command "Get-ScheduledTask -TaskName DmClient | Disable-ScheduledTask"
Powershell -Command "Get-ScheduledTask -TaskName DmClientOnScenarioDownload | Disable-ScheduledTask"

REM Disabling services:
sc config diagnosticshub.standardcollector.service start=disabled >nul 2>&1
sc config DiagTrack start=disabled >nul 2>&1
sc config dmwappushservice start=disabled >nul 2>&1
sc config WerSvc start=disabled >nul 2>&1
sc config OneSyncSvc start=disabled >nul 2>&1
sc config MessagingService start=disabled >nul 2>&1
sc config wercplsupport start=disabled >nul 2>&1
sc config PcaSvc start=disabled >nul 2>&1
sc config wisvc start=disabled >nul 2>&1
sc config RetailDemo start=disabled >nul 2>&1
sc config diagsvc start=disabled >nul 2>&1
sc config shpamsvc start=disabled >nul 2>&1
sc config TermService start=disabled >nul 2>&1
sc config UmRdpService start=disabled >nul 2>&1
sc config SessionEnv start=disabled >nul 2>&1
sc config TroubleshootingSvc start=disabled >nul 2>&1

:: Remove Useless PowerShell Packages
REM Removing Windows Alarms app for all users
Powershell "get-appxpackage -AllUsers *windowsalarms* | Remove-AppxPackage"

REM Removing Windows Communications Apps (Mail, Calendar, etc.) for all users
Powershell "get-appxpackage -AllUsers *windowscommunicationsapps* | Remove-AppxPackage"

REM Removing Office Hub app for all users
Powershell "get-appxpackage -AllUsers *officehub* | Remove-AppxPackage"

REM Removing Skype app for all users
Powershell "get-appxpackage -AllUsers *skypeapp* | Remove-AppxPackage"

REM Removing Get Started app for all users
Powershell "get-appxpackage -AllUsers *getstarted* | Remove-AppxPackage"

REM Removing Zune Music app for all users
Powershell "get-appxpackage -AllUsers *zunemusic* | Remove-AppxPackage"

REM Removing Windows Maps app for all users
Powershell "get-appxpackage -AllUsers *windowsmaps* | Remove-AppxPackage"

REM Removing Solitaire Collection app for all users
Powershell "get-appxpackage -AllUsers *solitairecollection* | Remove-AppxPackage"

REM Removing Bing Finance app for all users
Powershell "get-appxpackage -AllUsers *bingfinance* | Remove-AppxPackage"

REM Removing Zune Video app for all users
Powershell "get-appxpackage -AllUsers *zunevideo* | Remove-AppxPackage"

REM Removing Bing News app for all users
Powershell "get-appxpackage -AllUsers *bingnews* | Remove-AppxPackage"

REM Removing OneNote app for all users
Powershell "get-appxpackage -AllUsers *onenote* | Remove-AppxPackage"

REM Removing Windows Phone app for all users
Powershell "get-appxpackage -AllUsers *windowsphone* | Remove-AppxPackage"

REM Removing Photos app for all users
Powershell "get-appxpackage -AllUsers *photos* | Remove-AppxPackage"

REM Removing Bing Sports app for all users
Powershell "get-appxpackage -AllUsers *bingsports* | Remove-AppxPackage"

REM Removing Sound Recorder app for all users
Powershell "get-appxpackage -AllUsers *soundrecorder* | Remove-AppxPackage"

REM Removing Bing Weather app for all users
Powershell "get-appxpackage -AllUsers *bingweather* | Remove-AppxPackage"

REM Removing Connectivity Store app for all users
Powershell "get-appxpackage -AllUsers *connectivitystore* | Remove-AppxPackage"

REM Removing Messaging app for all users
Powershell "get-appxpackage -AllUsers *messaging* | Remove-AppxPackage"

REM Removing Sway app for all users
Powershell "get-appxpackage -AllUsers *sway* | Remove-AppxPackage"

REM Removing 3D Builder app for all users
Powershell "get-appxpackage -AllUsers *3d* | Remove-AppxPackage"

REM Removing Holographic app for all users
Powershell "get-appxpackage -AllUsers *holographic* | Remove-AppxPackage"

REM Removing Microsoft Xbox Gaming Overlay app for all users
Powershell "get-appxpackage -AllUsers Microsoft.XboxGamingOverlay | Remove-AppxPackage"

REM Removing 3D Viewer app for all users
Powershell -Command "Get-AppxPackage Microsoft.Microsoft3DViewer | Remove-AppxPackage"

REM Removing Bing app for all users
PowerShell -Command "Get-AppxPackage bing | Remove-AppxPackage"

:: Main Tweaks is completed
REM Opening MsgBox
set "msgboxTitle=Completed"
set "msgboxBody=Main tweaks has successfully implemented!"
set "tmpmsgbox=%temp%\~tmpmsgbox.vbs"

if exist "%tmpmsgbox%" del /f /q "%tmpmsgbox%"

(
    echo MsgBox "%msgboxBody%", 0, "%msgboxTitle%"
) > "%tmpmsgbox%"

set REGKEY[0]=HKLM\SOFTWARE\Microsoft\Direct3D,EnableDebugging,REG_DWORD,0
set REGKEY[1]=HKLM\SOFTWARE\Microsoft\Direct3D,FullDebug,REG_DWORD,0
set REGKEY[2]=HKLM\SOFTWARE\Microsoft\Direct3D,DisableDM,REG_DWORD,1
set REGKEY[3]=HKLM\SOFTWARE\Microsoft\Direct3D,EnableMultimonDebugging,REG_DWORD,0
set REGKEY[4]=HKLM\SOFTWARE\Microsoft\Direct3D,LoadDebugRuntime,REG_DWORD,0
set REGKEY[5]=HKLM\SOFTWARE\Microsoft\DirectDraw,DisableAGPSupport,REG_DWORD,0
set REGKEY[6]=HKLM\SOFTWARE\Wow6432Node\Microsoft\DirectDraw,DisableAGPSupport,REG_DWORD,0
set REGKEY[7]=HKLM\SOFTWARE\Microsoft\DirectDraw,UseNonLocalVidMem,REG_DWORD,1
set REGKEY[8]=HKLM\SOFTWARE\Wow6432Node\Microsoft\DirectDraw,UseNonLocalVidMem,REG_DWORD,1
set REGKEY[9]=HKLM\SOFTWARE\Microsoft\Direct3D,UseNonLocalVidMem,REG_DWORD,1
set REGKEY[10]=HKLM\SOFTWARE\Wow6432Node\Microsoft\Direct3D,UseNonLocalVidMem,REG_DWORD,1
set REGKEY[11]=HKLM\SOFTWARE\Microsoft\DirectDraw,DisableDDSCAPSInDDSD,REG_DWORD,0
set REGKEY[12]=HKLM\SOFTWARE\Wow6432Node\Microsoft\DirectDraw,DisableDDSCAPSInDDSD,REG_DWORD,0
set REGKEY[13]=HKLM\SOFTWARE\Microsoft\DirectDraw,EmulationOnly,REG_DWORD,0
set REGKEY[14]=HKLM\SOFTWARE\Wow6432Node\Microsoft\DirectDraw,EmulationOnly,REG_DWORD,0
set REGKEY[15]=HKLM\SOFTWARE\Microsoft\DirectDraw,EmulatePointSprites,REG_DWORD,0
set REGKEY[16]=HKLM\SOFTWARE\Wow6432Node\Microsoft\DirectDraw,EmulatePointSprites,REG_DWORD,0
set REGKEY[17]=HKLM\SOFTWARE\Microsoft\Direct3D\Drivers,ForceRgbRasterizer,REG_DWORD,0
set REGKEY[18]=HKLM\SOFTWARE\Wow6432Node\Microsoft\Direct3D\Drivers,ForceRgbRasterizer,REG_DWORD,0
set REGKEY[19]=HKLM\SOFTWARE\Microsoft\DirectDraw,EmulateStateBlocks,REG_DWORD,0
set REGKEY[20]=HKLM\SOFTWARE\Wow6432Node\Microsoft\DirectDraw,EmulateStateBlocks,REG_DWORD,0
set REGKEY[21]=HKLM\SOFTWARE\Microsoft\Direct3D\Drivers,EnumReference,REG_DWORD,1
set REGKEY[22]=HKLM\SOFTWARE\Wow6432Node\Microsoft\Direct3D\Drivers,EnumReference,REG_DWORD,1
set REGKEY[23]=HKLM\SOFTWARE\Microsoft\Direct3D\Drivers,EnumSeparateMMX,REG_DWORD,1
set REGKEY[24]=HKLM\SOFTWARE\Wow6432Node\Microsoft\Direct3D\Drivers,EnumSeparateMMX,REG_DWORD,1
set REGKEY[25]=HKLM\SOFTWARE\Microsoft\Direct3D\Drivers,EnumRamp,REG_DWORD,1
set REGKEY[26]=HKLM\SOFTWARE\Wow6432Node\Microsoft\Direct3D\Drivers,EnumRamp,REG_DWORD,1
set REGKEY[27]=HKLM\SOFTWARE\Microsoft\Direct3D\Drivers,EnumNullDevice,REG_DWORD,1
set REGKEY[28]=HKLM\SOFTWARE\Wow6432Node\Microsoft\Direct3D\Drivers,EnumNullDevice,REG_DWORD,1
set REGKEY[29]=HKLM\SOFTWARE\Microsoft\Direct3D,FewVertices,REG_DWORD,1
set REGKEY[30]=HKLM\SOFTWARE\Wow6432Node\Microsoft\Direct3D,FewVertices,REG_DWORD,1
set REGKEY[31]=HKLM\SOFTWARE\Microsoft\DirectDraw,DisableMMX,REG_DWORD,0
set REGKEY[32]=HKLM\SOFTWARE\Wow6432Node\Microsoft\DirectDraw,DisableMMX,REG_DWORD,0
set REGKEY[33]=HKLM\SOFTWARE\Microsoft\Direct3D,DisableMMX,REG_DWORD,0
set REGKEY[34]=HKLM\SOFTWARE\Wow6432Node\Microsoft\Direct3D,DisableMMX,REG_DWORD,0

:: count of entries + 1
set COUNT=35

for /L %%i in (0,1,%COUNT%) do (
    for /f "tokens=1,2,3,4 delims=," %%a in ("!REGKEY[%%i]!") do (
        Reg.exe add "%%a" /v "%%b" /t "%%c" /d "%%d" /f
    )
)

::DirectX Tweaks is completed
REM Opening MsgBox
set "msgboxTitle=Completed"
set "msgboxBody=DirectX tweaks has successfully implemented!"
set "tmpmsgbox=%temp%\~tmpmsgbox.vbs"

if exist "%tmpmsgbox%" del /f /q "%tmpmsgbox%"

(
    echo MsgBox "%msgboxBody%", 0, "%msgboxTitle%"
) > "%tmpmsgbox%"
set "setting1=memoryusage 2"
set "setting2=mftzone 4"
set "setting3=disablelastaccess 1"
set "setting4=disabledeletenotify 0"
set "setting5=encryptpagingfile 0"

fsutil behavior set %setting1%
fsutil behavior set %setting2%
fsutil behavior set %setting3%
fsutil behavior set %setting4%
fsutil behavior set %setting5%

::Drive Tweaks is completed
REM Opening MsgBox
set "msgboxTitle=Completed"
set "msgboxBody=Drive tweaks has successfully implemented!"
set "tmpmsgbox=%temp%\~tmpmsgbox.vbs"

if exist "%tmpmsgbox%" del /f /q "%tmpmsgbox%"

(
    echo MsgBox "%msgboxBody%", 0, "%msgboxTitle%"
) > "%tmpmsgbox%"

wscript "%tmpmsgbox%"
goto MainMenu2

:USB
chcp 65001 >nul 2>&1
cd /d "%~dp0"
cls
mode 120, 25
REM USB Device Priority & Enable MSI Mode
for /f %%i in ('wmic path Win32_USBController get PNPDeviceID') do (
    reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f
    reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f
)

REM USB Power Management
for /f %%u in ('wmic path Win32_USBController get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
    set REG_PATH="HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters"
    
    reg add !REG_PATH! /v SelectiveSuspendOn /t REG_DWORD /d 0 /f
    reg add !REG_PATH! /v SelectiveSuspendEnabled /t REG_BINARY /d 00 /f
    reg add !REG_PATH! /v EnhancedPowerManagementEnabled /t REG_DWORD /d 0 /f
    reg add !REG_PATH! /v AllowIdleIrpInD3 /t REG_DWORD /d 0 /f
    reg add !REG_PATH!\WDF /v IdleInWorkingState /t REG_DWORD /d 0 /f
)

REM Thread Priorities
reg add "HKLM\SYSTEM\CurrentControlSet\Services\usbxhci\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\USBHUB3\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NDIS\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl\Parameters" /v "ThreadPriority" /t REG_DWORD /d "15" /f

REM IDE Controller Device Priority
for /f %%i in ('wmic path Win32_IDEController get PNPDeviceID 2^>nul') do (
    if "!str:PCI\VEN_=!" neq "!str!" (
        reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f
    )
)

::USB Tweaks is completed
REM Opening MsgBox
set "msgboxTitle=Completed"
set "msgboxBody=USB tweaks has successfully implemented!"
set "tmpmsgbox=%temp%\~tmpmsgbox.vbs"

if exist "%tmpmsgbox%" del /f /q "%tmpmsgbox%"

(
    echo MsgBox "%msgboxBody%", 0, "%msgboxTitle%"
) > "%tmpmsgbox%"

wscript "%tmpmsgbox%"
echo %w% - More Memory Managment Tweaks%b%
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "ClearPageFileAtShutdown" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "NonPagedPoolQuota" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "NonPagedPoolSize" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PagedPoolQuota" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PagedPoolSize" /t REG_DWORD /d "192" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "SecondLevelDataCache" /t REG_DWORD /d "1024" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "SessionPoolSize" /t REG_DWORD /d "192" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "SessionViewSize" /t REG_DWORD /d "192" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "SystemPages" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PhysicalAddressExtension" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "IoPageLockLimit" /t REG_DWORD /d "16710656" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PoolUsageMaximum" /t REG_DWORD /d "96" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "Start" /t REG_DWORD /d "4" /f
echo %w% - Disabling Paging Executive%b%
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "DpiMapIommuContiguous" /t REG_DWORD /d "1" /f 
timeout /t 1 /nobreak > NUL


echo %w% - SVC split host%b%
for /f "skip=1" %%i in ('wmic os get TotalVisibleMemorySize') do if not defined TOTAL_MEMORY set "TOTAL_MEMORY=%%i" & set /a SVCHOST=%%i+1024000
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "!SVCHOST!" /f 
timeout /t 1 /nobreak > NUL

echo %w% - Disabling Prefetch and superfetch%b%
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f
timeout /t 1 /nobreak > NUL
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Executive" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\ModernSleep" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "PlatformAoAcOverride" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EnergyEstimationEnabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EventProcessorEnabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CsEnabled" /t REG_DWORD /d "0" /f 
timeout /t 1 /nobreak > NUL

echo %w% - Disabling Power Throttling%b%
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f 
timeout /t 1 /nobreak > NUL

cls
echo %w% - Disabling GPU Energy Driver%b%
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\GpuEnergyDrv" /v "Start" /t REG_DWORD /d "4" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\GpuEnergyDr" /v "Start" /t REG_DWORD /d "4" /f 
timeout /t 1 /nobreak > NUL

echo %w% - Disabling Energy Logging%b%
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "DisableTaggedEnergyLogging" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "TelemetryMaxApplication" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "TelemetryMaxTagPerApplication" /t REG_DWORD /d "0" /f 
timeout /t 1 /nobreak > NUL

echo %w% - Disabling Fast Startup%b%
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f 
timeout /t 1 /nobreak > NUL

echo %w% - Disabling Hibernation%b%
powercfg /h off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "SleepReliabilityDetailedDiagnostics" /t REG_DWORD /d "0" /f 
timeout /t 1 /nobreak > NUL

echo %w% - Disabling Sleep Study%b%
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "SleepStudyDisabled" /t REG_DWORD /d "1" /f 
timeout /t 1 /nobreak > NUL
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "PassiveIntRealTimeWorkerPriority" /t REG_DWORD /d "18" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\KernelVelocity" /v "DisableFGBoostDecay" /t REG_DWORD /d "1" /f

Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dwm.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dwm.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "PagePriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ntoskrnl.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ntoskrnl.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchIndexer.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchIndexer.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TrustedInstaller.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TrustedInstaller.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\wuauclt.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\wuauclt.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\audiodg.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\audiodg.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dwm.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dwm.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "PagePriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ntoskrnl.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ntoskrnl.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchIndexer.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchIndexer.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TrustedInstaller.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TrustedInstaller.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\wuauclt.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\wuauclt.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f


