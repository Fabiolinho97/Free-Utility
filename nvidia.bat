@echo off
setlocal

:: Set download URLs
set "INSPECTOR_URL=https://github.com/Orbmu2k/nvidiaProfileInspector/releases/latest/download/nvidiaProfileInspector.zip"
set "NIP_URL=https://drive.google.com/uc?export=download&id=1tOrahzXFW6DRwdP0mC2ZmRJoYtYP8sU-"

:: Set local file names
set "INSPECTOR_ZIP=nvidiaProfileInspector.zip"
set "INSPECTOR_EXE=nvidiaProfileInspector.exe"
set "NIP_FILE=profile.nip"

:: Download and extract inspector
powershell -Command "Invoke-WebRequest -Uri '%INSPECTOR_URL%' -OutFile '%INSPECTOR_ZIP%'"
powershell -Command "Expand-Archive -Path '%INSPECTOR_ZIP%' -DestinationPath . -Force"

:: Download .nip
powershell -Command "Invoke-WebRequest -Uri '%NIP_URL%' -OutFile '%NIP_FILE%'"

:: Run import first
"%INSPECTOR_EXE%" /import "%NIP_FILE%"

:: --- NVIDIA telemetry & cleanup ---
rmdir /s /q "%systemdrive%\Windows\System32\drivers\NVIDIA Corporation" >nul 2>&1
cd /d "%systemdrive%\Windows\System32\DriverStore\FileRepository\" >nul 2>&1
dir NvTelemetry64.dll /a /b /s >nul 2>&1
del NvTelemetry64.dll /a /s >nul 2>&1
cd /d "%systemdrive%\Windows\System32\DriverStore\FileRepository\nv_dispig.inf_amd64_20ea7d0c917cde22" >nul 2>&1
del NvTelemetry64.dll /a /s >nul 2>&1
rd /s /q "%systemdrive%\Program Files\NVIDIA Corporation\Display.NvContainer\plugins\LocalSystem\DisplayDriverRAS" >nul 2>&1
rd /s /q "%systemdrive%\Program Files\NVIDIA Corporation\DisplayDriverRAS" >nul 2>&1
rd /s /q "%systemdrive%\ProgramData\NVIDIA Corporation\DisplayDriverRAS" >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client" /v "OptInOrOutPreference" /t REG_DWORD /d 0 /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup" /v "SendTelemetryData" /t REG_DWORD /d 0 /f >nul 2>&1
for %%i in (NvTmMon NvTmRep) do (
    for /f "tokens=1 delims=," %%a in ('schtasks /query /fo csv ^| findstr /v "TaskName" ^| findstr "%%~i" ^| findstr /v "Microsoft\\Windows"') do (
        schtasks /change /tn %%a /disable
    )
)
sc config NvTelemetryContainer start=disabled >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup\SendTelemetryData" /ve /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "RMHdcpKeyglobZero" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableDynamicPstate" /t REG_DWORD /d "1" /f >nul 2>&1

exit
