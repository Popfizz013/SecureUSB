; Basic NSIS installer example. Edit paths and details as needed.

Name "SecureUSB"
OutFile "SecureUSB-Installer.exe"
InstallDir "$PROGRAMFILES\SecureUSB"
RequestExecutionLevel admin

!define APP_EXE "SecureUSB.exe"
!define CLI_EXE "secureusb-cli.exe"

Section "Install"
  SetOutPath "$INSTDIR"
  File /oname=$INSTDIR\${APP_EXE} "dist\${APP_EXE}"
  File /oname=$INSTDIR\${CLI_EXE} "dist\${CLI_EXE}"
  CreateShortCut "$DESKTOP\SecureUSB.lnk" "$INSTDIR\${APP_EXE}"
SectionEnd

Section "Uninstall"
  Delete "$INSTDIR\${APP_EXE}"
  Delete "$INSTDIR\${CLI_EXE}"
  Delete "$DESKTOP\SecureUSB.lnk"
  RMDir "$INSTDIR"
SectionEnd
