!define PRODUCT_NAME "SecureUSB"
!define PRODUCT_VERSION "1.0.0"
!define COMPANY_NAME "SecureUSB"

OutFile "SecureUSB-Installer.exe"
InstallDir "$PROGRAMFILES\${PRODUCT_NAME}"
RequestExecutionLevel admin

Page directory
Page instfiles

Section "Install"
  SetOutPath "$INSTDIR"
  File "${PRODUCT_NAME}.exe"
  ; Create Desktop shortcut
  CreateShortCut "$DESKTOP\${PRODUCT_NAME}.lnk" "$INSTDIR\${PRODUCT_NAME}.exe"
  ; Create Start Menu shortcut
  CreateDirectory "$SMPROGRAMS\${PRODUCT_NAME}"
  CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\${PRODUCT_NAME}.lnk" "$INSTDIR\${PRODUCT_NAME}.exe"
  ; Write uninstall information
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  ; Write uninstall registry key
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "DisplayName" "${PRODUCT_NAME}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "UninstallString" "$INSTDIR\\Uninstall.exe"
SectionEnd

Section "Uninstall"
  Delete "$INSTDIR\${PRODUCT_NAME}.exe"
  Delete "$SMPROGRAMS\${PRODUCT_NAME}\${PRODUCT_NAME}.lnk"
  RMDir "$SMPROGRAMS\${PRODUCT_NAME}"
  Delete "$DESKTOP\${PRODUCT_NAME}.lnk"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"
SectionEnd
