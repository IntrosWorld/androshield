Unicode true
Name "AndroShield Portable"
OutFile "${OUTPUT}"
RequestExecutionLevel user
SilentInstall silent
SetCompressor zlib
!include "FileFunc.nsh"
Var Lock
Var Args
!macro SystemCall COMMAND
  Push '${COMMAND}'
  CallInstDLL "$EXEDIR\AndroShield Data\tmp\bootstrap-${BUILD_ID}\System.dll" Call
!macroend

Function .onInit
  ; Preserve the previous product's workspace on the same portable drive.
  IfFileExists "$EXEDIR\AndroShield Data\*.*" migration_done
  IfFileExists "$EXEDIR\APK Fraud Analyzer Data\*.*" 0 migration_done
  ClearErrors
  Rename "$EXEDIR\APK Fraud Analyzer Data" "$EXEDIR\AndroShield Data"
  IfErrors migration_failed
migration_done:
  StrCpy $INSTDIR "$EXEDIR\AndroShield Data\runtime\${BUILD_ID}"
  CreateDirectory "$EXEDIR\AndroShield Data\tmp"
  IfErrors failed
  ; Load the bootstrap DLL directly, avoiding NSIS system-temp extraction.
  SetOutPath "$EXEDIR\AndroShield Data\tmp\bootstrap-${BUILD_ID}"
  SetOverwrite off
  File "${NSISDIR}\Plugins\x86-unicode\System.dll"
  SetOverwrite on
  !insertmacro SystemCall 'kernel32::SetEnvironmentVariable(t "TEMP", t "$EXEDIR\AndroShield Data\tmp")'
  !insertmacro SystemCall 'kernel32::SetEnvironmentVariable(t "TMP", t "$EXEDIR\AndroShield Data\tmp")'
  !insertmacro SystemCall 'kernel32::SetEnvironmentVariable(t "PORTABLE_EXECUTABLE_DIR", t "$EXEDIR")'
  !insertmacro SystemCall 'kernel32::SetEnvironmentVariable(t "APK_DESKTOP_USER_DATA", t "$EXEDIR\AndroShield Data")'
  !insertmacro SystemCall 'kernel32::CreateFile(t "$EXEDIR\AndroShield Data\launcher.lock", i 0x40000000, i 0, p 0, i 4, i 0x80, p 0) p.r0'
  StrCpy $Lock $0
  StrCmp $Lock -1 busy
  Return
migration_failed:
  MessageBox MB_OK "Close the previous app before upgrading. Could not move the saved workspace to AndroShield Data. Your existing data has been preserved."
  Abort
busy:
  MessageBox MB_OK "The portable analyzer is already running. Close it before launching another copy from this folder."
  Abort
failed:
  MessageBox MB_OK "Cannot write beside the EXE. Move it to a writable folder and try again."
  Abort
FunctionEnd

Section
  IfFileExists "$INSTDIR\complete" 0 extract
  IfFileExists "$INSTDIR\AndroShield.exe" launch extract
extract:
  ClearErrors
  SetOutPath "$INSTDIR"
  File /r "${APP_DIR}\*"
  IfErrors failed
  FileOpen $0 "$INSTDIR\complete" w
  FileWrite $0 "${BUILD_ID}"
  FileClose $0
  IfErrors failed
launch:
  SetOutPath "$EXEDIR"
  ${GetParameters} $Args
  ClearErrors
  ExecWait '"$INSTDIR\AndroShield.exe" $Args' $1
  IfErrors failed
  !insertmacro SystemCall 'kernel32::CloseHandle(p $Lock)'
  SetErrorLevel $1
  Quit
failed:
  !insertmacro SystemCall 'kernel32::CloseHandle(p $Lock)'
  MessageBox MB_OK "Could not extract or launch the analyzer. Check free space and write access beside the EXE, then retry."
  SetErrorLevel 1
SectionEnd

