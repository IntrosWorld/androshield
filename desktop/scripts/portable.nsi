Unicode true
Name "APK Fraud Analyzer Portable"
OutFile "${OUTPUT}"
RequestExecutionLevel user
SilentInstall silent
SetCompressor zlib
!include "FileFunc.nsh"
Var Lock
Var Args
!macro SystemCall COMMAND
  Push '${COMMAND}'
  CallInstDLL "$EXEDIR\APK Fraud Analyzer Data\tmp\bootstrap-${BUILD_ID}\System.dll" Call
!macroend

Function .onInit
  StrCpy $INSTDIR "$EXEDIR\APK Fraud Analyzer Data\runtime\${BUILD_ID}"
  CreateDirectory "$EXEDIR\APK Fraud Analyzer Data\tmp"
  IfErrors failed
  ; Load the bootstrap DLL directly, avoiding NSIS system-temp extraction.
  SetOutPath "$EXEDIR\APK Fraud Analyzer Data\tmp\bootstrap-${BUILD_ID}"
  SetOverwrite off
  File "${NSISDIR}\Plugins\x86-unicode\System.dll"
  SetOverwrite on
  !insertmacro SystemCall 'kernel32::SetEnvironmentVariable(t "TEMP", t "$EXEDIR\APK Fraud Analyzer Data\tmp")'
  !insertmacro SystemCall 'kernel32::SetEnvironmentVariable(t "TMP", t "$EXEDIR\APK Fraud Analyzer Data\tmp")'
  !insertmacro SystemCall 'kernel32::SetEnvironmentVariable(t "PORTABLE_EXECUTABLE_DIR", t "$EXEDIR")'
  !insertmacro SystemCall 'kernel32::SetEnvironmentVariable(t "APK_DESKTOP_USER_DATA", t "$EXEDIR\APK Fraud Analyzer Data")'
  !insertmacro SystemCall 'kernel32::CreateFile(t "$EXEDIR\APK Fraud Analyzer Data\launcher.lock", i 0x40000000, i 0, p 0, i 4, i 0x80, p 0) p.r0'
  StrCpy $Lock $0
  StrCmp $Lock -1 busy
  Return
busy:
  MessageBox MB_OK "The portable analyzer is already running. Close it before launching another copy from this folder."
  Abort
failed:
  MessageBox MB_OK "Cannot write beside the EXE. Move it to a writable folder and try again."
  Abort
FunctionEnd

Section
  IfFileExists "$INSTDIR\complete" 0 extract
  IfFileExists "$INSTDIR\APK Fraud Analyzer.exe" launch extract
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
  ExecWait '"$INSTDIR\APK Fraud Analyzer.exe" $Args' $1
  IfErrors failed
  !insertmacro SystemCall 'kernel32::CloseHandle(p $Lock)'
  SetErrorLevel $1
  Quit
failed:
  !insertmacro SystemCall 'kernel32::CloseHandle(p $Lock)'
  MessageBox MB_OK "Could not extract or launch the analyzer. Check free space and write access beside the EXE, then retry."
  SetErrorLevel 1
SectionEnd

