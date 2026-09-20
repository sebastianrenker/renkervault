; RenkerVault Windows installer (Inno Setup)
; ==========================================
; Installs the Tauri desktop app (RenkerVault.exe) plus, optionally, the
; content-blind relay server for local self-hosting.
;
; Build:  ISCC.exe installer\RenkerVault.iss
; Requirement: client\src-tauri\target\release\renkervault.exe must exist
;              (run `npx tauri build` in the client directory first).

#define MyAppName "RenkerVault"
#define MyAppVersion "0.1.0"
#define MyAppPublisher "Renker Industries"
#define MyAppExeName "RenkerVault.exe"
#define ClientDir "..\client"
#define ServerDir "..\server"

[Setup]
AppId={{8F2B1E3E-4C9A-4E7B-9B1E-9D2C7B6A2F11}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppVerName={#MyAppName} {#MyAppVersion}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputDir=output
OutputBaseFilename=RenkerVault-Setup-{#MyAppVersion}
SetupIconFile={#ClientDir}\src-tauri\icons\icon.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "relaycomponent"; Description: "Also install the local content-blind relay server (for running your own server, requires Node.js)"; Flags: unchecked

[Files]
Source: "{#ClientDir}\src-tauri\target\release\renkervault.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "start-relay.bat"; DestDir: "{app}"; Flags: ignoreversion; Tasks: relaycomponent
Source: "{#ServerDir}\src\*"; DestDir: "{app}\relay\src"; Flags: ignoreversion recursesubdirs createallsubdirs; Tasks: relaycomponent
Source: "{#ServerDir}\node_modules\*"; DestDir: "{app}\relay\node_modules"; Flags: ignoreversion recursesubdirs createallsubdirs; Tasks: relaycomponent
Source: "{#ServerDir}\package.json"; DestDir: "{app}\relay"; Flags: ignoreversion; Tasks: relaycomponent
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\SECURITY.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\RenkerVault Relay Server (local)"; Filename: "{app}\start-relay.bat"; Tasks: relaycomponent
Name: "{group}\Security documentation (SECURITY.md)"; Filename: "{app}\SECURITY.md"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#MyAppName}}"; Flags: nowait postinstall skipifsilent

[Messages]
english.WelcomeLabel2=This program installs [name/ver] on your computer.%n%nRenkerVault is an end-to-end encrypted chat prototype. Important security notes are in SECURITY.md in the installation directory.%n%nRequires: Microsoft Edge WebView2 Runtime (usually already present on current Windows 10/11 systems).
