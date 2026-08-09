; RenkerVault Windows-Installer (Inno Setup)
; ==========================================
; Installiert die Tauri-Desktop-App (RenkerVault.exe) plus optional den
; Zero-Knowledge-Relay-Server zum lokalen Selbstbetrieb.
;
; Bauen:  ISCC.exe installer\RenkerVault.iss
; Voraussetzung: client\src-tauri\target\release\renkervault.exe muss existieren
;                (vorher `npx tauri build` im client-Verzeichnis ausfuehren).

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
Name: "german"; MessagesFile: "compiler:Languages\German.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "relaycomponent"; Description: "Lokalen Zero-Knowledge-Relay-Server mitinstallieren (fuer eigenen Server-Betrieb, benoetigt Node.js)"; Flags: unchecked

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
Name: "{group}\RenkerVault Relay-Server (lokal)"; Filename: "{app}\start-relay.bat"; Tasks: relaycomponent
Name: "{group}\Sicherheitsdokumentation (SECURITY.md)"; Filename: "{app}\SECURITY.md"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#MyAppName}}"; Flags: nowait postinstall skipifsilent

[Messages]
german.WelcomeLabel2=Dieses Programm installiert [name/ver] auf Ihrem Computer.%n%nRenkerVault ist ein Ende-zu-Ende-verschluesselter Chat-Prototyp. Wichtige Sicherheitshinweise stehen in SECURITY.md im Installationsverzeichnis.%n%nBenoetigt: Microsoft Edge WebView2 Runtime (auf aktuellen Windows-10/11-Systemen i. d. R. bereits vorhanden).
