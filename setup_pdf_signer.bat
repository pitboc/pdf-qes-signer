@echo off
:: PDF QES Signer – Windows Installer
:: Laedt Python, VC++ Runtime und pdf-signer automatisch herunter und
:: installiert alles ohne Admin-Rechte (nur VC++ benoetigt einmalig UAC).
::
:: Aufruf: Doppelklick genuegt – keine weiteren Schritte notwendig.
::
:: Der eigentliche Installer-Code steht als PowerShell-Abschnitt am Ende
:: dieser Datei (nach dem Marker <#PS#>). Die Batch-Sektion liest die Datei
:: selbst ein und fuehrt den PS-Teil aus – so ist nur eine einzige Datei
:: zum Herunterladen noetig.
::
:: Hinweis: powershell -Command umgeht die ExecutionPolicy (gilt nur fuer
:: .ps1-Dateien), laeuft also auch bei Gruppenrichtlinien-Einschraenkungen.

powershell -NoProfile -Command "$f=[System.IO.File]::ReadAllText('%~f0',[System.Text.Encoding]::UTF8);$s=$f.IndexOf('<#PS#>')+6;Invoke-Expression $f.Substring($s)"
exit /b 0
<#PS#>
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# ---------------------------------------------------------------------------
# Konstanten
# ---------------------------------------------------------------------------
# Neueste Python-3.12.x-Version dynamisch ermitteln (endoflife.date API).
# Bei Netzwerkfehler greift der Fallback.
$PY_VERSION = "3.12.9"
try {
    $eol     = Invoke-RestMethod "https://endoflife.date/api/python.json" -UseBasicParsing
    $latest  = ($eol | Where-Object { $_.cycle -eq "3.12" }).latest
    if ($latest -match "^3\.12\.\d+$") { $PY_VERSION = $latest }
} catch { }
$PY_URL      = "https://www.python.org/ftp/python/$PY_VERSION/python-$PY_VERSION-amd64.exe"
$VC_URL      = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
$API_URL     = "https://codeberg.org/api/v1/repos/pitbo/pdf-qes-signer/releases/latest"
$INSTALL_DIR = Join-Path $env:LOCALAPPDATA "pdf-signer"
$VENV_DIR    = Join-Path $INSTALL_DIR ".venv"
$VENV_PY     = Join-Path $VENV_DIR "Scripts\pythonw.exe"
$VENV_PIP    = Join-Path $VENV_DIR "Scripts\pip.exe"

# ---------------------------------------------------------------------------
# GUI aufbauen
# ---------------------------------------------------------------------------
$form                  = New-Object System.Windows.Forms.Form
$form.Text             = "PDF QES Signer – Installation"
$form.Size             = New-Object System.Drawing.Size(540, 400)
$form.StartPosition    = "CenterScreen"
$form.FormBorderStyle  = "FixedDialog"
$form.MaximizeBox      = $false
$form.MinimizeBox      = $false

$lblTitle              = New-Object System.Windows.Forms.Label
$lblTitle.Text         = "PDF QES Signer"
$lblTitle.Font         = New-Object System.Drawing.Font("Segoe UI", 15, [System.Drawing.FontStyle]::Bold)
$lblTitle.Location     = New-Object System.Drawing.Point(20, 14)
$lblTitle.Size         = New-Object System.Drawing.Size(490, 32)

$lblSub                = New-Object System.Windows.Forms.Label
$lblSub.Text           = "Automatischer Windows-Installer"
$lblSub.Font           = New-Object System.Drawing.Font("Segoe UI", 9)
$lblSub.ForeColor      = [System.Drawing.Color]::Gray
$lblSub.Location       = New-Object System.Drawing.Point(22, 48)
$lblSub.Size           = New-Object System.Drawing.Size(490, 18)

$separator             = New-Object System.Windows.Forms.Label
$separator.BorderStyle = "Fixed3D"
$separator.Location    = New-Object System.Drawing.Point(20, 72)
$separator.Size        = New-Object System.Drawing.Size(490, 2)

$lstSteps              = New-Object System.Windows.Forms.ListBox
$lstSteps.Location     = New-Object System.Drawing.Point(20, 82)
$lstSteps.Size         = New-Object System.Drawing.Size(490, 190)
$lstSteps.Font         = New-Object System.Drawing.Font("Consolas", 9)
$lstSteps.BorderStyle  = "FixedSingle"

$progress              = New-Object System.Windows.Forms.ProgressBar
$progress.Location     = New-Object System.Drawing.Point(20, 285)
$progress.Size         = New-Object System.Drawing.Size(490, 20)
$progress.Style        = "Marquee"
$progress.MarqueeAnimationSpeed = 30

$lblStatus             = New-Object System.Windows.Forms.Label
$lblStatus.Text        = "Vorbereitung …"
$lblStatus.Font        = New-Object System.Drawing.Font("Segoe UI", 9)
$lblStatus.Location    = New-Object System.Drawing.Point(20, 312)
$lblStatus.Size        = New-Object System.Drawing.Size(490, 18)

$btnAction             = New-Object System.Windows.Forms.Button
$btnAction.Text        = "Abbrechen"
$btnAction.Location    = New-Object System.Drawing.Point(430, 338)
$btnAction.Size        = New-Object System.Drawing.Size(80, 26)
$btnAction.Add_Click({ $script:cancelled = $true; $form.Close() })

$form.Controls.AddRange(@($lblTitle,$lblSub,$separator,$lstSteps,$progress,$lblStatus,$btnAction))
$form.Show()
[System.Windows.Forms.Application]::DoEvents()

$script:cancelled = $false

# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------
function Step-Start($text) {
    $lstSteps.Items.Add("  …  $text")
    $lstSteps.SelectedIndex = $lstSteps.Items.Count - 1
    $lblStatus.Text = $text
    [System.Windows.Forms.Application]::DoEvents()
}

function Step-Ok($text) {
    if ($lstSteps.Items.Count -gt 0) {
        $lstSteps.Items[$lstSteps.Items.Count - 1] = "  OK  $text"
    }
    [System.Windows.Forms.Application]::DoEvents()
}

function Step-Warn($text) {
    if ($lstSteps.Items.Count -gt 0) {
        $lstSteps.Items[$lstSteps.Items.Count - 1] = "  !   $text"
    }
    [System.Windows.Forms.Application]::DoEvents()
}

function Show-Error($title, $msg) {
    [System.Windows.Forms.MessageBox]::Show(
        $msg, $title,
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    ) | Out-Null
}

function Download-File($url, $dest, $label) {
    $lblStatus.Text = "Lade herunter: $label …"
    [System.Windows.Forms.Application]::DoEvents()
    try {
        $wc = New-Object System.Net.WebClient
        $wc.DownloadFile($url, $dest)
    } catch {
        throw "Download fehlgeschlagen ($label): $_"
    }
}

# ---------------------------------------------------------------------------
# Schritt 1 – Python prüfen / installieren
# ---------------------------------------------------------------------------
Step-Start "Prüfe Python-Installation …"

$python = $null
$pyCmd  = Get-Command python -ErrorAction SilentlyContinue
if ($pyCmd) { $python = $pyCmd.Source }

if ($python -and $python -like "*WindowsApps*") {
    Show-Error "Falsche Python-Version" (
        "Die Microsoft-Store-Version von Python ist nicht kompatibel.`n`n" +
        "Bitte installieren Sie Python von https://www.python.org/downloads/`n" +
        "und aktivieren Sie 'Add python.exe to PATH'.`n`n" +
        "Anschließend diese Installation erneut starten."
    )
    $form.Close(); return
}

if (-not $python) {
    Step-Start "Python $PY_VERSION wird heruntergeladen (~25 MB) …"
    $pyTmp = Join-Path $env:TEMP "python-$PY_VERSION-amd64.exe"
    try { Download-File $PY_URL $pyTmp "Python $PY_VERSION" }
    catch { Show-Error "Download-Fehler" $_; $form.Close(); return }

    Step-Start "Python $PY_VERSION wird installiert (kein Admin erforderlich) …"
    $p = Start-Process -FilePath $pyTmp `
         -ArgumentList "/quiet InstallAllUsers=0 PrependPath=1 Include_pip=1 Include_test=0" `
         -Wait -PassThru
    Remove-Item $pyTmp -ErrorAction SilentlyContinue

    if ($p.ExitCode -ne 0) {
        Show-Error "Python-Installation fehlgeschlagen" "Exit-Code: $($p.ExitCode)"
        $form.Close(); return
    }
    # PATH für diese Session aktualisieren
    $userPath   = [System.Environment]::GetEnvironmentVariable("PATH", "User")
    $env:PATH   = $userPath + ";" + $env:PATH
    $pyCmd      = Get-Command python -ErrorAction SilentlyContinue
    if ($pyCmd) { $python = $pyCmd.Source }
    Step-Ok "Python $PY_VERSION installiert"
} else {
    $pyVer = (& python --version 2>&1) -replace "Python ",""
    Step-Ok "Python $pyVer bereits vorhanden"
}

if ($script:cancelled) { return }

# ---------------------------------------------------------------------------
# Schritt 2 – Visual C++ Runtime prüfen / installieren
# ---------------------------------------------------------------------------
Step-Start "Prüfe Visual C++ Runtime …"

$vcKey       = "HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64"
$vcInstalled = (Test-Path $vcKey) -and
               ((Get-ItemProperty $vcKey -ErrorAction SilentlyContinue).Installed -eq 1)

if (-not $vcInstalled) {
    Step-Start "Visual C++ Runtime wird heruntergeladen (~14 MB) …"
    $vcTmp = Join-Path $env:TEMP "vc_redist.x64.exe"
    try { Download-File $VC_URL $vcTmp "VC++ Redistributable" }
    catch { Show-Error "Download-Fehler" $_; $form.Close(); return }

    Step-Start "Visual C++ Runtime wird installiert (Admin-Berechtigung erforderlich) …"
    $lblStatus.Text = "Bitte den Administrator-Dialog bestätigen …"
    [System.Windows.Forms.Application]::DoEvents()

    try {
        $p = Start-Process -FilePath $vcTmp `
             -ArgumentList "/install /quiet /norestart" `
             -Verb RunAs -Wait -PassThru
    } catch {
        Show-Error "VC++ Installation abgebrochen" "Der Administrator-Dialog wurde abgelehnt oder ist fehlgeschlagen."
        $form.Close(); return
    }
    Remove-Item $vcTmp -ErrorAction SilentlyContinue

    # 0 = Erfolg, 3010 = Neustart empfohlen aber installiert
    if ($p.ExitCode -notin @(0, 3010)) {
        Show-Error "VC++ Installation fehlgeschlagen" "Exit-Code: $($p.ExitCode)"
        $form.Close(); return
    }
    if ($p.ExitCode -eq 3010) {
        Step-Warn "Visual C++ Runtime installiert (Neustart empfohlen)"
    } else {
        Step-Ok "Visual C++ Runtime installiert"
    }
} else {
    Step-Ok "Visual C++ Runtime bereits vorhanden"
}

if ($script:cancelled) { return }

# ---------------------------------------------------------------------------
# Schritt 3 – pdf-signer installieren
# ---------------------------------------------------------------------------
Step-Start "Erstelle virtuelle Python-Umgebung …"

New-Item -ItemType Directory -Force -Path $INSTALL_DIR | Out-Null
$venvOut = & python -m venv $VENV_DIR 2>&1
if ($LASTEXITCODE -ne 0) {
    Show-Error "venv-Fehler" "Virtuelle Umgebung konnte nicht erstellt werden:`n$venvOut"
    $form.Close(); return
}

Step-Start "Hole aktuelle Release-Version von Codeberg …"
try {
    $release  = Invoke-RestMethod -Uri $API_URL -UseBasicParsing
    $whlAsset = $release.assets | Where-Object { $_.name -like "*.whl" } | Select-Object -First 1
    if (-not $whlAsset) { throw "Kein .whl-Asset im Release gefunden." }
    $whlUrl  = $whlAsset.browser_download_url
    $version = $release.tag_name -replace "^v",""
} catch {
    Show-Error "Release-Abfrage fehlgeschlagen" "$_`n`nBitte Internetverbindung prüfen."
    $form.Close(); return
}

Step-Start "Installiere pdf-signer $version und Abhängigkeiten …"
$lblStatus.Text = "pip läuft – das kann einen Moment dauern …"
[System.Windows.Forms.Application]::DoEvents()

$pipOut = & $VENV_PIP install $whlUrl 2>&1
if ($LASTEXITCODE -ne 0) {
    Show-Error "Installation fehlgeschlagen" "pip install fehlgeschlagen:`n$pipOut"
    $form.Close(); return
}
Step-Ok "pdf-signer $version installiert"

if ($script:cancelled) { return }

# ---------------------------------------------------------------------------
# Schritt 4 – Verknüpfungen anlegen
# ---------------------------------------------------------------------------
Step-Start "Erstelle Verknüpfungen …"

$wsh = New-Object -ComObject WScript.Shell

# Desktop-Verknüpfung
$lnkDesktop          = $wsh.CreateShortcut("$env:USERPROFILE\Desktop\PDF QES Signer.lnk")
$lnkDesktop.TargetPath      = $VENV_PY
$lnkDesktop.Arguments       = "-m pdf_signer"
$lnkDesktop.WorkingDirectory = $INSTALL_DIR
$lnkDesktop.Description     = "PDF QES Signer"
$lnkDesktop.Save()

# Start-Menü
$startDir = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs"
$lnkStart            = $wsh.CreateShortcut("$startDir\PDF QES Signer.lnk")
$lnkStart.TargetPath        = $VENV_PY
$lnkStart.Arguments         = "-m pdf_signer"
$lnkStart.WorkingDirectory  = $INSTALL_DIR
$lnkStart.Description       = "PDF QES Signer"
$lnkStart.Save()

Step-Ok "Verknüpfungen auf Desktop und im Start-Menü erstellt"

# ---------------------------------------------------------------------------
# Fertig
# ---------------------------------------------------------------------------
$progress.Style = "Continuous"
$progress.Value = 100
$lblStatus.Text = "Installation abgeschlossen."
$btnAction.Text = "Fertig"
$btnAction.Add_Click({ $form.Close() })

[System.Windows.Forms.MessageBox]::Show(
    "PDF QES Signer $version wurde erfolgreich installiert.`n`n" +
    "Eine Verknüpfung wurde auf dem Desktop und im Start-Menü erstellt.",
    "Installation abgeschlossen",
    [System.Windows.Forms.MessageBoxButtons]::OK,
    [System.Windows.Forms.MessageBoxIcon]::Information
) | Out-Null

$form.Close()
