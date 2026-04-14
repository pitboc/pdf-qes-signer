@echo off
:: PDF QES Signer – Windows Installer
:: Downloads Python, VC++ Runtime and pdf-signer automatically and
:: installs everything without admin rights (VC++ requires UAC once).
::
:: Usage: Double-click – no further steps required.
::        setup_pdf_signer.bat --installversion v0.3.3
::
:: Options:
::   --installversion vX.Y.Z   Install a specific version (e.g. v0.3.3).
::                             Use this to downgrade or pin a release.
::
:: The actual installer code is embedded as a PowerShell section at the end
:: of this file (after the PS marker). The batch section reads the file
:: itself and executes the PS part – so only one file needs to be downloaded.
::
:: Note: powershell -Command bypasses ExecutionPolicy (applies only to .ps1
:: files), so it works even with Group Policy restrictions.

:: Parse --installversion argument and pass via environment variable
SET INSTALL_VERSION=
:parse_args
if "%~1"=="--installversion" (
    SET INSTALL_VERSION=%~2
    shift /1
    shift /1
    goto parse_args
)
if not "%~1"=="" (
    shift /1
    goto parse_args
)

powershell -NoProfile -Command "$f=[System.IO.File]::ReadAllText('%~f0',[System.Text.Encoding]::UTF8);$s=$f.LastIndexOf('<#PS#>')+6;Invoke-Expression $f.Substring($s)"
exit /b 0
<#PS#>
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
$installVersion = if ($env:INSTALL_VERSION) { $env:INSTALL_VERSION.Trim() } else { "" }
$PY_URL      = $null   # determined on demand in Start-Install
$DEFAULT_DIR = Join-Path $env:LOCALAPPDATA "pdf-signer"
$savedDir    = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\PDFQESSigner" -ErrorAction SilentlyContinue).InstallLocation
if ($savedDir -and (Test-Path $savedDir)) { $DEFAULT_DIR = $savedDir }
$savedChannel = (Get-ItemProperty "HKCU:\Software\PDF-QES-Signer" -ErrorAction SilentlyContinue).Channel
if (-not $savedChannel) { $savedChannel = "stable" }
$arch    = $env:PROCESSOR_ARCHITECTURE          # AMD64 or ARM64
$pyArch  = if ($arch -eq "ARM64") { "arm64" } else { "amd64" }
$vcArch  = if ($arch -eq "ARM64") { "arm64" } else { "x64" }
$VC_URL  = "https://aka.ms/vs/17/release/vc_redist.$vcArch.exe"

# ---------------------------------------------------------------------------
# Log buffer – flushed to install.log once the install dir exists
# ---------------------------------------------------------------------------
$script:logLines = [System.Collections.Generic.List[string]]::new()

function Write-Log {
    param($msg, $level = "INFO")
    $script:logLines.Add("$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$level] $msg")
}

function Save-Log {
    param($dir)
    try {
        $script:logLines | Set-Content (Join-Path $dir "install.log") -Encoding UTF8
    } catch { }
}

# ---------------------------------------------------------------------------
# Welcome dialog
# ---------------------------------------------------------------------------
function Show-WelcomeDialog {
    $wf                 = New-Object System.Windows.Forms.Form
    $wf.Text            = "PDF QES Signer – Setup"
    $wf.Size            = New-Object System.Drawing.Size(580, 500)
    $wf.StartPosition   = "CenterScreen"
    $wf.FormBorderStyle = "FixedDialog"
    $wf.MaximizeBox     = $false

    $lblTitle          = New-Object System.Windows.Forms.Label
    $lblTitle.Text     = "Welcome to PDF QES Signer Setup"
    $lblTitle.Font     = New-Object System.Drawing.Font("Segoe UI", 13, [System.Drawing.FontStyle]::Bold)
    $lblTitle.Location = New-Object System.Drawing.Point(16, 14)
    $lblTitle.Size     = New-Object System.Drawing.Size(544, 28)

    $sep               = New-Object System.Windows.Forms.Label
    $sep.BorderStyle   = "Fixed3D"
    $sep.Location      = New-Object System.Drawing.Point(16, 48)
    $sep.Size          = New-Object System.Drawing.Size(544, 2)

    $txt               = New-Object System.Windows.Forms.TextBox
    $txt.Multiline     = $true
    $txt.ReadOnly      = $true
    $txt.ScrollBars    = "Vertical"
    $txt.Font          = New-Object System.Drawing.Font("Segoe UI", 9)
    $txt.Location      = New-Object System.Drawing.Point(16, 58)
    $txt.Size          = New-Object System.Drawing.Size(544, 340)
    $txt.Text          = "PDF QES Signer allows you to visually place signature fields in PDF documents and apply electronic signatures:`r`n`r`n" +
                         "  - Qualified signatures via PKCS#11 tokens (smart cards, USB tokens)`r`n" +
                         "  - Advanced signatures using self-signed certificates`r`n`r`n" +
                         "----------------------------------------------------------------`r`n`r`n" +
                         "This installer will check and set up the following components:`r`n`r`n" +
                         "  - PDF QES Signer  (downloaded from Codeberg)`r`n" +
                         "  - Python 3.x  –  downloaded and installed automatically if not present (~25 MB)`r`n" +
                         "  - Visual C++ 2022 Runtime  –  installed if not present (~14 MB)`r`n" +
                         "    Requires a one-time administrator confirmation.`r`n`r`n" +
                         "----------------------------------------------------------------`r`n`r`n" +
                         "Please note:`r`n`r`n" +
                         "  - On Windows 11 the context menu entry appears under 'Show more options'`r`n" +
                         "    or directly via Shift+right-click on a PDF file.`r`n" +
                         "  - The Microsoft Store version of Python is NOT supported.`r`n" +
                         "    If detected, the installer will explain how to resolve this.`r`n" +
                         "  - Administrator rights are only needed for the Visual C++ Runtime,`r`n" +
                         "    not for the application itself.`r`n" +
                         "  - Installation directory and shortcuts can be chosen in the next step.`r`n`r`n" +
                         "----------------------------------------------------------------`r`n`r`n" +
                         "Uninstallation:`r`n`r`n" +
                         "  - PDF QES Signer can be removed cleanly via Settings -> Apps`r`n" +
                         "    or the uninstaller in the installation directory.`r`n" +
                         "  - Python and Visual C++ Runtime have their own entries in`r`n" +
                         "    Settings -> Apps and are not removed automatically."

    $btnNext            = New-Object System.Windows.Forms.Button
    $btnNext.Text       = "Next >"
    $btnNext.Font       = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $btnNext.Location   = New-Object System.Drawing.Point(386, 418)
    $btnNext.Size       = New-Object System.Drawing.Size(80, 28)
    $btnNext.DialogResult = [System.Windows.Forms.DialogResult]::OK

    $btnCancel          = New-Object System.Windows.Forms.Button
    $btnCancel.Text     = "Cancel"
    $btnCancel.Font     = New-Object System.Drawing.Font("Segoe UI", 9)
    $btnCancel.Location = New-Object System.Drawing.Point(480, 418)
    $btnCancel.Size     = New-Object System.Drawing.Size(80, 28)
    $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel

    $wf.Controls.AddRange(@($lblTitle, $sep, $txt, $btnNext, $btnCancel))
    $wf.AcceptButton = $btnNext
    $wf.CancelButton = $btnCancel
    $wf.Add_Shown({ $btnNext.Focus() })
    return $wf.ShowDialog()
}

# ---------------------------------------------------------------------------
# License dialog
# ---------------------------------------------------------------------------
function Show-LicenseDialog {
    $lf                 = New-Object System.Windows.Forms.Form
    $lf.Text            = "PDF QES Signer – License Agreement"
    $lf.Size            = New-Object System.Drawing.Size(580, 440)
    $lf.StartPosition   = "CenterScreen"
    $lf.FormBorderStyle = "FixedDialog"
    $lf.MaximizeBox     = $false

    $lbl          = New-Object System.Windows.Forms.Label
    $lbl.Text     = "PDF QES Signer is distributed under the GNU General Public License v3.0 (GPL-3.0)."
    $lbl.Font     = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $lbl.Location = New-Object System.Drawing.Point(16, 14)
    $lbl.Size     = New-Object System.Drawing.Size(544, 34)

    $txt               = New-Object System.Windows.Forms.TextBox
    $txt.Multiline     = $true
    $txt.ReadOnly      = $true
    $txt.ScrollBars    = "Vertical"
    $txt.Font          = New-Object System.Drawing.Font("Segoe UI", 9)
    $txt.Location      = New-Object System.Drawing.Point(16, 54)
    $txt.Size          = New-Object System.Drawing.Size(544, 252)
    $txt.Text          = "GNU GENERAL PUBLIC LICENSE`r`nVersion 3, 29 June 2007`r`n`r`n" +
                         "Copyright (C) 2026 Pit Muß`r`n`r`n" +
                         "This program is free software: you can redistribute it and/or modify it under " +
                         "the terms of the GNU General Public License as published by the Free Software " +
                         "Foundation, either version 3 of the License, or (at your option) any later version.`r`n`r`n" +
                         "This program is distributed in the hope that it will be useful, but WITHOUT ANY " +
                         "WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A " +
                         "PARTICULAR PURPOSE. See the GNU General Public License for more details.`r`n`r`n" +
                         "You should have received a copy of the GNU General Public License along with this " +
                         "program. If not, see <https://www.gnu.org/licenses/>.`r`n`r`n" +
                         "The complete license text is available at:`r`n" +
                         "https://codeberg.org/pitbo/pdf-qes-signer/src/branch/master/LICENSE"

    $chk          = New-Object System.Windows.Forms.CheckBox
    $chk.Text     = "I have read and accept the terms of the license agreement."
    $chk.Font     = New-Object System.Drawing.Font("Segoe UI", 9)
    $chk.Location = New-Object System.Drawing.Point(16, 316)
    $chk.Size     = New-Object System.Drawing.Size(544, 20)

    $btnAccept                = New-Object System.Windows.Forms.Button
    $btnAccept.Text           = "Accept"
    $btnAccept.Font           = New-Object System.Drawing.Font("Segoe UI", 9)
    $btnAccept.Location       = New-Object System.Drawing.Point(386, 352)
    $btnAccept.Size           = New-Object System.Drawing.Size(80, 28)
    $btnAccept.Enabled        = $false
    $btnAccept.DialogResult   = [System.Windows.Forms.DialogResult]::OK

    $btnDecline               = New-Object System.Windows.Forms.Button
    $btnDecline.Text          = "Decline"
    $btnDecline.Font          = New-Object System.Drawing.Font("Segoe UI", 9)
    $btnDecline.Location      = New-Object System.Drawing.Point(480, 352)
    $btnDecline.Size          = New-Object System.Drawing.Size(80, 28)
    $btnDecline.DialogResult  = [System.Windows.Forms.DialogResult]::Cancel

    $chk.Add_CheckedChanged({ $btnAccept.Enabled = $chk.Checked })

    $lf.Controls.AddRange(@($lbl, $txt, $chk, $btnAccept, $btnDecline))
    $lf.AcceptButton = $btnAccept
    $lf.CancelButton = $btnDecline
    $lf.Add_Shown({ $chk.Focus() })
    return $lf.ShowDialog()
}

# ---------------------------------------------------------------------------
# Update dialog (shown instead of Welcome+License when upgrading)
# ---------------------------------------------------------------------------
function Show-UpdateDialog {
    $venvPy = Join-Path $DEFAULT_DIR ".venv\Scripts\python.exe"
    $installedVersion = if (Test-Path $venvPy) {
        & $venvPy -c "import importlib.metadata; print(importlib.metadata.version('pdf-qes-signer'))" 2>$null
    } else { "" }
    if (-not $installedVersion) { $installedVersion = "unknown" }

    $uf                 = New-Object System.Windows.Forms.Form
    $uf.Text            = "PDF QES Signer – Update"
    $uf.Size            = New-Object System.Drawing.Size(500, 260)
    $uf.StartPosition   = "CenterScreen"
    $uf.FormBorderStyle = "FixedDialog"
    $uf.MaximizeBox     = $false

    $lblTitle          = New-Object System.Windows.Forms.Label
    $lblTitle.Text     = "PDF QES Signer – Update"
    $lblTitle.Font     = New-Object System.Drawing.Font("Segoe UI", 13, [System.Drawing.FontStyle]::Bold)
    $lblTitle.Location = New-Object System.Drawing.Point(16, 14)
    $lblTitle.Size     = New-Object System.Drawing.Size(460, 28)

    $sep              = New-Object System.Windows.Forms.Label
    $sep.BorderStyle  = "Fixed3D"
    $sep.Location     = New-Object System.Drawing.Point(16, 48)
    $sep.Size         = New-Object System.Drawing.Size(460, 2)

    $lblInfo          = New-Object System.Windows.Forms.Label
    $lblInfo.Text     = "An existing installation was found.`n`n" +
                        "Installed version :  $installedVersion`n" +
                        "Install location  :  $DEFAULT_DIR`n`n" +
                        "Click 'Update' to upgrade to the latest version."
    $lblInfo.Font     = New-Object System.Drawing.Font("Segoe UI", 9)
    $lblInfo.Location = New-Object System.Drawing.Point(16, 58)
    $lblInfo.Size     = New-Object System.Drawing.Size(460, 100)

    $btnUpdate                = New-Object System.Windows.Forms.Button
    $btnUpdate.Text           = "Update"
    $btnUpdate.Font           = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $btnUpdate.Location       = New-Object System.Drawing.Point(304, 162)
    $btnUpdate.Size           = New-Object System.Drawing.Size(80, 28)
    $btnUpdate.DialogResult   = [System.Windows.Forms.DialogResult]::OK

    $btnCancel                = New-Object System.Windows.Forms.Button
    $btnCancel.Text           = "Cancel"
    $btnCancel.Font           = New-Object System.Drawing.Font("Segoe UI", 9)
    $btnCancel.Location       = New-Object System.Drawing.Point(398, 162)
    $btnCancel.Size           = New-Object System.Drawing.Size(80, 28)
    $btnCancel.DialogResult   = [System.Windows.Forms.DialogResult]::Cancel

    $uf.Controls.AddRange(@($lblTitle, $sep, $lblInfo, $btnUpdate, $btnCancel))
    $uf.AcceptButton = $btnUpdate
    $uf.CancelButton = $btnCancel
    return $uf.ShowDialog()
}

$script:isUpgrade = $savedDir -and (Test-Path (Join-Path $savedDir ".venv\Scripts\pythonw.exe"))

if ($script:isUpgrade) {
    if ((Show-UpdateDialog)   -ne [System.Windows.Forms.DialogResult]::OK) { exit 0 }
} else {
    if ((Show-WelcomeDialog)  -ne [System.Windows.Forms.DialogResult]::OK) { exit 0 }
    if ((Show-LicenseDialog)  -ne [System.Windows.Forms.DialogResult]::OK) { exit 0 }
}

# ---------------------------------------------------------------------------
# Main form
# ---------------------------------------------------------------------------
$form                 = New-Object System.Windows.Forms.Form
$form.Text            = "PDF QES Signer – Installation"
$form.Size            = New-Object System.Drawing.Size(560, 630)
$form.StartPosition   = "CenterScreen"
$form.FormBorderStyle = "FixedDialog"
$form.MaximizeBox     = $false
$form.MinimizeBox     = $false

$lblTitle          = New-Object System.Windows.Forms.Label
$lblTitle.Text     = "PDF QES Signer"
$lblTitle.Font     = New-Object System.Drawing.Font("Segoe UI", 15, [System.Drawing.FontStyle]::Bold)
$lblTitle.Location = New-Object System.Drawing.Point(20, 14)
$lblTitle.Size     = New-Object System.Drawing.Size(510, 32)

$lblSub           = New-Object System.Windows.Forms.Label
$lblSub.Text      = "Windows Installer"
$lblSub.Font      = New-Object System.Drawing.Font("Segoe UI", 9)
$lblSub.ForeColor = [System.Drawing.Color]::Gray
$lblSub.Location  = New-Object System.Drawing.Point(22, 48)
$lblSub.Size      = New-Object System.Drawing.Size(510, 18)

$sep1              = New-Object System.Windows.Forms.Label
$sep1.BorderStyle  = "Fixed3D"
$sep1.Location     = New-Object System.Drawing.Point(20, 70)
$sep1.Size         = New-Object System.Drawing.Size(510, 2)

# Install directory
$lblDir          = New-Object System.Windows.Forms.Label
$lblDir.Text     = "Install directory:"
$lblDir.Font     = New-Object System.Drawing.Font("Segoe UI", 9)
$lblDir.Location = New-Object System.Drawing.Point(20, 82)
$lblDir.Size     = New-Object System.Drawing.Size(510, 18)

$txtDir          = New-Object System.Windows.Forms.TextBox
$txtDir.Text     = $DEFAULT_DIR
$txtDir.Font     = New-Object System.Drawing.Font("Segoe UI", 9)
$txtDir.Location = New-Object System.Drawing.Point(20, 102)
$txtDir.Size     = New-Object System.Drawing.Size(390, 22)

$btnBrowse          = New-Object System.Windows.Forms.Button
$btnBrowse.Text     = "Browse..."
$btnBrowse.Font     = New-Object System.Drawing.Font("Segoe UI", 9)
$btnBrowse.Location = New-Object System.Drawing.Point(424, 100)
$btnBrowse.Size     = New-Object System.Drawing.Size(106, 26)

# Options
$lblOpts          = New-Object System.Windows.Forms.Label
$lblOpts.Text     = "Options:"
$lblOpts.Font     = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$lblOpts.Location = New-Object System.Drawing.Point(20, 140)
$lblOpts.Size     = New-Object System.Drawing.Size(510, 18)

$chkDesktop          = New-Object System.Windows.Forms.CheckBox
$chkDesktop.Text     = "Create Desktop shortcut"
$chkDesktop.Font     = New-Object System.Drawing.Font("Segoe UI", 9)
$chkDesktop.Location = New-Object System.Drawing.Point(30, 162)
$chkDesktop.Size     = New-Object System.Drawing.Size(500, 20)
$chkDesktop.Checked  = $true

$chkStartMenu          = New-Object System.Windows.Forms.CheckBox
$chkStartMenu.Text     = "Create Start Menu shortcut"
$chkStartMenu.Font     = New-Object System.Drawing.Font("Segoe UI", 9)
$chkStartMenu.Location = New-Object System.Drawing.Point(30, 184)
$chkStartMenu.Size     = New-Object System.Drawing.Size(500, 20)
$chkStartMenu.Checked  = $true

$chkCtx          = New-Object System.Windows.Forms.CheckBox
$chkCtx.Text     = "Add 'Sign with PDF QES Signer' to Explorer context menu for PDF files (on Windows 11: use Shift+right-click or 'Show more options')"
$chkCtx.Font     = New-Object System.Drawing.Font("Segoe UI", 9)
$chkCtx.Location = New-Object System.Drawing.Point(30, 206)
$chkCtx.Size     = New-Object System.Drawing.Size(500, 20)
$chkCtx.Checked  = $true

$chkLaunch          = New-Object System.Windows.Forms.CheckBox
$chkLaunch.Text     = "Launch PDF QES Signer after installation"
$chkLaunch.Font     = New-Object System.Drawing.Font("Segoe UI", 9)
$chkLaunch.Location = New-Object System.Drawing.Point(30, 228)
$chkLaunch.Size     = New-Object System.Drawing.Size(500, 20)
$chkLaunch.Checked  = $false

$grpChannel          = New-Object System.Windows.Forms.GroupBox
$grpChannel.Text     = "Update channel"
$grpChannel.Font     = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$grpChannel.Location = New-Object System.Drawing.Point(20, 254)
$grpChannel.Size     = New-Object System.Drawing.Size(510, 66)

$rbStable            = New-Object System.Windows.Forms.RadioButton
$rbStable.Text       = "stable  –  official releases  (recommended)"
$rbStable.Font       = New-Object System.Drawing.Font("Segoe UI", 9)
$rbStable.Location   = New-Object System.Drawing.Point(12, 20)
$rbStable.Size       = New-Object System.Drawing.Size(486, 20)
$rbStable.Checked    = ($savedChannel -ne "develop")

$rbDevelop           = New-Object System.Windows.Forms.RadioButton
$rbDevelop.Text      = "develop  –  pre-releases and test builds"
$rbDevelop.Font      = New-Object System.Drawing.Font("Segoe UI", 9)
$rbDevelop.Location  = New-Object System.Drawing.Point(12, 42)
$rbDevelop.Size      = New-Object System.Drawing.Size(486, 20)
$rbDevelop.Checked   = ($savedChannel -eq "develop")

$grpChannel.Controls.AddRange(@($rbStable, $rbDevelop))

$sep2             = New-Object System.Windows.Forms.Label
$sep2.BorderStyle = "Fixed3D"
$sep2.Location    = New-Object System.Drawing.Point(20, 326)
$sep2.Size        = New-Object System.Drawing.Size(510, 2)

# Progress area
$lstLog              = New-Object System.Windows.Forms.ListBox
$lstLog.Location     = New-Object System.Drawing.Point(20, 334)
$lstLog.Size         = New-Object System.Drawing.Size(510, 148)
$lstLog.Font         = New-Object System.Drawing.Font("Consolas", 9)
$lstLog.BorderStyle  = "FixedSingle"

$progress                        = New-Object System.Windows.Forms.ProgressBar
$progress.Location               = New-Object System.Drawing.Point(20, 490)
$progress.Size                   = New-Object System.Drawing.Size(510, 20)
$progress.Style                  = "Continuous"
$progress.Value                  = 0

$lblStatus          = New-Object System.Windows.Forms.Label
$lblStatus.Text     = "Ready."
$lblStatus.Font     = New-Object System.Drawing.Font("Segoe UI", 9)
$lblStatus.Location = New-Object System.Drawing.Point(20, 516)
$lblStatus.Size     = New-Object System.Drawing.Size(510, 18)

$btnInstall          = New-Object System.Windows.Forms.Button
$btnInstall.Text     = "Install"
$btnInstall.Font     = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$btnInstall.Location = New-Object System.Drawing.Point(344, 540)
$btnInstall.Size     = New-Object System.Drawing.Size(90, 28)

$btnCancel          = New-Object System.Windows.Forms.Button
$btnCancel.Text     = "Cancel"
$btnCancel.Font     = New-Object System.Drawing.Font("Segoe UI", 9)
$btnCancel.Location = New-Object System.Drawing.Point(444, 540)
$btnCancel.Size     = New-Object System.Drawing.Size(90, 28)
$btnCancel.Add_Click({ $script:cancelled = $true; $form.Close() })

$form.Controls.AddRange(@(
    $lblTitle, $lblSub, $sep1,
    $lblDir, $txtDir, $btnBrowse,
    $lblOpts, $chkDesktop, $chkStartMenu, $chkCtx, $chkLaunch,
    $grpChannel,
    $sep2,
    $lstLog, $progress, $lblStatus,
    $btnInstall, $btnCancel
))

$script:cancelled = $false

# Upgrade detection – updates button label live as the user changes the path
function Update-InstallButton {
    $vp = Join-Path $txtDir.Text ".venv\Scripts\pythonw.exe"
    if (Test-Path $vp) {
        $btnInstall.Text = "Update"
        $lblSub.Text     = "Windows Installer  –  existing installation detected"
    } else {
        $btnInstall.Text = "Install"
        $lblSub.Text     = "Windows Installer"
    }
}

$txtDir.Add_TextChanged({ Update-InstallButton })

$btnBrowse.Add_Click({
    $fbd              = New-Object System.Windows.Forms.FolderBrowserDialog
    $fbd.Description  = "Select installation directory"
    $fbd.SelectedPath = $txtDir.Text
    if ($fbd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $txtDir.Text = $fbd.SelectedPath
    }
})

Update-InstallButton

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
function Step-Start($text) {
    $lstLog.Items.Add("  ...  $text")
    $lstLog.SelectedIndex = $lstLog.Items.Count - 1
    $lblStatus.Text = $text
    Write-Log $text
    [System.Windows.Forms.Application]::DoEvents()
}

function Step-Ok($text) {
    if ($lstLog.Items.Count -gt 0) {
        $lstLog.Items[$lstLog.Items.Count - 1] = "  OK   $text"
    }
    Write-Log $text "OK"
    [System.Windows.Forms.Application]::DoEvents()
}

function Step-Warn($text) {
    if ($lstLog.Items.Count -gt 0) {
        $lstLog.Items[$lstLog.Items.Count - 1] = "  WARN $text"
    }
    Write-Log $text "WARN"
    [System.Windows.Forms.Application]::DoEvents()
}

function Show-Err($title, $msg) {
    [System.Windows.Forms.MessageBox]::Show(
        $msg, $title,
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    ) | Out-Null
}

function Get-File($url, $dest, $label) {
    $lblStatus.Text = "Downloading: $label ..."
    Write-Log "Downloading $label from $url"
    [System.Windows.Forms.Application]::DoEvents()
    try {
        (New-Object System.Net.WebClient).DownloadFile($url, $dest)
        Write-Log "Download complete: $label"
    } catch {
        throw "Download failed ($label): $_"
    }
}

# ---------------------------------------------------------------------------
# Uninstaller template (written to $INSTALL_DIR\uninstall.ps1)
# Single-quote here-string: $ signs are kept literal for the target script.
# ##INSTALL_DIR## is substituted with the actual path before writing.
# ---------------------------------------------------------------------------
$uninstTemplate = @'
Add-Type -AssemblyName System.Windows.Forms
$INSTALL_DIR = '##INSTALL_DIR##'

$r = [System.Windows.Forms.MessageBox]::Show(
    "This will completely remove PDF QES Signer from your computer.`n`nDirectory: $INSTALL_DIR`n`nDo you want to continue?",
    "Uninstall PDF QES Signer",
    [System.Windows.Forms.MessageBoxButtons]::YesNo,
    [System.Windows.Forms.MessageBoxIcon]::Warning)
if ($r -ne [System.Windows.Forms.DialogResult]::Yes) { exit 0 }

$log = [System.Collections.Generic.List[string]]::new()
$log.Add("=== PDF QES Signer Uninstall $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===")

$sk = "HKCU:\Software\Classes\SystemFileAssociations\.pdf\shell\PDFQESSigner"
if (Test-Path $sk) {
    Remove-Item $sk -Recurse -Force -ErrorAction SilentlyContinue
    $log.Add("OK   Context menu entry removed")
}

$uk = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\PDFQESSigner"
if (Test-Path $uk) {
    Remove-Item $uk -Recurse -Force -ErrorAction SilentlyContinue
    $log.Add("OK   Apps & Features entry removed")
}

$dsk = "$env:USERPROFILE\Desktop\PDF QES Signer.lnk"
if (Test-Path $dsk) { Remove-Item $dsk -Force -ErrorAction SilentlyContinue; $log.Add("OK   Desktop shortcut removed") }

$sm = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\PDF QES Signer.lnk"
if (Test-Path $sm)  { Remove-Item $sm  -Force -ErrorAction SilentlyContinue; $log.Add("OK   Start Menu shortcut removed") }

$log.Add("OK   Removing installation directory: $INSTALL_DIR")
$log | Set-Content "$env:TEMP\pdf-signer-uninstall.log" -Encoding UTF8

if (Test-Path $INSTALL_DIR) {
    # Deferred deletion via cmd so the running PS process can exit first
    $arg = '/c timeout /t 2 /nobreak >nul & rmdir /s /q "' + $INSTALL_DIR + '"'
    Start-Process -FilePath "cmd.exe" -ArgumentList $arg -WindowStyle Hidden
}

[System.Windows.Forms.MessageBox]::Show(
    "PDF QES Signer has been uninstalled successfully.`n`nA log was saved to:`n$env:TEMP\pdf-signer-uninstall.log",
    "Uninstall complete",
    [System.Windows.Forms.MessageBoxButtons]::OK,
    [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
'@

# ---------------------------------------------------------------------------
# Python detection – 3 stages, ignores MS Store stubs
# ---------------------------------------------------------------------------
$MIN_PYTHON = [version]"3.11"

function Test-PythonVersion($exe) {
    # Returns the exe path if version >= $MIN_PYTHON, otherwise $null
    $ver = & $exe --version 2>&1
    if ($ver -match "^Python (3\.\d+)") {
        if ([version]$Matches[1] -ge $script:MIN_PYTHON) { return $exe }
    }
    return $null
}

function Find-Python {
    # Stage 1: PATH search (skip WindowsApps stub)
    $cmd = Get-Command python -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source -notlike "*WindowsApps*") {
        $result = Test-PythonVersion $cmd.Source
        if ($result) { return $result }
    }

    # Stage 2: Python Launcher (py.exe) – installed by python.org installer
    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($py) {
        $path = & py -3 -c "import sys; print(sys.executable)" 2>$null
        if ($path -and (Test-Path $path) -and $path -notlike "*WindowsApps*") {
            $result = Test-PythonVersion $path
            if ($result) { return $result }
        }
    }

    # Stage 3: Registry (HKCU and HKLM)
    foreach ($hive in @("HKCU:\SOFTWARE\Python\PythonCore", "HKLM:\SOFTWARE\Python\PythonCore")) {
        if (-not (Test-Path $hive)) { continue }
        $best = Get-ChildItem $hive -ErrorAction SilentlyContinue |
                Where-Object { $_.PSChildName -match "^3\." } |
                Sort-Object { [version]($_.PSChildName + ".0") } -Descending |
                Select-Object -First 1
        if (-not $best) { continue }
        $ip = Get-ItemProperty "$($best.PSPath)\InstallPath" -ErrorAction SilentlyContinue
        if (-not $ip) { continue }
        $exe = if ($ip.ExecutablePath) { $ip.ExecutablePath }
               else { Join-Path $ip.'(default)' "python.exe" }
        if ($exe -and (Test-Path $exe)) {
            $result = Test-PythonVersion $exe
            if ($result) { return $result }
        }
    }

    return $null
}

# ---------------------------------------------------------------------------
# Installation routine
# ---------------------------------------------------------------------------
function Start-Install {
    # Lock UI during installation
    foreach ($c in @($btnInstall, $txtDir, $btnBrowse, $chkDesktop, $chkStartMenu, $chkCtx, $chkLaunch, $rbStable, $rbDevelop)) {
        $c.Enabled = $false
    }
    $progress.Style                  = "Marquee"
    $progress.MarqueeAnimationSpeed  = 30

    $INSTALL_DIR  = $txtDir.Text.TrimEnd('\')
    $VENV_DIR     = Join-Path $INSTALL_DIR ".venv"
    $VENV_PY      = Join-Path $VENV_DIR "Scripts\pythonw.exe"   # GUI – app launch only
    $VENV_PYTHON  = Join-Path $VENV_DIR "Scripts\python.exe"    # console – pip operations
    $VENV_PIP     = Join-Path $VENV_DIR "Scripts\pip.exe"
    $isUpgrade    = Test-Path $VENV_PY

    Write-Log "=== PDF QES Signer installation started ==="
    Write-Log "Mode: $(if ($isUpgrade) { 'upgrade' } else { 'fresh install' })"
    Write-Log "Install directory: $INSTALL_DIR"
    Write-Log "Desktop shortcut: $($chkDesktop.Checked)"
    Write-Log "Start Menu shortcut: $($chkStartMenu.Checked)"
    Write-Log "Context menu: $($chkCtx.Checked)"
    Write-Log "Launch after install: $($chkLaunch.Checked)"

    try {

        # --- Step 1: Python ---
        Step-Start "Checking Python installation ..."
        $python = Find-Python

        if (-not $python) {
            Step-Start "Determining latest Python version ..."
            $PY_VERSION = "3.14.3"   # fallback if query fails
            try {
                $resp       = Invoke-WebRequest "https://www.python.org/ftp/python/" -UseBasicParsing -TimeoutSec 8
                $candidates = [regex]::Matches($resp.Content, '"(3\.\d+\.\d+)/"') |
                              ForEach-Object { $_.Groups[1].Value } |
                              Sort-Object { [version]$_ } -Descending
                foreach ($v in $candidates) {
                    $url  = "https://www.python.org/ftp/python/$v/python-$v-$pyArch.exe"
                    $head = Invoke-WebRequest $url -Method Head -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue
                    if ($head -and $head.StatusCode -eq 200) { $PY_VERSION = $v; break }
                }
            } catch { }
            $PY_URL = "https://www.python.org/ftp/python/$PY_VERSION/python-$PY_VERSION-$pyArch.exe"
            Step-Ok "Python $PY_VERSION selected"

            Step-Start "Downloading Python $PY_VERSION (~25 MB) ..."
            $pyTmp = Join-Path $env:TEMP "python-$PY_VERSION-$pyArch.exe"
            try   { Get-File $PY_URL $pyTmp "Python $PY_VERSION" }
            catch { Show-Err "Download error" "$_"; $form.Close(); return }

            Step-Start "Installing Python $PY_VERSION (no admin required) ..."
            $p = Start-Process -FilePath $pyTmp `
                 -ArgumentList "/quiet InstallAllUsers=0 PrependPath=1 Include_pip=1 Include_test=0" `
                 -Wait -PassThru
            Remove-Item $pyTmp -ErrorAction SilentlyContinue

            if ($p.ExitCode -ne 0) {
                Show-Err "Python installation failed" "Exit code: $($p.ExitCode)"
                Write-Log "Python installation failed (exit $($p.ExitCode))" "ERROR"
                $form.Close(); return
            }
            # Refresh PATH and re-detect
            $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "User") + ";" + $env:PATH
            $python   = Find-Python
            Step-Ok "Python $PY_VERSION installed"
        } else {
            $pyVer = (& $python --version 2>&1) -replace "Python ", ""
            Step-Ok "Python $pyVer found"
            Write-Log "Python found at: $python"
        }

        if ($script:cancelled) { return }

        # --- Step 2: Visual C++ Runtime ---
        Step-Start "Checking Visual C++ Runtime ..."

        $vcKey  = "HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\$vcArch"
        $vcProp    = Get-ItemProperty $vcKey -ErrorAction SilentlyContinue
        $vcVerStr  = ($vcProp.Version -replace "^v","")
        $vcOk      = (Test-Path $vcKey) -and
                     ($vcProp.Installed -eq 1) -and
                     ([version]$vcVerStr -ge [version]"14.30.0.0")

        if (-not $vcOk) {
            Step-Start "Downloading Visual C++ Runtime (~14 MB) ..."
            $vcTmp = Join-Path $env:TEMP "vc_redist.$vcArch.exe"
            try   { Get-File $VC_URL $vcTmp "VC++ Redistributable" }
            catch { Show-Err "Download error" "$_"; $form.Close(); return }

            Step-Start "Installing Visual C++ Runtime (admin prompt will appear) ..."
            $lblStatus.Text = "Please confirm the administrator prompt ..."
            [System.Windows.Forms.Application]::DoEvents()

            try {
                $p = Start-Process -FilePath $vcTmp `
                     -ArgumentList "/install /quiet /norestart" `
                     -Verb RunAs -Wait -PassThru
            } catch {
                Show-Err "VC++ installation cancelled" "The administrator prompt was denied or failed."
                Write-Log "VC++ installation cancelled by user" "WARN"
                $form.Close(); return
            }
            Remove-Item $vcTmp -ErrorAction SilentlyContinue

            if ($p.ExitCode -notin @(0, 3010)) {
                Show-Err "VC++ installation failed" "Exit code: $($p.ExitCode)"
                Write-Log "VC++ installation failed (exit $($p.ExitCode))" "ERROR"
                $form.Close(); return
            }
            if ($p.ExitCode -eq 3010) { Step-Warn "Visual C++ Runtime installed (restart recommended)" }
            else                      { Step-Ok "Visual C++ Runtime installed" }
        } else {
            Step-Ok "Visual C++ Runtime already present"
        }

        if ($script:cancelled) { return }

        # --- Step 3: pdf-signer ---
        Step-Start "$(if ($isUpgrade) { 'Updating' } else { 'Creating' }) virtual environment ..."

        New-Item -ItemType Directory -Force -Path $INSTALL_DIR | Out-Null
        $prevEnc = [Console]::OutputEncoding
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
        $venvOut = & $python -m venv $VENV_DIR 2>&1
        [Console]::OutputEncoding = $prevEnc
        if ($LASTEXITCODE -ne 0) {
            Write-Log "venv creation failed: $venvOut" "ERROR"
            Save-Log $INSTALL_DIR
            Show-Err "venv error" "Could not create virtual environment:`n$venvOut"
            $form.Close(); return
        }

        Step-Start "Updating pip ..."
        $pipUpOut = & $VENV_PYTHON -m pip install --upgrade pip 2>&1
        if ($LASTEXITCODE -eq 0) {
            $pipUpdated = ($pipUpOut | Out-String) -match "Successfully installed pip"
            if ($pipUpdated) { Step-Ok "pip updated" } else { Step-Ok "pip up to date" }
        } else {
            Write-Log "pip upgrade failed: $pipUpOut" "WARN"
            Step-Ok "pip upgrade skipped"
        }

        if ($installVersion) {
            # Specific version requested – build URL directly
            Step-Start "Preparing install of version $installVersion ..."
            $tag     = $installVersion
            $version = $tag -replace "^v", ""
            $whlUrl  = "https://codeberg.org/pitbo/pdf-qes-signer/releases/download/$tag/pdf_qes_signer-$version-py3-none-any.whl"
            Write-Log "Specific version requested: $version"
            Step-Ok "Target version: $version"
        } else {
            Step-Start "Fetching latest release from Codeberg ..."
            try {
                $channel = if ($rbDevelop.Checked) { "develop" } else { "stable" }
                Write-Log "Update channel: $channel"
                if ($channel -eq "develop") {
                    $releases = Invoke-RestMethod -Uri "https://codeberg.org/api/v1/repos/pitbo/pdf-qes-signer/releases?limit=5" -UseBasicParsing
                    if (-not $releases -or $releases.Count -eq 0) { throw "No releases found." }
                    $rel = $releases[0]
                } else {
                    $rel = Invoke-RestMethod -Uri "https://codeberg.org/api/v1/repos/pitbo/pdf-qes-signer/releases/latest" -UseBasicParsing
                }
                $whl = $rel.assets | Where-Object { $_.name -like "*.whl" } | Select-Object -First 1
                if (-not $whl) { throw "No .whl asset found in release." }
                $whlUrl  = $whl.browser_download_url
                $version = $rel.tag_name -replace "^v", ""
                Write-Log "Target version: $version"
            } catch {
                Write-Log "Release query failed: $_" "ERROR"
                Save-Log $INSTALL_DIR
                Show-Err "Release query failed" "$_`n`nPlease check your internet connection."
                $form.Close(); return
            }
        }

        # --- Downgrade check (upgrade path only) ---
        if ($isUpgrade) {
            $installedVer = & $VENV_PYTHON -c "import importlib.metadata; print(importlib.metadata.version('pdf-qes-signer'))" 2>$null
            if ($installedVer) {
                $pyCompare = @'
import sys
try:
    from packaging.version import Version as V
    print("gt" if V(sys.argv[1]) > V(sys.argv[2]) else "le")
except Exception:
    print("unknown")
'@
                $cmp = & $VENV_PYTHON -c $pyCompare $installedVer $version 2>$null
                if ($cmp -eq 'gt') {
                    Write-Log "Downgrade detected: $installedVer -> $version"
                    $ans = [System.Windows.Forms.MessageBox]::Show(
                        "Downgrade detected!`n`n  Installed : $installedVer`n  Target    : $version`n`nDo you want to continue with the downgrade?",
                        "PDF QES Signer – Downgrade Warning",
                        [System.Windows.Forms.MessageBoxButtons]::YesNo,
                        [System.Windows.Forms.MessageBoxIcon]::Warning,
                        [System.Windows.Forms.MessageBoxDefaultButton]::Button2)
                    if ($ans -ne [System.Windows.Forms.DialogResult]::Yes) {
                        Write-Log "Downgrade cancelled by user"
                        $form.Close(); return
                    }
                    Write-Log "Downgrade confirmed by user"
                }
            }
        }

        Step-Start "$(if ($isUpgrade) { "Updating to $version" } else { "Installing pdf-signer $version" }) ..."
        $lblStatus.Text = "pip is running – this may take a moment ..."
        [System.Windows.Forms.Application]::DoEvents()

        $pipFlags = if ($installVersion) { "--force-reinstall" } else { "--upgrade" }
        $pipOut = & $VENV_PIP install $pipFlags $whlUrl 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Log "pip install failed: $pipOut" "ERROR"
            Save-Log $INSTALL_DIR
            Show-Err "Installation failed" "pip install failed:`n$pipOut"
            $form.Close(); return
        }
        Step-Ok "pdf-signer $version $(if ($isUpgrade) { 'updated' } else { 'installed' })"
        Write-Log "pip output: $pipOut"

        $icoPath = Join-Path $VENV_DIR "Lib\site-packages\pdf_signer\icons\app.ico"

        if ($script:cancelled) { return }

        # --- Step 4: Shortcuts ---
        if ($chkDesktop.Checked -or $chkStartMenu.Checked) {
            Step-Start "Creating shortcuts ..."
            $wsh     = New-Object -ComObject WScript.Shell
            $created = @()

            if ($chkDesktop.Checked) {
                $lnk                  = $wsh.CreateShortcut("$env:USERPROFILE\Desktop\PDF QES Signer.lnk")
                $lnk.TargetPath       = $VENV_PY
                $lnk.Arguments        = "-m pdf_signer"
                $lnk.WorkingDirectory = $INSTALL_DIR
                $lnk.Description      = "PDF QES Signer"
                if (Test-Path $icoPath) { $lnk.IconLocation = "$icoPath,0" }
                $lnk.Save()
                $created += "Desktop"
                Write-Log "Desktop shortcut created"
            }

            if ($chkStartMenu.Checked) {
                $startDir             = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs"
                $lnk                  = $wsh.CreateShortcut("$startDir\PDF QES Signer.lnk")
                $lnk.TargetPath       = $VENV_PY
                $lnk.Arguments        = "-m pdf_signer"
                $lnk.WorkingDirectory = $INSTALL_DIR
                $lnk.Description      = "PDF QES Signer"
                if (Test-Path $icoPath) { $lnk.IconLocation = "$icoPath,0" }
                $lnk.Save()
                $created += "Start Menu"
                Write-Log "Start Menu shortcut created"
            }

            Step-Ok "Shortcuts created ($($created -join ', '))"
        }

        if ($script:cancelled) { return }

        # --- Step 5: Explorer context menu ---
        if ($chkCtx.Checked) {
            Step-Start "Registering Explorer context menu ..."
            $sk = "HKCU:\Software\Classes\SystemFileAssociations\.pdf\shell\PDFQESSigner"
            New-Item -Path $sk -Force | Out-Null
            Set-ItemProperty -Path $sk -Name "(Default)" -Value "Sign with PDF QES Signer"
            New-Item -Path "$sk\command" -Force | Out-Null
            Set-ItemProperty -Path "$sk\command" -Name "(Default)" -Value "`"$VENV_PY`" -m pdf_signer `"%1`""
            Step-Ok "Context menu entry registered for .pdf files"
            Write-Log "Context menu registered"
        }

        if ($script:cancelled) { return }

        # --- Step 6: Uninstaller ---
        Step-Start "Creating uninstaller ..."
        $escapedDir = $INSTALL_DIR.Replace("'", "''")
        $uninstPS   = $uninstTemplate.Replace('##INSTALL_DIR##', $escapedDir)
        $uninstBat  = "@echo off`r`npowershell -NoProfile -Command `"`$f=[System.IO.File]::ReadAllText('%~dp0uninstall.ps1',[System.Text.Encoding]::UTF8);Invoke-Expression `$f`"`r`nexit /b 0`r`n"
        $utf8       = [System.Text.Encoding]::UTF8
        [System.IO.File]::WriteAllText("$INSTALL_DIR\uninstall.ps1", $uninstPS, $utf8)
        [System.IO.File]::WriteAllText("$INSTALL_DIR\uninstall.bat", $uninstBat, $utf8)

        if ($chkStartMenu.Checked) {
            $startDir  = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs"
            $wsh2      = New-Object -ComObject WScript.Shell
            $lnkUninst = $wsh2.CreateShortcut("$startDir\Uninstall PDF QES Signer.lnk")
            $lnkUninst.TargetPath       = "$INSTALL_DIR\uninstall.bat"
            $lnkUninst.WorkingDirectory = $INSTALL_DIR
            $lnkUninst.Description      = "Uninstall PDF QES Signer"
            $lnkUninst.Save()
            Write-Log "Uninstall shortcut added to Start Menu"
        }

        Step-Ok "Uninstaller created"
        Write-Log "Uninstaller written to $INSTALL_DIR"

        if ($script:cancelled) { return }

        # --- Step 7: Apps & Features entry ---
        Step-Start "Registering in Apps & Features ..."
        $uk = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\PDFQESSigner"
        New-Item -Path $uk -Force | Out-Null
        Set-ItemProperty -Path $uk -Name "DisplayName"     -Value "PDF QES Signer"
        Set-ItemProperty -Path $uk -Name "DisplayVersion"  -Value $version
        Set-ItemProperty -Path $uk -Name "Publisher"       -Value "Pit Muß"
        Set-ItemProperty -Path $uk -Name "InstallDate"     -Value (Get-Date -Format "yyyyMMdd")
        Set-ItemProperty -Path $uk -Name "InstallLocation" -Value $INSTALL_DIR
        Set-ItemProperty -Path $uk -Name "UninstallString" -Value "`"$INSTALL_DIR\uninstall.bat`""
        Set-ItemProperty -Path $uk -Name "NoModify"        -Value 1 -Type DWord
        Set-ItemProperty -Path $uk -Name "NoRepair"        -Value 1 -Type DWord
        if (Test-Path $icoPath) {
            Set-ItemProperty -Path $uk -Name "DisplayIcon" -Value "$icoPath,0"
        }
        Step-Ok "Registered in Apps & Features"
        Write-Log "Apps & Features entry created (version $version)"

        # Save selected channel to Registry
        $chReg = "HKCU:\Software\PDF-QES-Signer"
        New-Item -Path $chReg -Force -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path $chReg -Name "Channel" -Value $channel

        # Write channel to app settings.ini so the app reads it on first start
        # (%APPDATA%\pdf-signer\settings.ini, INI format, [update] section)
        # Use UTF-8 without BOM – [System.Text.Encoding]::UTF8 emits a BOM which
        # configparser cannot handle; New-Object System.Text.UTF8Encoding $false does not.
        $cfgDir    = Join-Path $env:APPDATA "pdf-signer"
        $cfgFile   = Join-Path $cfgDir "settings.ini"
        $utf8NoBOM = New-Object System.Text.UTF8Encoding $false
        New-Item -ItemType Directory -Force -Path $cfgDir | Out-Null
        if (Test-Path $cfgFile) {
            # Update existing file: replace or append channel= in [update] section.
            # Read with utf8NoBOM so any existing BOM is stripped and not re-written.
            $lines   = [System.IO.File]::ReadAllLines($cfgFile, $utf8NoBOM)
            $inUpd   = $false; $written = $false; $out = [System.Collections.Generic.List[string]]::new()
            foreach ($line in $lines) {
                if ($line -match '^\[update\]') { $inUpd = $true }
                elseif ($line -match '^\[')     { if ($inUpd -and -not $written) { $out.Add("channel = $channel"); $written = $true }; $inUpd = $false }
                if ($inUpd -and $line -match '^channel\s*=') { $out.Add("channel = $channel"); $written = $true; continue }
                $out.Add($line)
            }
            if (-not $written) { $out.Add("[update]"); $out.Add("channel = $channel") }
            [System.IO.File]::WriteAllLines($cfgFile, $out, $utf8NoBOM)
        } else {
            # Create minimal settings.ini with just the channel
            [System.IO.File]::WriteAllText($cfgFile, "[update]`nchannel = $channel`n", $utf8NoBOM)
        }
        Write-Log "Channel saved: $channel"

        # --- Step 8: Save install log ---
        Write-Log "=== Installation completed successfully ==="
        Save-Log $INSTALL_DIR

        $progress.Style = "Continuous"
        $progress.Value = 100
        $lblStatus.Text = "Installation complete."
        $btnCancel.Text = "Close"

        $msgLines = @("PDF QES Signer $version has been installed successfully.", "", "Directory: $INSTALL_DIR")
        if ($chkDesktop.Checked -or $chkStartMenu.Checked) { $msgLines += "Shortcuts have been created." }
        if ($chkCtx.Checked) { $msgLines += "Context menu entry added for PDF files." }
        $msgLines += ""; $msgLines += "The install log is at: $INSTALL_DIR\install.log"

        [System.Windows.Forms.MessageBox]::Show(
            ($msgLines -join "`n"),
            "Installation complete",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null

        if ($chkLaunch.Checked) {
            Start-Process -FilePath $VENV_PY -ArgumentList "-m pdf_signer" -WorkingDirectory $INSTALL_DIR
        }

        $form.Close()

    } catch {
        Write-Log "FATAL: $_" "ERROR"
        Save-Log $INSTALL_DIR
        Show-Err "Unexpected error" "$_"
        $form.Close()
    }
}

$btnInstall.Add_Click({ Start-Install })
$form.ShowDialog() | Out-Null
