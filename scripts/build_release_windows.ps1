# Build SecureUSB on Windows using PyInstaller
Set-StrictMode -Version Latest

Write-Host "Installing Python packages..."
try {
    python -m pip install --upgrade pip
} catch {
    Write-Error "python is not found on PATH or pip failed to run. Ensure Python is installed and on PATH."
    exit 2
}
Write-Host "Installing required packages via python -m pip..."
python -m pip install --user -r requirements.txt
python -m pip install --user pyinstaller

Write-Host "Cleaning previous builds..."
Remove-Item -Recurse -Force build, dist, __pycache__ -ErrorAction SilentlyContinue

Write-Host "Building SecureUSB.exe..."
python -m PyInstaller --clean --onefile --name SecureUSB src\main.py

$artifact = Join-Path -Path (Get-Location) -ChildPath "dist\SecureUSB.exe"
if (Test-Path $artifact) {
    Write-Host "Build complete: $artifact"
    $desktop = [Environment]::GetFolderPath('Desktop')
    Copy-Item $artifact -Destination $desktop -Force
    Write-Host "Copied to Desktop: $desktop"
} else {
    Write-Error "Build failed: artifact not found"
    exit 1
}
