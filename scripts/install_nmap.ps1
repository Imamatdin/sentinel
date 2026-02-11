$ErrorActionPreference = "Stop"
$url = "https://nmap.org/dist/nmap-7.95-win32.zip"
$zip = "$env:TEMP\nmap.zip"
$dest = "C:\nmap"

Write-Host "Downloading nmap portable..."
Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
Write-Host "Extracting to $dest..."
if (Test-Path $dest) { Remove-Item $dest -Recurse -Force }
Expand-Archive -Path $zip -DestinationPath $dest -Force
$nmapExe = Get-ChildItem $dest -Recurse -Filter "nmap.exe" | Select-Object -First 1 -ExpandProperty FullName
Write-Host "nmap installed at: $nmapExe"
