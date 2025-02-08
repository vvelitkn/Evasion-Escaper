$vcvarsall = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
$solution = ".\Source\Agent.sln"

Write-Host "[+] Setting up Visual Studio environment..."
cmd /c """$vcvarsall"" x64 && set" | ForEach-Object {
    $name, $value = $_ -split '=', 2
    Set-Item -Path "Env:\$name" -Value $value
}

Write-Host "[+] Compiling the project..."
msbuild $solution /p:Configuration=Release /m

if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Build failed!" -ForegroundColor Red
    exit 1
}

Write-Host "[+] Running Install.reg..."
Start-Process -FilePath "regedit.exe" -ArgumentList "/s .\Bin\scripts\Install.reg" -Wait

Write-Host "[+] Running Install.bat..."
Start-Process -FilePath ".\Bin\scripts\Install.bat" -Wait

Write-Host "[✔] Build and installation completed successfully!" -ForegroundColor Green
