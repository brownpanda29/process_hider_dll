

---

```markdown
# Process Hider  

A lightweight Windows DLL for dynamically hiding processes. This can be used for testing stealth techniques and understanding process manipulation on Windows.  

## Compilation  

Compile the DLL using either **MinGW** or **Visual Studio**:  

### Using MinGW  
```sh
x86_64-w64-mingw32-gcc -shared -o process_hider.dll process_hider_stealth.c -Wall
```  

### Using Visual Studio (cl.exe)  
```sh
cl.exe /LD process_hider_stealth.c /Fe:process_hider.dll
```  

## Usage  

Once compiled, the DLL can be injected using Python or any other method of choice.  

### Injecting with Python  
```python
import ctypes

hider = ctypes.WinDLL("process_hider_stealth.dll")

# Hide process by name
hider.HideProcessByName(b"notepad.exe")

# Hide process by PID
hider.HideProcess(1234)

# Unhide process (restore)
hider.UnhideProcess()
```

## Persistence  

By default, the process remains hidden only until the next reboot. To maintain persistence, two PowerShell scripts are included:  

- **`hide_process.ps1`** – Hides the process after startup.  
- **`schtask.ps1`** – Creates a scheduled task to run `hide_process.ps1` automatically after reboot.  

### Persistence Workflow  

1. **Inject the DLL** to hide the process using Python or another method.  
2. **Manually run `hide_process.ps1`** to verify that it successfully hides `test.exe`.  
3. **Save `hide_process.ps1`** to a persistent location.  
4. **Run `schtask.ps1`** to create a scheduled task that executes `hide_process.ps1` on startup.  
5. After a reboot, when `test.exe` starts, the scheduled task will automatically hide it again.  

## How This Evades Detection  

✅ **Syscall Usage:** Calls `NtQuerySystemInformation` directly, bypassing user-mode hooks.  
✅ **Self-Unhooking:** Keeps original bytes intact, making it difficult for memory scans to detect.  
✅ **Obfuscation:** Resolves API names dynamically to evade signature-based detection.  

## Disclaimer  

This project is intended for **educational and research purposes only**. Use responsibly and ensure compliance with applicable laws.  
```

---

This version is **clear, professional, and to the point**, with structured formatting for easy reading. Let me know if you want any refinements!
