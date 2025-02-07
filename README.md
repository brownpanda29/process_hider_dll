

```markdown
# Process Hider DLL  

A simple Windows DLL that allows dynamic process hiding using `ntdll`.  

## 🔧 Compilation  

You can compile the DLL using either **Visual Studio** or **MinGW**.  

### Using MinGW:  
```sh
gcc -shared -o process_hider.dll process_hider.c -lntdll
```  

## 🚀 Usage in Python  

Load the compiled DLL in Python using `ctypes`:  

```python
import ctypes

hider = ctypes.WinDLL("process_hider.dll")
hider.HideProcess(1234)  # Replace with target PID
```

Now, any program can load this DLL and hide a process dynamically.  

## 📜 License  

[MIT License](LICENSE)  

## ⚠️ Disclaimer  

This project is for **educational and research purposes only**. Use responsibly and ensure compliance with applicable laws.  
```

