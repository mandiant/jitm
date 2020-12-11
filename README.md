# What is this?

- **Detail blog**: [Bypassing MassLogger Anti-Analysis — a Man-in-the-Middle Approach](https://www.fireeye.com/blog/threat-research/2020/08/bypassing-masslogger-anti-analysis-man-in-the-middle-approach.html)
- **NOTE: This tool is designed to parse and execute malicious payloads. Please take the necessary precautions and only use this tool in a controlled environment like a sandbox or a Virtual Machine**

JITM is an automated tool to bypass the JIT Hooking protection on a .NET sample. JIT Hooking is the technique where the sample hooks the `compileMethod()` function. With the hook in place, the sample can easily replace the MSIL with a decrypted/deobfuscated version at run time. This makes static analysis almost impossible.

One possible solution is to install our own hook before loading the sample. We can have a chance to save/recover the real MSIL and save the content to a file. We can then rebuild the .NET executable by adding a brand new section containing the dumped methods and fix all methods in the MethodDef tables of the .NET `#~` stream. The end result is still not runable without further intervention; however, it should be good enough to perform advanced static analysis.

# How do I use this? 
- Make sure your sample is runable. If not, you may have to modify the tool
- Run `jitm sample.exe [optional_timeout_in_miliseconds]`. `jitm` will first loads `jitmhook.dll` and calls `HookNative()` export to install a native hook. `jitm` then loads and run the sample entry point and wait for the timeout to expire before exiting. This should produces a `jitm.log` and `jitm.json`
- Run the `fix_assembly.py` script: `py -2 fix_assembly.py -f sample.exe -o output.exe -j jitm.json`.
- Use de4dot and dnSpy to statically analyze `output.exe`. However, to use a debugger, load and debug `sample.exe` instead.

# Known issues
- `jitmhook` saves both the MSIL and the method body header as tested on a variant of MassLogger. Future variants may change this behavior
- Current python scripts only run on Python 2.7

# How to build
## Build and install `PolyHook_2_0`

Recommendation: use `vcpkg` method, and build statically to have all dependencies included in one DLL
```
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
.\bootstrap-vcpkg.bat -disableMetrics
(as admin) .\vcpkg integrate install
vcpkg install polyhook2:x64-windows-static polyhook2:x86-windows-static 
```

## Build JITM
Open the `sln` file using `Visual Studio 2017` or `Visual Studio 2019` and build using the GUI.
