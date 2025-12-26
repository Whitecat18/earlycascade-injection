### Earlycascade Injeciton in Rust [Re-Implemented]

Earlycascade Injeciton is an modern and stealthy process injection technique that was first discovered by Outflank. This involves injecting and executing our shellcode in the early stages of process creation before loading EDRs for their user mode detection measures. EarlyCascade technique forces enabling the Shim engine, allowing to hijack a Shim engine callback.

> Note: For x64 version only. Works on Windows 11..

### Stub Mechanics 

* Iterates through loaded modules using PEB. If it finds a module that is not a critical system DLL.... it assumes it is an EDR/Security DLL and attempts to disable it by overwriting its entrypoint in the loader structures...

* Patching the g_ShimsEnabled flag aka..placeholder address to disable the shim engine after the injection triggers, cleaning up the environment

* Parses the EAT of ntdll.dll to find NtQueueApcThread using a custom hash funciton.

* The last but not least... queuing an APC to current thread to execute the payload.

#### My Thoughts: 

>This technique can evade AV's solutions when combined with runtime decryption... <br><br>
> But when it comes to EDRs, Its not not feasible to do so.. In fact, I have  implemented this PoC using NT-Func + Custom Call backs to check if i could bypass EDRs but the results were inconsistent. some EDRs was successfully bypassed (often only temporarily, for a few minutes), while others detected it immedieatly when interacting with Shim Engine. you know the reason why...

> For research and analysis purposes, I have reimplemented ie..portrayed my private code into standard, well documented windows API calls. Feel free to modify or EDIT on your own...<br>

### Credits & References

* https://www.outflank.nl/blog/2024/10/15/introducing-early-cascade-injection-from-windows-process-creation-to-stealthy-injection
* https://github.com/Cracked5pider/earlycascade-injection?tab=readme-ov-file
* https://malwaretech.com/2024/02/bypassing-edrs-with-edr-preload.html

For more PoC & Encryption techniques. Check: [Rust for Malware Development Repository](https://github.com/Whitecat18/Rust-for-Malware-Development)