# VirtualMemAllocMon
VirtualMemAllocMon is for Monitoring VirtualMemAlloc Event via ETW, when Native some APIs like "VirtualAllocEx" called by your code this event will happen via ETW. (Payload Detection by VirtualMemAlloc Events [in-memory] for All Processes).

### VirtualMemAllocMon.exe
"VirtualMemAllocMon" is simple tool for Monitor VirtualMemAlloc events in all Processes via ETW, with this code you can Monitor New VirtualMemAlloc Events for each Processes, the goal is Payload Detection & my focus was on "Local Create Thread" & "Remote Thread Injection" + Meterpreter payload & Pe "MZ header" in-memory.

Note: this code tested for Meterpreter Payload + Remote Thread Injection Techniques , like Dinvoke/Process Hollowing/Classic RemoteThreadInjection & ... 
