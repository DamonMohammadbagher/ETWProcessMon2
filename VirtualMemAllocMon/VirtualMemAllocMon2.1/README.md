# VirtualMemAllocMon v2.1

VirtualMemAllocMon is for Monitoring VirtualMemAlloc Event via ETW, when some Native APIs like "VirtualAllocEx" called by your code this event will happen via ETW. (Payload Detection by VirtualMemAlloc Events [in-memory] for All Processes).


### VirtualMemAllocMon.exe
"VirtualMemAllocMon" is simple tool for Monitor VirtualMemAlloc events in all Processes via ETW, with this code you can Monitor New VirtualMemAlloc Events for each Process, the goal is Payload Detection & my focus was on "Local Create Thread" & "Remote Thread Injection" + Meterpreter payload & Pe "MZ header" in-memory which made by Meterpreter x64 payload or Cobaltstrike x86 payload. this code will useful sometimes for Defenders & Blue Teamers but Pentesters/Red Teamers can use this too.

Note: for this code you need to install Nuget [Microsoft.Diagnostics.Tracing.TraceEvent "v2.0.71"]

link: https://www.nuget.org/packages/Microsoft.Diagnostics.Tracing.TraceEvent

md5 info:
                 
         effd066c8c-d4d1f9db4d-8d78a501a075 => VirtualMemAllocMon.exe (v2.1.0.1) 01,Jan,2024
         

### VirtualMemAllocMon.exe [v2.1.0.1]

 usage:  
    
    step1: [win, Run As Admin] VirtualMemAllocMon.exe  
    Note: you need Run As Admin
    
-----------

Video: https://www.youtube.com/watch?v=26ZBx5fw25s


 ### VirtualMemAllocMon & Remote Thread Injection Attack (Meterpreter session & Pe Header)  
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/VirtualMemAllocMon/VirtualMemAllocMon2/Pictures/VirtualMemAllocMonv2.png)

