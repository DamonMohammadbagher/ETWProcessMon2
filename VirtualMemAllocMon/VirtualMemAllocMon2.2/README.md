# VirtualMemAllocMon v2.2

VirtualMemAllocMon is for Monitoring VirtualMemAlloc Event via ETW, when some Native APIs like "VirtualAllocEx" called by your code this event will happen via ETW. (Payload Detection by VirtualMemAlloc Events [in-memory] for All Processes).


### VirtualMemAllocMon.exe
"VirtualMemAllocMon" is simple tool for Monitor VirtualMemAlloc events in all Processes via ETW, with this code you can Monitor New VirtualMemAlloc Events for each Process, the goal is Payload Detection & my focus was on "Local Create Thread" & "Remote Thread Injection" + Meterpreter payload & Pe "MZ header" in-memory which made by Meterpreter x64 payload or Cobaltstrike x86 payload. this code will useful sometimes for Defenders & Blue Teamers but Pentesters/Red Teamers can use this too.

in v2.2 EKKO Technique Detection added to the source code also in v2.1 and v2.2 Jump Detection Added too

Note: for this code you need to install Nuget [Microsoft.Diagnostics.Tracing.TraceEvent "v2.0.71"]

link: https://www.nuget.org/packages/Microsoft.Diagnostics.Tracing.TraceEvent

md5 info:
                          
         fe5d3c1214-2313d64f32-a87de101332c => VirtualMemAllocMon.exe (v2.2.0.4) 17,Jan,2024
         

### VirtualMemAllocMon.exe [v2.2.0.4]

 usage:  
    
    step1: [win, Run As Admin] VirtualMemAllocMon.exe  
    Note: you need Run As Admin
    
-----------

Video for v2.2: https://www.youtube.com/watch?v=TMQJ7jMbgQk

Video for v2.2: https://www.aparat.com/v/GtMIi 

Video step by step: https://www.youtube.com/watch?v=26ZBx5fw25s


 ### VirtualMemAllocMon & Remote Thread Injection Attack (EKKO Technique and jmp Method + Pe MZ Bytes)  
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/VirtualMemAllocMon/VirtualMemAllocMon2.2/Pics/v2.2-1.png)

   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/VirtualMemAllocMon/VirtualMemAllocMon2.2/Pics/v2.2-2.png)

