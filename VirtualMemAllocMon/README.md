# VirtualMemAllocMon
VirtualMemAllocMon is for Monitoring VirtualMemAlloc Event via ETW, when Native some APIs like "VirtualAllocEx" called by your code this event will happen via ETW. (Payload Detection by VirtualMemAlloc Events [in-memory] for All Processes).

### VirtualMemAllocMon.exe
"VirtualMemAllocMon" is simple tool for Monitor VirtualMemAlloc events in all Processes via ETW, with this code you can Monitor New VirtualMemAlloc Events for each Processes, the goal is Payload Detection & my focus was on "Local Create Thread" & "Remote Thread Injection" + Meterpreter payload & Pe "MZ header" in-memory.

Note: this code tested for Meterpreter Payload + Remote Thread Injection Techniques , like Dinvoke/Process Hollowing/Classic RemoteThreadInjection & ... 

### Build Project Note: you should install this nuget in your project for VirtualMemAllocMon
            
    PM> Install-Package Microsoft.Diagnostics.Tracing.TraceEvent -Version 2.0.71           
    or
    PM> Install-Package Microsoft.Diagnostics.Tracing.TraceEvent -Version 2.0.70
    
Related Video about (VirtualMemAllocMon.exe with using ETWProcessMon2)

Video1:

----------
### VirtualMemAllocMon

 VirtualMemAllocMon & Remote Thread Injection Attack (Meterpreter session & Pe Header)  
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/VirtualMemAllocMon/Pics/3.png)
   -------------
 VirtualMemAllocMon & VirtualMemAlloc Event + Memory Address (ProcessHacker & Pe Header) 
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/VirtualMemAllocMon/Pics/1.png)
   -------------
 VirtualMemAllocMon & Remote Thread Injection Attack (Meterpreter session & Pe Header) 
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/VirtualMemAllocMon/Pics/2.png)



<p><a href="https://hits.seeyoufarm.com"><img src="https://hits.seeyoufarm.com/api/count/incr/badge.svg?url=https://github.com/DamonMohammadbagher/ETWProcessMon2/VirtualMemAllocMon"/></a></p>
