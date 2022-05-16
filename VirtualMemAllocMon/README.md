# VirtualMemAllocMon v1.1 & VirtualMemAllocMon v2.0
VirtualMemAllocMon is for Monitoring VirtualMemAlloc Event via ETW, when some Native APIs like "VirtualAllocEx" called by your code this event will happen via ETW. (Payload Detection by VirtualMemAlloc Events [in-memory] for All Processes).

Note : this code VirtualMemAllocMon (v1.1) tested on Win7x64SP1 & Win10 (only), here is my last test on Window10 which was good => [https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/Pics/w10.png]

### VirtualMemAllocMon.exe
"VirtualMemAllocMon" is simple tool for Monitor VirtualMemAlloc events in all Processes via ETW, with this code you can Monitor New VirtualMemAlloc Events for each Process, the goal is Payload Detection & my focus was on "Local Create Thread" & "Remote Thread Injection" + Meterpreter payload & Pe "MZ header" in-memory which made by Meterpreter x64 payload or Cobaltstrike x86 payload, this code will useful sometimes for Defenders & Blue Teamers but Pentesters/Red Teamers can use this too.

md5 info:
             
            25d54c2073-74411e9f4f-7488ee33cc78 => VirtualMemAllocMon.exe (v1.1) 16,May,2022


Note: this code tested for Meterpreter Payload + Remote Thread Injection Techniques , like Dinvoke/Process Hollowing/Classic RemoteThreadInjection & ... 

Related Video about (VirtualMemAllocMon.exe without using ETWProcessMon2.exe)

Video1: https://share.vidyard.com/watch/vQvfgkd8332F5K4MryrHQZ

Related Article:

Article1:

------

### Build Project Note: you should install this nuget in your project for VirtualMemAllocMon
            
    PM> Install-Package Microsoft.Diagnostics.Tracing.TraceEvent -Version 2.0.71           
    or
    PM> Install-Package Microsoft.Diagnostics.Tracing.TraceEvent -Version 2.0.70


### VirtualMemAllocMon.exe has error sometimes...
if you have error like this "System.Runtime.InteropServicesCOMException:..." more often this was because of ProcessHacker/ProcessExplorer etc which Run as normal user or Run As Admin you can fix this problem with these steps:

    step1: close all ProcessHacker/ProcessExplorer/ProcessMon etc Tools
    step2: Run VirtualMemAllocMon.exe (Run As Admin)
    step3: after 10 seconds, run ProcessHacker/ProcessExplorer etc Tools

   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/VirtualMemAllocMon/Pics/err.png)

------

### VirtualMemAllocMon.exe

 usage:  
    
    step1: [win, Run As Admin] VirtualMemAllocMon.exe  
    Note: you need Run As Admin
 
    
----------
 ### VirtualMemAllocMon & Remote Thread Injection Attack (Meterpreter session & Pe Header)  
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/VirtualMemAllocMon/Pics/3.png)
   -------------
   
 ### VirtualMemAllocMon & VirtualMemAlloc Event + Memory Address (ProcessHacker & Pe Header) 
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/VirtualMemAllocMon/Pics/1.png)
   -------------
   
 ### VirtualMemAllocMon & Remote Thread Injection Attack (Meterpreter session & Pe Header) 
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/VirtualMemAllocMon/Pics/2.png)
   -------------



<p><a href="https://hits.seeyoufarm.com"><img src="https://hits.seeyoufarm.com/api/count/incr/badge.svg?url=https://github.com/DamonMohammadbagher/ETWProcessMon2/VirtualMemAllocMon"/></a></p>
