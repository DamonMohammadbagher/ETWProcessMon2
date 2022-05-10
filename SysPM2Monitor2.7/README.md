# SysPM2Monitor2.7

this tool [SysPM2Monitor2 v2.7] is for Monitor Sysmon Event-Logs & this code almost is same with ETWPM2Monitor2.exe code but in this case this code Integrated with Sysmon Events so we dont have all ETW Events in this case, but we have ETW VirtualMemAllocMon code in this tool so we have at the same time Sysmon logs + ETW VirtualMemAlloc logs (memory scanner via ETW VirtualMemAlloc Events)...

#### Note: `"sysmonconfig-export.xml" file was my rules for test sysmon so you should use these rules in this file for sysmon but only Event IDs 1,3,8,25 are important for this tool and you do not need other events IDs for running SysPM2Monitor2.7 so you can use your own rules with these Events IDs too.`

##### Sysmon Config => https://github.com/SwiftOnSecurity/sysmon-config


Important: `this Code will use memory scanner "VirtualMemAllocMon.exe" v1.1 so before run SysPM2Monitor2.7 you need copy/paste this exe to \SysPM2Monitor2.7\Bin\Debug\VirtualMemAllocMon\Debug\ folder you can download/compile source code for VirtualMemAllocMon v1.1 from here => https://github.com/DamonMohammadbagher/ETWProcessMon2/tree/main/VirtualMemAllocMon or you can use exe file in github.`

#### warning: `VirtualMemAllocMon.exe has awesome ETW C# codes (https://www.nuget.org/packages/Microsoft.Diagnostics.Tracing.TraceEvent) for monitoring ETW Events and this code has Conflict and error like [System.Runtime.InteropServicesCOMException] with some tools like TCPView (Sysinternals), or maybe i should say TCPView has conflict with ETW [Tracing.TraceEvent] codes, so if you use these tools (like TCPView/ProcessExplorer/ProcessMon...) with VirtualMemAllocMon.exe at the same time then VirtualMemAllocMon.exe code will be crash and VirtualMemAllocMon.exe Memory scanner will not work for SysPM2Monitor2_7.exe .... , (i will work on this thing to fix it but for sure dont use these tools (TCPView,ProcessMon,ProcessExplorer,...) at the same time with SysPM2Monitor2_7.exe)`

#### VirtualMemAllocMon.exe v1.1 => https://github.com/DamonMohammadbagher/ETWProcessMon2/tree/main/VirtualMemAllocMon

Important: `this Code will use memory scanners "pe-sieve64.exe" & "hollows_hunter64.exe",so before run SysPM2Monitor2.7 you need download/paste these exe files to \SysPM2Monitor2.7\Bin\Debug\ folder then you can run SysPM2Monitor2.7.exe , you can download these files from here link1: https://github.com/hasherezade/pe-sieve , link2: https://github.com/hasherezade/hollows_hunter.`


### Technique Detection & Payload Detection via Sysmon events: 
in this code the goal is Monitoring Process for (RemoteThreadInjection Techniques) via Sysmon Events like EventID 1 [New Process], EventID 8 [CreateRemoteThread] & EventID 3 [Tcp/ip Connections] + EventID 25, so background of code is exactly same with ETWPM2Monitor2.exe but in this case we use Sysmon Events instead ETW events which made by ETWProcessMon2.exe C# tool, but we have VirtualMemAllocMon.exe v1.1 which is ETW Memory Scanner (based on VirtualMemAlloc ETW Events), so We have Sysmon + ETW events in this tool.

Video1 : https://www.youtube.com/watch?v=E7mB1we9GhU

Video2 : https://www.youtube.com/watch?v=Q8fSpUXR2kw

Related Article : https://damonmohammadbagher.github.io/Posts/18mar2022x.html

md5 info:
               
       3d81808d17-7d0fb89ed8-1b20e2d03f36 => SysPM2Monitor2_7.exe [v2.7.20.70]
       5ee176af45-524d29ea3e-b89fe0c3e928 => VirtualMemAllocMon.exe (v1.1)


Note: SysPM2Monitor2_7.exe will save all System/Detection logs to Windows eventlog Name "SysPM2Monitor2_7". 
            
     [information] EventId 1 is for Scanned events.
     [warning]     EventId 2 is for Terminated, Suspended, Scanned & Found events.
     [warning]     EventId 4 is for Found Shell events.
           


#### Running SysPM2Monitor2_7.exe step by step

      step1: config your Sysmon rules (example: sysmon64.exe -i sysmonconfig-export.xml)
      step2: make folder "c:\test"
      step3: copy/paste SysPM2Monitor2_7.exe to test folder 
      step4: download/paste memory scanners Pe-sieve64.exe/hollows_hunter64.exe to the test folder.
      step5: download/paste ETW Memory scanner VirtualMemAllocMon.exe to folder "c:\test\VirtualMemAllocMon\Debug\"
      step6: SysPM2Monitor2_7.exe (Run as Admin) 

usage: 

      SysPM2Monitor2_7.exe  (Run as admin)

------------------------- 
SysPM2Monitor2.7 [v 2.7.21.74] (update 6), some bytes for cobaltstrike detection added to ETW MemoryScanner VirtualMemAllocMon v1.1 , ....  (10 apr , 2022)

SysPM2Monitor2.7 [v 2.7.20.70] (update 5), bugs fixed, ....  (16 mar , 2022)

SysPM2Monitor2.7 [v 2.7.18.68] (update 4), Processes Info/Details Tab Added to the source code (11 mar , 2022)

### SysPM2Monitor2.7 [v 2.7.17.59] (update 3), Processes Tab Added to the source code (10 mar , 2022)
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/SysPM2Monitor2.7/Pic/Process3.png)

### SysPM2Monitor2.7 [v 2.7.12.58] (28 feb , 2022)
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/SysPM2Monitor2.7/Pic/SysPM2Monitor2.7.png)
-------------------------   
### SysPM2Monitor2.7 & Detection Logs & Memory Scanners (ETW VirtualMemAllocMon v1.1 works very well & fast)
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/SysPM2Monitor2.7/Pic/logs.png)
------------------------- 
### SysPM2Monitor2.7 & Detection Logs & Memory Scanners (Module Stomping [Module Overloading or DLL Hollowing] Detected by Sysmon but it seems Shell not Detected by Memory Scanner PE-sieve [maybe need to reset scanner switches] also not Detected by ETW Events via ETW VirtualMemAllocMon v1.1)
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/SysPM2Monitor2.7/Pic/ModuleStomping-DLLHollowing.png)
#### link for Technique [Module Overloading/DLL Hollowing]: https://www.ired.team/offensive-security/code-injection-process-injection/modulestomping-dll-hollowing-shellcode-injection
------------------------- 
### SysPM2Monitor2.7 & Detection Logs & Memory Scanners (AddressofEntryPoint Technique not Detected by Sysmon Events but Detected via ETW & ETW VirtualMemAllocMon v1.1)
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/SysPM2Monitor2.7/Pic/AddressofEntryPoint-3.png)
#### link for Technique [AddressofEntryPoint]: https://www.ired.team/offensive-security/code-injection-process-injection/addressofentrypoint-code-injection-without-virtualallocex-rwx
-------------------------   
### SysPM2Monitor2.7 & Detection Logs & Memory Scanners (after shell execute, PE MZ bytes detected via ETW VirtualMemAllocMon v1.1)
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/SysPM2Monitor2.7/Pic/localshell_WithoutAPI.png)   
#### link for Technique [local-shellcode-execution-without-windows-apis]: https://www.ired.team/offensive-security/code-injection-process-injection/local-shellcode-execution-without-windows-apis
-------------------------      
### SysPM2Monitor2.7 & Detection Logs & Memory Scanners (as you can see Something detected in svchost by ETW VirtualMemAllocMon v1.1)
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/SysPM2Monitor2.7/Pic/svchost.png)
-------------------------   
### SysPM2Monitor2.7 & Detection Logs & Memory Scanners (Callback Function techniques detected by ETW VirtualMemAllocMon v1.1 very well)
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/SysPM2Monitor2.7/Pic/cbt.png)   
-------------------------   
### SysPM2Monitor2.7 & ThreadHijacking Not Detected by Sysmon Events
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/SysPM2Monitor2.7/Pic/new3.png)
-------------------------   
### SysPM2Monitor2.7 & ThreadHijacking Detected by ETW Events via VirtualMemAllocMon tool (ETW Memory Scanner)
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/SysPM2Monitor2.7/Pic/new4.png)
-------------------------   
### SysPM2Monitor2.7 & Payload Detection via ETW Events [Memory Scanner via ETW VirtualMemAllocate Events by VirtualMemAllocMon Scanner tool] 
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/SysPM2Monitor2.7/Pic/new5.png)
-------------------------
### SysPM2Monitor2.7 & ProcessHollowing Detection via Sysmon Events
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/SysPM2Monitor2.7/Pic/25.png)
-------------------------   
### SysPM2Monitor2.7 & ProcessHollowing Detection via Sysmon Events
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/SysPM2Monitor2.7/Pic/25-1.png)
-------------------------   
### SysPM2Monitor2.7 & RemoteThreadInjection Detection via Sysmon Events
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/SysPM2Monitor2.7/Pic/v2.7-4.png)
-------------------------   
### SysPM2Monitor2.7 & RemoteThreadInjection Detection via Sysmon Events
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/SysPM2Monitor2.7/Pic/v2.7-2.png)
-------------------------   
### SysPM2Monitor2.7 & RemoteThreadInjection Detection via Sysmon Events
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/SysPM2Monitor2.7/Pic/v2.7-1.png)
 -------------------------  
### SysPM2Monitor2.7 & RemoteThreadInjection Detection via Sysmon Events
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/SysPM2Monitor2.7/Pic/v2.7-3.png)
-------------------------      
### SysPM2Monitor2.7 & System/Detection Logs + SysPM2Monitor2.7 Console (monitoring detection logs)
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/SysPM2Monitor2.7/Pic/console.png)

-------------------------   

### SysPM2Monitor2.7 [Sysmon] vs ETWPM2Monitor2 [ETW]
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/SysPM2Monitor2.7/Pic/hijack.png) 

### SysPM2Monitor2.7 [Sysmon] vs ETWPM2Monitor2 [ETW]
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/SysPM2Monitor2.7/Pic/timd-2.png) 
   
### SysPM2Monitor2.7 [Sysmon] vs ETWPM2Monitor2 [ETW]
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/SysPM2Monitor2.7/Pic/dinvoke.png)    
      
   
### All Pentesters/RedTeamers after Meterpreter Session Established + All Defenders after your Established Session Closed by their Defensive Tools (every day)... ;)
https://user-images.githubusercontent.com/24144801/149812254-8ed792b0-abd1-4ad8-8f34-9822ac22b2e3.mp4


   
<p><a href="https://hits.seeyoufarm.com"><img src="https://hits.seeyoufarm.com/api/count/incr/badge.svg?url=https://github.com/DamonMohammadbagher/ETWProcessMon2/SysPM2Monitor2.7"/></a></p>
