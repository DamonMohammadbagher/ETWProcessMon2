# SysPM2Monitor2.7

this tool [SysPM2Monitor2 v2.7] is for Monitor Sysmon Event-Logs & this code almost is same with ETWPM2Monitor2.exe code but in this case this code Integrated with Sysmon Events so we dont have ETW Events in this case, but in the future i will add ETW VirtualMemAllocMon code to this tool so then we have at same time Sysmon logs + ETW VirtualMemAlloc logs (memory scanner via ETW VirtualMemAlloc Events)...

Note: i will publish this code soon but some codes should change before publish.

### Technique Detection & Payload Detection via Sysmon events: 
in this code the goal is Monitoring Process for (RemoteThreadInjection Techniques) via Sysmon Events like EventID 1 [New Process], EventID 8 [CreateRemoteThread] & EventID 3 [Tcp/ip Connections] so background of code is exactly same with ETWPM2Monitor2.exe but in this case we use Sysmon Events instead ETW events which made by ETWProcessMon2.exe C# tool.

Video : https://www.youtube.com/watch?v=Q8fSpUXR2kw

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

### SysPM2Monitor2.7 [Sysmon] vs ETWPM2Monitor2 [ETW]
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/SysPM2Monitor2.7/Pic/hijack.png) 

### SysPM2Monitor2.7 [Sysmon] vs ETWPM2Monitor2 [ETW]
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/SysPM2Monitor2.7/Pic/timd-2.png) 
   
### SysPM2Monitor2.7 [Sysmon] vs ETWPM2Monitor2 [ETW]
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/SysPM2Monitor2.7/Pic/dinvoke.png)    
      
   
### All Pentesters/RedTeamers after Meterpreter Session Established + All Defenders after your Established Session Closed by their Defensive Tools (every day)... ;)
https://user-images.githubusercontent.com/24144801/149812254-8ed792b0-abd1-4ad8-8f34-9822ac22b2e3.mp4


   
<p><a href="https://hits.seeyoufarm.com"><img src="https://hits.seeyoufarm.com/api/count/incr/badge.svg?url=https://github.com/DamonMohammadbagher/ETWProcessMon2/SysPM2Monitor2.7"/></a></p>
