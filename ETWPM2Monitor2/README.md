# ETWPM2Monitor2 `(v2.1)`
This tool [ETWPM2Monitor version2] is for Monitor ETW Event-Logs [log name: ETWPM2] which made by ETWProcessMon2.exe & the goal is Monitoring RemoteThreadInjection Techniques (Technique Detection & Payload Detection via ETW).

```diff 
! Note: ETWPM2Monitor2 v2.1 is new version of code & you can use this code with ETWProcessMon2.1 (v2.1),
! this version ETWPM2Monitor2 v2.1 will work with ETWProcessMon2.1 and both are
! very fast for (Remote-Thread-Injection) Technique/Payload Detection via ETW Events)
+ code performance now is good and "a lot bugs" fixed. 
+ last source/exe update(31) v2.1.31.167 [Apr 20, 2022]...
```
Video: https://www.youtube.com/watch?v=DMtMTkAfFNo

Note: if you want new v2.1 you should Re-compile this project with new Source code [compile with .NETFramework v4.5] ;), woow i had a lot bugs in code v2.0 , now fixed in v2.1, compiler says (not me), `code performance now is good and "a lot bugs" [like tcp events flooding] fixed with last source update(11) v2.1.17.74 [Feb 21, 2022]...` 

`Note for update(30) v2.1.30.165: Simple Codes always is better than .... , so i decided to change core code for memory scanners (which is simpler than before) and now we have only "Pe-sieve64.exe" file for Memory Scan , it does not mean HollowsHunter has/had problem, i just think one memory scanner will make code simpler than before... also code performance will be better etc. (Still Some Windows Forms Components in .Net like Listview & TreeNode have Very High CPU Usage and they are not very strong/good for fast refreshing without High Cpu usage etc, so i need to changes code for better performance with low CPU usage....), i think microsoft should update all windows forms Components in new ver VS.NET with BETTER performance/stability and LOW CPU USAGE which is very important ;)`


Note: I will Publish Article & Help Documents for this tool soon... 

Related Article : https://damonmohammadbagher.github.io/Posts/18mar2022x.html

Related Article: https://www.linkedin.com/pulse/etwpm2monitor2-remote-thread-injection-detection-etw-mohammadbagher

Related Article: https://damonmohammadbagher.github.io/Posts/12aug2021x.html

Video1: https://www.linkedin.com/posts/damonmohammadbagher_etwprocessmon2-etwpm2monitor-v2-almost-activity-6828777557819752448-6dbv/ 

Note: the goal is talking/thinking about how can use ETW as Defender/Blue teamer for Defensive tools like EDR/AVs or your own Tools etc. so does not matter what i did in my C# codes, these codes just is for test to show you how can use ETW as Blue teamer but these things/codes made by my opinion & my focus was on Remote Thread Injection attack also my focus was on those things which i think blue teamers should know them better than before (especially Alarms TAB Events in this tool)  and these code was for Chapter15 of ebook [bypassing AVs by C# Programming], (i will publish ch15 soon ;D) which is about how can use ETW for Defenders/Blue teamers & ... 

Note: `if your "Windows Defender Anti-virus" have/had problem with ETWPM2Monitor2.exe you should Disable AV to use this Tool (Real-time should be off also Tamper Protection should be off, ...)` Sometimes ETWPM2Monitor2.exe crashed by AVs so you should test these tools (ETWPM2Monitor2.1 , SysPM2Monitor2.7) in windows without Antivirus (Disabled AV) 

Note: in this code we have "Pe-sieve64.exe" as memory scanner , so to use you need to download this exe file & paste them in same folder with ETWPM2Monitor2.exe & i tested ETWPM2Monitor2 with Pe-sieve64.exe (ver 0.2.9.6).

Note: all alarms (Those Processes which Detected by ETWPM2Monitor2 v2.1) will save in windows eventlog name "ETWPM2Monitor2".  

    link1: https://github.com/hasherezade/pe-sieve
    

Note: EventIDs 1,2,3,4,255, these events will save save by ETWPM2Monitor2.1 in Windows Eventlog Name "ETWPM2Monitor2":

        [Information] Event ID 1 : Detected + Scanned but not found 
        [Warning]     Event ID 2 : Detected + Scanned & Found or Suspended or Terminated via ETW Injection Events
        [Informarion] Event ID 3 : Detection for Meterpreter Traffic only via ETW Tcp Events 
        [Warning]     Event ID 4 : Detection for Shell Activity via ETW New Process Events


md5 info, "exe files are not safe here in github so make your own exe files with C# source by yourself [i recommend]":

    b913a0d66d-750478c5a8-1d557aad377d => ETWProcessMon2.exe    
    e2133acacd-2d03d23212-3276ddae943a => ETWProcessMon2.exe (v2.1)
    0eba28c62d-8fc9261649-900bf20f98ee => ETWPM2Monitor2.exe (v2.1)



    

Usage Steps

    Step1: ETWProcessMon2.exe (Run as Admin)

    Step2: ETWPM2Monitor2.exe (Run as Admin)

----------------------------------------------------------

## ETWPM2Monitor2 v2.1 , update(31) v2.1.31.167 [Apr 20, 2022]
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/ETWPM2Monitor2/Pics/CSInject1.png)
   
### ETWPM2Monitor2 v2.1 , update(22) v2.1.22.100 [Mar 11, 2022] (Processes Info Tab Added)
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/ETWPM2Monitor2/Pics/ProcessInfo.png)
   
### ETWPM2Monitor2 v2.1 , update(21) v2.1.21.97 [Mar 08, 2022] (Processes Tab Added)
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/ETWPM2Monitor2/Pics/Process.png)
   
#### note: Simple Processes Tab + Simple Search added to the source code ;) [Mar 08, 2022]
   
### ETWPM2Monitor2 v2.1 , update(17) v2.1.18.84 [Feb 27, 2022]
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/Pics/ETWPM2Monitor2.1.png)
   
### ETWPM2Monitor2 v2.1 (Search/Filters)
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/ETWPM2Monitor2/Pics/filters.png)
   
#### note: Search/Filters from Event log "ETWPM2", added to the source code ;)  [25 feb 2022]

### ETWPM2Monitor2 v2.1 (Search/Filters)
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/ETWPM2Monitor2/Pics/filters2.png)
   
#### note: you can use Filters in your search result for ... , this simple code worked but i will update search/filters source code soon ;)  [25 feb 2022]

### ETWPM2Monitor2 v2.1 (System/Detection Logs)
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/ETWPM2Monitor2/Pics/detection_logs.png)
   
#### note: System/Detection Logs added to the source code ;)  [12 feb 2022]

### ETWPM2Monitor2 v2.1 (Detecting Cmd.exe for shell via [EventID 1] & Meterpreter Traffic Packets via [EventID 3])
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/ETWPM2Monitor2/Pics/tcp.png)
   
#### note: this traffic detection via EventID 3 added to source code ;)  [08 feb 2022]

### ETWPM2Monitor2 v2.1 (Memory Scanners Logs added to code, now you can see what happened in background when something Detected or not by [Memory Scanners & events])
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/ETWPM2Monitor2/Pics/v21_11.35_scannerlogs.png)

### ETWPM2Monitor2 v2.1 (all Alarms & System/Detection logs Now will save in windows Eventlog "ETWPM2Monitor2")
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/ETWPM2Monitor2/Pics/EVT.png)
      
#### note: this simple important code added/updated to source code ;) [13 feb 2022] , 
    
    windows Eventlog "ETWPM2Monitor2": EventIDs 1,2,3,4,255 Added...
    [Event ID 1 Detected + Scanned but not found] , 
    [Event ID 2 Detected + Scanned & Found or Suspended or Terminated via ETW Injection Events] ,
    [Event ID 3 Detection for Meterpreter Traffic only via ETW Tcp Events] , 
    [Event ID 4 Detection for Shell Activity via ETW New Process Events] ...

### ETWPM2Monitor2 v2.1 (Memory Scanner Dump files details/hex file added to source code for better report result)
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/ETWPM2Monitor2/Pics/reportresult.png)
   
#### note: this simple tab for Memory Scanner Report added to source code ;)  [10 feb 2022]

### ETWPM2Monitor2 v2.1 (Network Connections Tab & Meterpreter Traffic Packets via [EventID 3])
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/ETWPM2Monitor2/Pics/NetworkConnections.png)
   
#### note: this Network Connections Tab added to the source code ;)  [17 feb 2022]

### ETWPM2Monitor2 v2.1 (Detecting Cmd.exe with Parent_Process_Path/ID, when cmd process has ParentPID which is not normal)
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/ETWPM2Monitor2/Pics/v21-cmd.png)

### ETWPM2Monitor2 v2.1 (Detecting Cmd.exe with Parent_Process_Path/ID, when cmd process has ParentPID which is not normal)
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/ETWPM2Monitor2/Pics/v21-cmd2.png)
   
#### note: this simple shell detection added to source code.
-------------------------
### ETWPM2Monitor2 & RemoteThreadInjection Detection via ETW Events
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/ETWPM2Monitor2/Pics/ETWPM2Monitor2-1.png)

### ETWPM2Monitor2 & RemoteThreadInjection Detection via ETW Events & integrating with Memory Scanners
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/ETWPM2Monitor2/Pics/ETWMP2Monitor2.png)
   
### ETWPM2Monitor2 & RemoteThreadInjection (Technique + Payload Detection) via ETW Events
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/ETWPM2Monitor2/Pics/ETWPM2Monitor2-2.png)

### ETWPM2Monitor2 & Integrating with Memory Scanners Pe-sieve64.exe (ProcessHollowing Technique Detection) via ETW Events
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/ETWPM2Monitor2/Pics/ETWPM2Monitor2-3.png)
      
   
<p><a href="https://hits.seeyoufarm.com"><img src="https://hits.seeyoufarm.com/api/count/incr/badge.svg?url=https://github.com/DamonMohammadbagher/ETWProcessMon2/ETWPM2Monitor2"/></a></p>
