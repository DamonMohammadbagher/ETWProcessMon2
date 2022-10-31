# ETWProcessMon2 `(v2.1)`
ETWProcessMon2 (ver2) is for Monitoring Process/Thread/Memory/Imageloads/TCPIP via ETW + Detection for Remote-Thread-Injection & Payload Detection by VirtualMemAlloc Events (in-memory) etc.

Note: `ETWProcessMon2.1 (v2.1) is new version of code, in this new version VirtualMemAlloc Events removed from source code & now Code Performance is very fast/good (this version ETWProcessMon2.1 will work with ETWPM2Monitor2 v2.1 very good for Technique/Payload Detection via ETW Events)`

Note: `if your "Windows Defender Anti-virus" have/had problem with ETWPM2Monitor2.exe you should Disable AV to use this Tool (Real-time should be off also Tamper Protection should be off, ...)`, Sometimes ETWPM2Monitor2.exe crashed by AVs so you should test these tools (ETWPM2Monitor2.1 , SysPM2Monitor2.7) in windows without Antivirus (Disabled AV)

### ETWProcessMon2.exe
"ETWProcessMon" is simple tool for Monitor Processes/Threads/Memory/Imageloads/TCPIP Events via ETW, with this code you can Monitor New Processes also you can See New Threads (Thread Started event) + Technique Detection for Remote-Thread-Injection (Which Means Your New Thread Created into Target Process by Another Process), also with this code you can Monitor VirtualMemAllocation Events in Memory for All Processes (which sometimes is very useful for Payload Detection in-memory) also you can see ImageLoads for each Process & you can see TCPIP Send Events for each Process too. 

in this simple example you can see how we can use ETWProcessMon/2 v1/v1.1 or v2.1 for Payload Detection or Beacon Detection via Abnormal ETW VirtualMemAlloc Events & Thread Start Events .
 ### ETWProcessMon.exe v1.0/v1.1/v2.0 vs ETWProcessMon2.exe v2.1 for Beacon Detection via VirtualMemAlloc ETW Events....  
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/Pics/BeaconDetection1.png)
   
 ### ETWProcessMon.exe v1.0/v1.1/v2.0 vs ETWProcessMon2.exe v2.1 for Beacon Detection via VirtualMemAlloc ETW Events....  
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/Pics/BeaconDetection2.png)

also in the next picture you can see what we can find in "ETWProcessMonlog.txt" file which made by ETWProcessMon v1.0 , v1.1 and v2.0 , but in ETWProcessMon2.exe v2.1 we don't have this text log file, for example you can see in Cobaltstrike v4.4 with Sleep Command (which will Encrypt/Decrypt MZ Header in-memory)
you will have Abnormal ETW VirtualMemAlloc Events for Target Process in this case "Notepad", as you can see when Sleep set to 2 then we have every 2 sec ETW VirtualMemAlloc Events for same StartAddress (in-memory) for Process Notepad. (Delta time for Each ETW event is 2 sec because Sleep Set to 2 secs)

### ETWProcessMon.exe v1.0/v1.1 for Beacon Detection via VirtualMemAlloc ETW Events....  
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/Pics/EventWatcher01.png)

when you change Delay execution (DelayExecution,SleepEx APIs) from 2 to 4 then in-memory you will have ETW VirtualMemAlloc Events every 4 Sec (Delta-time) for Notepad Process (Real-time)

### ETWProcessMon.exe v1.0/v1.1 for Beacon Detection via VirtualMemAlloc ETW Events....  
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/Pics/EventWatcher02.png)

in this simple example you can see how we can use ETWProcessMon2.exe v2.1 + ETWPM2Monitor2.exe v2.1 for Technique Detection & Payload Detection via ETW Events, in this case syscall technique Detected by ETW Events & ETWPM2Monitor2 v2.1

### ETWProcessMon2.exe v2.1 + ETWPM2Monitor2 v2.1 for Technique Detection via ETW Events....  
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/Pics/syscall.png)
   
Note: VirtualMemAlloc for (Payload-Detection) + ImageLoad & Remote-Thread-Injection Detection for (Technique-Detection) are useful for Blue Teams/Defenders, New Code "VirtualMemAllocMon.exe" created & in this code you can monitor all VirtualMemAlloc Events for ALL Process without using "ETWProcessMon2.exe" for more information => (https://github.com/DamonMohammadbagher/ETWProcessMon2/tree/main/VirtualMemAllocMon)

Note: in ETWProcessMon2 (v2.0) NewProcess events + Remote-Thread-Injection Detecetion events + TCPIP send events all will save in Windows Event Log which with EventViewer you can watch them also VirtualMemAlloc events + Remote-thread-injection Detection Events will save in text "ETWProcessMonlog.txt" log file too (at the same time). so in this version2 we have two type of Events log files => 1."windows event logs [ETWPM2]" , 2."ETWProcessMonlog.txt". 

Note: ETWProcessMon2.1 (v2.1) is new version of code, in this new version VirtualMemAlloc Events removed from source code that means now we don't have Text log file for VirtualMemAlloc Events & now Code Performance is very fast/good (this version ETWProcessMon2.1 will work with ETWPM2Monitor2 v2.1 very good for Technique/Payload Detection via ETW Events) but if you want VirtualMemAlloc Events by ETW you can use VirtualMemAllocMon.exe v1.1 C# Source code which is Memory scanner based on ETW VirtualMemAlloc events. 

Note: ETWProcessMon2.exe (v2.1) & ETWPM2Monitor2.exe (v2.1) published in "bin" directory. (8 Feb, 2022)


ETW Events in event log [ETWPM2]:

    [Information] Event ID 1  => NewProcess event 
    [Warning]     Event ID 2  => Remote-Thread-Injection Detection event 
    [Information] Event ID 3  => TCPIP Send event


### Build Project Note: you should install this nuget in your project for ETWProcessMon2
            
    PM> Install-Package Microsoft.Diagnostics.Tracing.TraceEvent -Version 2.0.69            
    or
    PM> Install-Package Microsoft.Diagnostics.Tracing.TraceEvent -Version 2.0.70

md5 info [ETWProcessMon2.exe], "exe files are not safe here in github so make your own exe files with C# source by yourself [i recommend]":

    b913a0d66d-750478c5a8-1d557aad377d => ETWProcessMon2.exe
    951aef1888-093fca9e67-d881615ed10b => ETWProcessMon2.exe (v2.1) 16,May,2022
 

### Videos: 

Video: https://www.youtube.com/watch?v=DMtMTkAfFNo

this Video is for (Version 1), ETWProcessMon.exe v1 download & (step by step with details) => https://github.com/DamonMohammadbagher/ETWNetMonv3

Video [3], [Video-3 of Chapter15-Part2]: (video is about C# + ETW vs Process Hollowing, DInvoke (syscall),Loading dll/functions from Memory,Classic-RemoteThreadInjection)  

   C# + ETW vs Some Thread/Process/Code Injection Techniques (CH15-Part2):
   
   link1 => https://www.youtube.com/watch?v=d1a8WqOvE84
   
   link2 => https://share.vidyard.com/watch/4kB2Xy1bLfhRxaTD6pwaLD

-----------------------------------------------------------    
### VirtualMemAllocMon.exe v1.1 & VirtualMemAllocMon.exe v2.0

VirtualMemAllocMon is for Monitoring VirtualMemAlloc Event via ETW, when some Native APIs like "VirtualAllocEx" called by your code this event will happen via ETW. (Payload Detection by VirtualMemAlloc Events [in-memory] for All Processes).

"VirtualMemAllocMon" is simple tool for Monitor VirtualMemAlloc events in all Processes via ETW, with this code you can Monitor New VirtualMemAlloc Events for each Process, the goal is Payload Detection & my focus was on "Local Create Thread" & "Remote Thread Injection" + Meterpreter payload & Pe "MZ header" in-memory which made by Meterpreter x64 payload or Cobaltstrike x86 payload. this code will useful sometimes for Defenders & Blue Teamers but Pentesters/Red Teamers can use this too.

md5 info:

    25d54c2073-74411e9f4f-7488ee33cc78 => VirtualMemAllocMon.exe (v1.1) 16,May,2022
    d42ca87133-977815440d-be8bd04c9589 => VirtualMemAllocMon.exe (v2.0.0.1) 16,May,2022
    

 ### VirtualMemAllocMon v2.0 & VirtualMemAlloc ETW Event  
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/VirtualMemAllocMon/VirtualMemAllocMon2/Pictures/VirtualMemAllocMonv2.png)
   
 ### VirtualMemAllocMon v1.1 & VirtualMemAlloc ETW Event + Memory Address (ProcessHacker & Pe Header) 
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/Pics/w10.png)
   
   
For more Information & Details with Picture about this Code => https://github.com/DamonMohammadbagher/ETWProcessMon2/tree/main/VirtualMemAllocMon 

-----------------------------------------------------------   
### SysPM2Monitor2.7.exe

this tool [SysPM2Monitor2 v2.7] is for Monitor Sysmon Event-Logs & this code almost is same with ETWPM2Monitor2.exe code but in this case this code Integrated with Sysmon Events so we dont have all ETW Events in this case, but we have ETW VirtualMemAllocMon code in this tool so we have at the same time Sysmon logs + ETW VirtualMemAlloc logs (memory scanner via ETW VirtualMemAlloc Events)...

link : https://github.com/DamonMohammadbagher/ETWProcessMon2/tree/main/SysPM2Monitor2.7

#### Note: `"sysmonconfig-export.xml" file was my rules for test sysmon so you should use these rules in this file for sysmon but only Event IDs 1,3,8,25 are important for this tool and you do not need other events IDs for running SysPM2Monitor2.7 so you can use your own rules with these Events IDs too.`

##### Sysmon Config => https://github.com/SwiftOnSecurity/sysmon-config

### SysPM2Monitor2.7 [v 2.7.12.58] (28 feb , 2022)
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/SysPM2Monitor2.7/Pic/SysPM2Monitor2.7.png)

Important: `this Code will use memory scanner "VirtualMemAllocMon.exe" v1.1 so before run SysPM2Monitor2.7 you need copy/paste this exe to \SysPM2Monitor2.7\Bin\Debug\VirtualMemAllocMon\Debug\ folder you can download/compile source code for VirtualMemAllocMon v1.1 from here => https://github.com/DamonMohammadbagher/ETWProcessMon2/tree/main/VirtualMemAllocMon or you can use exe file in github.`

#### VirtualMemAllocMon.exe v1.1 => https://github.com/DamonMohammadbagher/ETWProcessMon2/tree/main/VirtualMemAllocMon

Important: `this Code will use memory scanners "pe-sieve64.exe" & "hollows_hunter64.exe",so before run SysPM2Monitor2.7 you need download/paste these exe files to \SysPM2Monitor2.7\Bin\Debug\ folder then you can run SysPM2Monitor2.7.exe , you can download these files from here link1: https://github.com/hasherezade/pe-sieve
link2: https://github.com/hasherezade/hollows_hunter.`

Video1 : https://www.youtube.com/watch?v=E7mB1we9GhU

Video2 : https://www.youtube.com/watch?v=Q8fSpUXR2kw

md5 info:
                          
           3d81808d17-7d0fb89ed8-1b20e2d03f36 => SysPM2Monitor2_7.exe [v2.7.20.70]



Note: SysPM2Monitor2_7.exe will save all System/Detection logs to Windows eventlog Name "SysPM2Monitor2_7". 
            
     [information] EventId 1 is for Scanned events.
     [warning]     EventId 2 is for Terminated, Suspended, Scanned & Found events.
     [warning]     EventId 4 is for Found Shell events.           

#### Running SysPM2Monitor2_7.exe step by step

      step1: config your Sysmon rules
      step2: make folder "c:\test"
      step3: copy/paste SysPM2Monitor2_7.exe to test folder 
      step4: download/paste memory scanners Pe-sieve64.exe/hollows_hunter64.exe to the test folder.
      step5: download/paste ETW Memory scanner VirtualMemAllocMon.exe v1.1 to folder "c:\test\VirtualMemAllocMon\Debug\"
      step6: SysPM2Monitor2_7.exe (Run as Admin) 

usage: 

      SysPM2Monitor2_7.exe  (Run as admin)

-----------------------------------------------------------
### ETWPM2Monitor2.exe (v2.1)
"ETWPM2Monitor2" [v2.1] is simple C# code for Realtime Event Log Monitor, but this code only will work with logname "ETWPM2" which made by "ETWProcessMon2.exe", so you need run as Admin "ETWProcessMon2.exe" (step1) before use "ETWPM2Monitor2.1.exe" (step2) for monitor windows event logs which made by "ETWProcessMon2.exe (v2.1)".

This tool [ETWPM2Monitor version2] is for Monitor ETW Event-Logs [log name: ETWPM2] which made by ETWProcessMon2.exe & the goal is Monitoring RemoteThreadInjection Techniques (Technique Detection & Payload Detection via ETW).

```diff 
! Note: ETWPM2Monitor2 v2.1 is new version of code & you can use this code with ETWProcessMon2.1 (v2.1),
! this version ETWPM2Monitor2 v2.1 will work with ETWProcessMon2.1 and both are
! very fast for (Remote-Thread-Injection) Technique/Payload Detection via ETW Events)
+ code performance now is good and "a lot bugs" fixed. New Memory Scanner Added to source code, CobaltStrikeScan.exe, C# code made by Apr4h. 
+ last source/exe update(47) v2.1.47.480 [Oct 31, 2022]...
```
Video: https://www.youtube.com/watch?v=DMtMTkAfFNo

Note: "ETWPM2Monitor2 v2.1" code Published here => https://github.com/DamonMohammadbagher/ETWProcessMon2/tree/main/ETWPM2Monitor2

Note: EventIDs 1,2,3,4,5,255, these events will save save by ETWPM2Monitor2.1 in Windows Eventlog Name "ETWPM2Monitor2":

        [Information] Event ID 1 : Detected + Scanned but not found 
        [Warning]     Event ID 2 : Detected + Scanned & Found or Suspended or Terminated via ETW Injection Events
        [Informarion] Event ID 3 : Detection for Meterpreter Traffic only via ETW Tcp Events 
        [Warning]     Event ID 4 : Detection for Shell Activity via ETW New Process Events
        [Informarion] Event ID 5 : ETWPM2 (Injection Events) Tab : TargetProcess, InjectorProcess, MZ header in bytes + Injection Bytes   

md5 info [ETWPM2Monitor2.exe], "exe files are not safe here in github so make your own exe files with C# source by yourself [i recommend]":
                    
    bc42bb0ace-5de9f8ed08-e26c46503614 => ETWPM2Monitor2.exe (v2.1) [v2.1.47.480] 31,Oct,2022 
    
### ETWPM2Monitor2 v2.1 [v2.1.41.380]  
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/ETWPM2Monitor2/Pics/NetworkConnectionsx3.png)
   
### ETWPM2Monitor2 v2.1 [v2.1.33.194]  
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/Pics/ProcrssListTabx1.png)
    
### ETWPM2Monitor2 v2.1 [v2.1.18.84]  
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/Pics/ETWPM2Monitor2.1.png)

Note: with "ETWPM2Monitor2 v2" code we have "Pe-sieve64.exe" as Memory Scanner so to use you need to download these exe files & paste them in same folder with ETWPM2Monitor2.exe & i tested ETWPM2Monitor2 with Pe-sieve64.exe (ver 0.2.9.6).

Related Article about (ETWPM2Monitor2.exe & ETWProcessMon2.exe) + VirtualMemAlloc ETW Events made by ETWProcessMon2: 

Link1: https://www.linkedin.com/pulse/etwpm2monitor2-remote-thread-injection-detection-etw-mohammadbagher

Link2: https://damonmohammadbagher.github.io/Posts/12aug2021x.html

Related Video about (VirtualMemAllocMon.exe & ETWProcessMon2.exe) + VirtualMemAlloc ETW Events made by ETWProcessMon2: 

Video1: https://www.linkedin.com/posts/damonmohammadbagher_new-video-etwprocessmon2-virtualmemallocmon-activity-6832801206688112640-yAWG/

Video2: 


Video for ETWPM2Monitor2 (ver 2) => https://www.linkedin.com/posts/damonmohammadbagher_etwprocessmon2-etwpm2monitor-v2-almost-activity-6828777557819752448-6dbv/

with this Application you can watch [Realtime ETW Events] with "EventIDs 1,2 & 3" which made by "ETWProcessMon2.exe"
    
    [Information] Event ID 1  => NewProcess event 
    [Warning]     Event ID 2  => Remote-Thread-Injection Detection event 
    [Information] Event ID 3  => TCPIP Send event
    
in this tool you can use Filters to watch realtime these events very simple (Filtering by EventIDs), also you save filtered events to text file.

### Build Project Note: If you have error for build Project name "ETWPM2Monitor", please read this page => [https://github.com/DamonMohammadbagher/ETWProcessMon2/tree/main/ETWPM2Monitor#readme] 

Note: with "ETWProcessMon2" you make ETW Events in Windows Event log so you can watch them by Windows EventViewer too but with this tool
you can see them like realtime (Result Refreshed by New Events), this will help you as Defender/Blue Teamer for RemoteThredInjection Detection + TCPIP traffic etc.

Note: after running "ETWPM2Monitor.exe", this code will show you all 3 EventIDs 1,2,3 without filters, but you can use Filter Menu to change this very simple.

Note: Filter [EventIDs 1,2] is good if you want to know which Process Created & which RemoteThreadInjection Detection you have after Payload execution etc...

Note: Filter [EventIDs 2,3] is good if you want to know, after which RemoteThreadInjection you will have TCPIP Network Traffic (Send Traffic). 

Note: this ETWPM2Monitor is [test version] & this code need to test more & more ;)

New Video ETWPM2Monitor v1.2 : 

Video link1: https://www.linkedin.com/posts/damonmohammadbagher_new-video-in-this-video-you-can-see-as-defender-activity-6821891432748601344-BecI

Video link2: https://share.vidyard.com/watch/PjBybo5BNHbfCXazoLmN6f

 usage:  
    
    step1: [win, Run As Admin] ETWProcessMon2.exe > Save_all_outputs.txt
    step2: [win, Run As Admin] ETWPM2Monitor2.exe 
    
### ETWPM2Monitor2 v2.1 [v2.1.15.53] (last update of code & All Detection Now Will Save to Windows Event Log [ETWPM2Monitor2])
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/ETWPM2Monitor2/Pics/EVT.png)

### ETWPM2Monitor2 v2.1 [v2.1.11.35] (Detecting Cmd.exe for shell via [EventID 1] & Meterpreter Traffic Packets via [EventID 3])
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/ETWPM2Monitor2/Pics/tcp.png)

### ETWPM2Monitor2 & Integrating with Memory Scanners Pe-sieve64.exe (ProcessHollowing Technique Detection) via ETW Events
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/ETWPM2Monitor2/Pics/ETWPM2Monitor2-3.png)

### ETWPM2Monitor2 & RemoteThreadInjection Detection via ETW Events
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/ETWPM2Monitor2/Pics/ETWPM2Monitor2-1.png)
   
### ETWPM2Monitor v1.2 [test version 1.2.10.18]

   1.ETWPM2Monitor v1.2 & Remote-Thread-Injection (classic)
   
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/Pics/v12-0.png)

   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/Pics/v12-1.png)
   
   2.ETWPM2Monitor v1.2 & Process Hollowing (C#)
   
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/Pics/v2_ProcessHollowing3.jpeg)

   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/Pics/v2_ProcessHollowing2.jpeg)

   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/Pics/v2_ProcessHollowing1.jpeg)

-----------------------------------------------------------    

### ETWProcessMon2.exe
  1. ETWProcessMon2.cs (ETWProcessMon v2)
  
  Note: "this code tested for Detection against some new/old methods like C# code for Process Hollowing, DInvoke (syscall), Loading dll/functions from Memory [32BIT], Classic-RemoteThreadInjection, APC Queue Code Injection, Process-Ghosting, Process Hollowing & Process Doppelganging by [Minjector], ..."
  
  Note: in EventViewer you should change your log limits [maximum log size] for log name "ETWPM2" from 1mb to 10mb at least, otherwise event logs will be overwrite ;)
 
 usage:  
    
    step1: [win, Run As Admin] ETWProcessMon2.exe
    example 1: ETWProcessMon2.exe
    example 2: ETWProcessMon2.exe > Save_all_outputs.txt
    Note: in "example 2" you can have all outputs in text file [Imageload/TCPIP/NewThreads events + Injection Detection + Details etc] also at the same time VirMemAlloc events + Injections Detection events saved into log file ETWProcessMonlog.txt 
    Note: also in this ver2 NewProcess/Remote-Thread-Injection events + TCPIP Send Events will save in Windows Event Logs (log name => ETWPM2).
    
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/Pics/V2_0.png)
   
-----------------------------------------------------------   
### ETWProcessMon2.exe & Remote-Thread-Injection Detection by event log (ETWPM2 Events)

   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/Pics/V2_2.png)

    Note: about Debug info => TID 228 Injected to Notepad:4060 by this process "NativePayload_TId.exe:3972"
    Note: about Debug info => TID::TIDWin32StartAddress:ParentThreadID:ParentID/Injector

-----------------------------------------------------------   
### ETWProcessMon2.exe & Remote-Thread-Injection Detection by event log (ETWPM2 Events)

   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/Pics/V2_1.png)
-----------------------------------------------------------   
### ETWProcessMon2.exe & TCPIP Send events by event log (ETWPM2 Events)

   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/Pics/V2_3.png)   
-----------------------------------------------------------   
### ETWProcessMon2.exe & VirtualMemAlloc Events in All Processes with "ETWProcessMonlog.txt" (Text log file + VirtualMemAlloc Events)
Note: you can see in Callback API Function Techniques (CBT) we don't have Remote-Thread-Injection for execute payloads in target process but with VirtualMemAlloc Events made by ETW you can find Meterpreter Payload (Payload Detection) in Target Processes etc.
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/Pics/PH-VirtualMemAlloc-Events.jpeg)
   
   
<p><a href="https://hits.seeyoufarm.com"><img src="https://hits.seeyoufarm.com/api/count/incr/badge.svg?url=https://github.com/DamonMohammadbagher/ETWProcessMon2"/></a></p>


