# ETWProcessMon2
ETWProcessMon2 (ver2) is for Monitoring Process/Thread/Memory/Imageloads/TCPIP via ETW + Detection for Remote-Thread-Injection & Payload Detection by VirtualMemAlloc Events (in-memory) etc.

### ETWProcessMon2.exe
"ETWProcessMon" is simple tool for Monitor Processes/Threads/Memory/Imageloads/TCPIP Events via ETW, with this code you can Monitor New Processes also you can See New Threads (Thread Started event) + Technique Detection for Remote-Thread-Injection (Which Means Your New Thread Created into Target Process by Another Process), also with this code you can Monitor VirtualMemAllocation Events in Memory for All Processes (which sometimes is very useful for Payload Detection in-memory) also you can see ImageLoads for each Process & you can see TCPIP Send Events for each Process too. 

Note: VirtualMemAlloc for (Payload-Detection) + ImageLoad & Remote-Thread-Injection Detection for (Technique-Detection) are useful for Blue Teams/Defenders.

Note: in (Version 2) NewProcess events + Remote-Thread-Injection Detecetion events + TCPIP send events all will save in Windows Event Log which with EventViewer you can watch them also VirtualMemAlloc events + Remote-thread-injection Detection Events will save in text "ETWProcessMonlog.txt" log file too (at the same time). so in this version2 we have two type of Events log files => 1."windows event logs [ETWPM2]" , 2."ETWProcessMonlog.txt" 

ETW Events in event log [ETWPM2]:

    [Information] Event ID 1  => NewProcess event 
    [Warning]     Event ID 2  => Remote-Thread-Injection Detection event 
    [Information] Event ID 3  => TCPIP Send event


### Build Project Note: you should install this nuget in your project for ETWProcessMon2
            
    PM> Install-Package Microsoft.Diagnostics.Tracing.TraceEvent -Version 2.0.69            
    or
    PM> Install-Package Microsoft.Diagnostics.Tracing.TraceEvent -Version 2.0.70

### Videos: 
Note: i will make video for "ETWProcessMon2" soon.

this Video is for (Version 1), ETWProcessMon.exe v1 download & (step by step with details) => https://github.com/DamonMohammadbagher/ETWNetMonv3

Video [3], [Video-3 of Chapter15-Part2]: (video is about C# + ETW vs Process Hollowing, DInvoke (syscall),Loading dll/functions from Memory,Classic-RemoteThreadInjection)  

    C# + ETW vs Some Thread/Process/Code Injection Techniques (CH15-Part2):
    link1 => https://www.youtube.com/watch?v=d1a8WqOvE84
    link2 => https://share.vidyard.com/watch/4kB2Xy1bLfhRxaTD6pwaLD

-----------------------------------------------------------    
### ETWPM2Monitor.exe
"ETWPM2Monitor" v1.2 is simple C# code [test version] for Realtime Event Log Monitor, but this code only will work with logname "ETWPM2" which made by "ETWProcessMon2.exe".
with this Application you can watch [Realtime ETW Events] with "EventIDs 1,2 & 3" which made by "ETWProcessMon2"
    
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
    step2: [win] ETWPM2Monitor.exe    

   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/Pics/ETWPM2Monitor0.png)
   
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/Pics/ETWPM2Monitor1.png)



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
    Note: about Debug info => TID::TIDWin32StartAddress:ParentThreadID:ParentID

-----------------------------------------------------------   
### ETWProcessMon2.exe & Remote-Thread-Injection Detection by event log (ETWPM2 Events)

   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/Pics/V2_1.png)
-----------------------------------------------------------   
### ETWProcessMon2.exe & TCPIP Send events by event log (ETWPM2 Events)

   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/Pics/V2_3.png)
   
   
<p><a href="https://hits.seeyoufarm.com"><img src="https://hits.seeyoufarm.com/api/count/incr/badge.svg?url=https://github.com/DamonMohammadbagher/ETWProcessMon2"/></a></p>


