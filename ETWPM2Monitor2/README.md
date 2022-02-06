# ETWPM2Monitor2 `(v2.1)`
This tool [ETWPM2Monitor version2] is for Monitor ETW Event-Logs [log name: ETWPM2] which made by ETWProcessMon2.exe & the goal is Monitoring RemoteThreadInjection Techniques (Technique Detection & Payload Detection via ETW).

`Note: ETWPM2Monitor2 v2.1 is new version of code & you can use this code with ETWProcessMon2.1 (v2.1), this version ETWPM2Monitor2 v2.1 will work with ETWProcessMon2.1 very fast for (Remote-Thread-Injection) Technique/Payload Detection via ETW Events)`

Note: if you want new v2.1 you should Re-compile this project with new Source code [compile with .NETFramework v4.6 or v4.7.2] ;), woow i had a lot bugs in code v2.0 , now fixed in v2.1, compiler says (not me), `code performance now is good and "a lot bugs" [like tcp events flooding] fixed with last source update(2) v2.1.10.87 [Feb 5, 2022]...` 

Note: I will Publish Article & Help Documents for this tool soon... 

Related Article: https://www.linkedin.com/pulse/etwpm2monitor2-remote-thread-injection-detection-etw-mohammadbagher

Related Article: https://damonmohammadbagher.github.io/Posts/12aug2021x.html

Video1: https://www.linkedin.com/posts/damonmohammadbagher_etwprocessmon2-etwpm2monitor-v2-almost-activity-6828777557819752448-6dbv/ 

Note: the goal is talking/thinking about how can use ETW as Defender/Blue teamer for Defensive tools like EDR/AVs or your own Tools etc. so does not matter what i did in my C# codes, these codes just is for test to show you how can use ETW as Blue teamer but these things/codes made by my opinion & my focus was on Remote Thread Injection attack also my focus was on those things which i think blue teamers should know them better than before (especially Alarms TAB Events in this tool)  and these code was for Chapter15 of ebook [bypassing AVs by C# Programming], (i will publish ch15 soon ;D) which is about how can use ETW for Defenders/Blue teamers & ... 

Note: in this code we have "Pe-sieve64.exe" & "Hollowshunter.exe" so to use you need to download these exe files & paste them in same folder with ETWPM2Monitor2.exe & i tested ETWPM2Monitor2 with Pe-sieve64.exe (ver 0.2.9.6) & Hollowshunter.exe (ver 0.2.9.6)

    link1: https://github.com/hasherezade/pe-sieve
    link2: https://github.com/hasherezade/hollows_hunter

md5 info, "exe files are not safe here in github so make your own exe files with C# source by yourself [i recommend]":

    b913a0d66d-750478c5a8-1d557aad377d => ETWProcessMon2.exe
    40d799fd84-a7dbb7a981-d3eebed3c7e5 => ETWPM2Monitor2.exe

Usage Steps

    Step1: ETWProcessMon2.exe (Run as Admin)

    Step2: ETWPM2Monitor2.exe (Run as Admin)

-------------------------
### ETWPM2Monitor2 v2.1 (New ver)
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/ETWPM2Monitor2/Pics/v2.1.png)
   
#### Note: for New Exe file, you can use/add this project [ETWPM2Monitor2 v2.1] in your vs.net 2017/2019 very simple. (compiler says => bugs fixed ;D)

### ETWPM2Monitor2 v2.1 (Detecting Cmd.exe for shell via [EventID 1] & Meterpreter Traffic Packets via [EventID 3])
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/ETWPM2Monitor2/Pics/tcp.png)
   
#### note: this traffic detection via EventID 3 added to source code ;)

### ETWPM2Monitor2 v2.1 (Memory Scanners Logs added to code, now you can see what happened in background when something Detected or not by [Memory Scanners & events])
   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/ETWPM2Monitor2/Pics/v21_11.35_scannerlogs.png)

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
