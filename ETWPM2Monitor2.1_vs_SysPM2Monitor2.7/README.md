# ETWPM2Monitor2.1 vs SysPM2Monitor2.7
### in this page i will share my tests on both source codes (ETWPM2Monitor2.1 & SysPM2Monitor2.7) against Some Attack Codes (Process/Thread/Code Injection Attacks etc)

ETW is very strong thing for Defenders/BlueTeamers also Sysmon but some security researcher ignored ETW becuse they think ETW is very Noisy ;) which i think that thing 
which you called noisy exactly are things you should focous on them and you will find a lot attack in those Events (you should change your mindset) , in my opinion only work with Sysmon is not good idea also working only with ETW is not good too so i think we should work with both at the same time for check events then you will have better result. (Sysmon & ETW both have Bugs & vulnerabilities so working with only one of them for all Defensive tools is not good idea, sometimes Sysmon events are useful for some attacks, sometimes ETW events are ...)   

i am working on these projects [ETWPM2Monitor2.1 , SysPM2Monitor2.7] and i will share some result of these codes against some Process Injection Attacks here with examples:  

### Test1: ETWPM2Monitor2.1 vs SysPM2Monitor2.7 & Dll Hollowing Attack.

#### Test1-1: ETWPM2Monitor2.1 against Dll Hollowing Attack.
in Pic1 you can see steps for use ETWProcessMon2.exe (v2.1) + ETWPM2Monitor2 (v2.1), first you need to collect ETW Events then you can Detect some Process Injection attacks by ETWPM2Monitor2...

   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/ETWPM2Monitor2.1_vs_SysPM2Monitor2.7/Pictures/1.png)
   
Step1: ETW Event will collect to Windows Event Log name "ETWPM2" by ETWProcessMon2 (v2.1) and these ETW events are :
         
         [Information] Event ID 1  => NewProcess event 
         [Warning]     Event ID 2  => Remote-Thread-Injection Detection event 
         [Information] Event ID 3  => TCPIP Send event & TCPIP Connect event (added in v2.1)
Step2: all ETW events will Monitor by ETWPM2Monitor2 (v2.1) real-time for Detection also this tool will use Memory scanner for Scanning Target Process which detected by ETW Events etc.

Step3; after run code for [Dll-hollowing attack] you can see payload injected to Amsi.dll for Target process in this case mspaint and shell executed very well also this injection detected by ETW & ETWPM2Monitor2 (v2.1) and Not detected by Memory Scanner Hollows_Hunter but this code Detected in memory by Pe-sieve which in the next pic2 you can see which was detected by Memory scaner Pe-sieve.



