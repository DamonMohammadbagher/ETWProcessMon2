### Test4: ETWPM2Monitor2.1 vs SysPM2Monitor2.7 & PoshC2 Server.

#### Test4-1: ETWPM2Monitor2.1 against PoshC2.

in Pic1 you can see PoshC2 Session Detected by ETWPM2Monitor2.1 + ETW Events and in this case Injector was Posh_v4_dropper_migrate_x64.exe (which create new process [netsh.exe] and payload was injected into netsh.exe process)

   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/ETWPM2Monitor2.1_vs_SysPM2Monitor2.7/Pictures/Test5_1.png)
       Picture1:
       
in Pic2 you can see Target Process was Detected by ETWPM2Monitor2.1 via ETW events, you can see PoshC2 Agents very well detected by this tool also by Memory Scanner.

   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/ETWPM2Monitor2.1_vs_SysPM2Monitor2.7/Pictures/Test5_2.png)
       Picture2:       

in Pic3 you can see PoshC2 Agent was detected by ETWPM2Monitor2.1 via ETW events and you can see Network Connections with Delta time for Beacon with Sleep (5 sec) but in my tool you can see Minutes for Delta time i will add Seconds to ETWPM2Monitor2.1 source code soon to fix this.

   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/ETWPM2Monitor2.1_vs_SysPM2Monitor2.7/Pictures/Test5_4.png)
       Picture3:
       
in Pic4 you can see Memory Scanner result for Target Process too.

   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/ETWPM2Monitor2.1_vs_SysPM2Monitor2.7/Pictures/Test5_5.png)
       Picture4:  
       
#### Test4-2: SysPM2Monitor2.7 against PoshC2.       

in Pic5 you can see PoshC2 Injection Attack Detected by SysPM2Monitor2.7 via Sysmon Events very well

   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/ETWPM2Monitor2.1_vs_SysPM2Monitor2.7/Pictures/Test5_6.png)
       Picture5:  

in Pic6 you can see Sysmon has/had Problem in detection for Process Name "Netsh.exe" and this process was detected as "Unknown-Process"

   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/ETWPM2Monitor2.1_vs_SysPM2Monitor2.7/Pictures/Test5_7.png)
       Picture6:  
       
in Pic7 you can see PoshC2 Injector was Detected very well but still we have Target Process with Name "Unknown-Process"

   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/ETWPM2Monitor2.1_vs_SysPM2Monitor2.7/Pictures/Test5_8.png)
       Picture7:  
              
in Pic8 you can PoshC2 Agents Delay time (Mins) and in SysPM2Monitor2.7 we dont have Seconds Time like ETWPM2Monitor2.1 so i will add Seconds to SysPM2Monitor2.7 source code soon.

   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/ETWPM2Monitor2.1_vs_SysPM2Monitor2.7/Pictures/Test5_9.png)
       Picture8:      
       
in Pic9 you can PoshC2 Agents Delay time (Mins) & Seconds + TotalSeconds via ETW Events by ETWPM2Monitor2.1 , this simple code added to last source code ETWPM2Monitor2.1 [v2.1.32.174].

   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/ETWPM2Monitor2.1_vs_SysPM2Monitor2.7/Pictures/Test5_10.png)
       Picture9:  ProcrssListTabx1      
       
in Pic you can PoshC2 Agents Delay time (Mins) & Seconds + TotalSeconds via ETW Events by ETWPM2Monitor2.1 , this simple code added to last source code ETWPM2Monitor2.1 [v2.1.33.194].

   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/ETWPM2Monitor2.1_vs_SysPM2Monitor2.7/Pictures/ProcrssListTabx1.png)
       Picture10:               
