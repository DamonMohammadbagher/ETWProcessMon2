### Test3: ETWPM2Monitor2.1 vs SysPM2Monitor2.7 & Remote Thread Injection.

#### Test3-1: SysPM2Monitor2.7 against Remote Thread Injection.

in Pic1 you can see Remote Thread Injection detected by Sysmon Events [Event ID 8] & Result of Memory Scanners + Detection Logs saved to Windows Event log [SysPM2Monitor2_7]

   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/ETWPM2Monitor2.1_vs_SysPM2Monitor2.7/Pictures/4-2.png)
       Picture1:
       
in Pic2 you can see Shell detected by SysPM2Monitor2.7 via Sysmon Events [Event ID 1] & Detection events saved to Windows Event log [SysPM2Monitor2_7]

   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/ETWPM2Monitor2.1_vs_SysPM2Monitor2.7/Pictures/4-1.png)
       Picture2:
       
#### Test3-2: ETWPM2Monitor2.1 against Remote Thread Injection.

in Pic1 you can see Remote Thread Injection detected by ETW Events & Result of Memory Scanners saved to Windows Event log [ETWPM2Monitor2]
and you can see ETW detection for Attack Saved with [Event id 2] in windows event log also shell detection with [event id 4] saved to Windows Event log [ETWPM2Monitor2]

   ![](https://github.com/DamonMohammadbagher/ETWProcessMon2/blob/main/ETWPM2Monitor2.1_vs_SysPM2Monitor2.7/Pictures/4-3.png)
       Picture3:
