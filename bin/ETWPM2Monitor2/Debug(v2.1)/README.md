md5 info, "exe files are not safe here in github so make your own exe files with C# source by yourself [i recommend]":
     
    951aef1888-093fca9e67-d881615ed10b => ETWProcessMon2.exe (v2.1) 16,May,2022        
    bc42bb0ace-5de9f8ed08-e26c46503614 => ETWPM2Monitor2.exe (v2.1) [v2.1.47.480] 31,Oct,2022 
    a89536efe5-2adbfbaa1c-5a46aeb032e0 => CobaltStrikeScan.exe (v1.0) 26,May,2022   

Usage Steps

    Step1 (Run as Admin): ETWProcessMon2.exe > output.txt

    Step2 (Run as Admin): ETWPM2Monitor2.exe

----------------------------------

Note: New Memory Scanner "CobaltStrikeScan" which is for Scan Target Process to Find Cobaltsrike Beacons Added to the source code (26 may 2022). this code is optional you can use that if you want, you should use those files in Folder "CobaltStrikeScan" and copy this folder to "Debug" folder.

`Important point: CobaltStrikeScan Source code "changed" by me ;) for Add new Switch "-t" and you should use CobaltStrikeScan.exe file which made by me in folder "CobaltStrikeScan" , if you want to see the original source code link is below (nice code made by Apr4h).`

    link2: https://github.com/Apr4h/CobaltStrikeScan
 
New Switch syntax (scanning target process to find CobaltStrike Beacons): 
                
    CobaltStrikeScan.exe -t TargetPID 
                    
    example: CobaltStrikeScan.exe -t 1234            
   
 md5 info for Exe file which created by me (new switch -t added to this exe):
            
    a89536efe5-2adbfbaa1c-5a46aeb032e0 => CobaltStrikeScan.exe (v1.0) 26,May,2022   
