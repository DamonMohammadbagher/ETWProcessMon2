md5 info, "exe files are not safe here in github so make your own exe files with C# source by yourself [i recommend]":
     
    951aef1888-093fca9e67-d881615ed10b => ETWProcessMon2.exe (v2.1) 16,May,2022    
    bc42bb0ace-5de9f8ed08-e26c46503614 => ETWPM2Monitor2.exe (v2.1) [v2.1.47.480] 31,Oct,2022 
    3066c279ad-acf3f2971e-2bdf5c163fdf => ETWPM2Monitor2.exe (v2.1) [v2.1.51.590] 17,Sep,2023
    34064d7e1c-4ae5a43e39-9c806767d425 => ETWPM2Monitor2.exe (v2.1) [v2.1.52.628] 21,Nov,2023
    f7749e4e0a-b16fccf5bd-d2a66bf81167 => ETWPM2Monitor2.exe (v2.1) [v2.1.52.630] 19,Mar,2024
    a89536efe5-2adbfbaa1c-5a46aeb032e0 => CobaltStrikeScan.exe (v1.0) 26,May,2022
    86f92a09f5-9be4a4148e-a5f0ccef2355 => Hunt-Sleeping-Beacons.exe 17,Sep,2023
    bc8bfbe7ce-08b43d1a43-a5e6d73cf389 => pe-sieve.exe [v0.3.5] (compatible ver with ETWPM2Monitor2.exe)

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


#### Note: pe-sieve64.exe [v0.3.5] is compatible with ETWPM2Monitor2.exe and SysPM2Monitor2.7.exe

#### Note: New Ver of pe-sieve64.exe [v0.3.9] is not compatible to use for these projects like ETWPM2Monitor2.exe and SysPM2Monitor2.7.exe
