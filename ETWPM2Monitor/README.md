Note about Compile Project ETWPM2Monitor:

### Error => [Couldn't process file resx due to its being in the Internet or Restricted zone or having the mark of the web on the file]

if you have this error for Build this project you need to do these steps :


    1.Open the file explorer. Navigate to project/solution directory  
    2.Search for Form1.resx.
    3.Right click the resx file, open the properties and check the option 'Unblock'
    4.Reload the project & build again.
    
### Error => [Cross-Thread Operation Not valid...]

if you have this error for Build+Run this project you need to do these steps :

    1.Open the Project & Build this project with (Solution Configurations: Debug)
    2.After build Succeeded, Directly Run ETWPM2Monitor.exe without using VS.NET Play button  ¯\_(ツ)_/¯ 
    Note: First you need to run ETWProcessMon2.exe THEN you should run this ETWPM2Monitor.exe 
