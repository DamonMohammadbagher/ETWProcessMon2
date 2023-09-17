using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace ETWPM2Monitor2
{
    public class ExtendedMemoryScanners_Info
    {
        public static string Task_RESULT_for_CobaltstrikeScanner = "";
        public static string Task_RESULT_for_Hunt_Sleep_Beacons = "";
        static bool _isFileExist = false;
        public delegate void ___RunAsyn_Hunt_Sleeping_Beacons(object obj);
        public static string result2 = "";
        public static string strOutput = "";

        public static string lastMemoryScannerIIResult = "";
        public static List<ListViewItem> _DetectedItemsByMemoryScannerII_Alarms = new List<ListViewItem>();
        public static ListViewItem xiList3 = new ListViewItem();
        public static string MemoryScanner_Hunt_Sleeping_Beacons_Details = "";
        public static string DetectedPID_via__Hunt_Sleeping_Beacons = "";
        public static string DetectedProcess_via__Hunt_Sleeping_Beacons = "";
        public static string[] _Results_for__Hunt_Sleeping_Beacons = new string[1];
        public static string Result__in_background__Hunt_Sleeping_Beacons = "";
        public static int SearchProcessinNetHistoryListview7 = -1;
        public static bool _IsMemoryScanner_PeSieve_isBusy = false;
        public static string Xresult = "";

        public static async void RunAsyn_CobaltstrikeScan(object pid)
        {
            Task_RESULT_for_CobaltstrikeScanner = await CobaltstrikeScan(Convert.ToString(pid));         
        }
        public static string CobaltstrikeScan(Int32 DetectedPID_via__Hunt_Sleeping_Beacons)
        {
            Process outputs = new Process();
            Xresult = "";
            try
            {
                if (File.Exists(@".\CobaltStrikeScan\CobaltStrikeScan.exe"))
                {
                    try
                    {
                        if (!Process.GetProcessById(DetectedPID_via__Hunt_Sleeping_Beacons).HasExited)
                        {
                            try
                            {
                                outputs.StartInfo.FileName = @".\CobaltStrikeScan\CobaltStrikeScan.exe";
                                /// -t added to the source code "CobaltStrikeScan" by me ;)
                                /// scanning target process -t pid => syntax : CobaltStrikeScan.exe -t 1234
                                outputs.StartInfo.Arguments = "-t " + DetectedPID_via__Hunt_Sleeping_Beacons.ToString();
                                outputs.StartInfo.CreateNoWindow = true;
                                outputs.StartInfo.UseShellExecute = false;
                                outputs.StartInfo.RedirectStandardOutput = true;
                                outputs.StartInfo.RedirectStandardInput = true;
                                outputs.StartInfo.RedirectStandardError = true;
                                outputs.Start();
                                string strOutput = outputs.StandardOutput.ReadToEnd();
                                Xresult = strOutput;
                            }
                            catch (Exception)
                            {

                            }

                        }
                        else
                        {
                            Xresult = "Process Not Found!";
                        }

                    }
                    catch (Exception ee)
                    {

                    }
                }
                else
                {
                    Xresult = @"Memory Scanner => .\CobaltStrikeScan\CobaltStrikeScan.exe Not Found!";
                }
            }
            catch (Exception)
            {
            }

            return Xresult;
        }

        public static async Task<string> CobaltstrikeScan(string pid)
        {
            string result2 = "";
            await Task.Run(() =>
            {
                Task_RESULT_for_CobaltstrikeScanner = "";
                Process outputs = new Process();

                try
                {
                    if (File.Exists(@".\CobaltStrikeScan\CobaltStrikeScan.exe"))
                    {
                        try
                        {
                            if (!Process.GetProcessById(Convert.ToInt32(pid)).HasExited)
                            {
                                try
                                {
                                    outputs.StartInfo.FileName = @".\CobaltStrikeScan\CobaltStrikeScan.exe";
                                    /// -t added to the source code "CobaltStrikeScan" by me ;)
                                    /// scanning target process -t pid => syntax : CobaltStrikeScan.exe -t 1234
                                    outputs.StartInfo.Arguments = "-t " + pid.ToString();
                                    outputs.StartInfo.CreateNoWindow = true;
                                    outputs.StartInfo.UseShellExecute = false;
                                    outputs.StartInfo.RedirectStandardOutput = true;
                                    outputs.StartInfo.RedirectStandardInput = true;
                                    outputs.StartInfo.RedirectStandardError = true;
                                    outputs.Start();
                                    string strOutput = outputs.StandardOutput.ReadToEnd();
                                    result2 = strOutput;
                                }
                                catch (Exception)
                                {

                                }

                            }
                            else
                            {
                                result2 = "Process Not Found!";
                            }

                        }
                        catch (Exception ee)
                        {

                        }
                    }
                    else
                    {
                        result2 = @"Memory Scanner => .\CobaltStrikeScan\CobaltStrikeScan.exe Not Found!";
                    }
                }
                catch (Exception)
                {
                }

                return result2;
            });

            return result2;

        }

        /// new memory scanner added to the source code
        /// this Memory Scanner [Hunt-Sleeping-Beacons] will have something like this:

        //// [!] Suspicious Process: PhantomDllHollower.exe

        ////        [*] Thread(9192) has State: DelayExecution and abnormal calltrace:

        ////                NtDelayExecution -> C:\WINDOWS\SYSTEM32\ntdll.dll
        ////                SleepEx -> C:\WINDOWS\System32\KERNELBASE.dll
        ////                0x00007FF8C13A103F -> Unknown or modified module
        ////                0x000001E3C3F48FD0 -> Unknown or modified module
        ////                0x00007FF700000000 -> Unknown or modified module
        ////                0x00007FF7C00000BB -> Unknown or modified module

        ////        [*] Suspicious Sleep() found
        ////        [*] Sleep Time: 600s
        ////  

        //// Sample Beacon using module stomping:
        //// 
        ////[!] Suspicious Process: beacon.exe(5296)

        ////       [*] Thread(2968) has State: DelayExecution and uses potentially stomped module
        ////       [*] Potentially stomped module: C:\Windows\SYSTEM32\xpsservices.dll

        ////                NtDelayExecution -> C:\Windows\SYSTEM32\ntdll.dll
        ////                SleepEx -> C:\Windows\System32\KERNELBASE.dll
        ////                DllGetClassObject -> C:\Windows\SYSTEM32\xpsservices.dll

        ////        [*] Suspicious Sleep() found
        ////        [*] Sleep Time: 5s

        //// Sample AceLdr:  
        ////
        ////* Now enumerating all thread in state wait:UserRequest
        ////* Found 783 threads, now checking for delays caused by APC
        ////! Possible Foliage identified in process: 16436
        ////        * Thread 15768 state Wait:UserRequest seems to be triggered by KiUserApcDispatcher
        ////* End
        ////

        //// Sample Ekko [Sleep-mask]:

        ////! Possible Ekko identified in process: 3996
        ////        * Thread 14756 state Wait:UserRequest seems to be triggered by Callback of waitable Timer
        public static async void RunAsyn_Hunt_Sleeping_Beacons(object _obj)
        {
            Task_RESULT_for_Hunt_Sleep_Beacons = await Hunt_Sleeping_Beacons(_obj);
        }
        public static async Task<string> Hunt_Sleeping_Beacons(object obj)
        {
            Task_RESULT_for_Hunt_Sleep_Beacons = "";
            
            try
            {
                
                await Task.Run(() =>
                {
                    Process outputs = new Process();

                    try
                    {
                      

                        outputs.StartInfo.FileName = @".\HuntSleepingBeacons\Hunt-Sleeping-Beacons.exe";                                            
                        outputs.StartInfo.CreateNoWindow = true;
                        outputs.StartInfo.UseShellExecute = false;
                        outputs.StartInfo.RedirectStandardOutput = true;
                        outputs.StartInfo.RedirectStandardInput = true;
                        outputs.StartInfo.RedirectStandardError = true;
                        outputs.Start();
                        strOutput = outputs.StandardOutput.ReadToEnd();
                        result2 = strOutput;
                        Task.Delay(20);
                        outputs.Dispose();

                        Sorting_Result_of_Hunt_Sleeping_Beacons_MemScanner(result2);
                        
                        var v = _DetectedItemsByMemoryScannerII_Alarms;

                    }
                    catch (Exception)
                    {
                        outputs.Dispose();
                    }
                });

                

            }
            catch (Exception ee)
            {
                return result2;
            }
        
            return result2;
        }

        public static async void _Invoke_Every_1_min_RunAsyn_Hunt_Sleeping_Beacons()
        {
            

            if (File.Exists(@".\HuntSleepingBeacons\Hunt-Sleeping-Beacons.exe")) _isFileExist = true;
            else _isFileExist = false;

            if (_isFileExist)
            {
                await Task.Run(() =>
                {
                    var _Delay = Task.Delay(TimeSpan.FromSeconds(60));
                    while (true)
                    {

                        /// timer to wait
                        do
                        {
                            Task.Delay(25);
                            if (_Delay.IsCompleted)
                            {                               
                                break;
                            }

                            System.Threading.Thread.Sleep(100);

                        } while (!_Delay.IsCompleted);

                        ___RunAsyn_Hunt_Sleeping_Beacons _RunInBackground = new ___RunAsyn_Hunt_Sleeping_Beacons(RunAsyn_Hunt_Sleeping_Beacons);
                        _RunInBackground.BeginInvoke(new object[] { 1 }, null, null);

                        _Delay = Task.Delay(TimeSpan.FromSeconds(60));
                    }

                });
            }
            else
            {


            }
        }

        public static void Sorting_Result_of_Hunt_Sleeping_Beacons_MemScanner(string Task_RESULT_for_Hunt_Sleep_Beacons)
        {
            /// checking Result for Memory Scan by Hunt-Sleeping-Beacons.exe
            /// 
            Result__in_background__Hunt_Sleeping_Beacons = Task_RESULT_for_Hunt_Sleep_Beacons;

            if (lastMemoryScannerIIResult.ToUpper() != Result__in_background__Hunt_Sleeping_Beacons.ToUpper())
            {                

                try
                {

                    _Results_for__Hunt_Sleeping_Beacons = Result__in_background__Hunt_Sleeping_Beacons.Split('\n');

                    for (int i = 0; i < _Results_for__Hunt_Sleeping_Beacons.Length; i++)
                    {

                        if (_Results_for__Hunt_Sleeping_Beacons[i].StartsWith("! Suspicious Process:"))
                        {
                            try
                            {
                                xiList3 = new ListViewItem();
                                xiList3.SubItems.Add(DateTime.Now.ToString());

                                ////! Suspicious Process: dwm.exe(1128)
                                DetectedPID_via__Hunt_Sleeping_Beacons = _Results_for__Hunt_Sleeping_Beacons[i].Split(':')[1].Substring(1).Split('(')[1].Split(')')[0];
                                try
                                {
                                    if (-1 != Process.GetProcesses().ToList().FindIndex(id => id.Id == Convert.ToInt32(DetectedPID_via__Hunt_Sleeping_Beacons)))
                                    {
                                        DetectedProcess_via__Hunt_Sleeping_Beacons = Process.GetProcessById(Convert.ToInt32(DetectedPID_via__Hunt_Sleeping_Beacons)).MainModule.FileName;
                                        xiList3.Name = Process.GetProcessById(Convert.ToInt32(DetectedPID_via__Hunt_Sleeping_Beacons)).ProcessName;
                                    }
                                    else { DetectedProcess_via__Hunt_Sleeping_Beacons = "Process Exited"; }

                                    xiList3.SubItems.Add(DetectedProcess_via__Hunt_Sleeping_Beacons);
                                    xiList3.SubItems.Add(DetectedPID_via__Hunt_Sleeping_Beacons);

                                }
                                catch (Exception)
                                {
                                    if (-1 != Process.GetProcesses().ToList().FindIndex(id => id.Id == Convert.ToInt32(DetectedPID_via__Hunt_Sleeping_Beacons)))
                                    {
                                        DetectedProcess_via__Hunt_Sleeping_Beacons = Process.GetProcessById(Convert.ToInt32(DetectedPID_via__Hunt_Sleeping_Beacons)).ProcessName;
                                        xiList3.Name = Process.GetProcessById(Convert.ToInt32(DetectedPID_via__Hunt_Sleeping_Beacons)).ProcessName;
                                    }
                                    else { DetectedProcess_via__Hunt_Sleeping_Beacons = "Process Exited"; }

                                    xiList3.SubItems.Add(DetectedProcess_via__Hunt_Sleeping_Beacons);
                                    xiList3.SubItems.Add(DetectedPID_via__Hunt_Sleeping_Beacons);

                                }



                                for (int ii = 1 + i; ii < _Results_for__Hunt_Sleeping_Beacons.Length; ii++)
                                {


                                    if (_Results_for__Hunt_Sleeping_Beacons[ii].StartsWith("\t* Thread ")
                                        || _Results_for__Hunt_Sleeping_Beacons[ii].StartsWith("\t\t0x")
                                        || _Results_for__Hunt_Sleeping_Beacons[ii].StartsWith("\t* Potentially")
                                        || _Results_for__Hunt_Sleeping_Beacons[ii].Contains(" -> ")
                                        || _Results_for__Hunt_Sleeping_Beacons[ii].Contains("\t* Suspicious Sleep()")
                                        || _Results_for__Hunt_Sleeping_Beacons[ii].Contains("\t* Sleep Time:"))
                                    {
                                        MemoryScanner_Hunt_Sleeping_Beacons_Details += _Results_for__Hunt_Sleeping_Beacons[ii] + "\n";
                                    }

                                    if (_Results_for__Hunt_Sleeping_Beacons[ii].StartsWith("- Failed")
                                        || _Results_for__Hunt_Sleeping_Beacons[ii].StartsWith("! Suspicious Process:")
                                        || _Results_for__Hunt_Sleeping_Beacons[ii].StartsWith("* Done"))
                                        break;

                                }

                                /// this is/via etw events list of network connections
                                /// Int32 IndexofTCPRecord = TCPConnectionTable_To_Show.ToList<_TCPConnection_Struc>().FindIndex(index => index._SUID == __obj.SubItems[3].Text + sip + dip + dip_port);

                                /// this is/via native api list of network connections
                                ///  int index = _Listview7_Items_NetworkConnection_history.ToList().FindIndex(x =>
                                ///  x.SubItems[2].Text + x.SubItems[3].Text
                                ///  + x.SubItems[7].Text + x.SubItems[9].Text ==
                                ///  item.SubItems[2].Text + item.SubItems[3].Text
                                ///  + item.SubItems[7].Text + item.SubItems[9].Text);

                                /// search is that process has/had Network Connection via Network Connection history by Native API [not etw]        

                                SearchProcessinNetHistoryListview7 = Form1._Listview7_Items_NetworkConnection_history.ToList().FindIndex(x =>
                                   x.SubItems[2].Text.ToLower() == xiList3.Name.ToLower()
                                   && Convert.ToInt32(x.SubItems[3].Text) == Convert.ToInt32(xiList3.SubItems[3].Text));

                                if (SearchProcessinNetHistoryListview7 != -1)
                                {
                                    /* xiList3.ForeColor = Color.DarkRed; */
                                    xiList3.ImageIndex = 2;
                                    xiList3.SubItems.Add(Form1._Listview7_Items_NetworkConnection_history[SearchProcessinNetHistoryListview7].SubItems[7].Text.ToString());
                                    xiList3.SubItems.Add("2/2");

                                }
                                else
                                {
                                    xiList3.ImageIndex = 1;
                                    xiList3.SubItems.Add("--");
                                    xiList3.SubItems.Add("1/2");
                                }

                                xiList3.SubItems.Add("Memory Scanner Hunt-Sleeping-Beacons , Result: \n" + "\n" + MemoryScanner_Hunt_Sleeping_Beacons_Details);

                                // System.Runtime.CompilerServices.TaskAwaiter<string> _Task =  CobaltstrikeScan(DetectedPID_via__Hunt_Sleeping_Beacons).GetAwaiter();
                                // do { Thread.Sleep(1000); } while (_Task.IsCompleted);
                                //xiList3.SubItems.Add(_Task.GetResult());

                                var resultx = CobaltstrikeScan(Convert.ToInt32(DetectedPID_via__Hunt_Sleeping_Beacons));
                                xiList3.SubItems.Add(resultx.ToString());
                                
                                Thread.Sleep(100);
                                xiList3.SubItems.Add(DetectedProcess_via__Hunt_Sleeping_Beacons
                                    + DetectedPID_via__Hunt_Sleeping_Beacons
                                    + xiList3.SubItems[3].Text
                                    + xiList3.SubItems[4].Text);

                                MemoryScanner_Hunt_Sleeping_Beacons_Details = "";

                                if (-1 == _DetectedItemsByMemoryScannerII_Alarms.FindIndex(x =>
                                     x.SubItems[2].Text == xiList3.SubItems[2].Text
                                     && x.SubItems[3].Text == xiList3.SubItems[3].Text
                                     && x.SubItems[4].Text == xiList3.SubItems[4].Text))
                                {
                                    _DetectedItemsByMemoryScannerII_Alarms.Add(xiList3);
                                     
                                }
                            }
                            catch (Exception)
                            {


                            }



                        }

                        ////! Possible Ekko identified in process: 11572
                        ////     * Thread 7308 state Wait:UserRequest seems to be triggered by Callback of waitable Timer
                        ////! Possible Foliage identified in process: 11572
                        ////   * Thread 7308 state Wait:UserRequest seems to be triggered by KiUserApcDispatcher
                        ////* End

                        if (_Results_for__Hunt_Sleeping_Beacons[i].StartsWith("! Possible Ekko") || _Results_for__Hunt_Sleeping_Beacons[i].StartsWith("! Possible Foliage"))
                        {
                            xiList3 = new ListViewItem();
                            xiList3.SubItems.Add(DateTime.Now.ToString());

                            ////! Possible Ekko identified in process: 11572
                            ////! Possible Foliage identified in process: 11572
                            try
                            {


                                try
                                {
                                    DetectedPID_via__Hunt_Sleeping_Beacons = _Results_for__Hunt_Sleeping_Beacons[i].Split(':')[1].Substring(1);

                                    if (-1 != Process.GetProcesses().ToList().FindIndex(id => id.Id == Convert.ToInt32(DetectedPID_via__Hunt_Sleeping_Beacons)))
                                    {
                                        DetectedProcess_via__Hunt_Sleeping_Beacons = Process.GetProcessById(Convert.ToInt32(DetectedPID_via__Hunt_Sleeping_Beacons)).MainModule.FileName;
                                        xiList3.Name = Process.GetProcessById(Convert.ToInt32(DetectedPID_via__Hunt_Sleeping_Beacons)).ProcessName;
                                    }
                                    else { DetectedProcess_via__Hunt_Sleeping_Beacons = "Process Exited"; }

                                    xiList3.SubItems.Add(DetectedProcess_via__Hunt_Sleeping_Beacons);
                                    xiList3.SubItems.Add(DetectedPID_via__Hunt_Sleeping_Beacons);
                                   
                                }
                                catch (Exception)
                                {
                                    DetectedPID_via__Hunt_Sleeping_Beacons = _Results_for__Hunt_Sleeping_Beacons[i].Split(':')[1].Substring(1);

                                    if (-1 != Process.GetProcesses().ToList().FindIndex(id => id.Id == Convert.ToInt32(DetectedPID_via__Hunt_Sleeping_Beacons)))
                                    {
                                        DetectedProcess_via__Hunt_Sleeping_Beacons = Process.GetProcessById(Convert.ToInt32(DetectedPID_via__Hunt_Sleeping_Beacons)).ProcessName;
                                        xiList3.Name = Process.GetProcessById(Convert.ToInt32(DetectedPID_via__Hunt_Sleeping_Beacons)).ProcessName;
                                    }
                                    else { DetectedProcess_via__Hunt_Sleeping_Beacons = "Process Exited"; }

                                    xiList3.SubItems.Add(DetectedProcess_via__Hunt_Sleeping_Beacons);
                                    xiList3.SubItems.Add(DetectedPID_via__Hunt_Sleeping_Beacons);
                                  

                                }


                                for (int ii = 1 + i; ii < _Results_for__Hunt_Sleeping_Beacons.Length; ii++)
                                {


                                    if (_Results_for__Hunt_Sleeping_Beacons[ii].StartsWith("\t* Thread "))
                                    {
                                        MemoryScanner_Hunt_Sleeping_Beacons_Details += _Results_for__Hunt_Sleeping_Beacons[ii] + "\n";
                                    }

                                    if (_Results_for__Hunt_Sleeping_Beacons[ii].StartsWith("- Failed")
                                        || _Results_for__Hunt_Sleeping_Beacons[ii].StartsWith("! Suspicious Process:")
                                        || _Results_for__Hunt_Sleeping_Beacons[ii].StartsWith("* Done"))
                                        break;

                                }

                                /// this is/via etw events list of network connections
                                /// Int32 IndexofTCPRecord = TCPConnectionTable_To_Show.ToList<_TCPConnection_Struc>().FindIndex(index => index._SUID == __obj.SubItems[3].Text + sip + dip + dip_port);

                                /// this is/via native api list of network connections
                                ///  int index = _Listview7_Items_NetworkConnection_history.ToList().FindIndex(x =>
                                ///  x.SubItems[2].Text + x.SubItems[3].Text
                                ///  + x.SubItems[7].Text + x.SubItems[9].Text ==
                                ///  item.SubItems[2].Text + item.SubItems[3].Text
                                ///  + item.SubItems[7].Text + item.SubItems[9].Text);

                                /// search is that process has/had Network Connection via Network Connection history by Native API [not etw]         

                                SearchProcessinNetHistoryListview7 = Form1._Listview7_Items_NetworkConnection_history.ToList().FindIndex(x =>
                                 x.SubItems[2].Text.ToLower() == xiList3.Name.ToLower()
                                 && Convert.ToInt32(x.SubItems[3].Text) == Convert.ToInt32(xiList3.SubItems[3].Text));

                                if (SearchProcessinNetHistoryListview7 != -1)
                                {
                                    /* xiList3.ForeColor = Color.DarkRed; */
                                    xiList3.ImageIndex = 2;
                                    xiList3.SubItems.Add(Form1._Listview7_Items_NetworkConnection_history[SearchProcessinNetHistoryListview7].SubItems[7].Text.ToString());
                                    xiList3.SubItems.Add("2/2");
                                }
                                else
                                {
                                    xiList3.ImageIndex = 1;
                                    xiList3.SubItems.Add("--");
                                    xiList3.SubItems.Add("1/2");
                                    //xiList3.ForeColor = Color.Black;
                                }

                                xiList3.SubItems.Add("Memory Scanner Hunt-Sleeping-Beacons , Result: \n" +
                                    "\nPossible Ekko/Nighthawk identified in process: " + DetectedPID_via__Hunt_Sleeping_Beacons
                                    + "\n" + MemoryScanner_Hunt_Sleeping_Beacons_Details);

                                //System.Runtime.CompilerServices.TaskAwaiter<string> _Task = CobaltstrikeScan(DetectedPID_via__Hunt_Sleeping_Beacons).GetAwaiter();
                                //do { Thread.Sleep(1000); } while (_Task.IsCompleted);
                                //xiList3.SubItems.Add(_Task.GetResult());
                                //xiList3.SubItems.Add("");

                                var resultx = CobaltstrikeScan(Convert.ToInt32(DetectedPID_via__Hunt_Sleeping_Beacons));
                                xiList3.SubItems.Add(resultx.ToString());

                                Thread.Sleep(100);
                                xiList3.SubItems.Add(DetectedProcess_via__Hunt_Sleeping_Beacons
                                  + DetectedPID_via__Hunt_Sleeping_Beacons
                                  + xiList3.SubItems[3].Text
                                  + xiList3.SubItems[4].Text);

                                MemoryScanner_Hunt_Sleeping_Beacons_Details = "";

                                if (-1 == _DetectedItemsByMemoryScannerII_Alarms.FindIndex(x =>
                                     x.SubItems[2].Text == xiList3.SubItems[2].Text
                                     && x.SubItems[3].Text == xiList3.SubItems[3].Text
                                     && x.SubItems[4].Text == xiList3.SubItems[4].Text))
                                {
                                    _DetectedItemsByMemoryScannerII_Alarms.Add(xiList3);
  
                                }
                            }
                            catch (Exception)
                            {


                            }

                            

                        }

                    }
                }
                catch (Exception)
                {


                }

            }

            lastMemoryScannerIIResult = Result__in_background__Hunt_Sleeping_Beacons;
            //var v = _DetectedItemsByMemoryScannerII_Alarms;
        }
    }
}
