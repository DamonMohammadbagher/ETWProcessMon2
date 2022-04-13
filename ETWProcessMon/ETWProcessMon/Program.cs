using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Diagnostics.Tracing.Parsers;
using System.IO;

namespace ETWProcessMon
{
    public  class _ProcessInfo
    {
        public DateTime PTime { get; set; }
        public String ProcessName { get; set; }
        public String PID { get; set; } 
        public String PIDPath { get; set; }
        public String MemAPIName { get; set; }
        public String TCPIPCon { get; set; }
        public String MemAllocInfo { get; set; }
        public int PPID { get; set; }
    }
    class Program
    {
        public static int tempPIDMemoAlloca = 0;
        public static Int32 tempsearch_4_all = 0;
        private static int temptimer = 0;
        private static int _v1, _v2, _v3, _v4, _v5;
        public static bool detected = false;
        public static bool initdotmemoalloc = false;
        public static bool exec_error = false;

        public static DateTime _ThreadStartEvent = DateTime.Now;

        public static string lastname = "";
        public static string _arg = "";
        public static string _arg1 = "";
        public static string _arg2 = "x";
        public static string tempMemAllocInfo = "";
        public static string tempETWdetails = "";
        public static string templastinfo = "";
        public static string TemptcptipInfo;
        public static string temppath = "";

        public static List<string> PList = new List<string>();
        public static List<_ProcessInfo> Process_Events_db = new List<_ProcessInfo>();
        public static List<int> detectedPIDs = new List<int>();

        public static System.Threading.Thread Bingo;
        public static Task _t;
        public static async Task logfilewrite(string filename, string text)
        {
            using (StreamWriter _file = new StreamWriter(filename, true))
            {
                await _file.WriteLineAsync(text);
            };

        }
        public static string getpathPID(Int32 pid)
        {
            temppath = "Process Exited (PID:" + pid + ")";
            try
            {
                if (!System.Diagnostics.Process.GetProcessById(pid).HasExited)
                {
                    temppath = System.Diagnostics.Process.GetProcessById(pid).MainModule.FileName;

                }
            }
            catch (Exception e)
            {

                temppath = "Process Exited (PID:" + pid + ")";

            }
            return temppath;
        }
        public static void ETWCoreI()
        {
            using (var KS = new TraceEventSession(KernelTraceEventParser.KernelSessionName))
            {
                Console.CancelKeyPress += delegate (object s, ConsoleCancelEventArgs e) { KS.Dispose(); };

                KS.EnableKernelProvider(KernelTraceEventParser.Keywords.VirtualAlloc |
                 KernelTraceEventParser.Keywords.Thread
                 | KernelTraceEventParser.Keywords.Process
                 | KernelTraceEventParser.Keywords.ImageLoad
                 | KernelTraceEventParser.Keywords.NetworkTCPIP);

                /// Imageload & NetworkTCPIP is optional ;)
                /// Important things in this code are VirtualAlloc + Threads + Process)
                /// Only VirtualAlloc events + Thread Injections will save in log file 
                /// Imageload,TCPIP Network Connection and New Processes Events are not in log file.
                /// For better performance you can remove codes for these events (imageload,tcpip,new process)... ;) 
                
              

                KS.Source.Kernel.ThreadStart += Kernel_ThreadStart;
                KS.Source.Kernel.MemoryVirtualAllocDCStart += Kernel_MemoryVirtualAllocDCStart;
                KS.Source.Kernel.VirtualMemAlloc += Kernel_VirtualMemAlloc;
                KS.Source.Kernel.TcpIpSend += Kernel_TcpIpSend;
                KS.Source.Kernel.ImageLoad += Kernel_ImageLoad;
                KS.Source.Kernel.ProcessStart += Kernel_ProcessStart;

                // KS.Source.Kernel.TcpIpConnect += Kernel_TcpIpConnect;

                ////_arg = args[0];               
                ////_arg1 = args[1];
                ////_arg2 = args[2];
                
                /// DEBUG & TEST ONLY
                /// arg 1 and 2 was for monitoring via filters for 2 proceesses only... but in this code i want to monitor all processes via ETW
                _arg = "MonAll";
                _arg1 = "x";
                _arg2 = "x";
                if (_arg.ToUpper() == "ALL") { _arg = "MonAll"; }

                KS.Source.Process();
                //GC.GetTotalMemory(true);
            }
        }
        
        static void Main(string[] args)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("ETWProcessMon v1.1 Tool , Published by Damon Mohammadbagher , 2020");
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine("ETWProcessMon tool is simple Monitoring for Processes/Threads/Memory/Network via ETW + C#");
            Console.WriteLine();
            Bingo = new System.Threading.Thread(ETWCoreI)
            {
                Priority = System.Threading.ThreadPriority.Highest
            };
            Bingo.Start();
          
        }
      
        private static void Kernel_ImageLoad(Microsoft.Diagnostics.Tracing.Parsers.Kernel.ImageLoadTraceData obj)
        {
           // GC.GetTotalMemory(true);

            
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write("[etw] ");
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write("[+DLL+] ImageLoad ");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine("Detected, Target_Process: " + obj.ProcessName + ":" + obj.ProcessID + "   TID(" + obj.ThreadID + ")" + " TaskName(" + obj.TaskName + ") " + obj.TimeStamp.ToString());

                Console.ForegroundColor = ConsoleColor.Green;
                _v1 = 0;
                foreach (var item in obj.PayloadNames)
                {

                    if (item.Contains("File"))
                        Console.WriteLine("[etw] [" + item + ": " + obj.PayloadValue(_v1).ToString() + "]");

                    if (_v1 == 0)
                        Console.WriteLine("[etw] [" + item + ": " + obj.PayloadValue(_v1).ToString() + "]");

                    _v1++;
                }
                Console.WriteLine();
            
            Process_Events_db.Add(new _ProcessInfo { PPID = -1, MemAPIName = "ImageLoad", PID = obj.ProcessID.ToString(), PIDPath = getpathPID(obj.ProcessID), ProcessName = obj.ProcessName, PTime = obj.TimeStamp, TCPIPCon = "-", MemAllocInfo = "-" });

        }
        private static void Kernel_TcpIpSend(Microsoft.Diagnostics.Tracing.Parsers.Kernel.TcpIpSendTraceData obj)
        {
            //GC.GetTotalMemory(true);

            TemptcptipInfo = "";

             
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write("[etw] ");
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write("[TCPIP] TcpIpSend ");
                Console.ForegroundColor = ConsoleColor.Gray;
                Console.WriteLine("Detected, Target_Process: " + obj.ProcessName + ":" + obj.ProcessID + "   TID(" + obj.ThreadID + ")" + " TaskName(" + obj.TaskName + ") " + obj.TimeStamp.ToString());

                Console.ForegroundColor = ConsoleColor.Green;
                _v2 = 0;
                foreach (var item in obj.PayloadNames)
                {
                    if (_v2 == 4) Console.Write('\n' + "[etw]");
                    if (_v2 == 0)
                        Console.Write("[etw] [" + item + ": " + obj.PayloadValue(_v2).ToString() + "]");

                    if (_v2 > 0)
                        Console.Write(" [" + item + ": " + obj.PayloadValue(_v2).ToString() + "]");

                    TemptcptipInfo += "[" + item + ":" + obj.PayloadValue(_v2).ToString() + "]";


                    _v2++;
                }
                Console.ForegroundColor = ConsoleColor.Gray;

                Console.WriteLine();

           

            Process_Events_db.Add(new _ProcessInfo { PPID=-1, MemAPIName = "STcp", PID = obj.ProcessID.ToString(), PIDPath = getpathPID(obj.ProcessID), ProcessName = obj.ProcessName, PTime = obj.TimeStamp, TCPIPCon = TemptcptipInfo, MemAllocInfo="-" });

        }
        private static void Kernel_ProcessStart(Microsoft.Diagnostics.Tracing.Parsers.Kernel.ProcessTraceData obj)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("[etw] ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("[PrcID] New Process ");
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.Write("Detected, Process:PID");
            PList.Add(obj.ProcessName + ":" + obj.ProcessID.ToString());

            Console.Write(" " + obj.ProcessName + ":" + obj.ProcessID.ToString());
            Console.WriteLine(" Started! " + DateTime.Now.ToString());

            Process_Events_db.Add(new _ProcessInfo { PPID = obj.ParentID, MemAPIName = "ProcessStart", PID = obj.ProcessID.ToString(), PIDPath = getpathPID(obj.ProcessID), ProcessName = obj.ProcessName, PTime = obj.TimeStamp, TCPIPCon = "-", MemAllocInfo = "-" });          
        }
        private static void Kernel_VirtualMemAlloc(Microsoft.Diagnostics.Tracing.Parsers.Kernel.VirtualAllocTraceData obj)
        {
            // GC.GetTotalMemory(true);

            tempMemAllocInfo = "";
            tempPIDMemoAlloca = 0;

            if (_arg2 == "x")
            {
                if ((!initdotmemoalloc) && (tempPIDMemoAlloca != obj.ProcessID))
                {
                   
                    initdotmemoalloc = true;
                }

                ////Console.Write(".");
            }
            else
            {
                
                /// adding binding code betwee ETWProcessMon + ETWNetMonv3-v4
                /// start step1
                // _t = logfilewrite("ETWProcessMonlog.txt", "[etw][+MEM+] VirtualMemAlloc " + "Detected, Process: (" + obj.ProcessName + ":" + obj.ProcessID + ") TID(" + obj.ThreadID + ")" + " TaskName(" + obj.TaskName + ") " + DateTime.Now.ToString());

            }
            Console.ForegroundColor = ConsoleColor.Green;
            _v3 = 0;
            if (obj.ProcessID != tempPIDMemoAlloca)
            {
                /////Console.WriteLine();
                initdotmemoalloc = false;
                foreach (var item in obj.PayloadNames)
                {

 
                    tempMemAllocInfo += "[" + item + ": " + obj.PayloadValue(_v3).ToString() + "]";
                    // tempETWdetails += "[" + item +"=>" + obj.PayloadValue(i).ToString() + "] ";
                    tempETWdetails += ":" + obj.PayloadValue(_v3).ToString();


                    _v3++;
                }
                tempPIDMemoAlloca = obj.ProcessID;
                if (templastinfo != tempMemAllocInfo)
                {
                    _t = logfilewrite("ETWProcessMonlog.txt", "[" + obj.TimeStamp.ToString() + "] PID:(" + obj.ProcessID + ") TID(" + obj.ThreadID + ") " + tempETWdetails + " [VirtualMemAlloc]");
                    templastinfo = tempMemAllocInfo;
                }

                tempETWdetails = "";

            }
            Console.ForegroundColor = ConsoleColor.Gray;



            Process_Events_db.Add(new _ProcessInfo { PPID = -1, MemAPIName = "VirtualMemAlloc", PID = obj.ProcessID.ToString(), PIDPath = getpathPID(obj.ProcessID), ProcessName = obj.ProcessName, PTime = obj.TimeStamp, TCPIPCon = "-", MemAllocInfo = tempMemAllocInfo });

        }
        private static void Kernel_MemoryVirtualAllocDCStart(Microsoft.Diagnostics.Tracing.EmptyTraceData obj)
        {
            //GC.GetTotalMemory(true);

            tempMemAllocInfo = "";
            tempPIDMemoAlloca = 0;
            
                if (_arg2 == "x")
                {
                    if ((!initdotmemoalloc) && (tempPIDMemoAlloca != obj.ProcessID))
                    {
                       
                        initdotmemoalloc = true;
                    }

                    ////Console.Write(".");
                }
                else
                {

                }
                Console.ForegroundColor = ConsoleColor.Green;
                _v4 = 0;
                if (obj.ProcessID != tempPIDMemoAlloca)
                {
                    Console.WriteLine();
                    initdotmemoalloc = false;
                    foreach (var item in obj.PayloadNames)
                    {

                        tempMemAllocInfo += "[" + item + ": " + obj.PayloadValue(_v4).ToString() + "]";

                        _v4++;
                    }
                    tempPIDMemoAlloca = obj.ProcessID;
                    if (templastinfo != tempMemAllocInfo)
                    {
                        _t = logfilewrite("ETWProcessMonlog.txt", "[" + obj.TimeStamp.ToString() + "] PID:(" + obj.ProcessID + ") TID(" + obj.ThreadID + ") " + tempETWdetails + " [VirtualMemAlloc]");
                        templastinfo = tempMemAllocInfo;
                    }

                }
                Console.ForegroundColor = ConsoleColor.Gray;

            

            Process_Events_db.Add(new _ProcessInfo { PPID = -1, MemAPIName = "VirtualMemAllocDC", PID = obj.ProcessID.ToString(), PIDPath = getpathPID(obj.ProcessID), ProcessName = obj.ProcessName, PTime = obj.TimeStamp, TCPIPCon = "-", MemAllocInfo = tempMemAllocInfo });

        }
        private static void Kernel_ThreadStart(Microsoft.Diagnostics.Tracing.Parsers.Kernel.ThreadTraceData obj)
        {
         //  GC.GetTotalMemory(true);

            
                string prc = "Process Exited";
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write("[etw] ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write("[ MEM ] ThreadStart ");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine("Detected, in Process: " + obj.ProcessName + ":" + obj.ProcessID + "   TID(" + obj.ThreadID + ")" + " TaskName(" + obj.TaskName + ") " + obj.TimeStamp.ToString());

                Console.ForegroundColor = ConsoleColor.Green;
                _v5 = 0;
                if (obj.PayloadValue(obj.PayloadNames.Length - 1).ToString() != obj.ProcessID.ToString())
                {
                    try
                    {
                        exec_error = false;
                        prc = System.Diagnostics.Process.GetProcessById((Int32)obj.PayloadValue(obj.PayloadNames.Length - 1)).ProcessName;
                    }
                    catch (Exception)
                    {
                        exec_error = true;
                        prc = "Process Exited";
                        prc = PList.Find(myx => myx.Contains(Convert.ToString(obj.PayloadValue(obj.PayloadNames.Length - 1))));
                    }
                    Console.WriteLine();

                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.Write("[inj] ");
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.Write("[ MEM ] Injected ThreadStart ");
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("Detected, Target_Process: " + obj.ProcessName + ":" + obj.ProcessID + "   TID(" + obj.ThreadID + ")" + " Injected by " + prc);
                    Console.WriteLine("[inj] Injector ProcesName:PID " + prc + "  ==> [" + obj.PayloadValue(obj.PayloadNames.Length - 1).ToString() + "]");
                    if (exec_error)
                        Console.WriteLine("[inj] Injector Process Exited, found this ProcesName:PID in db: {0}", PList.Find(myx => myx.Contains(Convert.ToString(obj.PayloadValue(obj.PayloadNames.Length - 1)))));

                    Console.ForegroundColor = ConsoleColor.Green;

                    foreach (var item in obj.PayloadNames)
                    {
                        if (item.Contains("Parent") || item.Contains("Win"))
                        {
                            Console.WriteLine("[inj] [" + item + ": " + obj.PayloadValue(_v5).ToString() + "]");
                            tempETWdetails += ":" + obj.PayloadValue(_v5).ToString();

                        }
                        _v5++;
                    }

                    _t = logfilewrite("ETWProcessMonlog.txt", "[" + obj.TimeStamp.ToString() + "] PID:(" + obj.ProcessID + ")(" + obj.ProcessName + ") " + obj.ThreadID + ":" + tempETWdetails + "[Injected by " + prc + "]");

                    tempETWdetails = "";

                    /// show details about Injection
                    _WriteResult_Inj_Info(_Search_MemInfoPlusDateTime(obj.ProcessID.ToString()));
                    _Search_all_4_VirtualMemAlloc(_Search_MemInfoPlusDateTime(obj.ProcessID.ToString()));
                    /// show details about Injection
                }
            
            
            Process_Events_db.Add(new _ProcessInfo { PPID = obj.ParentProcessID,  MemAPIName = "ThreadStart", PID = obj.ProcessID.ToString(), PIDPath = getpathPID(obj.ProcessID), ProcessName = obj.ProcessName, PTime = obj.TimeStamp, TCPIPCon = "-", MemAllocInfo = "-" });
        }

        public static List<_ProcessInfo> _Search_MemInfoPlusDateTime (string Pid)
        {
            List<_ProcessInfo> Result = Process_Events_db.FindAll(Y => Y.PID.Contains(Pid) && Y.MemAPIName== "VirtualMemAlloc");
            return Result;
        }  
        public static void _WriteResult_Inj_Info(List<_ProcessInfo> search)
        {          
            foreach (_ProcessInfo item in search)
            {                
                if (temptimer >= 5)
                {
                    Console.WriteLine("\t {2} - MemoryVirtualAlloc Detectted ==> PID:{0} PName:{1} ", item.PID, item.ProcessName, item.PTime);
                    break;
                }
                temptimer++;
            }
        }
        public static void _Search_all_4_VirtualMemAlloc(List<_ProcessInfo> search2)
        {
            /// just do something, which i have no idea what exactly i found in list ;)
            List<_ProcessInfo> Result = Process_Events_db.FindAll(Y => Y.MemAPIName == "VirtualMemAlloc");
            foreach (_ProcessInfo item in search2)
            {
                foreach (_ProcessInfo item2 in Result)
                {
                    if (item.PTime == item2.PTime || (item.PTime.Minute - item2.PTime.Minute) >= -700000)
                    {
                        detected = false;

                        if (item2.PID != lastname)
                        {
                            foreach (int found in detectedPIDs)
                            {
                                if(found == Convert.ToInt32(item2.PID))
                                {
                                    detected = true;
                                    break;
                                }
                            }
                            if (!detected)
                            {
                                Console.ForegroundColor = ConsoleColor.White;
                                Console.WriteLine("\t\t {2} - MemoryVirtualAlloc Detectted ==> PID:{0} PName:{1} ", item2.PID, item2.ProcessName, item.PTime);
                                Console.WriteLine("\t\t Path: {0} ", item2.PIDPath);
                                Console.WriteLine();
                            }
                           Console.ForegroundColor = ConsoleColor.DarkGray;

                            tempsearch_4_all++;
                            lastname = item2.PID;
                            detectedPIDs.Add(Convert.ToInt32(item2.PID));

                        }
                        if (tempsearch_4_all >= 550) break;
                    }
                }


            }

        }
    }
}
