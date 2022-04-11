using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Diagnostics.Tracing.Parsers;
using System.IO;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ETWProcessMon2
{

    public struct _ProcessInfo<String>
    {

        public String PTime { get; set; }
        public String ProcessName { get; set; }
        public String PID { get; set; }
        public String PIDPath { get; set; }
        public String MemAPIName { get; set; }
        public String TCPIPCon { get; set; }
        public String MemAllocInfo { get; set; }
        public String PPID { get; set; }
    }


    class Program
    {
        [DllImport("Kernel32.dll")]
        public static extern uint QueryFullProcessImageName(IntPtr hProcess, uint flags, StringBuilder str, out uint size);

        public static uint ch = 256;
        public static int tempPIDMemoAlloca = 0;
        public static Int32 tempsearch_4_all = 0;
        private static int _v0, _v1, _v2, _v3, _v4, _v5;
        public static bool detected = false;
        public static bool initdotmemoalloc = false;
        public static bool exec_error = false;
        public static bool __found = false;
        public static DateTime _ThreadStartEvent = DateTime.Now;

        public static string _FullstrPATH = string.Empty;
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
        public static List<_ProcessInfo<String>> Process_Events_db = new List<_ProcessInfo<String>>();
        public static List<int> detectedPIDs = new List<int>();
        public static StringBuilder _BytesStr;

        public static System.Threading.Thread Bingo;
        public static Task _t;
        public static EventLog ETW2MON;

        public static event EventHandler _Event_VirtualMemAlloc_NewThreadInj_into_TxtLogFile;
        public static event EventHandler _Event_Add_ETWEvent_to_WindowsEventLog_ETWPM2;

        public static string PPath(Process Process)
        {

            if (null != Process)
            {
                ch = 256;
                _BytesStr = new StringBuilder((int)ch);

                uint Result = QueryFullProcessImageName(Process.Handle, 0, _BytesStr, out ch);

                if (0 != Result)
                {
                    _FullstrPATH = _BytesStr.ToString();
                }
                else
                {

                    _FullstrPATH = "Process Exited (PID:" + ")";
                }
            }

            return _FullstrPATH;
        }
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
                    temppath = PPath(Process.GetProcessById(pid));

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
            //__NewEvent_VirtualMemAlloc += Program___NewEvent_VirtualMemAlloc;
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


                KS.Source.Kernel.ThreadStart += Kernel_ThreadStart;
                KS.Source.Kernel.MemoryVirtualAllocDCStart += Kernel_MemoryVirtualAllocDCStart;
                KS.Source.Kernel.VirtualMemAlloc += Kernel_VirtualMemAlloc;
                KS.Source.Kernel.TcpIpSend += Kernel_TcpIpSend;
                KS.Source.Kernel.ImageLoad += Kernel_ImageLoad;
                KS.Source.Kernel.ProcessStart += Kernel_ProcessStart;


                /// DEBUG & TEST ONLY
                /// arg 1 and 2 was for monitoring via filters for 2 proceesses only... but in this code i want to monitor all processes via ETW
                _arg = "MonAll";
                _arg1 = "x";
                _arg2 = "x";
                if (_arg.ToUpper() == "ALL") { _arg = "MonAll"; }

                KS.Source.Process();
                //  GC.GetTotalMemory(true);
            }
        }

        [Obsolete]
        static void Main(string[] args)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("ETWProcessMon v2 Tool , Published by Damon Mohammadbagher , 2020-2021");
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine("ETWProcessMon tool is simple Monitoring for Processes/Threads/Memory/Network via ETW + C#");
            Console.WriteLine();

            _Event_VirtualMemAlloc_NewThreadInj_into_TxtLogFile += Program__Event_VirtualMemAlloc_NewThreadInj_into_TxtLogFile;
            _Event_Add_ETWEvent_to_WindowsEventLog_ETWPM2 += Program__Event_Add_ETWEvent_to_WindowsEventLog_ETWPM2;

            if (!EventLog.Exists("ETWPM2"))
            {
                EventSourceCreationData ESCD = new EventSourceCreationData("ETW", "ETWPM2");
                System.Diagnostics.EventLog.CreateEventSource(ESCD);

            }
            ETW2MON = new EventLog("ETWPM2", ".", "ETW");
            ETW2MON.WriteEntry("ETWProcessMon2 Started", EventLogEntryType.Information, 1);
            ch = 256;
            _BytesStr = new StringBuilder((int)ch);


            Bingo = new System.Threading.Thread(ETWCoreI)
            {
                Priority = System.Threading.ThreadPriority.AboveNormal
            };
            Bingo.Start();
            //GC.GetTotalMemory(true);
        }

        private static void Program__Event_Add_ETWEvent_to_WindowsEventLog_ETWPM2(object sender, EventArgs e)
        {
            string _str_obj = sender.ToString();

            if (_str_obj.ToString().Contains("\n[TCPIP] TcpIpSend Detected\n"))
            { ETW2MON.WriteEntry(_str_obj, EventLogEntryType.Information, 3); }

            if (_str_obj.ToString().Contains("[MEM] Injected ThreadStart Detected,\n"))
            { ETW2MON.WriteEntry(_str_obj, EventLogEntryType.Warning, 2); }

            if (_str_obj.ToString().Contains("\n[MEM] NewProcess Started \n"))
            { ETW2MON.WriteEntry(_str_obj, EventLogEntryType.Information, 1); }
           
        }
        private static void Program__Event_VirtualMemAlloc_NewThreadInj_into_TxtLogFile(object sender, EventArgs e)
        {
            string _str_obj = sender.ToString();

            _t = logfilewrite("ETWProcessMonlog.txt", _str_obj);
        }


        private static void Kernel_ImageLoad(Microsoft.Diagnostics.Tracing.Parsers.Kernel.ImageLoadTraceData obj)
        {
            /// best way is using this syntax to dump logs about Imageload => ETWProcessMon2.exe > outputs.txt
            /// all imageload events will be save in this outputs.txt file ;)
            /// i think it is not good idea to save these ImageLoads ETW events to event logs ;)

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

                if (item.Contains("File") || item.Contains("BuildTime") || item.Contains("DefaultBase") || item.Contains("ImageBase"))
                    Console.WriteLine("[etw] [" + item + ": " + obj.PayloadValue(_v1).ToString() + "]");

                _v1++;
            }
            Console.WriteLine();
        }
        private static void Kernel_TcpIpSend(Microsoft.Diagnostics.Tracing.Parsers.Kernel.TcpIpSendTraceData obj)
        {
            /// these ETW events will save to event log ETWPM2.
          
            TemptcptipInfo = "";

            if (_arg == "MonAll")
            {
                //Console.WriteLine();
                //Console.ForegroundColor = ConsoleColor.DarkGray;
                //Console.Write("[etw] ");
                //Console.ForegroundColor = ConsoleColor.Red;
                //Console.Write("[TCPIP] TcpIpSend ");
                //Console.ForegroundColor = ConsoleColor.Gray;
                //Console.WriteLine("Detected, Target_Process: " + obj.ProcessName + ":" + obj.ProcessID + "   TID(" + obj.ThreadID + ")" + " TaskName(" + obj.TaskName + ") " + obj.TimeStamp.ToString());

                //Console.ForegroundColor = ConsoleColor.Green;
                _v2 = 0;
                foreach (var item in obj.PayloadNames)
                {
                    //if (_v2 == 4) Console.Write('\n' + "[etw]");
                    //if (_v2 == 0)
                    //    Console.Write("[etw] [" + item + ": " + obj.PayloadValue(_v2).ToString() + "]");

                    //if (_v2 > 0)
                    //    Console.Write(" [" + item + ": " + obj.PayloadValue(_v2).ToString() + "]");

                    TemptcptipInfo += "[" + item + ":" + obj.PayloadValue(_v2).ToString() + "]";


                    _v2++;
                }

                //   ETW2MON.WriteEntry("[ETW] " + "\n[TCPIP] TcpIpSend Detected" + "\nTarget_Process: " + obj.ProcessName + ":" + obj.ProcessID + "  TID(" + obj.ThreadID + ")" + " TaskName(" + obj.TaskName + ") " + "\nPIDPath = "
                //+ getpathPID(obj.ProcessID) + "\nEventTime = " + obj.TimeStamp.ToString() + "\n\n" + TemptcptipInfo
                // , EventLogEntryType.Information, 3) ;


                _Event_Add_ETWEvent_to_WindowsEventLog_ETWPM2.Invoke((object)("[ETW] " + "\n[TCPIP] TcpIpSend Detected" + "\nTarget_Process: " + obj.ProcessName + ":" + obj.ProcessID + "  TID(" + obj.ThreadID + ")" + " TaskName(" + obj.TaskName + ") " + "\nPIDPath = "
             + getpathPID(obj.ProcessID) + "\nEventTime = " + obj.TimeStamp.ToString() + "\n\n" + TemptcptipInfo), null);
            }

        }
        public static void Kernel_ProcessStart(Microsoft.Diagnostics.Tracing.Parsers.Kernel.ProcessTraceData obj)
        {
            /// these ETW events will save to event log ETWPM2.

            _v0 = 0;
           
            __found = false;
            foreach (string item in PList)
            {
                if (item.Contains(":" + obj.ProcessID.ToString()))
                {

                    __found = true;
                    break;
                }

            }

            if (__found)
            {

                PList.RemoveAll(x => x.Contains(":" + obj.ProcessID.ToString()));
                PList.Add(obj.ImageFileName + ":" + obj.ProcessID.ToString());

            }
            if (!__found)
            {
                PList.Add(obj.ImageFileName + ":" + obj.ProcessID.ToString());
            }



            //ETW2MON.WriteEntry("[ETW] " + "\n[MEM] NewProcess Started \n" + "PID = " + obj.ProcessID.ToString() + "  PIDPath = "
            //   + getpathPID(obj.ProcessID) + "\nProcessName = " + obj.ProcessName
            //   + "\n[" + "CommandLine: " + obj.PayloadByName("CommandLine").ToString() + "]"
            //   + "\n[" + "ParentID: " + obj.PayloadByName("ParentID").ToString() + "]"
            //   + "\n[ParentID Path: " + getpathPID((Int32)obj.PayloadByName("ParentID")) + "]"
            //   + "\nEventTime = " + obj.TimeStamp.ToString()
            //    , EventLogEntryType.Information, 1);

            _Event_Add_ETWEvent_to_WindowsEventLog_ETWPM2.Invoke((object)("[ETW] " + "\n[MEM] NewProcess Started \n" + "PID = " + obj.ProcessID.ToString() + "  PIDPath = "
               + getpathPID(obj.ProcessID) + "\nProcessName = " + obj.ProcessName
               + "\n[" + "CommandLine: " + obj.PayloadByName("CommandLine").ToString() + "]"
               + "\n[" + "ParentID: " + obj.PayloadByName("ParentID").ToString() + "]"
               + "\n[ParentID Path: " + getpathPID((Int32)obj.PayloadByName("ParentID")) + "]"
               + "\nEventTime = " + obj.TimeStamp.ToString()), null);

            //GC.Collect();
        }
        private static void Kernel_VirtualMemAlloc(Microsoft.Diagnostics.Tracing.Parsers.Kernel.VirtualAllocTraceData obj)
        {
            /// these ETW events will save to text log file.
            
            tempMemAllocInfo = "";
            tempPIDMemoAlloca = 0;

            if (_arg == "MonAll")
            {
                if (_arg2 == "x")
                {
                    if ((!initdotmemoalloc) && (tempPIDMemoAlloca != obj.ProcessID))
                    {

                        initdotmemoalloc = true;
                    }

                }
                else
                {

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
                        tempETWdetails += ":" + obj.PayloadValue(_v3).ToString();

                        _v3++;
                    }
                    tempPIDMemoAlloca = obj.ProcessID;
                    if (templastinfo != tempMemAllocInfo)
                    {
                        //+// _t = logfilewrite("ETWProcessMonlog.txt", "[" + obj.TimeStamp.ToString() + "] PID:(" + obj.ProcessID + ") TID(" + obj.ThreadID + ") " + tempETWdetails + " [VirtualMemAlloc]");
                        templastinfo = tempMemAllocInfo;

                        _Event_VirtualMemAlloc_NewThreadInj_into_TxtLogFile.Invoke((object)("[" + obj.TimeStamp.ToString() + "] PID:(" + obj.ProcessID +
                            ") TID(" + obj.ThreadID + ") " + tempETWdetails + " [VirtualMemAlloc]"), null);
                    }

                    tempETWdetails = "";

                }
                Console.ForegroundColor = ConsoleColor.Gray;

            }

        }
        private static void Kernel_MemoryVirtualAllocDCStart(Microsoft.Diagnostics.Tracing.EmptyTraceData obj)
        {
            /// these ETW events will save to text log file.

            tempMemAllocInfo = "";
            tempPIDMemoAlloca = 0;
            if (_arg == "MonAll")
            {
                if (_arg2 == "x")
                {
                    if ((!initdotmemoalloc) && (tempPIDMemoAlloca != obj.ProcessID))
                    {

                        initdotmemoalloc = true;
                    }

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
                        //+// _t = logfilewrite("ETWProcessMonlog.txt", "[" + obj.TimeStamp.ToString() + "] PID:(" + obj.ProcessID + ") TID(" + obj.ThreadID + ") " + tempETWdetails + " [VirtualMemAlloc]");
                        templastinfo = tempMemAllocInfo;
                        _Event_VirtualMemAlloc_NewThreadInj_into_TxtLogFile.Invoke((object)("[" + obj.TimeStamp.ToString() + "] PID:(" + obj.ProcessID +
                           ") TID(" + obj.ThreadID + ") " + tempETWdetails + " [VirtualMemAlloc]"), null);
                    }

                }
                Console.ForegroundColor = ConsoleColor.Gray;

            }

        }
        private static void Kernel_ThreadStart(Microsoft.Diagnostics.Tracing.Parsers.Kernel.ThreadTraceData obj)
        {
            /// these ETW events will save to event log ETWPM2.

            if (_arg == "MonAll")
            {
                string prc = "Process Exited";
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write("[etw] ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write("[ MEM ] ThreadStart ");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine("Detected, in Prc: " + obj.ProcessName + ":" + obj.ProcessID + " TID(" + obj.ThreadID + ")" + " StartAddr(" + obj.PayloadStringByName("Win32StartAddr", null).ToString() + ") " + obj.TimeStamp.ToString());

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
                        // prc = PList.Find(myx => myx.Contains(":" + Convert.ToString(obj.PayloadValue(obj.PayloadNames.Length - 1))));
                        prc = PList.Find(myx => myx.Split(':')[1] == Convert.ToString(obj.PayloadValue(obj.PayloadNames.Length - 1)));

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

                            if (item.Contains("Win"))
                                tempETWdetails += ":" + obj.PayloadStringByName("Win32StartAddr", null).ToString();

                            if (item.Contains("Parent"))
                                tempETWdetails += ":" + obj.PayloadValue(_v5).ToString();

                        }
                        _v5++;


                    }
                    try
                    {

                        //+// _t = logfilewrite("ETWProcessMonlog.txt", "[" + obj.TimeStamp.ToString() + "] PID:(" + obj.ProcessID + ")(" + obj.ProcessName + ") " + obj.ThreadID + ":" + tempETWdetails + "[Injected by " + prc + "]");

                        _Event_VirtualMemAlloc_NewThreadInj_into_TxtLogFile.Invoke((object)("[" + obj.TimeStamp.ToString() + "] PID:(" +
                            obj.ProcessID + ")(" + obj.ProcessName + ") " + obj.ThreadID + ":" + tempETWdetails + "[Injected by " + prc + "]"), null);

                        //    ETW2MON.WriteEntry("[ETW] \n" + "[MEM] Injected ThreadStart " + "Detected,\nTarget_Process: " + obj.ProcessName + ":" + obj.ProcessID + "   TID(" + obj.ThreadID + ")" + " Injected by " + getpathPID((Int32)obj.PayloadValue(obj.PayloadNames.Length - 1))
                        //    + "\nTarget_ProcessPath: " + getpathPID(obj.ProcessID) + "\n\nDebug info:" + " [" + obj.TimeStamp.ToString() + "] PID: (" + obj.ProcessID + ")(" + obj.ProcessName + ") " + obj.ThreadID + ":" + tempETWdetails + "[Injected by " + prc + "]"
                        //, EventLogEntryType.Warning, 2);


                        _Event_Add_ETWEvent_to_WindowsEventLog_ETWPM2.Invoke((object)("[ETW] \n" + "[MEM] Injected ThreadStart " + "Detected,\nTarget_Process: " + obj.ProcessName + ":" + obj.ProcessID
                            + "   TID(" + obj.ThreadID + ")" + " Injected by " + getpathPID((Int32)obj.PayloadValue(obj.PayloadNames.Length - 1))
                        + "\nTarget_ProcessPath: " + getpathPID(obj.ProcessID) + "\n\nDebug info:"
                        + " [" + obj.TimeStamp.ToString() + "] PID: (" + obj.ProcessID + ")(" + obj.ProcessName
                        + ") " + obj.ThreadID + ":" + tempETWdetails + "[Injected by " + prc + "]"), null);


                        tempETWdetails = "";

                    }
                    catch (Exception ops)
                    {

                    }
                }

            }

        }
    }
}
