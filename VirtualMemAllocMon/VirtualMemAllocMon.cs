using System;
using System.Collections.Generic;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Diagnostics.Tracing.Parsers;

namespace VirtualMemAllocMon
{

    class Program
    {
        [Flags]
        public enum ProcessAccessFlags : uint
        {
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VMOperation = 0x00000008,
            VMRead = 0x00000010,
            VMWrite = 0x00000020,
            DupHandle = 0x00000040,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            Synchronize = 0x00100000,
            All = 0x001F0FFF
        }

        [Flags]
        public enum AllocationType
        {
            Commit = 0x00001000,
            Reserve = 0x00002000,
            Decommit = 0x00004000,
            Release = 0x00008000,
            Reset = 0x00080000,
            TopDown = 0x00100000,
            WriteWatch = 0x00200000,
            Physical = 0x00400000,
            LargePages = 0x20000000
        }

        [Flags]
        public enum MemoryProtection
        {
            NoAccess = 0x0001,
            ReadOnly = 0x0002,
            ReadWrite = 0x0004,
            WriteCopy = 0x0008,
            Execute = 0x0010,
            ExecuteRead = 0x0020,
            ExecuteReadWrite = 0x0040,
            ExecuteWriteCopy = 0x0080,
            GuardModifierflag = 0x0100,
            NoCacheModifierflag = 0x0200,
            WriteCombineModifierflag = 0x0400
        }
        [DllImport("kernelbase.dll")]

        public static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernelbase.dll")]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernelbase.dll")]

        public static extern bool WriteProcessMemory(IntPtr hProcess, uint lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

        [DllImport("kernelbase.dll")]

        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, AllocationType flAllocationType, MemoryProtection flProtect);
        public static string HexDump(byte[] bytes, int bytesPerLine = 16)
        {
            /// hexdump output ... 
            ///00000000   48 83 EC 28 E8 2B FF FF  FF 48 83 C4 28 EB 15 90   Hì(è+ÿÿÿHÄ(ë·
            ///00000010   90 90 90 90 90 90 90 90  90 90 90 90 90 90 90 90   
            ///00000020   90 90 90 90 48 8B C4 48  89 58 08 48 89 78 10 4C   HÄHX·Hx·L

            if (bytes == null) return "<null>";
            int bytesLength = bytes.Length;

            char[] HexChars = "0123456789ABCDEF".ToCharArray();

            int firstHexColumn =
                  8                   // 8 characters for the address
                + 3;                  // 3 spaces

            int firstCharColumn = firstHexColumn
                + bytesPerLine * 3       // - 2 digit for the hexadecimal value and 1 space
                + (bytesPerLine - 1) / 8 // - 1 extra space every 8 characters from the 9th
                + 2;                  // 2 spaces 

            int lineLength = firstCharColumn
                + bytesPerLine           // - characters to show the ascii value
                + Environment.NewLine.Length; // Carriage return and line feed (should normally be 2)

            char[] line = (new String(' ', lineLength - Environment.NewLine.Length) + Environment.NewLine).ToCharArray();
            int expectedLines = (bytesLength + bytesPerLine - 1) / bytesPerLine;
            StringBuilder result = new StringBuilder(expectedLines * lineLength);

            for (int i = 0; i < bytesLength; i += bytesPerLine)
            {
                line[0] = HexChars[(i >> 28) & 0xF];
                line[1] = HexChars[(i >> 24) & 0xF];
                line[2] = HexChars[(i >> 20) & 0xF];
                line[3] = HexChars[(i >> 16) & 0xF];
                line[4] = HexChars[(i >> 12) & 0xF];
                line[5] = HexChars[(i >> 8) & 0xF];
                line[6] = HexChars[(i >> 4) & 0xF];
                line[7] = HexChars[(i >> 0) & 0xF];

                int hexColumn = firstHexColumn;
                int charColumn = firstCharColumn;

                for (int j = 0; j < bytesPerLine; j++)
                {
                    if (j > 0 && (j & 7) == 0) hexColumn++;
                    if (i + j >= bytesLength)
                    {
                        line[hexColumn] = ' ';
                        line[hexColumn + 1] = ' ';
                        line[charColumn] = ' ';
                    }
                    else
                    {
                        byte b = bytes[i + j];
                        line[hexColumn] = HexChars[(b >> 4) & 0xF];
                        line[hexColumn + 1] = HexChars[b & 0xF];
                        line[charColumn] = (b < 32 ? '·' : (char)b);
                    }
                    hexColumn += 3;
                    charColumn++;
                }
                result.Append(line);
            }
            return UTF8Encoding.UTF8.GetString(UTF8Encoding.UTF8.GetBytes(result.ToString()));

            // return result.ToString();
        }

        [DllImport("kernelbase.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, uint lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, IntPtr lpNumberOfBytesRead);

        public static string ETW_VAx_Event_RealtimeChangedStrings = string.Empty;
        public static byte[] buf = new byte[208];
        public static string[] Flag_to_detection_VAx = new string[5];
        public static string[] Flag_to_detection_Bytes = new string[4];
        public static bool VaxFound, BytesFound = false;
        public static System.Timers.Timer __t = new System.Timers.Timer(350);
        public static System.Threading.Thread Bingo;
        public static string tempMemAllocInfo, tempETWdetails, templastinfo = "";
        public static Int32 tempPIDMemoAlloca,_v1;
        public static bool initdotmemoalloc = false;
        public static event EventHandler _Event_VirtualMemAlloc_etw_evt;
        public static string dumpmem = "";
        public static int result = 0;

        public static bool _SearchVAxEvents(string input_to_search)
        {

            VaxFound = false;
            foreach (string item in Flag_to_detection_VAx)
            {
                if (input_to_search.Contains(item))
                {
                    VaxFound = true;
                    break;
                }
            }
            return VaxFound;
        }
        public static int _SearchBytes(string input_to_search)
        {
            int count = 0;
            BytesFound = false;
            foreach (string item in Flag_to_detection_Bytes)
            {
                if (input_to_search.Contains(item))
                {
                    BytesFound = true;
                    count++;
                    if (count >= 4) break;
                }
            }
            return count;
        }
        public static void _ShowDetailsBytes(string RealtimeChangedStrings)
        {
            Flag_to_detection_Bytes[0] = "is program canno";
            Flag_to_detection_Bytes[1] = "t be run in DOS";
            Flag_to_detection_Bytes[2] = "00000000   4D 5A 41";
            Flag_to_detection_Bytes[3] = "00000000   4D 5A";
            Console.ForegroundColor = ConsoleColor.DarkGreen;
            Console.WriteLine(RealtimeChangedStrings);
            string _ProcessName = System.Diagnostics.Process.GetProcessById(Convert.ToInt32(RealtimeChangedStrings.Split('(')[1].Split(')')[0])).MainModule.FileName;
            string __PID = RealtimeChangedStrings.Split('(')[1].Split(')')[0];
            IntPtr ph = OpenProcess(ProcessAccessFlags.All, false, Convert.ToInt32(RealtimeChangedStrings.Split('(')[1].Split(')')[0]));
            ReadProcessMemory(ph, (uint)Convert.ToInt32(RealtimeChangedStrings.Split(':')[4]), buf, buf.Length, IntPtr.Zero);
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine("[{2}] Something Detected, VirtualMemAlloc Memory Address {0} in Process: {1} with PID: {3} ", RealtimeChangedStrings.Split(':')[4], _ProcessName, DateTime.Now, __PID);
            dumpmem = HexDump(buf);
            result = _SearchBytes(dumpmem);
            if (result > 0)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("[!] Found {0} of 4", result.ToString());
                Console.WriteLine(dumpmem);
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.DarkYellow;
                Console.WriteLine("[!] Found {0} of 4", result.ToString());
                Console.WriteLine(dumpmem);
            }
            CloseHandle(ph);
        }

        private static void Program__Event_VirtualMemAlloc_etw_evt(object sender, EventArgs e)
        {

            string ETW_VAx_Event_RealtimeChangedStrings = sender.ToString();

            if (_SearchVAxEvents(ETW_VAx_Event_RealtimeChangedStrings))
            {

                if (ETW_VAx_Event_RealtimeChangedStrings.Contains("[Injected by "))
                { Console.ForegroundColor = ConsoleColor.DarkYellow; }
                else
                { Console.ForegroundColor = ConsoleColor.Green; }

                _ShowDetailsBytes(ETW_VAx_Event_RealtimeChangedStrings);
            }
            else
            {

            }

        }
        public static void ETWCoreI()
        {
            using (var KS = new TraceEventSession(KernelTraceEventParser.KernelSessionName))
            {
                Console.CancelKeyPress += delegate (object s, ConsoleCancelEventArgs e) { KS.Dispose(); };

                KS.EnableKernelProvider(KernelTraceEventParser.Keywords.VirtualAlloc          
                // | KernelTraceEventParser.Keywords.ImageLoad
                 );

               
                KS.Source.Kernel.MemoryVirtualAllocDCStart += Kernel_MemoryVirtualAllocDCStart; 
                KS.Source.Kernel.VirtualMemAlloc += Kernel_VirtualMemAlloc; 

                //KS.Source.Kernel.ImageLoad += Kernel_ImageLoad;

                KS.Source.Process();
               
            }
        }

        private static void Kernel_VirtualMemAlloc(Microsoft.Diagnostics.Tracing.Parsers.Kernel.VirtualAllocTraceData obj)
        {
            GC.Collect();
            tempMemAllocInfo = "";
            tempPIDMemoAlloca = 0;


                    if ((!initdotmemoalloc) && (tempPIDMemoAlloca != obj.ProcessID))
                    {

                        initdotmemoalloc = true;
                    }

                _v1 = 0;
                if (obj.ProcessID != tempPIDMemoAlloca)
                {
                    initdotmemoalloc = false;
                    foreach (var item in obj.PayloadNames)
                    {

                        tempMemAllocInfo += "[" + item + ": " + obj.PayloadValue(_v1).ToString() + "]";
                        tempETWdetails += ":" + obj.PayloadValue(_v1).ToString();

                        _v1++;
                    }
                    tempPIDMemoAlloca = obj.ProcessID;
                    if (templastinfo != tempMemAllocInfo)
                    {
                        templastinfo = tempMemAllocInfo;

                    _Event_VirtualMemAlloc_etw_evt.Invoke((object)("[" + obj.TimeStamp.ToString() + "] PID:(" + obj.ProcessID +
                            ") TID(" + obj.ThreadID + ") " + tempETWdetails + " [VirtualMemAlloc]"), null);
                    }

                    tempETWdetails = "";

                }
   
        }

        private static void Kernel_MemoryVirtualAllocDCStart(Microsoft.Diagnostics.Tracing.EmptyTraceData obj)
        {
            GC.Collect();
            tempMemAllocInfo = "";
            tempPIDMemoAlloca = 0;

            if ((!initdotmemoalloc) && (tempPIDMemoAlloca != obj.ProcessID))
            {
                initdotmemoalloc = true;
            }

            _v1 = 0;
            if (obj.ProcessID != tempPIDMemoAlloca)
            {
                /////Console.WriteLine();
                initdotmemoalloc = false;
                foreach (var item in obj.PayloadNames)
                {

                    tempMemAllocInfo += "[" + item + ": " + obj.PayloadValue(_v1).ToString() + "]";
                    tempETWdetails += ":" + obj.PayloadValue(_v1).ToString();

                    _v1++;
                }
                tempPIDMemoAlloca = obj.ProcessID;
                if (templastinfo != tempMemAllocInfo)
                {
                    templastinfo = tempMemAllocInfo;

                    _Event_VirtualMemAlloc_etw_evt.Invoke((object)("[" + obj.TimeStamp.ToString() + "] PID:(" + obj.ProcessID +
                            ") TID(" + obj.ThreadID + ") " + tempETWdetails + " [VirtualMemAlloc]"), null);
                }

                tempETWdetails = "";

            }
        }

        static void Main(string[] args)
        {

            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("VirtualMemAllocMon Tool , Published by Damon Mohammadbagher , Jun-Jul 2021");
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine("VirtualMemAllocMon, ETW VirtualMemAlloc Events Realtime Monitor tool (Payload Detection by ETW Events)");
            Console.WriteLine();
            Thread.Sleep(1000);

            /// x64 payloads/events (only)
            /// note: for x86 payloads your x86 payloads will have new sizes...
            Flag_to_detection_VAx[0] = ":434176:MEM_COMMIT, MEM_RESERVE:";
            Flag_to_detection_VAx[1] = ":155648:MEM_COMMIT, MEM_RESERVE:";
            Flag_to_detection_VAx[2] = ":200704:MEM_COMMIT, MEM_RESERVE:";
            Flag_to_detection_VAx[3] = ":233472:MEM_COMMIT, MEM_RESERVE:";
            /// 
            Flag_to_detection_VAx[4] = "[Injected by ";
            Thread.Sleep(250);

            _Event_VirtualMemAlloc_etw_evt += Program__Event_VirtualMemAlloc_etw_evt;

                
            if (args.Length > 0 && args[0].ToLower() == "help")
            {
                Console.WriteLine("Syntax: VirtualMemAllocMon.exe ");
                Console.WriteLine("Description: VirtualMemAllocMon.exe will monitor all VirtualMemAlloc ETW Events for All Processes");
              
                Console.WriteLine();
            }
            else
            {
                Bingo = new System.Threading.Thread(ETWCoreI)
                {
                    Priority = System.Threading.ThreadPriority.AboveNormal
                };
                Bingo.Start();
                Thread.Sleep(1000);

                GC.GetTotalMemory(true);
            }

        }


    }
}
