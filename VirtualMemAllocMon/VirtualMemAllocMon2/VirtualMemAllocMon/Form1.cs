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
using System.Windows.Forms;
using System.Diagnostics;

namespace VirtualMemAllocMon
{
    public partial class Form1 : Form
    {
        public struct VirtualMemAllocEvents
        {
            // "[3/23/2022 5:07:51 PM] PID:(5140) TID(6628) :1661968515072:65536:MEM_COMMIT, MEM_RESERVE:0x10000:0x182f50c0000 [VirtualMemAlloc]"
            private DateTime Time;
            public DateTime _Time { get { return Time; } set { Time = value; } }

            private string Process;
            public string _Process { get { return Process; } set { Process = value; } }

            private string Type_of_MEM;
            public string _Type_of_MEM { get { return Type_of_MEM; } set { Type_of_MEM = value; } }

            private string DeltaTime;
            public string _DeltaTime { get { return DeltaTime; } set { DeltaTime = value; } }

            private Int64 EventCount;
            public Int64 _EventCount { get { return EventCount; } set { EventCount = value; } }

            private string EventTTL;
            public string _EventTTL { get { return EventTTL; } set { EventTTL = value; } }

            private DateTime Event_FirstTime;
            public DateTime _Event_FirstTime { get { return Event_FirstTime; } set { Event_FirstTime = value; } }

            private string SUID;
            public string _SUID { get { return SUID; } set { SUID = value; } }

            private Int64 Update_Events;
            public Int64 _Update_Events { get { return Update_Events; } set { Update_Events = value; } }

            private string StartAddress;
            public string _StartAddress { get { return StartAddress; } set { StartAddress = value; } }

            private Int32 TID;
            public Int32 _TID { get { return TID; } set { TID = value; } }

            private Int32 PID;
            public Int32 _PID { get { return PID; } set { PID = value; } }

            private Int32 Size;
            public Int32 _Size { get { return Size; } set { Size = value; } }
        }

        public static List<VirtualMemAllocEvents> ETWVirtualMemAllocEvents = new List<VirtualMemAllocEvents>();

        public static string ETW_VAx_Event_RealtimeChangedStrings = string.Empty;
        public static byte[] buf = new byte[208];
        public static string[] Flag_to_detection_VAx = new string[17];
        public static string[] Flag_to_detection_Bytes = new string[11];
        public static bool VaxFound, BytesFound = false;
        public static System.Timers.Timer __t = new System.Timers.Timer(350);
        public static System.Threading.Thread Bingo;
        public static string tempMemAllocInfo, tempETWdetails, templastinfo = "";
        public static Int32 tempPIDMemoAlloca, _v1;
        public static bool initdotmemoalloc = false;
        public static event EventHandler _Event_VirtualMemAlloc_etw_evt;
        public static event EventHandler _VirtualMemAlloc_etw_evt_save_to_WindowsLog;
        public static string dumpmem = "";
        public static int result = 0;
        public static UInt32 temp;                     
        public static ListViewItem iList5 = new ListViewItem();
        public static ListViewItem iList6 = new ListViewItem();
        public static EventLog _VirtualMemAllocMon;
         

        public static bool _SearchVAxEvents(string input_to_search)
        {
            try
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

            }
            catch (Exception)
            {
               
            }
            return VaxFound;
        }

        public static int _SearchBytes(string input_to_search)
        {
            int count = 0;
            try
            {
 
                BytesFound = false;
                foreach (string item in Flag_to_detection_Bytes)
                {
                    if (input_to_search.Contains(item))
                    {
                        BytesFound = true;
                        count++;
                        if (count >= 11) break;
                    }
                }
            }
            catch (Exception)
            {


            }
            return count;
        }

        public  void _ShowDetailsBytes(string RealtimeChangedStrings)
        {
            try
            {

                Flag_to_detection_Bytes[0] = "is program canno";
                Flag_to_detection_Bytes[1] = "t be run in DOS";
                Flag_to_detection_Bytes[2] = "00000000   4D 5A 41";
                Flag_to_detection_Bytes[3] = "00000000   4D 5A";

                /// CobaltStrike
                Flag_to_detection_Bytes[4] = "MZARUH?";
                Flag_to_detection_Bytes[5] = "DOS mode";
                /// yeah hura ;)
                Flag_to_detection_Bytes[6] = "MZARUH";
                Flag_to_detection_Bytes[7] = "ARUH";

                Flag_to_detection_Bytes[8] = "in DOS mode.";
                Flag_to_detection_Bytes[9] = "This progra";
                Flag_to_detection_Bytes[10] = "m cannot be run";

                string _ProcessName = System.Diagnostics.Process.GetProcessById((int)Convert.ToInt32(RealtimeChangedStrings.Split('(')[1].Split(')')[0])).MainModule.FileName;
                string __PID = RealtimeChangedStrings.Split('(')[1].Split(')')[0];

                IntPtr ph = OpenProcess(ProcessAccessFlags.All, false, Convert.ToInt32(RealtimeChangedStrings.Split('(')[1].Split(')')[0]));

                temp = 0;
                NtReadVirtualMemory(ph, ((IntPtr)Convert.ToUInt64(RealtimeChangedStrings.Split(':')[4])), buf, (uint)buf.Length, ref temp);
              
                dumpmem = HexDump(buf);

                result = _SearchBytes(dumpmem);
                string tid = RealtimeChangedStrings.Split('(')[2].Split(')')[0];
                if (result > 0)
                {
                    // "[3/23/2022 5:07:51 PM] PID:(5140) TID(6628) :1661968515072:65536:MEM_COMMIT, MEM_RESERVE:0x10000:0x182f50c0000 [VirtualMemAlloc]"
                    listView1.BeginInvoke((MethodInvoker)delegate
                    {

                        iList5 = new ListViewItem();
                        iList5.Name = "4D 5A 90 MZ bytes Detected In Process: " + _ProcessName + " With PID: " + __PID
                             + "\nDetails: [TID: " + tid + "] with BaseAddress: "
                             + RealtimeChangedStrings.Split(':')[7] + "," + RealtimeChangedStrings.Split(':')[8]
                             + "\n\n[ETW VirtualMemAlloc Event] => " + RealtimeChangedStrings.ToString() + "\n\n"
                             + "[!] Found " + result.ToString() + " of 11"
                             + "\nMemory Bytes: " + "\n" 
                             +  dumpmem;
                        iList5.SubItems.Add(RealtimeChangedStrings.Split(']')[0].Split('[')[1]);
                        iList5.SubItems.Add(_ProcessName + ":" + __PID);
                        iList5.SubItems.Add(tid);
                        iList5.SubItems.Add("[!] Found " + result.ToString() + " of 11");
                        iList5.SubItems.Add("VirtualMemAlloc");
                        iList5.SubItems.Add(RealtimeChangedStrings);
                        iList5.SubItems.Add("4D 5A 90 MZ Bytes Detected In Process: " + _ProcessName + " With PID: " + __PID
                             + "\nDetails: [TID: " + tid + "] with BaseAddress: "
                             + RealtimeChangedStrings.Split(':')[7] + "," + RealtimeChangedStrings.Split(':')[8]);
                        
                        iList5.ImageIndex = 2;

                        listView1.Items.Add(iList5);

                        Thread.Sleep(10);

                        _VirtualMemAlloc_etw_evt_save_to_WindowsLog.Invoke((object)iList5, null);

                    });
                    
                }
                else
                {
                 
                }
                CloseHandle(ph);
            }
            catch (Exception)
            {


            }
        }

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
       
        public void Program__Event_VirtualMemAlloc_etw_evt(object sender, EventArgs e)
        {
           
            try
            {

                ///"[4/13/2022 6:19:13 PM] PID:(7628) TID(2860) :2225218912256:131072:2109440:0x20000:0x20619640000:2225216806912:77824:MEM_COMMIT:0x13000:0x20619431000:2225219043328:131072:MEM_COMMIT, MEM_RESERVE:0x20000:0x20619660000:2225219174400:131072:2109440:0x20000:0x20619680000:2225216884736:487424:MEM_COMMIT:0x77000:0x206194a8000:1608888221696:65536:MEM_COMMIT, MEM_RESERVE:0x10000:0x17699370000:1608888287232:65536:MEM_COMMIT, MEM_RESERVE:0x10000:0x17699380000:2225219305472:131072:2109440:0x20000:0x206196a0000:2225214455808:16384:MEM_COMMIT:0x4000:0x206191e4000:2225217372160:77824:MEM_COMMIT:0x13000:0x206194bb000:2225214488576:32768:MEM_COMMIT:0x8000:0x206191f0000:2225214472192:16384:MEM_COMMIT:0x4000:0x206191e8000 [VirtualMemAlloc]"
                /// "[3/23/2022 5:07:51 PM] PID:(5140) TID(6628) :1661968515072:65536:MEM_COMMIT, MEM_RESERVE:0x10000:0x182f50c0000 [VirtualMemAlloc]"
                string ETW_VAx_Event_RealtimeChangedStrings = sender.ToString();

                if (_SearchVAxEvents(ETW_VAx_Event_RealtimeChangedStrings))
                {

                    _ShowDetailsBytes(ETW_VAx_Event_RealtimeChangedStrings);
                }
                else
                {

                }
            }
            catch (Exception)
            {


            }

         

        }

        public static string Delta_Time(DateTime currenttime, DateTime lasttime)
        {
            DateTime date1 = lasttime;
            DateTime date2 = currenttime;
            TimeSpan _ts = date2 - date1;


            return "Min:" + _ts.TotalMinutes.ToString() + " OR " + "Sec:" + _ts.Seconds.ToString();
        }

        private void ListView1_SelectedIndexChanged(object sender, EventArgs e)
        {
            richTextBox1.BeginInvoke((MethodInvoker)delegate
            {
                try
                {
                    richTextBox1.Text = listView1.SelectedItems[0].Name;
                }
                catch (Exception)
                {

                   
                }
               
            });
        }

        public static void ETWCoreI()
        {
            try
            {

                using (var KS = new TraceEventSession(KernelTraceEventParser.KernelSessionName))
                {
                    Console.CancelKeyPress += delegate (object s, ConsoleCancelEventArgs e) { KS.Dispose(); };

                    KS.EnableKernelProvider(KernelTraceEventParser.Keywords.VirtualAlloc);

                    KS.Source.Kernel.MemoryVirtualAllocDCStart += Kernel_MemoryVirtualAllocDCStart;
                    KS.Source.Kernel.VirtualMemAlloc += Kernel_VirtualMemAlloc;

                    KS.Source.Process();
                }
            }
            catch (Exception)
            {


            }
        }

        private static void Kernel_VirtualMemAlloc(Microsoft.Diagnostics.Tracing.Parsers.Kernel.VirtualAllocTraceData obj)
        {
            try
            {

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
            catch (Exception)
            {

                
            }

        }

        private static void Kernel_MemoryVirtualAllocDCStart(Microsoft.Diagnostics.Tracing.EmptyTraceData obj)
        {
            try
            {

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
            catch (Exception)
            {


            }
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            try
            {
               
                if (!EventLog.Exists("VirtualMemAllocMon"))
                {
                    EventSourceCreationData ESCD = new EventSourceCreationData("VirtualMemAllocMonv2", "VirtualMemAllocMon");
                    System.Diagnostics.EventLog.CreateEventSource(ESCD);

                }
                _VirtualMemAllocMon = new EventLog("VirtualMemAllocMon", ".", "VirtualMemAllocMonv2");
                _VirtualMemAllocMon.WriteEntry("VirtualMemAllocMon v2.0 Started", EventLogEntryType.Information, 255);
            }
            catch (Exception)
            {


            }

            _VirtualMemAlloc_etw_evt_save_to_WindowsLog += Form1__VirtualMemAlloc_etw_evt_save_to_WindowsLog;

            startMonitorToolStripMenuItem.Checked = true;
            listView1.SmallImageList = imageList1;
            /// Set the view to show details.
            listView1.View = View.Details;
            /// Allow the user to edit item text.
            listView1.LabelEdit = false;
            /// Allow the user to rearrange columns.
            listView1.AllowColumnReorder = true;
            /// Display check boxes.
            listView1.CheckBoxes = false;
            /// Select the item and subitems when selection is made.
            listView1.FullRowSelect = true;
            /// Display grid lines.
            listView1.GridLines = false;
            listView1.Sorting = SortOrder.Ascending;
            /// lisview1 for ETW VirtualMemAllocMon tool [process memory scanner] via VirtualMemAlloc Events (ETW Technique/Payload Detection)
            listView1.Columns.Add(" ", 20, HorizontalAlignment.Left);
            listView1.Columns.Add("EventTime", 140, HorizontalAlignment.Left);
            listView1.Columns.Add("Process", 260, HorizontalAlignment.Left);
            listView1.Columns.Add("TID", 80, HorizontalAlignment.Left);          
            listView1.Columns.Add("Status PE:Header:Bytes", 100, HorizontalAlignment.Left);
            listView1.Columns.Add("ETW Event", 100, HorizontalAlignment.Left);
            listView1.Columns.Add("Event Details Size:Type:StartAddress", 560, HorizontalAlignment.Left);
            listView1.Columns.Add("EventMessage", 500, HorizontalAlignment.Left);




            /// meterpreter x64 payloads/events (only)
            /// note: for x86 payloads your x86 payloads will have new sizes...
            Flag_to_detection_VAx[0] = ":434176:MEM_COMMIT, MEM_RESERVE:";
            Flag_to_detection_VAx[1] = ":155648:MEM_COMMIT, MEM_RESERVE:";
            Flag_to_detection_VAx[2] = ":200704:MEM_COMMIT, MEM_RESERVE:";
            Flag_to_detection_VAx[3] = ":233472:MEM_COMMIT, MEM_RESERVE:";

            /// CobaltStrike (x86)
            Flag_to_detection_VAx[4] = ":208896:MEM_COMMIT, MEM_RESERVE:";
            Flag_to_detection_VAx[5] = ":249856:MEM_COMMIT, MEM_RESERVE:";
            Flag_to_detection_VAx[6] = ":311296:MEM_COMMIT, MEM_RESERVE:";
            Flag_to_detection_VAx[7] = ":4194304:MEM_COMMIT, MEM_RESERVE:";
            ///[4/11/2022 7:49:23 AM] PID:(8544) TID(8796) :145096704:241664:MEM_COMMIT, MEM_RESERVE:0x3b000:0x8a9b000 [VirtualMemAlloc]
            Flag_to_detection_VAx[8] = ":241664:MEM_COMMIT, MEM_RESERVE:";
            ///[4/11/2022 7:49:23 AM] PID:(8544) TID(8848) :144572416:204800:MEM_COMMIT, MEM_RESERVE:0x32000:0x8a12000 [VirtualMemAlloc]
            Flag_to_detection_VAx[9] = ":204800:MEM_COMMIT, MEM_RESERVE:";
            /// CobaltStrike4.4
            Flag_to_detection_VAx[10] = ":245760:MEM_COMMIT, MEM_RESERVE:";
            Flag_to_detection_VAx[11] = ":253952:MEM_COMMIT, MEM_RESERVE:";
            Flag_to_detection_VAx[12] = ":212992:MEM_COMMIT, MEM_RESERVE:";
            Flag_to_detection_VAx[13] = ":318488:MEM_COMMIT, MEM_RESERVE:";
            Flag_to_detection_VAx[14] = ":24576:MEM_COMMIT, MEM_RESERVE:";

            Flag_to_detection_VAx[15] = ":28672:MEM_COMMIT:";
            Flag_to_detection_VAx[16] = ":24576:MEM_COMMIT:";


            Thread.Sleep(250);
            try
            {
                _Event_VirtualMemAlloc_etw_evt += Program__Event_VirtualMemAlloc_etw_evt;

                Bingo = new System.Threading.Thread(ETWCoreI)
                {
                    Priority = System.Threading.ThreadPriority.Normal
                };
                Bingo.Start();

                Thread.Sleep(1000);
            }
            catch (Exception)
            {


            }

        }

        private void Form1__VirtualMemAlloc_etw_evt_save_to_WindowsLog(object sender, EventArgs e)
        {
            try
            {
                ListViewItem _items_Objects = (ListViewItem)sender;
                
                _VirtualMemAllocMon = new EventLog("VirtualMemAllocMon", ".", "VirtualMemAllocMonv2");

                StringBuilder st = new StringBuilder();
                st.AppendLine(_items_Objects.Name.ToString());

                _VirtualMemAllocMon.WriteEntry(st.ToString(), EventLogEntryType.Warning, 1);
                
            }
            catch (Exception)
            {


            }
        }

        private void Form1_FormClosing(object sender, FormClosingEventArgs e)
        {
            Bingo.Abort();

        }

        private void StartMonitorToolStripMenuItem_Click(object sender, EventArgs e)
        {
            startMonitorToolStripMenuItem.Checked = true;
            stopMonitorToolStripMenuItem.Checked = false;

            if (!Bingo.IsAlive)
            {
                Bingo = new System.Threading.Thread(ETWCoreI)
                {
                    Priority = System.Threading.ThreadPriority.Highest
                };
                Bingo.Start();
                toolStripStatusLabel1.Text = "VirtualMemAllocMon is on";
                Thread.Sleep(1000);
            }
        }

        private void StopMonitorToolStripMenuItem_Click(object sender, EventArgs e)
        {
            stopMonitorToolStripMenuItem.Checked = true;
            startMonitorToolStripMenuItem.Checked = false;
            toolStripStatusLabel1.Text = "VirtualMemAllocMon is off";

            if (Bingo.IsAlive)
            {
                Bingo.Abort();

            }
        }

        private void AboutToolStripMenuItem_Click(object sender, EventArgs e)
        {
            MessageBox.Show(null, "VirtualMemAllocMon v2.0 [2.0.0.0]\nCode Published by Damon Mohammadbagher , Mar 2022", "About ETW VirtualMemAllocMon v2.0",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        

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
        [Flags]
        public enum ThreadAccess : int
        {
            Terminate = 0x0001,
            SuspendResume = 0x0002,
            GetContext = 0x0008,
            SetContext = 0x0010,
            SetInformation = 0x0020,
            QueryInformation = 0x0040,
            SetThreadToken = 0x0080,
            Impersonate = 0x0100,
            DirectImpersonation = 0x0200
        }
        public enum NtStatus : uint
        {

            // Success
            Success = 0x00000000,
            Wait0 = 0x00000000,
            Wait1 = 0x00000001,
            Wait2 = 0x00000002,
            Wait3 = 0x00000003,
            Wait63 = 0x0000003f,
            Abandoned = 0x00000080,
            AbandonedWait0 = 0x00000080,
            AbandonedWait1 = 0x00000081,
            AbandonedWait2 = 0x00000082,
            AbandonedWait3 = 0x00000083,
            AbandonedWait63 = 0x000000bf,
            UserApc = 0x000000c0,
            KernelApc = 0x00000100,
            Alerted = 0x00000101,
            Timeout = 0x00000102,
            Pending = 0x00000103,
            Reparse = 0x00000104,
            MoreEntries = 0x00000105,
            NotAllAssigned = 0x00000106,
            SomeNotMapped = 0x00000107,
            OpLockBreakInProgress = 0x00000108,
            VolumeMounted = 0x00000109,
            RxActCommitted = 0x0000010a,
            NotifyCleanup = 0x0000010b,
            NotifyEnumDir = 0x0000010c,
            NoQuotasForAccount = 0x0000010d,
            PrimaryTransportConnectFailed = 0x0000010e,
            PageFaultTransition = 0x00000110,
            PageFaultDemandZero = 0x00000111,
            PageFaultCopyOnWrite = 0x00000112,
            PageFaultGuardPage = 0x00000113,
            PageFaultPagingFile = 0x00000114,
            CrashDump = 0x00000116,
            ReparseObject = 0x00000118,
            NothingToTerminate = 0x00000122,
            ProcessNotInJob = 0x00000123,
            ProcessInJob = 0x00000124,
            ProcessCloned = 0x00000129,
            FileLockedWithOnlyReaders = 0x0000012a,
            FileLockedWithWriters = 0x0000012b,

            // Informational
            Informational = 0x40000000,
            ObjectNameExists = 0x40000000,
            ThreadWasSuspended = 0x40000001,
            WorkingSetLimitRange = 0x40000002,
            ImageNotAtBase = 0x40000003,
            RegistryRecovered = 0x40000009,

            // Warning
            Warning = 0x80000000,
            GuardPageViolation = 0x80000001,
            DatatypeMisalignment = 0x80000002,
            Breakpoint = 0x80000003,
            SingleStep = 0x80000004,
            BufferOverflow = 0x80000005,
            NoMoreFiles = 0x80000006,
            HandlesClosed = 0x8000000a,
            PartialCopy = 0x8000000d,
            DeviceBusy = 0x80000011,
            InvalidEaName = 0x80000013,
            EaListInconsistent = 0x80000014,
            NoMoreEntries = 0x8000001a,
            LongJump = 0x80000026,
            DllMightBeInsecure = 0x8000002b,

            // Error
            Error = 0xc0000000,
            Unsuccessful = 0xc0000001,
            NotImplemented = 0xc0000002,
            InvalidInfoClass = 0xc0000003,
            InfoLengthMismatch = 0xc0000004,
            AccessViolation = 0xc0000005,
            InPageError = 0xc0000006,
            PagefileQuota = 0xc0000007,
            InvalidHandle = 0xc0000008,
            BadInitialStack = 0xc0000009,
            BadInitialPc = 0xc000000a,
            InvalidCid = 0xc000000b,
            TimerNotCanceled = 0xc000000c,
            InvalidParameter = 0xc000000d,
            NoSuchDevice = 0xc000000e,
            NoSuchFile = 0xc000000f,
            InvalidDeviceRequest = 0xc0000010,
            EndOfFile = 0xc0000011,
            WrongVolume = 0xc0000012,
            NoMediaInDevice = 0xc0000013,
            NoMemory = 0xc0000017,
            NotMappedView = 0xc0000019,
            UnableToFreeVm = 0xc000001a,
            UnableToDeleteSection = 0xc000001b,
            IllegalInstruction = 0xc000001d,
            AlreadyCommitted = 0xc0000021,
            AccessDenied = 0xc0000022,
            BufferTooSmall = 0xc0000023,
            ObjectTypeMismatch = 0xc0000024,
            NonContinuableException = 0xc0000025,
            BadStack = 0xc0000028,
            NotLocked = 0xc000002a,
            NotCommitted = 0xc000002d,
            InvalidParameterMix = 0xc0000030,
            ObjectNameInvalid = 0xc0000033,
            ObjectNameNotFound = 0xc0000034,
            ObjectNameCollision = 0xc0000035,
            ObjectPathInvalid = 0xc0000039,
            ObjectPathNotFound = 0xc000003a,
            ObjectPathSyntaxBad = 0xc000003b,
            DataOverrun = 0xc000003c,
            DataLate = 0xc000003d,
            DataError = 0xc000003e,
            CrcError = 0xc000003f,
            SectionTooBig = 0xc0000040,
            PortConnectionRefused = 0xc0000041,
            InvalidPortHandle = 0xc0000042,
            SharingViolation = 0xc0000043,
            QuotaExceeded = 0xc0000044,
            InvalidPageProtection = 0xc0000045,
            MutantNotOwned = 0xc0000046,
            SemaphoreLimitExceeded = 0xc0000047,
            PortAlreadySet = 0xc0000048,
            SectionNotImage = 0xc0000049,
            SuspendCountExceeded = 0xc000004a,
            ThreadIsTerminating = 0xc000004b,
            BadWorkingSetLimit = 0xc000004c,
            IncompatibleFileMap = 0xc000004d,
            SectionProtection = 0xc000004e,
            EasNotSupported = 0xc000004f,
            EaTooLarge = 0xc0000050,
            NonExistentEaEntry = 0xc0000051,
            NoEasOnFile = 0xc0000052,
            EaCorruptError = 0xc0000053,
            FileLockConflict = 0xc0000054,
            LockNotGranted = 0xc0000055,
            DeletePending = 0xc0000056,
            CtlFileNotSupported = 0xc0000057,
            UnknownRevision = 0xc0000058,
            RevisionMismatch = 0xc0000059,
            InvalidOwner = 0xc000005a,
            InvalidPrimaryGroup = 0xc000005b,
            NoImpersonationToken = 0xc000005c,
            CantDisableMandatory = 0xc000005d,
            NoLogonServers = 0xc000005e,
            NoSuchLogonSession = 0xc000005f,
            NoSuchPrivilege = 0xc0000060,
            PrivilegeNotHeld = 0xc0000061,
            InvalidAccountName = 0xc0000062,
            UserExists = 0xc0000063,
            NoSuchUser = 0xc0000064,
            GroupExists = 0xc0000065,
            NoSuchGroup = 0xc0000066,
            MemberInGroup = 0xc0000067,
            MemberNotInGroup = 0xc0000068,
            LastAdmin = 0xc0000069,
            WrongPassword = 0xc000006a,
            IllFormedPassword = 0xc000006b,
            PasswordRestriction = 0xc000006c,
            LogonFailure = 0xc000006d,
            AccountRestriction = 0xc000006e,
            InvalidLogonHours = 0xc000006f,
            InvalidWorkstation = 0xc0000070,
            PasswordExpired = 0xc0000071,
            AccountDisabled = 0xc0000072,
            NoneMapped = 0xc0000073,
            TooManyLuidsRequested = 0xc0000074,
            LuidsExhausted = 0xc0000075,
            InvalidSubAuthority = 0xc0000076,
            InvalidAcl = 0xc0000077,
            InvalidSid = 0xc0000078,
            InvalidSecurityDescr = 0xc0000079,
            ProcedureNotFound = 0xc000007a,
            InvalidImageFormat = 0xc000007b,
            NoToken = 0xc000007c,
            BadInheritanceAcl = 0xc000007d,
            RangeNotLocked = 0xc000007e,
            DiskFull = 0xc000007f,
            ServerDisabled = 0xc0000080,
            ServerNotDisabled = 0xc0000081,
            TooManyGuidsRequested = 0xc0000082,
            GuidsExhausted = 0xc0000083,
            InvalidIdAuthority = 0xc0000084,
            AgentsExhausted = 0xc0000085,
            InvalidVolumeLabel = 0xc0000086,
            SectionNotExtended = 0xc0000087,
            NotMappedData = 0xc0000088,
            ResourceDataNotFound = 0xc0000089,
            ResourceTypeNotFound = 0xc000008a,
            ResourceNameNotFound = 0xc000008b,
            ArrayBoundsExceeded = 0xc000008c,
            FloatDenormalOperand = 0xc000008d,
            FloatDivideByZero = 0xc000008e,
            FloatInexactResult = 0xc000008f,
            FloatInvalidOperation = 0xc0000090,
            FloatOverflow = 0xc0000091,
            FloatStackCheck = 0xc0000092,
            FloatUnderflow = 0xc0000093,
            IntegerDivideByZero = 0xc0000094,
            IntegerOverflow = 0xc0000095,
            PrivilegedInstruction = 0xc0000096,
            TooManyPagingFiles = 0xc0000097,
            FileInvalid = 0xc0000098,
            InstanceNotAvailable = 0xc00000ab,
            PipeNotAvailable = 0xc00000ac,
            InvalidPipeState = 0xc00000ad,
            PipeBusy = 0xc00000ae,
            IllegalFunction = 0xc00000af,
            PipeDisconnected = 0xc00000b0,
            PipeClosing = 0xc00000b1,
            PipeConnected = 0xc00000b2,
            PipeListening = 0xc00000b3,
            InvalidReadMode = 0xc00000b4,
            IoTimeout = 0xc00000b5,
            FileForcedClosed = 0xc00000b6,
            ProfilingNotStarted = 0xc00000b7,
            ProfilingNotStopped = 0xc00000b8,
            NotSameDevice = 0xc00000d4,
            FileRenamed = 0xc00000d5,
            CantWait = 0xc00000d8,
            PipeEmpty = 0xc00000d9,
            CantTerminateSelf = 0xc00000db,
            InternalError = 0xc00000e5,
            InvalidParameter1 = 0xc00000ef,
            InvalidParameter2 = 0xc00000f0,
            InvalidParameter3 = 0xc00000f1,
            InvalidParameter4 = 0xc00000f2,
            InvalidParameter5 = 0xc00000f3,
            InvalidParameter6 = 0xc00000f4,
            InvalidParameter7 = 0xc00000f5,
            InvalidParameter8 = 0xc00000f6,
            InvalidParameter9 = 0xc00000f7,
            InvalidParameter10 = 0xc00000f8,
            InvalidParameter11 = 0xc00000f9,
            InvalidParameter12 = 0xc00000fa,
            MappedFileSizeZero = 0xc000011e,
            TooManyOpenedFiles = 0xc000011f,
            Cancelled = 0xc0000120,
            CannotDelete = 0xc0000121,
            InvalidComputerName = 0xc0000122,
            FileDeleted = 0xc0000123,
            SpecialAccount = 0xc0000124,
            SpecialGroup = 0xc0000125,
            SpecialUser = 0xc0000126,
            MembersPrimaryGroup = 0xc0000127,
            FileClosed = 0xc0000128,
            TooManyThreads = 0xc0000129,
            ThreadNotInProcess = 0xc000012a,
            TokenAlreadyInUse = 0xc000012b,
            PagefileQuotaExceeded = 0xc000012c,
            CommitmentLimit = 0xc000012d,
            InvalidImageLeFormat = 0xc000012e,
            InvalidImageNotMz = 0xc000012f,
            InvalidImageProtect = 0xc0000130,
            InvalidImageWin16 = 0xc0000131,
            LogonServer = 0xc0000132,
            DifferenceAtDc = 0xc0000133,
            SynchronizationRequired = 0xc0000134,
            DllNotFound = 0xc0000135,
            IoPrivilegeFailed = 0xc0000137,
            OrdinalNotFound = 0xc0000138,
            EntryPointNotFound = 0xc0000139,
            ControlCExit = 0xc000013a,
            PortNotSet = 0xc0000353,
            DebuggerInactive = 0xc0000354,
            CallbackBypass = 0xc0000503,
            PortClosed = 0xc0000700,
            MessageLost = 0xc0000701,
            InvalidMessage = 0xc0000702,
            RequestCanceled = 0xc0000703,
            RecursiveDispatch = 0xc0000704,
            LpcReceiveBufferExpected = 0xc0000705,
            LpcInvalidConnectionUsage = 0xc0000706,
            LpcRequestsNotAllowed = 0xc0000707,
            ResourceInUse = 0xc0000708,
            ProcessIsProtected = 0xc0000712,
            VolumeDirty = 0xc0000806,
            FileCheckedOut = 0xc0000901,
            CheckOutRequired = 0xc0000902,
            BadFileType = 0xc0000903,
            FileTooLarge = 0xc0000904,
            FormsAuthRequired = 0xc0000905,
            VirusInfected = 0xc0000906,
            VirusDeleted = 0xc0000907,
            TransactionalConflict = 0xc0190001,
            InvalidTransaction = 0xc0190002,
            TransactionNotActive = 0xc0190003,
            TmInitializationFailed = 0xc0190004,
            RmNotActive = 0xc0190005,
            RmMetadataCorrupt = 0xc0190006,
            TransactionNotJoined = 0xc0190007,
            DirectoryNotRm = 0xc0190008,
            CouldNotResizeLog = 0xc0190009,
            TransactionsUnsupportedRemote = 0xc019000a,
            LogResizeInvalidSize = 0xc019000b,
            RemoteFileVersionMismatch = 0xc019000c,
            CrmProtocolAlreadyExists = 0xc019000f,
            TransactionPropagationFailed = 0xc0190010,
            CrmProtocolNotFound = 0xc0190011,
            TransactionSuperiorExists = 0xc0190012,
            TransactionRequestNotValid = 0xc0190013,
            TransactionNotRequested = 0xc0190014,
            TransactionAlreadyAborted = 0xc0190015,
            TransactionAlreadyCommitted = 0xc0190016,
            TransactionInvalidMarshallBuffer = 0xc0190017,
            CurrentTransactionNotValid = 0xc0190018,
            LogGrowthFailed = 0xc0190019,
            ObjectNoLongerExists = 0xc0190021,
            StreamMiniversionNotFound = 0xc0190022,
            StreamMiniversionNotValid = 0xc0190023,
            MiniversionInaccessibleFromSpecifiedTransaction = 0xc0190024,
            CantOpenMiniversionWithModifyIntent = 0xc0190025,
            CantCreateMoreStreamMiniversions = 0xc0190026,
            HandleNoLongerValid = 0xc0190028,
            NoTxfMetadata = 0xc0190029,
            LogCorruptionDetected = 0xc0190030,
            CantRecoverWithHandleOpen = 0xc0190031,
            RmDisconnected = 0xc0190032,
            EnlistmentNotSuperior = 0xc0190033,
            RecoveryNotNeeded = 0xc0190034,
            RmAlreadyStarted = 0xc0190035,
            FileIdentityNotPersistent = 0xc0190036,
            CantBreakTransactionalDependency = 0xc0190037,
            CantCrossRmBoundary = 0xc0190038,
            TxfDirNotEmpty = 0xc0190039,
            IndoubtTransactionsExist = 0xc019003a,
            TmVolatile = 0xc019003b,
            RollbackTimerExpired = 0xc019003c,
            TxfAttributeCorrupt = 0xc019003d,
            EfsNotAllowedInTransaction = 0xc019003e,
            TransactionalOpenNotAllowed = 0xc019003f,
            TransactedMappingUnsupportedRemote = 0xc0190040,
            TxfMetadataAlreadyPresent = 0xc0190041,
            TransactionScopeCallbacksNotSet = 0xc0190042,
            TransactionRequiredPromotion = 0xc0190043,
            CannotExecuteFileInTransaction = 0xc0190044,
            TransactionsNotFrozen = 0xc0190045,

            MaximumNtStatus = 0xffffffff
        }
        public enum ThreadInfoClass : int
        {
            ThreadQuerySetWin32StartAddress = 9
        }

     

        public Form1()
        {
            InitializeComponent();
        }
        [DllImport("kernelbase.dll")]
        public static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, bool bInheritHandle, Int32 dwProcessId);

        [DllImport("kernelbase.dll")]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern NtStatus NtReadVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, UInt32 NumberOfBytesToRead, ref UInt32 NumberOfBytesRead);

    }
}
