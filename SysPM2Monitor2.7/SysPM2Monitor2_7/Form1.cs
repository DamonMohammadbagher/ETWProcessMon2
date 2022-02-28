using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace SysPM2Monitor2_7
{
    public partial class Form1 : Form
    {
        /// <summary>
        /// SysPM2Monitor2.7 [test version] Code Published by Damon Mohammadbagher , 10 Jan 2022 
        /// Realtime monitor Sysmon Events (itegrated with sysmon) + ETW Events via VirtualMemAllocMon.exe (Memory scanner based on ETW VirtualMemAlloc Events) 
        /// SysPM2Monitor2.7 & ETWPM2Monitor2.1 both are for test by Blue Teamers & Red Teamers too.
        /// in SysPM2Monitor2.7 code we have Sysmon Events + ETW VirtualMemAlloc events via Memory scanner [VirtualMemAllocMon.exe v1.1] + some other Memory scanners
        /// in ETWPM2Monitor2.1 code we have only ETW events + Memory scanners too
        /// i will update source codes/exe for SysPM2Monitor2.7 & ETWPM2Monitor2.1 via github ...  
        /// </summary>

        public Int64 i6 = 0;
        public static System.Timers.Timer t = new System.Timers.Timer(1500);
        public static System.Timers.Timer t2 = new System.Timers.Timer(5000);
        public static System.Timers.Timer t3 = new System.Timers.Timer(5000);
        public static System.Timers.Timer t4 = new System.Timers.Timer(6000);
        public static System.Timers.Timer t4_1 = new System.Timers.Timer(1500);
        public static System.Timers.Timer t5 = new System.Timers.Timer(10000);
        public static uint NTReadTmpRef = 0;
        public static EventLogQuery SysmonPM2Query;
        public ListViewItem iList = new ListViewItem();
        public ListViewItem iList2 = new ListViewItem();
        public ListViewItem iList3 = new ListViewItem();
        public ListViewItem iList4 = new ListViewItem();
        public ListViewItem iList5 = new ListViewItem();
        public ListViewItem iList6 = new ListViewItem();

        public delegate void __Additem(object itemsOfListview1_2_5_6);
        public delegate void __AddTextTorichtexhbox1(object str);
        public delegate void __Updatelistview1();
        public delegate void __Obj_Updater_to_WinForm();
        public delegate void __Core2(object str);

        public static EventLogWatcher EvtWatcher = null;
        public string tempMessage, tempMessage2, EventMessage = "";
        public static byte[] buf = new byte[90];
        public static ListViewItem LviewItemsX = null;
        public static string evtstring, evtstring2, evtstring3, tmplasttcpevent = "";
        public static bool isPEScanonoff = true;
        public static bool isHollowHunteronoff = true;
        public bool _is_this_EventID8 = false;
      
        public struct _TableofProcess_NewProcess_evt
        {
            public string ProcessName;
            public string ProcessName_Path;
            public string CommandLine;
            public int PID;
            public int PPID;
            public string PPID_Path;
        }
        public struct _TableofProcess
        {
            public string TCPDetails { set; get; }
            public string Description { set; get; }
            public int PID { set; get; }
            public int Injector { set; get; }
            public string Injector_Path { set; get; }
            public string ProcessName { set; get; }
            public string ProcessName_Path { set; get; }
            public bool IsLive { set; get; }
            public bool IsShow { set; get; }
            public int SysMonEventId8_25 { set; get; }
            public string StartAddress_of_TID { set; get; }
            public Int32 TID { set; get; }

        }

        public static List<_TableOfMemoryInjection_Details> Query_Reslt1 = new List<_TableOfMemoryInjection_Details>();
        public static List<_TableofProcess_NewProcess_evt> NewProcess_Table = new List<_TableofProcess_NewProcess_evt>();
        public static List<string> showitemsHash = new List<string>();
        public static List<_TableofProcess> Process_Table = new List<_TableofProcess>();
        public string Tempops, Injectortmp = "";
        public string[] finalresult_Scanned_01 = new string[2];
        public string[] _finalresult_Scanned_01 = new string[2];
        public string[] finalresult_Scanned_02 = new string[3];
        public string[] _finalresult_Scanned_02 = new string[3];
        public struct _TableofProcess_Scanned_01
        {
            /// <summary>
            /// table/list for pe-sieve64.exe
            /// </summary>
            public string injectorPathPID { set; get; }
            public int time_min { set; get; }
            public int time_Hour { set; get; }
            public string ProcNameANDPath { set; get; }
            public int PID { set; get; }
        }
        public struct _TableofProcess_Scanned_02
        {
            /// <summary>
            /// table/list for hollowshunter.exe
            /// </summary>
            public string injectorPathPID { set; get; }
            public int time_min { set; get; }
            public int time_Hour { set; get; }
            public string ProcNameANDPath { set; get; }
            public int PID { set; get; }
        }

        public static List<_TableofProcess_Scanned_01> Scanned_PIds = new List<_TableofProcess_Scanned_01>();
        public static string strOutput = "";
        public static System.Diagnostics.Process outputs = new System.Diagnostics.Process();
        public static bool Init_to_runPEScanner_01 = false;

        public static List<_TableofProcess_Scanned_02> Scanned_PIds2 = new List<_TableofProcess_Scanned_02>();
        public static string strOutput2 = "";
        public static System.Diagnostics.Process outputs2 = new System.Diagnostics.Process();
        public static bool Init_to_runPEScanner_02 = false;
        public int HollowHunterLevel = 0;
        public static bool AlarmsByETW_onoff_WithoutScanners = false;

        /// <summary>
        /// Adding Process which had RemoteThreadInjection to the list for monitoring their TCP Connections etc...
        /// </summary>
        public event EventHandler RemoteThreadInjectionDetection_ProcessLists;


        /// <summary>
        /// event for Injection Detection + TCP Send event & Adding Target Process info to the list + details/debug info... [Event ID 2]
        /// when this event invoked? after any tcp connection via those process which had RemoteThreadInjection.
        /// so this event will invoke with/inside EventID 3 but this will check process in list if had remotethreadinjection + tcp send then flag = true
        /// for scan + add the proces name to list in the "Alrams by ETW TAB" 
        /// </summary>
        public event EventHandler NewProcessAddedtolist;

        public object[] obj = new object[2];
        public object objX = new object[2];
        public string AlarmsDisabled = "Warning: Alarms by Sysmon \"Tab\", is \"disabled\" by selecting this Filter, [All Memory Scanners are OFF]";

        /// <summary>
        /// event for New Process Detection & Adding NEW Process info to the list [Event ID 1]
        /// </summary>
        public event EventHandler NewProcessAddedtolist_NewProcessEvt;
        public object[] obj2 = new object[8];

        /// <summary>
        /// v0 => new process
        /// v1 => injection count
        /// v2 => tcp count
        /// v3 => alarms by sysmon red count
        /// v4 => alarms by sysmon orange count
        /// v5 => suspended process
        /// v6 => terminated proesses
        /// v7 => total new/inj/tcp counts (etw recored real-time)
        /// </summary>

        public static Int64 Chart_NewProcess, chart_Inj, Chart_Tcp, Chart_Redflag, Chart_Orange, Chart_suspend, Chart_Terminate, Chart_Counts = 0;
        /// <summary>
        ///  pe_sieve_DumpSwitches = 0 dump all Detected Process to disk
        ///  pe_sieve_DumpSwitches = 1 
        ///  pe_sieve_DumpSwitches = 2 Dont Dump any Process to disk
        /// </summary>
        public static int pe_sieve_DumpSwitches = 2;
        /// <summary>
        /// hollowshunter_DumpSwitches =  /ofilter  & => 0 dump all , 1 dump some files , 2 Dont Dump any Process to disk (if detected something)
        /// </summary>
        public static int hollowshunter_DumpSwitches = 0;
        public int _1, _2, _3, _4, _5, _6, _7, _8, time4t = 0;
        public static string subitemX = "";

        /// <summary>
        /// event for refresh/update events in listView1 for (real-time events)
        /// </summary>
        public event EventHandler NewEventFrom_EventLogsCome;

        public struct _TableofProcess_Sysmon_Event_Counts
        {
            private string LastTCP_Details;
            private Int64 TCPSend;
            private Int64 RemoteThreadInjection;
            public Int64 _TCPSend_count { get { return TCPSend; } set { TCPSend = value; } }
            public Int64 _RemoteThreadInjection_count { get { return RemoteThreadInjection; } set { RemoteThreadInjection = value; } }
            public string _LastTCP_Details { get { return LastTCP_Details; } set { LastTCP_Details = value; } }
            public string lastEventtime { set; get; }
            public string ProcNameANDPath { set; get; }
            public int PID { set; get; }
            public string CommandLine { set; get; }
        }

        public struct _TableOfMemoryInjection_Details
        {
            public Int32 TPID { set; get; }
            public string TTID { set; get; }
            public string _StartAddress { set; get; }
            public string _InjectedMemory_Sbytes { set; get; }
            public Int64 Sysmon_EventRecord_ID { set; get; }
            public string SourceImagePath_or_Injector_Path { set; get; }
            public Int32 SourceProcessId_or_InjectorPID { set; get; }
        }

        public struct _InjectedThreadDetails_bytes
        {

            public string _ThreadStartAddress { set; get; }
            public Int32 _RemoteThreadID { set; get; }
            public Int32 _TargetPID { set; get; }
            public Int32 _InjectorPID { set; get; }
            public string Injected_Memory_Bytes { set; get; }
            public string Injected_Memory_Bytes_Hex { set; get; }
            public string _TargetPIDName { set; get; }

        }

        public static List<_InjectedThreadDetails_bytes> _InjectedTIDList = new List<_InjectedThreadDetails_bytes>();
        public static List<string> List_ofProcess_inListview2 = new List<string>();
        public static List<Int32> temptids = new List<int>();

        public static List<_TableOfMemoryInjection_Details> _SysmonEventID8_InjectionMemory_Details = new List<_TableOfMemoryInjection_Details>();
        public static List<_TableofProcess_Sysmon_Event_Counts> _Sysmon_Events_Counts = new List<_TableofProcess_Sysmon_Event_Counts>();
        public static _TableofProcess_Sysmon_Event_Counts Temp_Table_structure;

        public static int _percent(int count, int total)
        {
            return (count * 100) / total;
        }

        /// <summary>
        /// event for ETW VirtualMemAllocMon events in listView5 for (real-time events for memory scanner via ETW VirtualMemAlloc Events)
        /// </summary>
        public event EventHandler NewProcessDetected_by_Sysmon_VirtualMemAllocMon;

        public static CancellationTokenSource _dowork;
        public Int64 line = 1;
        public static Int32 _ETWProcess_PID = 0;
        public bool initstart_B, init = true;
        public bool once = false;
        public static string ETW_payload_Detected = "";
        public static string ETW_LogsReader_ResultText = "";
        public delegate void __MyDelegate_LogFileReader_Method();
        public delegate void __MyDelegate_showdatagrid();
        public delegate void __LogReader();       
        public __MyDelegate_LogFileReader_Method AsyncMethod = new __MyDelegate_LogFileReader_Method(ETW_LogFileReader_Method);
        public static string Logfile = @".\VirtualMemAllocMon\Debug\VirtualMemAllocMonlog.txt";
        public static string eventstring_tmp3 = "";
        public static EventLog ETW2MON;
        public static bool NetworkConection_found = false;
        public static Int64 NetworkConection_TCP_counts = 0;
        public static List<string> ActiveTCP = new List<string>();
        public static NotifyIcon ico = new NotifyIcon();
        public static bool _isNotifyEnabled = true;
        public static bool ScannerMixedMode_Pesieve = true;
        public static bool ScannerEvery10minMode_Pesieve = false;
        public static bool error_eventlognotfouand = false;
        /// <summary>
        /// event for adding event logs to listView6 for all Sysmon/Etw Detection logs.
        /// </summary>
        public event EventHandler System_Detection_Log_events;

        /// <summary>
        /// event for adding event logs to listView6 for all Sysmon/Etw Detection logs.
        /// </summary>
        public event EventHandler System_Detection_Log_events2;

        /// <summary> event for add tcp events to Network Tab  </summary>  
        public event EventHandler NewTCP_Connection_Detected;

        /// <summary> event for change Listview4 colors </summary>        
        public event EventHandler ChangeColorstoDefault;

       

        public static void _Show_Notify_Ico_Popup(object obj)
        {
            try
            {
                ico.Visible = false;
                ListViewItem _Obj_notify = (ListViewItem)obj;

                var _value2 = _Obj_notify.SubItems[2].Text;
                var _value3 = _Obj_notify.SubItems[3].Text;
                var _value4 = _Obj_notify.SubItems[4].Text;
                var _value5 = _Obj_notify.SubItems[5].Text;
                var _value6 = _Obj_notify.SubItems[6].Text;

                ico.Icon = SystemIcons.Error;
                ico.Visible = true;
                ico.ShowBalloonTip(4000, _value3 + "\n" + _value2.Replace('\n', ' ')
                    + "\n" + _value4 + "\n" + _value5 + "\n" + _value6, _value5, ToolTipIcon.Error);
            }
            catch (Exception)
            {

            }
        }


        public void Update_listbox1_scanner_logs(object str)
        {
            try
            {


                if (str.ToString().Contains("Suspended") || str.ToString().Contains("Terminated"))
                {
                    listBox1.Items.Add("[#] " + DateTime.Now.ToString() + " " + str.ToString());
                    listBox2.Items.Add("[#] " + DateTime.Now.ToString() + " " + str.ToString());

                }
                else
                {
                    listBox1.Items.Add("[!!] " + DateTime.Now.ToString() + " " + str.ToString());
                    listBox2.Items.Add("[!!] " + DateTime.Now.ToString() + " " + str.ToString());
                }

                listBox1.SelectedIndex = listBox1.Items.Count - 1;
                listBox2.SelectedIndex = listBox2.Items.Count - 1;
            }
            catch (Exception)
            {


            }

        }


        public void BeginUpdateList()
        {
            /// ...
        }

        public static async void ETW_LogFileReader_Method()
        {
            try
            {

                byte[] b;

                Thread.CurrentThread.Priority = ThreadPriority.Highest;

                using (FileStream myfile = new FileStream(Logfile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    b = new byte[myfile.Length];
                    await myfile.ReadAsync(b, 0, b.Length);
                };

                ETW_LogsReader_ResultText = Encoding.ASCII.GetString(b);

            }
            catch (Exception b)
            {
               
               
                   
            }
        }


        public async void ETW_VirtualMemAllocMon_Events_Reader()
        {
            try
            {

                await Task.Run(() =>
                {
                    Thread.CurrentThread.Priority = ThreadPriority.Highest;
                   
                    __MyDelegate_showdatagrid AsyncMethod0 = new __MyDelegate_showdatagrid(BeginUpdateList);
                    __MyDelegate_LogFileReader_Method AsyncMethod = new __MyDelegate_LogFileReader_Method(ETW_LogFileReader_Method);
                    string[] textitems = null;

                    _dowork = new CancellationTokenSource();

                    var t = _dowork.Token;
                    do
                    {

                        Invoke(AsyncMethod);

                        textitems = ETW_LogsReader_ResultText.Split('\r');

                        init = false;
                        System.Threading.Thread.Sleep(250);
                        /// stupid idea ;)
                        t.ThrowIfCancellationRequested();

                        if (!init)
                        {
                            for (Int64 i = line; i <= textitems.Length - 1; i++)
                            {
                                t.ThrowIfCancellationRequested();
                                
                                if (i == textitems.Length - 1)
                                {
                                    if (!init && !once)
                                    {
 
                                        Thread.Sleep(100);

                                        once = true;
 
                                    }
                                    break;
                                }

                                line++;

                                try
                                {

                                    if (textitems[i].Contains("Something Detected"))
                                    {
                                         
                                        if (!(textitems[i + 1].Contains("[!] Found 0 of 4")))
                                        {
                                            for (int _i = 2; _i < 15; _i++)
                                            {
                                                ETW_payload_Detected += textitems[i + _i];
                                            }

                                            string b64 = Convert.ToBase64String(ASCIIEncoding.UTF8.GetBytes(ETW_payload_Detected));

                                            NewProcessDetected_by_Sysmon_VirtualMemAllocMon.Invoke((object)textitems[i - 1]+ "@" + textitems[i] + "@" + textitems[i + 1] + b64, null);

                                        }
                                    }
                                }
                                catch (Exception eeee)
                                {
                                     ETW_payload_Detected = "";
                                }

                                ETW_payload_Detected = "";
  
                            }

                        }

                    } while (true);
                });
            }
            catch (Exception ecore)
            {

            }
        }


        public Form1()
        {
            InitializeComponent();
        }

        public void StartQueries_Mon(string queries)
        {
            string _Query = queries;
            EvtWatcher.Dispose();
            SysmonPM2Query = new EventLogQuery("Microsoft-Windows-Sysmon/Operational", PathType.LogName, _Query);

            EvtWatcher = new EventLogWatcher(SysmonPM2Query);
            EvtWatcher.EventRecordWritten += Watcher_EventRecordWritten;
            EvtWatcher.Enabled = true;
            toolStripStatusLabel1.Text = "Monitor Status: on";
        }


        private void Form1_Load(object sender, EventArgs e)
        {
            try
            {

                Form.CheckForIllegalCrossThreadCalls = false;

                try
                {
                    /// added in SysPM2Monitor2_7 => All Sysmon/ETW Alarms & System/Detection will save to Windows EventLog "SysPM2Monitor2_7" (run as admin)
                    if (!EventLog.Exists("SysPM2Monitor2_7"))
                    {
                        EventSourceCreationData ESCD = new EventSourceCreationData("SysPM2Monitor2.7", "SysPM2Monitor2_7");
                        System.Diagnostics.EventLog.CreateEventSource(ESCD);

                    }
                    ETW2MON = new EventLog("SysPM2Monitor2_7", ".", "SysPM2Monitor2.7");
                    ETW2MON.WriteEntry("SysPM2Monitor2 v2.7 Started", EventLogEntryType.Information, 255);
                }
                catch (Exception)
                {


                }               

                try
                {

                    
                    Process[] p = Process.GetProcessesByName("VirtualMemAllocMon");
                    foreach (Process item in p)
                    {
                        Process.GetProcessById(item.Id).Kill();
                        Thread.Sleep(100);
                    }
                }
                catch (Exception)
                {


                }

                try
                {
                    Process clear_logfile = new Process();
                    clear_logfile.StartInfo.FileName = "cmd.exe";
                    clear_logfile.StartInfo.Arguments = @"/C DEL /F .\VirtualMemAllocMon\Debug\VirtualMemAllocMonlog.txt";
                    clear_logfile.StartInfo.CreateNoWindow = true;
                    clear_logfile.StartInfo.UseShellExecute = false;
                    clear_logfile.Start();

                    Thread.Sleep(2000);


                }
                catch (Exception _e)
                {
                    
                     
                }
               
                ETW_VirtualMemAllocMon_Events_Reader();
                //string Query = "*";
                SysmonPM2Query = new EventLogQuery("Microsoft-Windows-Sysmon/Operational", PathType.LogName);

                EvtWatcher = new EventLogWatcher(SysmonPM2Query);
                EvtWatcher.EventRecordWritten += Watcher_EventRecordWritten;

                listView1.SmallImageList = imageList1;
                /// Run As Admin ;)
                EvtWatcher.Enabled = true;

                listView2.HeaderStyle = ColumnHeaderStyle.Nonclickable;
                listView2.BorderStyle = BorderStyle.FixedSingle;
                listView1.HeaderStyle = ColumnHeaderStyle.Nonclickable;
                listView1.BorderStyle = BorderStyle.FixedSingle;
                listView5.HeaderStyle = ColumnHeaderStyle.Nonclickable;
                listView5.BorderStyle = BorderStyle.FixedSingle;
                listView6.HeaderStyle = ColumnHeaderStyle.Nonclickable;
                listView6.BorderStyle = BorderStyle.FixedSingle;

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

                t.Elapsed += T_Elapsed;
                t.Enabled = true;
                t2.Elapsed += T2_Elapsed;
                t2.Enabled = true;
                t3.Elapsed += T3_Elapsed;
                t3.Enabled = true;
                t3.Start();
                //t4.Elapsed += T4_Elapsed;
                //t4.Enabled = true;
                //t4.Start();
                t4_1.Elapsed += T4_1_Elapsed; ;
                t4_1.Enabled = true;
                t4_1.Start();
                t5.Elapsed += T5_Elapsed; 
                t5.Enabled = true;
                t5.Start();

                listView1.Columns.Add(" ", 20, HorizontalAlignment.Left);
                listView1.Columns.Add("Time", 130, HorizontalAlignment.Left);
                listView1.Columns.Add("EventID", 55, HorizontalAlignment.Left);
                listView1.Columns.Add("Process", 150, HorizontalAlignment.Left);
                listView1.Columns.Add("Evt-Type", 55, HorizontalAlignment.Left);
                listView1.Columns.Add("EventMessage", 1500, HorizontalAlignment.Left);


                listView2.SmallImageList = imageList1;
                /// Set the view to show details.
                listView2.View = View.Details;
                /// Allow the user to edit item text.
                listView2.LabelEdit = false;
                /// Allow the user to rearrange columns.
                listView2.AllowColumnReorder = true;
                /// Display check boxes.
                listView2.CheckBoxes = false;
                /// Select the item and subitems when selection is made.
                listView2.FullRowSelect = true;
                /// Display grid lines.
                listView2.GridLines = false;
                listView2.Sorting = SortOrder.Ascending;
                /// lisview2 for Sysmon Technique/Payload Detection
                listView2.Columns.Add(" ", 20, HorizontalAlignment.Left);
                listView2.Columns.Add("LocalTime", 100, HorizontalAlignment.Left);
                listView2.Columns.Add("Process", 200, HorizontalAlignment.Left);
                listView2.Columns.Add("Injection-Type", 100, HorizontalAlignment.Left);
                listView2.Columns.Add("Tcp Sends", 100, HorizontalAlignment.Left);
                listView2.Columns.Add("Status", 100, HorizontalAlignment.Left);
                listView2.Columns.Add("PE-Sieve Pe:Shell:Replaced", 250, HorizontalAlignment.Left);
                listView2.Columns.Add("HollowsHunter Pe:", 250, HorizontalAlignment.Left);
                listView2.Columns.Add("Description", 250, HorizontalAlignment.Left);
                listView2.Columns.Add("EventMessage", 500, HorizontalAlignment.Left);


                listView5.SmallImageList = imageList1;
                /// Set the view to show details.
                listView5.View = View.Details;
                /// Allow the user to edit item text.
                listView5.LabelEdit = false;
                /// Allow the user to rearrange columns.
                listView5.AllowColumnReorder = true;
                /// Display check boxes.
                listView5.CheckBoxes = false;
                /// Select the item and subitems when selection is made.
                listView5.FullRowSelect = true;
                /// Display grid lines.
                listView5.GridLines = false;
                listView5.Sorting = SortOrder.Ascending;
                /// lisview5 for ETW VirtualMemAllocMon tool [process memory scanner] via VirtualMemAlloc Events (ETW Technique/Payload Detection)
                listView5.Columns.Add(" ", 20, HorizontalAlignment.Left);
                listView5.Columns.Add("EventTime", 100, HorizontalAlignment.Left);
                listView5.Columns.Add("Process", 200, HorizontalAlignment.Left);
                listView5.Columns.Add("TID", 40, HorizontalAlignment.Left);
                listView5.Columns.Add("Status PE:Header:bytes", 100, HorizontalAlignment.Left);
                listView5.Columns.Add("Event Details Size:Type:StartAddress", 560, HorizontalAlignment.Left);                
                listView5.Columns.Add("Description", 330, HorizontalAlignment.Left);
                listView5.Columns.Add("EventMessage", 1000, HorizontalAlignment.Left);

                try
                {
                  
                    /// Run ETW Tool for Monitor VirtualMemAlloc ETW Events by VirtualMemAllocMon.exe v1.1 [Memory Scanner via ETW Events]
                    ProcessStartInfo ETW_VirtualMemAllocMonv1_1 = new ProcessStartInfo("CMD.EXE");                     
                    ETW_VirtualMemAllocMonv1_1.Arguments = @"/C .\VirtualMemAllocMon\Debug\VirtualMemAllocMon.exe > .\VirtualMemAllocMon\Debug\VirtualMemAllocMonlog.txt";
                    ETW_VirtualMemAllocMonv1_1.CreateNoWindow = true;
                    ETW_VirtualMemAllocMonv1_1.UseShellExecute = false;
                    ETW_VirtualMemAllocMonv1_1.RedirectStandardOutput = true;
                    ETW_VirtualMemAllocMonv1_1.RedirectStandardInput = true;
                    ETW_VirtualMemAllocMonv1_1.RedirectStandardError = true;
                    _ETWProcess_PID = _ETWProcess_PID = Process.Start(ETW_VirtualMemAllocMonv1_1).Id;
                   
                }
                catch (Exception Runerror)
                {
                    MessageBox.Show("ETW Tool VirtualMemAllocMon.exe Has Error or Not Running!\n" + Runerror.Message);
                   
                }


                listView6.SmallImageList = imageList1;
                /// Set the view to show details.
                listView6.View = View.Details;
                /// Allow the user to edit item text.
                listView6.LabelEdit = false;
                /// Allow the user to rearrange columns.
                listView6.AllowColumnReorder = true;
                /// Display check boxes.
                listView6.CheckBoxes = false;
                /// Select the item and subitems when selection is made.
                listView6.FullRowSelect = true;
                /// Display grid lines.
                listView6.GridLines = false;
                listView6.Sorting = SortOrder.Ascending;
                /// lisview5 for ETW VirtualMemAllocMon tool [process memory scanner] via VirtualMemAlloc Events (ETW Technique/Payload Detection)
                listView6.Columns.Add(" ", 20, HorizontalAlignment.Left);
                listView6.Columns.Add("Time", 120, HorizontalAlignment.Left);
                listView6.Columns.Add("Process", 250, HorizontalAlignment.Left);
                listView6.Columns.Add("Status", 130, HorizontalAlignment.Left);
                listView6.Columns.Add("Detection by Sysmon:ETW", 150, HorizontalAlignment.Left);
                listView6.Columns.Add("Action Scanned:Suspended:Terminated", 220, HorizontalAlignment.Left);
                listView6.Columns.Add("Memory Scanner", 200, HorizontalAlignment.Left);
                

                /// event for add Process to Alarm-Tab by ETW & scanning Target Process by Memory Scanners
                /// event is ready ...
                NewProcessAddedtolist += Form1_NewProcessAddedtolist1;

                /// event for add Process to list of New Process
                NewProcessAddedtolist_NewProcessEvt += Form1_NewProcessAddedtolist_NewProcessEvt;

                /// event for add target Process to list of Injected Process which had RemoteThreadInjection
                RemoteThreadInjectionDetection_ProcessLists += Form1_RemoteThreadInjectionDetection_ProcessLists;

                /// event for refresing listviw real-time events
                NewEventFrom_EventLogsCome += Form1_NewEventFrom_EventLogsCome;

                /// event for ETW VirtualMemAllocMon tool (memory scanner via ETW VirtualMemAlloc Events)
                NewProcessDetected_by_Sysmon_VirtualMemAllocMon += Form1_NewProcessDetected_by_ETW_VirtualMemAllocMon;

                /// event for add all detection events to System_Detection_logs Tab
                System_Detection_Log_events += Form1_System_Detection_Log_events;

                /// event for add all detection events to System_Detection_logs Tab
                System_Detection_Log_events2 += Form1_System_Detection_Log_events2;

                /// event for add all tcp events to Network Tab
                NewTCP_Connection_Detected += Form1_NewTCP_Connection_Detected;

                /// event fo change colors for listview4
                ChangeColorstoDefault += Form1_ChangeColorstoDefault; 

                groupBox1.Text = "New Processes events: " + Chart_NewProcess;
                groupBox2.Text = "Injection events: " + chart_Inj;
                groupBox3.Text = "TCP Send events: " + Chart_Tcp;
                groupBox4.Text = "Detection High: " + Chart_Redflag;
                groupBox5.Text = "Detection Medium: " + Chart_Orange;
                groupBox6.Text = "Suspended Processes: " + Chart_suspend;
                groupBox7.Text = "Terminated Processes: " + Chart_Terminate;
                groupBox8.Text = "All Real-time events: " + Chart_Counts;

                listView3.SmallImageList = imageList1;
                /// Set the view to show details.
                listView3.View = View.Details;
                /// Allow the user to edit item text.
                listView3.LabelEdit = false;
                /// Allow the user to rearrange columns.
                listView3.AllowColumnReorder = true;
                /// Display check boxes.
                listView3.CheckBoxes = false;
                /// Select the item and subitems when selection is made.
                listView3.FullRowSelect = true;
                /// Display grid lines.
                listView3.GridLines = false;
                listView3.Sorting = SortOrder.Ascending;
                listView3.Columns.Add(" ", 20, HorizontalAlignment.Left);
                listView3.Columns.Add("Time", 124, HorizontalAlignment.Left);
                listView3.Columns.Add("Process", 180, HorizontalAlignment.Left);
                listView3.Columns.Add("Status", 64, HorizontalAlignment.Left);
                listView3.Columns.Add("Source IP:Port", 120, HorizontalAlignment.Left);
                listView3.Columns.Add("Destination IP:Port", 120, HorizontalAlignment.Left);
                listView3.Columns.Add("Delta Time (Days or Hours or Minutes)", 187, HorizontalAlignment.Left);
                listView3.Columns.Add("Event Count", 77, HorizontalAlignment.Left);
                listView3.Columns.Add("Event TTL (D:H:Minutes)", 135, HorizontalAlignment.Left);
                listView3.Columns.Add("Event First Time", 130, HorizontalAlignment.Left);

            }
            catch (EventLogReadingException err)
            {
                MessageBox.Show(err.Message);
            }
        }


        private void T5_Elapsed(object sender, System.Timers.ElapsedEventArgs e)
        {
            try
            {
                new TaskFactory().StartNew(() =>
                {
                    ActiveTCP.Clear();
                    IPGlobalProperties _GetIPGlobalProperties = IPGlobalProperties.GetIPGlobalProperties();
                    TcpConnectionInformation[] _TCPConnections = _GetIPGlobalProperties.GetActiveTcpConnections();

                    foreach (TcpConnectionInformation t in _TCPConnections)
                    {

                        ActiveTCP.Add(t.LocalEndPoint.Address.ToString() + ":" + t.LocalEndPoint.Port.ToString() + ">" + t.RemoteEndPoint.Address.ToString()
                            + ":" + t.RemoteEndPoint.Port.ToString() + "@" + t.State.ToString());

                    }

                    for (int i = 0; i < listView3.Items.Count; i++)
                    {
                        string __find = ActiveTCP.Find(_tcp => _tcp.Split('>')[0] == listView3.Items[i].SubItems[4].Text && _tcp.Split('>')[1].Split('@')[0]
                        == listView3.Items[i].SubItems[5].Text);
                        if (__find != null)
                        {
                            if (__find.Split('@')[1].ToLower().Contains("established"))
                            {
                                listView3.Items[i].ImageIndex = 7;
                            }
                            else
                            {
                                listView3.Items[i].ImageIndex = 6;
                            }

                        }
                        else
                        {
                            listView3.Items[i].ImageIndex = 6;
                           
                        }
                    }
                    listView3.Refresh();
                });
            }
            catch (Exception)
            {


            }
        }


        private void T4_1_Elapsed(object sender, System.Timers.ElapsedEventArgs e)
        {
            try
            {
                System.Threading.Thread.Sleep(25);
                /// for sure check all index ;)
                for (int ii = 0; ii < listView3.Items.Count; ii++)
                {

                    listView3.Items[ii].BackColor = Color.White;

                }
                listView3.Refresh();

            }
            catch (Exception)
            {


            }
            t4_1.Enabled = false;
        }


        private void Form1_ChangeColorstoDefault(object sender, EventArgs e)
        {
            t4_1.Enabled = true;
        }


        private void Form1_NewTCP_Connection_Detected(object sender, EventArgs e)
        {
            BeginInvoke(new __Additem(Refresh_NetworkConection_in_Network_Tab), sender);
        }


        public static string Setinputs(double input)
        {
            if (input >= 1)
            {
                return input.ToString().Split('.')[0];
            }
            else
            {
                return "0";
            }
        }


        /// <summary>
        /// detect Delta time for tcp connections
        /// </summary>      
        public static string Delta_Time(DateTime currenttime_for_packet, DateTime lasttime_for_packet)
        {
            DateTime date1 = lasttime_for_packet;
            DateTime date2 = currenttime_for_packet;
            TimeSpan _ts = date2 - date1;


            return "D:" + Setinputs(_ts.TotalDays) + " or " + "H:" + Setinputs(_ts.TotalHours) + " or " + "M:" + _ts.TotalMinutes.ToString();
        }


        public async Task _ChangedProperty_Color_changed_delay(object itemid)
        {
            try
            {

                await new TaskFactory().StartNew(() =>
                {
                    listView3.Items[(int)itemid].BackColor = Color.Red;
                    listView3.Items[(int)itemid].SubItems[0].Text = "*";
                    listView3.Refresh();
                    ChangeColorstoDefault.Invoke((object)itemid, null);
                    System.Threading.Thread.Sleep(5);
                    listView3.BackColor = Color.White;
                    listView3.Refresh();

                });
            }
            catch (Exception)
            {


            }
        }


        public async void _Run_ChangeColor_for_listview4(object _item)
        {
            await _ChangedProperty_Color_changed_delay(_item);
        }


        /// <summary>
        /// add and refresh all tcp events to networ connection Tab
        /// </summary>
        public void Refresh_NetworkConection_in_Network_Tab(object obj)
        {
            try
            {
                //Network connection detected:
                //RuleName: Usermode
                //UtcTime:  
                //ProcessGuid: { }
                //ProcessId: 11992
                //Image: C:\Windows\System32\notepad.exe
                //User:  
                //Protocol: tcp
                //Initiated: true
                //SourceIsIpv6: false
                //SourceIp: 192.168.56.1
                //SourceHostname:  
                //SourcePort: 49952
                //SourcePortName: -
                //DestinationIsIpv6: false
                //DestinationIp: 192.168.56.101
                //DestinationHostname: -
                //DestinationPort: 4444
                //DestinationPortName: -

                ListViewItem NetworkTCP = (ListViewItem)obj;
                ListViewItem __obj = (ListViewItem)obj;

                /// each event message line has '\r' omg ;)
                string sip = __obj.SubItems[5].Text.Split('\n')[10].Split(':')[1].Substring(1, __obj.SubItems[5].Text.Split('\n')[10].Split(':')[1].Length - 2);
                string sip_port = __obj.SubItems[5].Text.Split('\n')[12].Split(':')[1].Substring(1, __obj.SubItems[5].Text.Split('\n')[12].Split(':')[1].Length - 2);
                string dip = __obj.SubItems[5].Text.Split('\n')[15].Split(':')[1].Substring(1, __obj.SubItems[5].Text.Split('\n')[15].Split(':')[1].Length - 2);
                string dip_port = __obj.SubItems[5].Text.Split('\n')[17].Split(':')[1].Substring(1, __obj.SubItems[5].Text.Split('\n')[17].Split(':')[1].Length - 2);
                NetworkTCP.Name = __obj.SubItems[3].Text + sip + sip_port + dip + dip_port;
                iList4 = new ListViewItem();

                if (listView3.Items.Count > 0)
                {
                    for (int i = 0; i < listView3.Items.Count; i++)
                    {
                        if (listView3.Items[i].Name != __obj.SubItems[3].Text + sip + dip + dip_port)
                        {
                            NetworkConection_found = false;

                        }
                        else if (listView3.Items[i].Name == __obj.SubItems[3].Text + sip + dip + dip_port)
                        {
                            listView3.Items[i].SubItems[6].Text = Delta_Time(Convert.ToDateTime(__obj.SubItems[1].Text), Convert.ToDateTime(listView3.Items[i].SubItems[1].Text));
                            listView3.Items[i].SubItems[1].Text = NetworkTCP.SubItems[1].Text;
                            listView3.Items[i].SubItems[4].Text = sip + ":" + sip_port;
                            NetworkConection_TCP_counts = Convert.ToInt64(listView3.Items[i].SubItems[7].Text);
                            NetworkConection_TCP_counts++;
                            listView3.Items[i].SubItems[7].Text = NetworkConection_TCP_counts.ToString();
                            TimeSpan _ttl = Convert.ToDateTime(NetworkTCP.SubItems[1].Text) - Convert.ToDateTime(listView3.Items[i].SubItems[9].Text);
                            listView3.Items[i].SubItems[8].Text = "D:" + _ttl.Days.ToString() + " , H:" + _ttl.Hours.ToString() + " , M:" + _ttl.Minutes.ToString();
                            listView3.Refresh();
                            BeginInvoke(new __Additem(_Run_ChangeColor_for_listview4), i);
                            NetworkConection_found = true;
                            tabPage10.Text = "Network Connections (" + listView3.Items.Count.ToString() + ")";
                            toolStripStatusLabel2.Text = "| Network Connections (" + listView3.Items.Count.ToString() + ")";
                            break;
                        }
                    }

                    if (!NetworkConection_found)
                    {
                        iList4.SubItems.Add(NetworkTCP.SubItems[1].Text);
                        iList4.SubItems.Add(NetworkTCP.SubItems[3].Text);
                        iList4.SubItems.Add("Connected");
                        iList4.SubItems.Add(sip + ":" + sip_port);
                        iList4.SubItems.Add(dip + ":" + dip_port);
                        iList4.SubItems.Add("0");
                        iList4.SubItems.Add("1");
                        /// event ttl
                        iList4.SubItems.Add("0");
                        /// event first time
                        iList4.SubItems.Add(NetworkTCP.SubItems[1].Text);
                        iList4.Name = __obj.SubItems[3].Text + sip + dip + dip_port;
                        int _i = listView3.Items.Add(iList4).Index;
                        BeginInvoke(new __Additem(_Run_ChangeColor_for_listview4), _i);
                        tabPage10.Text = "Network Connections (" + listView3.Items.Count.ToString() + ")";
                        toolStripStatusLabel2.Text = "| Network Connections (" + listView3.Items.Count.ToString() + ")";

                    }
                }
                else if (listView3.Items.Count <= 0)
                {
                    iList4.SubItems.Add(NetworkTCP.SubItems[1].Text);
                    iList4.SubItems.Add(NetworkTCP.SubItems[3].Text);
                    iList4.SubItems.Add("Connected");
                    iList4.SubItems.Add(sip + ":" + sip_port);
                    iList4.SubItems.Add(dip + ":" + dip_port);
                    iList4.SubItems.Add("0");
                    iList4.SubItems.Add("1");
                    /// event ttl
                    iList4.SubItems.Add("0");
                    /// event first time
                    iList4.SubItems.Add(NetworkTCP.SubItems[1].Text);
                    iList4.Name = __obj.SubItems[3].Text + sip + dip + dip_port;
                    int _i = listView3.Items.Add(iList4).Index;
                    BeginInvoke(new __Additem(_Run_ChangeColor_for_listview4), _i);
                    tabPage10.Text = "Network Connections (" + listView3.Items.Count.ToString() + ")";
                    toolStripStatusLabel2.Text = "| Network Connections (" + listView3.Items.Count.ToString() + ")";


                }
            }
            catch (Exception err)
            {

            }
        }


        public static void _SaveNew_ETW_Alarms_to_WinEventLog(object AlarmObjects)
        {
            try
            {

                ETW2MON = new EventLog("SysPM2Monitor2_7", ".", "SysPM2Monitor2.7");

                ListViewItem __AlarmObject = (ListViewItem)AlarmObjects;

                StringBuilder st = new StringBuilder();

                ListViewItem xitem = __AlarmObject;

                st.AppendLine("[#] Time: " + xitem.SubItems[1].Text + ", Process: " + xitem.SubItems[2].Text.Replace('\r', ' ').Replace('\n', ' ')
                    + ", Status: " + xitem.SubItems[3].Text.Replace('\r', ' ').Replace('\n', ' ') + "\nEvent Type: " + xitem.SubItems[4].Text +
                    " , Actions: " + xitem.SubItems[5].Text + "\n\nMemory Scanner Result: " + "\n" + xitem.Name);

                st.AppendLine(" ");


                if (__AlarmObject.SubItems[5].Text.Contains("Terminated") ||
                    __AlarmObject.SubItems[5].Text.Contains("Suspended") ||
                    __AlarmObject.SubItems[5].Text.Contains("Scanned & Found") ||
                     __AlarmObject.SubItems[7].Text.Contains(">>Detected") ||
                    Convert.ToInt32(string.Join("", ("0" + __AlarmObject.SubItems[6].Text).Where(char.IsDigit)).ToString()) > 0)
                {
                    string simpledescription = "[#] Time: " + xitem.SubItems[1].Text + "\nProcess: " + xitem.SubItems[2].Text + " Detected by SysPM2Monitor2.7 (Detection High level)!\n"
                        + "------------------------------------------------------------\n";
                    ETW2MON.WriteEntry(simpledescription + st.ToString(), EventLogEntryType.Warning, 2);
                }
                else
                {
                    string simpledescription = "[#] Time: " + xitem.SubItems[1].Text + "\nProcess: " + xitem.SubItems[2].Text + " Detected by SysPM2Monitor2.7 (Detection Medium level)!\n"
                      + "------------------------------------------------------------\n";
                    ETW2MON.WriteEntry(simpledescription + st.ToString(), EventLogEntryType.Information, 1);
                }
            }
            catch (Exception)
            {


            }
        }


        public static void _SaveNew_Sysmon_Alarms_to_WinEventLog(object AlarmObjects)
        {
            try
            {

                ETW2MON = new EventLog("SysPM2Monitor2_7", ".", "SysPM2Monitor2.7");

                ListViewItem __AlarmObject = (ListViewItem)AlarmObjects;

                StringBuilder st = new StringBuilder();

                ListViewItem xitem = __AlarmObject;

                st.AppendLine("[#] Time: " + xitem.SubItems[1].Text + ", Process: " + xitem.SubItems[2].Text.Replace('\r', ' ').Replace('\n', ' ')
                    + ", Status: " + xitem.SubItems[3].Text + "\nEvent Type: " + xitem.SubItems[4].Text +
                    " , Actions: " + xitem.SubItems[5].Text + "\n\nMemory Scanner Result: " + "\n" + xitem.Name);

                st.AppendLine(" ");

                if (__AlarmObject.SubItems[5].Text.Contains("Terminated") ||
                    __AlarmObject.SubItems[5].Text.Contains("Suspended") ||
                    __AlarmObject.SubItems[5].Text.Contains("Scanned & Found") ||
                     __AlarmObject.SubItems[7].Text.Contains(">>Detected") ||
                    Convert.ToInt32(string.Join("", ("0" + __AlarmObject.SubItems[6].Text).Where(char.IsDigit)).ToString()) > 0)
                {
                    string simpledescription = "[#] Time: " + xitem.SubItems[1].Text + "\nProcess: " + xitem.SubItems[2].Text + " Detected by SysPM2Monitor2.7 (Detection High level)!\n"
                        + "------------------------------------------------------------\n";
                    ETW2MON.WriteEntry(simpledescription + st.ToString(), EventLogEntryType.Warning, 2);
                }
                else
                {
                    string simpledescription = "[#] Time: " + xitem.SubItems[1].Text + "\nProcess: " + xitem.SubItems[2].Text + " Detected by SysPM2Monitor2.7 (Detection Medium level)!\n"
                      + "------------------------------------------------------------\n";
                    ETW2MON.WriteEntry(simpledescription + st.ToString(), EventLogEntryType.Information, 1);
                }
            }
            catch (Exception)
            {


            }
        }


        public static void _Save_New_DetectionLogs_TCP_Shell_Events_to_WinEventLog(object Obj)
        {
            try
            {

                ListViewItem _items_Objects = (ListViewItem)Obj;

                ETW2MON = new EventLog("SysPM2Monitor2_7", ".", "SysPM2Monitor2.7");

                StringBuilder st = new StringBuilder();

                st.AppendLine("[#] Time: " + _items_Objects.SubItems[1].Text + ", Process: " + _items_Objects.SubItems[2].Text.Replace('\r', ' ').Replace('\n', ' ')
                    + ", Status: " + _items_Objects.SubItems[3].Text + "\nEvent Type: " + _items_Objects.SubItems[4].Text +
                    " , Actions: " + _items_Objects.SubItems[5].Text + "\n\nEvent Message: " + "\n" + _items_Objects.Name);

                if (_items_Objects.SubItems[3].Text.Contains("Found Shell"))
                {
                    string simpledescription = "[#] Time: " + _items_Objects.SubItems[1].Text + "\n" + _items_Objects.SubItems[3].Text + " via Process: "
                        + _items_Objects.SubItems[2].Text.Replace('\r', ' ').Replace('\n', ' ') + " Detected by SysPM2Monitor2.7 (Detection High level)!\n"
                     + "------------------------------------------------------------\n";
                    ETW2MON.WriteEntry(simpledescription + st.ToString(), EventLogEntryType.Warning, 4);
                }

                //if (_items_Objects.SubItems[3].Text.Contains("Suspicious Traffic [Meterpreter!]"))
                //{
                //    string simpledescription = "[#] Time: " + _items_Objects.SubItems[1].Text + "\n" + _items_Objects.SubItems[3].Text + " via Process: "
                //        + _items_Objects.SubItems[2].Text.Replace('\r', ' ').Replace('\n', ' ') + " Detected by ETWPM2Monitor2 (Detection Medium level)!\n"
                //     + "------------------------------------------------------------\n";
                //    ETW2MON.WriteEntry(simpledescription + st.ToString(), EventLogEntryType.Information, 3);
                //}
            }
            catch (Exception)
            {


            }
        }


        private void Form1_System_Detection_Log_events2(object sender, EventArgs e)
        {
            ListViewItem tmp2 = (ListViewItem)sender;

            if (tmp2.SubItems[2].Text == "1")
            {
                string commandline = tmp2.SubItems[5].Text.Split('\n')[11].ToLower();
                string parentid = tmp2.SubItems[5].Text.Split('\n')[21].ToLower();
                string Shell_Pid = tmp2.SubItems[5].Text.Split('\n')[4].Split(':')[1];
                if (commandline.Contains("commandline: c:\\windows\\system32\\cmd.exe") || commandline.Contains("commandline: cmd"))

                {
                    if (parentid != "parentimage: c:\\windows\\explorer.exe]")
                    {
                        iList6 = new ListViewItem();
                        iList6.Name = tmp2.SubItems[5].Text;
                        iList6.SubItems.Add(tmp2.SubItems[1].Text);
                        iList6.SubItems.Add(tmp2.SubItems[3].Text + " " + " (with " + parentid + ")");

                        iList6.SubItems.Add("[!] Found Shell");
                        iList6.SubItems.Add("Sysmon [Process Create] event id 1");
                        iList6.SubItems.Add("Event Detected!");


                        iList6.SubItems.Add("--");
                        iList6.ImageIndex = 2;
                        if (tmp2.Name != eventstring_tmp3)
                        {
                            bool found = false;
                            for (int i = 0; i < listView6.Items.Count; i++)
                            {
                                if ((listView6.Items[i].SubItems[2].Text + listView6.Items[i].SubItems[3].Text) == (tmp2.SubItems[3].Text + "[!] Found Shell"))
                                {
                                    found = true;
                                }
                            }
                            if (!found)
                            {
                                BeginInvoke(new __Additem(_Additems_toListview6), iList6);
                                eventstring_tmp3 = tmp2.Name;
                                BeginInvoke(new __Additem(_Save_New_DetectionLogs_TCP_Shell_Events_to_WinEventLog), iList6);

                            }
                        }
                    }
                }
                else
                {

                }


            }
        }


        private void Form1_System_Detection_Log_events(object sender, EventArgs e)
        {
            try
            {

                ListViewItem tmp = (ListViewItem)sender;

                if (tmp.SubItems[3].Text.ToString() == "Injection" || tmp.SubItems[3].Text.ToString() == "Process-Hollowing")
                {
                    Thread.Sleep(100);
                    ///  detecting sysmon event
                    iList6 = new ListViewItem();
                    iList6.Name = tmp.Name;
                    iList6.SubItems.Add(tmp.SubItems[1].Text);
                    iList6.SubItems.Add(tmp.SubItems[2].Text);
                    if (tmp.SubItems[5].Text == "--")
                    {
                        iList6.SubItems.Add("[!] Found Suspicious");
                        iList6.SubItems.Add("Sysmon");
                        iList6.SubItems.Add("Scanned & Found!");
                    }
                    else
                    {
                        iList6.SubItems.Add("[!] " + tmp.SubItems[5].Text);
                        iList6.SubItems.Add("Sysmon");
                        iList6.SubItems.Add(tmp.SubItems[5].Text);
                    }

                    iList6.SubItems.Add("PESieve & HollowsHunter.exe");
                    iList6.ImageIndex = tmp.ImageIndex;

                    ThreadStart __T41_info_for_additems_to_Listview6 = new ThreadStart(delegate { BeginInvoke(new __Additem(_Additems_toListview6), iList6); });
                    Thread _T41_for_additems_to_Listview6 = new Thread(__T41_info_for_additems_to_Listview6);
                    _T41_for_additems_to_Listview6.Start();

                    /// add events to windows event log name SysPM2Monitor2_7
                    BeginInvoke(new __Additem(_SaveNew_Sysmon_Alarms_to_WinEventLog), iList6);


                    Thread.Sleep(100);
                }
                if (tmp.SubItems[4].Text.ToString().Contains("[!] Found"))
                {
                     
                    ///  detecting ETW [VirtualMemAllocMon ETW events]
                    iList6 = new ListViewItem();
                    iList6.Name = tmp.SubItems[6].Text + "\n" + tmp.SubItems[7].Text;
                    iList6.SubItems.Add(tmp.SubItems[1].Text);
                    iList6.SubItems.Add(tmp.SubItems[2].Text);
                    iList6.SubItems.Add(tmp.SubItems[4].Text);
                    iList6.SubItems.Add("ETW");
                    iList6.SubItems.Add("Scanned & Found!");
                    iList6.SubItems.Add("VirtualMemAllocMon.exe v1.1");
                    iList6.ImageIndex = 2;

                    ThreadStart __T4_info_for_additems_to_Listview6 = new ThreadStart(delegate { BeginInvoke(new __Additem(_Additems_toListview6), iList6); });
                    Thread _T4_for_additems_to_Listview6 = new Thread(__T4_info_for_additems_to_Listview6);
                    _T4_for_additems_to_Listview6.Start();

                    /// add events to windows event log name SysPM2Monitor2_7
                    BeginInvoke(new __Additem(_SaveNew_ETW_Alarms_to_WinEventLog), iList6);

                    Thread.Sleep(100);
                }
               
            }
            catch (Exception)
            {

               
            }
        }
             

        private void T3_Elapsed(object sender, System.Timers.ElapsedEventArgs e)
        {
            GC.Collect();

        }


        /// <summary>
        /// new to work... here to work
        /// </summary>
        /// <param name="etwEvtMessage"></param>
        public void InjectionMemoryInfoDetails_torichtectbox(object etwEvtMessage)
        {

            try
            {

                //CreateRemoteThread detected:
                //RuleName: -
                //UtcTime: 20 
                //SourceProcessGuid: { 38 8 - 000000005600}
                //SourceProcessId: 6588
                //SourceImage: C:\NativePayload_Tinjection\NativePayload_Tinjection\bin\Debug\NativePayload_Tinjection.exe
                //TargetProcessGuid: { 38  000000005600}
                //TargetProcessId: 10292
                //TargetImage: C:\Windows\System32\mspaint.exe
                //NewThreadId: 12584
                //StartAddress: 0x000001C74A1C0000
                //StartModule: -
                //StartFunction: -
                //SourceUser:  
                //TargetUser:  

                string EventMessage = etwEvtMessage.ToString();
                string EventMessageRecordId = "0";
                string ui64 = EventMessage.Split('\n')[10].Split(':')[1].Substring(3);
                ui64 = ui64.Replace('\r', ' ');
                string _i32StartAddress = ui64.Substring(0, ui64.Length - 1);
                ulong i32StartAddress = Convert.ToUInt64(_i32StartAddress,16);
 
                Int64 TID = Convert.ToInt64(EventMessage.Split('\n')[9].Split(':')[1]);
                Int32 prc = Convert.ToInt32(EventMessage.Split('\n')[7].Split(':')[1]);
                buf = new byte[208];
                buf = new byte[208];

                try
                {
                    IntPtr prch = System.Diagnostics.Process.GetProcessById(prc).Handle;
                    string pname = System.Diagnostics.Process.GetProcessById(prc).ProcessName;
                    string XStartAddress = EventMessage.Split('\n')[10].Split(':')[1].Substring(1).Split('\r')[0];
                    string _injector = EventMessage.Split('\n')[4].Split(':')[1].Substring(1).Split('\r')[0];
                    bool MemoryBytes = Memoryinfo.ReadProcessMemory(prch, (UIntPtr)i32StartAddress, buf, buf.Length, IntPtr.Zero);
                    string _buf = Memoryinfo.HexDump(buf);
                    string _bytes = BitConverter.ToString(buf).ToString();
                    /// added
                    ThreadStart __T5_info_for_additems_to_Richtextbox1 = new ThreadStart(delegate
                    {
                        BeginInvoke(new __Additem(_Additems_str_toRichtextbox1),
                        EventMessage + "\n\nEventID: " + "2" + "\nEventRecord_ID: " + EventMessageRecordId + "\n\n[Remote-Thread-Injection Memory Information]\n\tTID: " 
                        + TID.ToString() + "\n\tTID StartAddress: " +
                         XStartAddress.ToString() + "\n\tTID Win32StartAddress: " + i32StartAddress.ToString() + "\n\tTarget_Process PID: " + prc.ToString() +
                         "\n\nInjected Memory Bytes: " + _bytes + "\n\n" + _buf + "\n_____________________\n");
                    });

                    Thread _T5_for_additems_to_Richtextbox1 = new Thread(__T5_info_for_additems_to_Richtextbox1);
                    _T5_for_additems_to_Richtextbox1.Start();


                    /// new to work... here to work
                    _InjectedTIDList.Add(new _InjectedThreadDetails_bytes
                    {
                        _TargetPID = prc,
                        _ThreadStartAddress = _i32StartAddress.ToString(),
                        _RemoteThreadID = Convert.ToInt32(TID),
                        Injected_Memory_Bytes = _bytes,
                        Injected_Memory_Bytes_Hex = _buf,
                        _InjectorPID = Convert.ToInt32(_injector),
                        _TargetPIDName = pname

                    });

                }
                catch (Exception)
                {
                    BeginInvoke(new __Additem(_Additems_str_toRichtextbox1),
                   EventMessage + "\n\nEventID: " + "2" + "\n" + "EventID: 2, Read Target_Process Memory via API::ReadProcessMemory [ERROR] => " + "Access Error or Process Exited" + "\n[Remote-Thread-Injection Memory Information]\n_____________________________error______________________________\n");

                }

            }
            catch (Exception ohwoOwwtfk)
            {
                ThreadStart __T6_info_for_additems_to_Richtextbox1 = new ThreadStart(delegate
                {
                    BeginInvoke(new __Additem(_Additems_str_toRichtextbox1),
                   EventMessage + "\n\nEventID: " + "2" + "\n" + "EventID: 2, Read Target_Process Memory via API::ReadProcessMemory [ERROR] => " + ohwoOwwtfk.Message + "\n[Remote-Thread-Injection Memory Information]\n_____________________________error______________________________\n");
                });

                Thread _T6_for_additems_to_Richtextbox1 = new Thread(__T6_info_for_additems_to_Richtextbox1);
                _T6_for_additems_to_Richtextbox1.Start();


            }
        }


        public void _Additems_toListview1(object obj)
        {
           
            try
            {
                ListViewItem MyLviewItemsX1 = (ListViewItem)obj;
                Thread.Sleep(1);
                if (MyLviewItemsX1 != null)
                {
                    
                    if (MyLviewItemsX1.SubItems[2].Text == "3")
                    {
                        if (MyLviewItemsX1.Name != evtstring)
                        {
                            listView1.BeginUpdate();
                            listView1.Items.Add(MyLviewItemsX1);
                            listView1.Update();
                            listView1.EndUpdate();
                            evtstring = MyLviewItemsX1.Name;
                            Thread.Sleep(5);
                        }
                    }

                    if (MyLviewItemsX1.SubItems[2].Text == "8")
                    {
                        if (MyLviewItemsX1.Name != evtstring)
                        {
                            listView1.BeginUpdate();
                            listView1.Items.Add(MyLviewItemsX1);
                            listView1.Update();
                            listView1.EndUpdate();
                            evtstring = MyLviewItemsX1.Name;
                            Thread.Sleep(5);
                            InjectionMemoryInfoDetails_torichtectbox(MyLviewItemsX1.SubItems[5].Text);
                        }

                        
                      
                         

                    }

                    if (MyLviewItemsX1.SubItems[2].Text == "25")
                    {
                        if (MyLviewItemsX1.Name != evtstring)
                        {
                            listView1.BeginUpdate();
                            listView1.Items.Add(MyLviewItemsX1);
                            listView1.Update();
                            listView1.EndUpdate();
                            evtstring = MyLviewItemsX1.Name;
                            Thread.Sleep(5);
                        }
                    }



                    if (MyLviewItemsX1.SubItems[2].Text == "1")
                    {
                        string commandline = MyLviewItemsX1.SubItems[5].Text.Split('\n')[11].ToLower();
                        string parentid = MyLviewItemsX1.SubItems[5].Text.Split('\n')[21].ToLower();
                        if (commandline.Contains("commandline: c:\\windows\\system32\\cmd.exe") || commandline.Contains("commandline: cmd"))

                        {
                            if (parentid != "parentimage: c:\\windows\\explorer.exe")
                            {
                                MyLviewItemsX1.BackColor = Color.Red;
                                MyLviewItemsX1.ForeColor = Color.Black;
                                MyLviewItemsX1.ImageIndex = 2;
                                MyLviewItemsX1.SubItems[5].Text += "\n\n#This Description Added by SysPM2Monitor2.7 tool#\n##Warning Description: [ParentID Path] & [PPID] for this New Process is not Normal! (maybe Shell Activated?)##\n";
                                System_Detection_Log_events2.Invoke((object)MyLviewItemsX1, null);
                            }
                        }
                        else
                        {
                            MyLviewItemsX1.ForeColor = Color.Black;
                            MyLviewItemsX1.ImageIndex = 0;
                        }

                        listView1.Items.Add(MyLviewItemsX1);

                    }
                }
            }
            catch (Exception ee)
            {


            }
        }


        public void _Additems_toListview2(object obj)
        {
            /// add new items to Alarms by Sysmon TAB
            ListViewItem MyLviewItemsX2 = (ListViewItem)obj;
            try
            {

                Thread.Sleep(1);
                if (MyLviewItemsX2 != null)
                {

                    listView2.BeginUpdate();
                    listView2.Items.Add(MyLviewItemsX2);
                    listView2.Update();
                    listView2.EndUpdate();
                    Thread.Sleep(5);


                    tabPage4.Text = "Alarms by Sysmon " + "(" + listView2.Items.Count.ToString() + ")";
                    toolStripStatusLabel6.Text = "| Alarms by Sysmon " + "(" + listView2.Items.Count.ToString() + ")";
                   
                }
            }
            catch (Exception ee)
            {

               
            }

          
        }


        public void _Additems_toListview5(object obj)
        {
            /// add new items to Alarms by ETW TAB
            ListViewItem MyLviewItemsX5 = (ListViewItem)obj;
            try
            {
                //unknown process detected via sysmon ;)

                Thread.Sleep(1);
                if (MyLviewItemsX5 != null)
                {
                    if (MyLviewItemsX5.Name != evtstring2)
                    {
                        listView5.BeginUpdate();
                        listView5.Items.Add(MyLviewItemsX5);
                        listView5.Update();
                        listView5.EndUpdate();
                        evtstring2 = MyLviewItemsX5.Name;
                        Thread.Sleep(5);
                    }
                }

               tabPage3.Text = "Alarms by ETW (" + listView5.Items.Count + ")";
                toolStripStatusLabel7.Text = "| Alarms by ETW (" + listView5.Items.Count + ")";


            }
            catch (Exception ee)
            {
                

            }
           
            
           
        }


        public void _Additems_toListview6(object obj)
        {
            /// add new items to System/Detection Logs TAB
            ListViewItem MyLviewItemsX6 = (ListViewItem)obj;
            try
            {

                Thread.Sleep(10);
                if (MyLviewItemsX6 != null)
                {
                    if (MyLviewItemsX6.Name != evtstring3)
                    {

                        listView6.BeginUpdate();
                        listView6.Items.Add(MyLviewItemsX6);
                        listView6.Update();
                        listView6.EndUpdate();
                        evtstring3 = MyLviewItemsX6.Name;
                        Thread.Sleep(50);
                    }

                    if (_isNotifyEnabled)
                    {
                        if (MyLviewItemsX6.SubItems[3].Text.Contains("Scanned & Found")
                            || MyLviewItemsX6.SubItems[3].Text.Contains("Suspended")
                            || MyLviewItemsX6.SubItems[3].Text.Contains("Terminated"))
                            _Show_Notify_Ico_Popup(MyLviewItemsX6);
                    }

                    tabPage11.Text = "System/Detection Logs " + "(" + listView6.Items.Count.ToString() + ")";
                    toolStripStatusLabel8.Text = "| System/Detection Logs (" + listView6.Items.Count.ToString() + ")";
                }
            }
            catch (Exception ee)
            {
                
            }
          
        }


        public void _Additems_str_toRichtextbox1(object str)
        {
            try
            {
                Thread.Sleep(1);
                richTextBox1.Text += str.ToString();
                Thread.Sleep(10);
                
            }
            catch (Exception)
            {

               
            }
        }


        private void Form1_NewProcessDetected_by_ETW_VirtualMemAllocMon(object sender, EventArgs e)
        {

            try
            {
               
                string[] ETW_EventMessage = sender.ToString().Split('@');
                                
                /// [1/22/2022 10:57:05 AM] PID:(9408) TID(2664) :1842676301824:155648:MEM_COMMIT, MEM_RESERVE:0x26000:0x1ad08136000 [VirtualMemAlloc]                
                string _ETW_VirtualMemAllocDetails = ETW_EventMessage[0].ToString();

                string _ETW_Time = _ETW_VirtualMemAllocDetails.Split('[')[1].Split(']')[0];
                string _pid_v1 = _ETW_VirtualMemAllocDetails.Split('(')[1].Split(')')[0];
                string _tid_v1 = _ETW_VirtualMemAllocDetails.Split('(')[2].Split(')')[0];
                string _ETW_VirtualMemAlloc_Info_for_thread = "Size: " + _ETW_VirtualMemAllocDetails.Split(':')[5]+ " Type: " + _ETW_VirtualMemAllocDetails.Split(':')[6]
                    + " Base Address: " + _ETW_VirtualMemAllocDetails.Split(':')[7]+ "," + _ETW_VirtualMemAllocDetails.Split(':')[8];

                /// [1/22/2022 10:59:05 AM] Something Detected, VirtualMemAlloc Memory Address 2280498135040 in Process: C:\Windows\system32\mspaint.exe with PID: 5572 
                string _ETW_VirtualMemAlloc_Process_Path_PID = ETW_EventMessage[1].ToString();

                int _a = _ETW_VirtualMemAlloc_Process_Path_PID.IndexOf("in Process: ");
                int _b = _ETW_VirtualMemAlloc_Process_Path_PID.IndexOf("with PID: ");
                string _In_ProcessName = _ETW_VirtualMemAlloc_Process_Path_PID.Substring(_a, _b - _a - 1).Substring(12);
                string _In_PID = _ETW_VirtualMemAlloc_Process_Path_PID.Substring(_b).Split(':')[1];

                /// [!] Found 3 of 4
                string _ETW_DetectionNumbers = ETW_EventMessage[2].Substring(0,17);

                string _ETW_Payload_Detected_PE = ETW_EventMessage[2].Substring(17);            

                byte[] b64_str = Convert.FromBase64String(_ETW_Payload_Detected_PE);

                string _Detected_Payload_fromb64 = Encoding.UTF8.GetString(b64_str);

                iList5 = new ListViewItem();
                iList5.Name = _In_ProcessName + "@" + _pid_v1 + "@" + _ETW_VirtualMemAlloc_Info_for_thread;
                iList5.SubItems.Add(_ETW_Time);
                iList5.SubItems.Add(_In_ProcessName + ":" + _pid_v1);
                iList5.SubItems.Add(_tid_v1);               
                iList5.SubItems.Add(_ETW_DetectionNumbers);
                iList5.SubItems.Add(_ETW_VirtualMemAlloc_Info_for_thread);
                iList5.SubItems.Add("4D 5A 90 MZ bytes Detected In Process: " + _In_ProcessName + " With PID: " + _In_PID + "\n Details: [TID: " + _tid_v1 + "] with BaseAddress: " 
                     +_ETW_VirtualMemAllocDetails.Split(':')[7] + ","  + _ETW_VirtualMemAllocDetails.Split(':')[8]);
                iList5.SubItems.Add(_ETW_VirtualMemAllocDetails  + _ETW_VirtualMemAlloc_Process_Path_PID + _ETW_DetectionNumbers + "\nMemory Bytes: " + "\n" + _Detected_Payload_fromb64);
                iList5.ImageIndex = 2;

                ThreadStart __T2_info_for_additems_to_Listview5 = new ThreadStart(delegate { BeginInvoke(new __Additem(_Additems_toListview5), iList5); });
                Thread _T2_for_additems_to_Listview5 = new Thread(__T2_info_for_additems_to_Listview5);
                _T2_for_additems_to_Listview5.Start();

                BeginInvoke(new __AddTextTorichtexhbox1(Update_listbox1_scanner_logs), "[VirtualMemAllocMon.exe], bytes In-Memory Detected by ETW => PID:" + _In_PID.ToString());
                BeginInvoke(new __AddTextTorichtexhbox1(Update_listbox1_scanner_logs), "[VirtualMemAllocMon.exe], bytes In-Memory Found => " + _ETW_DetectionNumbers.ToString() + " in PID:" + _In_PID.ToString()+"");

                // BeginInvoke(new __Additem(_Additems_toListview5), iList5);

                Thread.Sleep(100);
                
                /// add log to System/Detection_log Tab
                System_Detection_Log_events.Invoke((object)iList5, null);

            }
            catch (Exception)
            {

              
            }
           

        }


        public void Form1_NewEventFrom_EventLogsCome(object sender, EventArgs e)
        {
            ListViewItem MyLviewItemsX = (ListViewItem)sender;
            try
            {
                ThreadStart __T1_info_for_additems_to_Listview1 = new ThreadStart(delegate { BeginInvoke(new __Additem(_Additems_toListview1), MyLviewItemsX); });
                Thread _T1_for_additems_to_Listview1 = new Thread(__T1_info_for_additems_to_Listview1);
                _T1_for_additems_to_Listview1.Start();

            }
            catch (Exception ee)
            {
               

            }
        }


        private void Form1_RemoteThreadInjectionDetection_ProcessLists(object sender, EventArgs e)
        {
            try
            {

                if (sender.ToString().Split('@')[0].Contains("8"))
                {

                    //CreateRemoteThread detected:
                    //RuleName: -
                    //UtcTime: 2022 - 01 - 17 18:16:52.948
                    //SourceProcessGuid: { 3854 02f00}
                    //SourceProcessId: 8044
                    //SourceImage: C:\NativePayload_Tinjection\NativePayload_Tinjection\bin\Debug\NativePayload_Tinjection.exe
                    //TargetProcessGuid: { 385  000000002f00}
                    //TargetProcessId: 12716
                    //TargetImage: C:\Windows\System32\mspaint.exe
                    //NewThreadId: 6532
                    //StartAddress: 0x0000013703FD0000
                    //StartModule: -
                    //StartFunction: -
                    //SourceUser: 
                    //TargetUser: 



                    string EventMessage = sender.ToString().Split('@')[1];
                    string PName_PID = sender.ToString().Split('\n')[7].Split(':')[1];
                    PName_PID = PName_PID.Substring(1, PName_PID.Length - 2);

                    Injectortmp = "";
                    Tempops = "";

                    string pn = EventMessage.Split('\n')[8].Split('\n')[0];
                    pn = pn.Substring(0, pn.Length - 1);

                    string pt = EventMessage.Split('\n')[2];
                    pt = pt.Substring(0, pt.Length - 1);

                    string pt_injector = EventMessage.Split('\n')[5];
                    pt_injector = pt_injector.Substring(0, pt_injector.Length - 1);

                    try
                    {


                        Process_Table.Add(new _TableofProcess
                        {

                            PID = Convert.ToInt32(PName_PID),
                            ProcessName = pn.Substring(13),
                            Description = EventMessage,
                            Injector_Path = pt_injector,
                            Injector = Convert.ToInt32(EventMessage.Split('\n')[4].Split(':')[1]),
                            ProcessName_Path = pn.Substring(13),
                            IsLive = true,
                            TCPDetails = "null",
                            IsShow = false,
                            SysMonEventId8_25 = 8,
                            TID = Convert.ToInt32(EventMessage.Split('\n')[9].Split(':')[1]),
                            StartAddress_of_TID = EventMessage.Split('\n')[10].Split(':')[1]
                        });
                    }
                    catch (Exception ff)
                    {


                    }
                    try
                    {


                        if (_Sysmon_Events_Counts.Exists(_xPID => _xPID.PID == Convert.ToInt32(PName_PID)))
                        {

                            string Procesname_path = pn.Substring(13);
                            Int32 Pid = Convert.ToInt32(PName_PID);
                            string evt_time = pt.Substring(8);
                            Temp_Table_structure = new _TableofProcess_Sysmon_Event_Counts();
                            Temp_Table_structure.PID = Pid;
                            Temp_Table_structure.lastEventtime = evt_time;
                            Temp_Table_structure.ProcNameANDPath = Procesname_path;
                            Temp_Table_structure._LastTCP_Details = _Sysmon_Events_Counts[_Sysmon_Events_Counts.FindIndex(__PID => __PID.PID == Pid)]._LastTCP_Details;
                            Temp_Table_structure._RemoteThreadInjection_count = _Sysmon_Events_Counts[_Sysmon_Events_Counts.FindIndex(__PID => __PID.PID == Pid)]._RemoteThreadInjection_count + 1;
                            Temp_Table_structure._TCPSend_count = _Sysmon_Events_Counts[_Sysmon_Events_Counts.FindIndex(__PID => __PID.PID == Pid)]._TCPSend_count;
                            Temp_Table_structure.CommandLine = _Sysmon_Events_Counts[_Sysmon_Events_Counts.FindIndex(__PID => __PID.PID == Pid)].CommandLine;

                            _Sysmon_Events_Counts[_Sysmon_Events_Counts.FindIndex(__PID => __PID.PID == Pid)] = Temp_Table_structure;
                        }
                        else
                        {

                            //string Procesname_path = EventMessage.Split('\n')[9].Split(' ')[1];
                            string Procesname_path = pn.Substring(13);
                            Int32 Pid = Convert.ToInt32(PName_PID);
                            string evt_time = pt.Substring(8);
                            //string evt_time = "";
                            Temp_Table_structure = new _TableofProcess_Sysmon_Event_Counts();
                            Temp_Table_structure.PID = Pid;
                            Temp_Table_structure.lastEventtime = evt_time;
                            Temp_Table_structure.ProcNameANDPath = Procesname_path;
                            Temp_Table_structure._LastTCP_Details = "";
                            Temp_Table_structure._RemoteThreadInjection_count = 1;
                            Temp_Table_structure._TCPSend_count = 0;
                            Temp_Table_structure.CommandLine = "";
                            _Sysmon_Events_Counts.Add(Temp_Table_structure);

                        }
                    }
                    catch (Exception ff)
                    {

                    }
                }

                if (sender.ToString().Split('@')[0].Contains("25"))
                {
                    //Process Tampering:
                    //RuleName: -
                    //UtcTime: 2022 - 01 - 20 18:02:55.740
                    //ProcessGuid: { 385 00}
                    //ProcessId: 6276
                    //Image: C:\Windows\System32\notepad.exe
                    //Type: Image is replaced
                    //User: 

                    string EventMessage = sender.ToString().Split('@')[1];

                    string PName_PID = sender.ToString().Split('\n')[4].Split(':')[1];
                    PName_PID = PName_PID.Substring(1, PName_PID.Length - 2);

                    Injectortmp = "";
                    Tempops = "";


                    string pn = EventMessage.Split('\n')[5].Split('\n')[0];
                    pn = pn.Substring(0, pn.Length - 1);


                    string pt = EventMessage.Split('\n')[2];
                    pt = pt.Substring(0, pt.Length - 1);


                    Process_Table.Add(new _TableofProcess
                    {

                        PID = Convert.ToInt32(PName_PID),
                        ProcessName = pn.Substring(7),
                        Description = EventMessage,
                        Injector_Path = "--",
                        Injector = -1,
                        ProcessName_Path = pn.Substring(7),
                        IsLive = true,
                        TCPDetails = "null",
                        IsShow = false,
                        SysMonEventId8_25 = 25,
                        TID = -1,
                        StartAddress_of_TID = "--"

                    });

                    try
                    {


                        if (_Sysmon_Events_Counts.Exists(_xPID => _xPID.PID == Convert.ToInt32(PName_PID)))
                        {

                            string Procesname_path = pn.Substring(7);
                            Int32 Pid = Convert.ToInt32(PName_PID);
                            string evt_time = pt.Substring(8);
                            Temp_Table_structure = new _TableofProcess_Sysmon_Event_Counts();
                            Temp_Table_structure.PID = Pid;
                            Temp_Table_structure.lastEventtime = evt_time;
                            Temp_Table_structure.ProcNameANDPath = Procesname_path;
                            Temp_Table_structure._LastTCP_Details = _Sysmon_Events_Counts[_Sysmon_Events_Counts.FindIndex(__PID => __PID.PID == Pid)]._LastTCP_Details;
                            Temp_Table_structure._RemoteThreadInjection_count = _Sysmon_Events_Counts[_Sysmon_Events_Counts.FindIndex(__PID => __PID.PID == Pid)]._RemoteThreadInjection_count + 1;
                            Temp_Table_structure._TCPSend_count = _Sysmon_Events_Counts[_Sysmon_Events_Counts.FindIndex(__PID => __PID.PID == Pid)]._TCPSend_count;
                            Temp_Table_structure.CommandLine = _Sysmon_Events_Counts[_Sysmon_Events_Counts.FindIndex(__PID => __PID.PID == Pid)].CommandLine;

                            _Sysmon_Events_Counts[_Sysmon_Events_Counts.FindIndex(__PID => __PID.PID == Pid)] = Temp_Table_structure;
                        }
                        else
                        {

                            string Procesname_path = pn.Substring(7);
                            Int32 Pid = Convert.ToInt32(PName_PID);
                            string evt_time = pt.Substring(8);
                            Temp_Table_structure = new _TableofProcess_Sysmon_Event_Counts();
                            Temp_Table_structure.PID = Pid;
                            Temp_Table_structure.lastEventtime = evt_time;
                            Temp_Table_structure.ProcNameANDPath = Procesname_path;
                            Temp_Table_structure._LastTCP_Details = "";
                            Temp_Table_structure._RemoteThreadInjection_count = 1;
                            Temp_Table_structure._TCPSend_count = 0;
                            Temp_Table_structure.CommandLine = "";
                            _Sysmon_Events_Counts.Add(Temp_Table_structure);

                        }
                    }
                    catch (Exception ff)
                    {


                    }
                }
            }
            catch (Exception ohwoOwwtfk)
            {

            }
        }


        private void Form1_NewProcessAddedtolist_NewProcessEvt(object sender, EventArgs e)
        {
            try
            {
                //Process Create:
                //RuleName: -
                //UtcTime: 2022 - 01 - 17 18:16:38.489
                //ProcessGuid: { 3854e6f8 - b286 - 61e5 - 2c06 - 000000002f00}
                //ProcessId: 5220
                //Image: C:\VirtualMemAllocMonv1.1\VirtualMemAllocMon\VirtualMemAllocMon\bin\Debug\VirtualMemAllocMon.exe
                //FileVersion: 1.0.0.0
                //Description: VirtualMemAllocMon
                //Product: VirtualMemAllocMon
                //Company: Microsoft
                //OriginalFileName: VirtualMemAllocMon.exe
                //CommandLine: "C:\VirtualMemAllocMonv1.1\VirtualMemAllocMon\VirtualMemAllocMon\bin\Debug\VirtualMemAllocMon.exe"
                //CurrentDirectory: C:\Users\source\repos\VirtualMemAllocMonv1.1\VirtualMemAllocMon\VirtualMemAllocMon\bin\Debug\
                //User:  
                //LogonGuid: { 36f8 - 8a79 0000}
                //LogonId:  
                //TerminalSessionId: 
                //IntegrityLevel:  
                //Hashes: MD5 = 0A5ADC ED6D9C744
                //ParentProcessGuid: { 385 000002f00}
                //ParentProcessId: 6212
                //ParentImage: C:\Windows\explorer.exe
                //ParentCommandLine: C:\Windows\Explorer.EXE
                //ParentUser: 

                string[] all = sender.ToString().Split('\n');
                string tmp_processname = "";

                string pn = all[5];
                pn = pn.Substring(0, pn.Length - 1);
                string pt = all[2];
                pt = pt.Substring(0, pt.Length - 1);

                if ((all[10].ToString().Split(':')[1].Contains(" -")) && (!all[10].ToString().Split(':')[1].Contains(".exe")))
                {
                    string pn1 = all[11];
                    pn1 = pn1.Substring(0, pn1.Length - 1);
                    tmp_processname = pn1.Substring(13);
                }
                else
                {
                    string pn1 = all[10];
                    pn1 = pn1.Substring(0, pn1.Length - 1);
                    tmp_processname = pn1.Substring(18);
                }

                string _1 = all[4].Split(':')[1].Split('\r')[0];
                string _2 = all[20].Split(':')[1].Split('\r')[0];
                string _PPID_Path = all[21].Substring(13);
                string ___PPID_Path = _PPID_Path.Substring(0, _PPID_Path.Length - 1);
                NewProcess_Table.Add(new _TableofProcess_NewProcess_evt
                {
                    ProcessName = tmp_processname
                    ,
                    ProcessName_Path = pn.Substring(7)
                    ,
                    PID = Convert.ToInt32(all[4].Split(':')[1].Split('\r')[0])
                    ,
                    CommandLine = all[11]
                    ,
                    PPID = Convert.ToInt32(all[20].Split(':')[1].Split('\r')[0])
                    ,
                    PPID_Path = ___PPID_Path
                });


                string Procesname_path = pn.Substring(7);
                Int32 Pid = Convert.ToInt32(all[4].Split(':')[1]);
                string evt_time = pt.Substring(8);
                Temp_Table_structure = new _TableofProcess_Sysmon_Event_Counts();
                Temp_Table_structure.PID = Pid;
                Temp_Table_structure.lastEventtime = evt_time;
                Temp_Table_structure.ProcNameANDPath = Procesname_path;
                Temp_Table_structure._LastTCP_Details = "--";
                Temp_Table_structure._RemoteThreadInjection_count = 0;
                Temp_Table_structure._TCPSend_count = 0;
                Temp_Table_structure.CommandLine = all[11];
                _Sysmon_Events_Counts.Add(Temp_Table_structure);


            }
            catch (Exception)
            {


            }

        }


        public void  Update_Charts_info()
        {
            try
            {                
                    Thread.Sleep(10);
                    _1 = _percent((int)Chart_NewProcess, ((int)Chart_Counts));
                    progressBar1.Value = _1;
                    groupBox1.Text = "New Processes events: " + Chart_NewProcess + " (" + _1 + "%)";

                    _2 = _percent((int)chart_Inj, ((int)Chart_Counts));
                    progressBar2.Value = _2;
                    groupBox2.Text = "Injection events: " + chart_Inj + " (" + _2 + "%)";

                    _3 = _percent((int)Chart_Tcp, ((int)Chart_Counts));
                    progressBar3.Value = _3;
                    groupBox3.Text = "TCP Send events: " + Chart_Tcp + " (" + _3 + "%)";

                    _4 = _percent((int)Chart_Redflag, ((int)Chart_Counts));
                    progressBar4.Value = _4;
                    groupBox4.Text = "Detection High: " + Chart_Redflag + " (" + _4 + "%)";

                    _5 = _percent((int)Chart_Orange, ((int)Chart_Counts));
                    progressBar5.Value = _5;
                    groupBox5.Text = "Detection Medium: " + Chart_Orange + " (" + _5 + "%)";

                    if (Chart_suspend == 0) groupBox6.ForeColor = Color.FromArgb(64, 64, 64);
                    _6 = _percent((int)Chart_suspend, ((int)Chart_Counts));
                    progressBar6.Value = _6;
                    groupBox6.Text = "Suspended Processes: " + Chart_suspend + " (" + _6 + "%)";
                    if (Chart_suspend > 0) groupBox6.ForeColor = Color.Red;

                    if (Chart_Terminate == 0) groupBox7.ForeColor = Color.FromArgb(64, 64, 64);
                    _7 = _percent((int)Chart_Terminate, ((int)Chart_Counts));
                    progressBar7.Value = _7;
                    groupBox7.Text = "Terminated Processes: " + Chart_Terminate + " (" + _7 + "%)";
                    if (Chart_Terminate > 0) groupBox7.ForeColor = Color.Red;

                    _8 = _percent((int)Chart_Counts, ((int)Chart_Counts));
                    progressBar8.Value = _8;
                    groupBox8.Text = "All Real-time events: " + Chart_Counts + " (" + _8 + "%)";
                    //Thread.Sleep(500);
                    /// <summary>
                    /// v0 => new process
                    /// v1 => injection count
                    /// v2 => tcp count
                    /// v3 => alarms by sysmon red count
                    /// v4 => alarms by sysmon orange count
                    /// v5 => suspended process by memory scanner
                    /// v6 => terminated proesses by memory scanner
                    /// v7 => All realtime events which made by ETWProcessMon2 in Windows Event logs (but this tool will not show all of them ;D because of filter for same/dublicated events etc...)
                    /// </summary>
                
            }
            catch (Exception err)
            {


            }
        }


        private void T2_Elapsed(object sender, System.Timers.ElapsedEventArgs e)
        {
            try
            {                
                BeginInvoke(new __Obj_Updater_to_WinForm(Update_Charts_info));              
            }
            catch (Exception err)
            {


            }
        }


        /// <summary>
        ///  bug here
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void Form1_NewProcessAddedtolist1(object sender, EventArgs e)
        {
            try
            {
                //Network connection detected:
                //RuleName: Usermode
                //UtcTime: 2 6.605
                //ProcessGuid: { 38  000003f00}
                //ProcessId: 8316
                //Image: C:\Windows\System32\mspaint.exe
                //User:  
                //Protocol: tcp
                //Initiated: true
                //SourceIsIpv6: false
                //SourceIp: 192.168.56.1
                //SourceHostname:  
                //SourcePort: 49722
                //SourcePortName: -
                //DestinationIsIpv6: false
                //DestinationIp: 192.168.56.101
                //DestinationHostname: -
                //DestinationPort: 4444
                //DestinationPortName: -

                //Network connection detected:
                //RuleName: Usermode
                //UtcTime: 2 2:22.628
                //ProcessGuid: { 3800}
                //ProcessId: 3152
                //Image: C:\Windows\System32\mspaint.exe
                //User:  
                //Protocol: tcp
                //Initiated: true
                //SourceIsIpv6: false
                //SourceIp: 192.168.56.1
                //SourceHostname:  
                //SourcePort: 49780
                //SourcePortName: -
                //DestinationIsIpv6: false
                //DestinationIp: 192.168.56.101
                //DestinationHostname: -
                //DestinationPort: 4444
                //DestinationPortName: -



                string PName_PID = sender.ToString().Split('@')[0];
                string tcpdetails = sender.ToString().Split('@')[1];

                subitemX = "Injection";
                bool foundinlist = false;
                string lastshow = "";
                Int32 PID = Convert.ToInt32(PName_PID.Split('>')[1]);

                string ProcessName = PName_PID.Split('>')[0];
                string _des_address_port = tcpdetails.Split('\n')[15].Split(':')[1] + ":" + tcpdetails.Split('\n')[17].Split(':')[1];

                string Procesname_path = ProcessName;
                Int32 Pid = PID;

                string pt = tcpdetails.Split('\n')[2];
                pt = pt.Substring(0, pt.Length - 1);

                Temp_Table_structure = new _TableofProcess_Sysmon_Event_Counts();

                try
                {


                    if (_Sysmon_Events_Counts.Exists(_xPID => _xPID.PID == PID))
                    {
                        Temp_Table_structure.PID = Pid;
                        Temp_Table_structure.lastEventtime = pt.Substring(8);
                        Temp_Table_structure.ProcNameANDPath = Procesname_path;
                        Temp_Table_structure._LastTCP_Details = _des_address_port;
                        Temp_Table_structure._RemoteThreadInjection_count = _Sysmon_Events_Counts[_Sysmon_Events_Counts.FindIndex(__PID => __PID.PID == Pid)]._RemoteThreadInjection_count;
                        Temp_Table_structure._TCPSend_count = _Sysmon_Events_Counts[_Sysmon_Events_Counts.FindIndex(__PID => __PID.PID == Pid)]._TCPSend_count + 1;
                        Temp_Table_structure.CommandLine = _Sysmon_Events_Counts[_Sysmon_Events_Counts.FindIndex(__PID => __PID.PID == Pid)].CommandLine;

                        _Sysmon_Events_Counts[_Sysmon_Events_Counts.FindIndex(__PID => __PID.PID == Pid)] = Temp_Table_structure;
                    }
                    else
                    {
                        Temp_Table_structure.PID = Pid;
                        Temp_Table_structure.lastEventtime = pt.Substring(8);
                        Temp_Table_structure.ProcNameANDPath = Procesname_path;
                        Temp_Table_structure._LastTCP_Details = _des_address_port;
                        Temp_Table_structure._RemoteThreadInjection_count = 0;
                        Temp_Table_structure._TCPSend_count = 1;
                        Temp_Table_structure.CommandLine = "";

                        _Sysmon_Events_Counts.Add(Temp_Table_structure);
                    }
                }
                catch (Exception err2)
                {

                 
                }

                if (Process_Table.Find(x => x.PID == PID && x.ProcessName == ProcessName).TCPDetails == "null")
                {
                    List<_TableofProcess> _Table = Process_Table.FindAll(x => x.PID == PID && x.ProcessName == ProcessName);

                    foreach (_TableofProcess item in _Table)
                    {
                        if (item.ProcessName + ":" + item.PID + item.ProcessName_Path + item.Injector_Path + item.Injector.ToString() != tmplasttcpevent)
                        {

                            iList2 = new ListViewItem();

                            /// pe-sieve64.exe scanner
                            _finalresult_Scanned_01 = executeutilities_01(item.PID.ToString(), item.ProcessName_Path, item.Injector_Path + ":" + item.Injector.ToString());

                            Thread.Sleep(100);
                            _finalresult_Scanned_02[2] = "-+";

                            /// hollowshunter.exe scanner
                            _finalresult_Scanned_02 = executeutilities_02(item.PID.ToString(), item.ProcessName_Path, item.Injector_Path + ":" + item.Injector.ToString());

                            iList2.Name = item.ProcessName + ":" + item.PID + ">\n" + _finalresult_Scanned_01[1] + _finalresult_Scanned_02[1]
                                + "\n-------------------\nScanner Result/Status: " + _finalresult_Scanned_02[2];
                            iList2.SubItems.Add(DateTime.Now.ToString());
                            iList2.SubItems.Add(item.ProcessName + ":" + item.PID.ToString());

                            if (isPEScanonoff != false)
                            {
                                if (_finalresult_Scanned_01[0].Contains("Replaced:0"))
                                {

                                    iList2.ImageIndex = 1;
                                    if (!_finalresult_Scanned_01[0].Contains("PE:0") && !_finalresult_Scanned_01[0].Contains("shc:0"))
                                    {
                                        iList2.ImageIndex = 2;
                                    }
                                    else if (!_finalresult_Scanned_01[0].Contains("PE:0") || !_finalresult_Scanned_01[0].Contains("shc:0"))
                                    {
                                        iList2.ImageIndex = 1;
                                    }
                                }
                                if (!(_finalresult_Scanned_01[0].Contains("Replaced:0")))
                                {
                                    if (_finalresult_Scanned_01[0] != "[error not found pe-sieve64.exe[not scanned:0]")
                                    {
                                        iList2.ImageIndex = 2;
                                    }
                                    else if (_finalresult_Scanned_01[0] == "[error not found pe-sieve64.exe[not scanned:0]")
                                    {
                                        subitemX = "Injection";
                                        iList2.ImageIndex = 1;
                                    }
                                }
                            }

                            if (isHollowHunteronoff)
                            {

                                if (_finalresult_Scanned_02[0].Contains("Detected:"))
                                {

                                    subitemX = "Injection";
                                    iList2.ImageIndex = 2;
                                    if (isPEScanonoff && (!_finalresult_Scanned_01[0].Contains("Replaced:0")) && (!_finalresult_Scanned_01[0].Contains("not scanned:0")))
                                    {
                                        subitemX = "Process-Hollowing";
                                        iList2.ImageIndex = 2;
                                    }
                                }
                                else if (!_finalresult_Scanned_02[0].Contains("Detected:"))
                                {
                                    subitemX = "Injection";
                                    iList2.ImageIndex = 2;

                                }

                                if (_finalresult_Scanned_02[0].Contains(">>NotDetected:"))
                                {
                                    subitemX = "Injection";
                                    iList2.ImageIndex = 1;
                                }

                            }

                            if (isHollowHunteronoff == false && isPEScanonoff == false)
                            {
                                subitemX = "Injection";
                                iList2.ImageIndex = 1;
                            }

                            if (!_finalresult_Scanned_01[0].Contains("Replaced:0") && (!_finalresult_Scanned_01[0].Contains("not scanned:0")))
                            {
                                if (isPEScanonoff)
                                {

                                    subitemX = "Process-Hollowing";
                                    iList2.ImageIndex = 2;

                                }
                            }
                            if (_finalresult_Scanned_02[0].Contains("not scanned:0"))
                            {
                                subitemX = "Injection";
                                iList2.ImageIndex = 1;
                            }

                            /// injection type
                            iList2.SubItems.Add(subitemX);
                            /// tcp send info
                            iList2.SubItems.Add(_des_address_port.Replace('\r', ' ').Replace('\n', ' '));
                            /// status for suspend/terminate by hollowshunter
                            iList2.SubItems.Add(_finalresult_Scanned_02[2]);
                            /// detection info by pe-sieve64
                            iList2.SubItems.Add(_finalresult_Scanned_01[0]);
                            /// detection info by hollowshunter
                            iList2.SubItems.Add(_finalresult_Scanned_02[0]);


                            /// injection description && / || [bug] (fiXed)
                            if (item.SysMonEventId8_25 == 8)
                            {
                                _TableofProcess_NewProcess_evt FindingInjectorInfo = NewProcess_Table.Find(x => x.PID == item.Injector || x.ProcessName_Path == item.Injector_Path);

                                _InjectedThreadDetails_bytes _injecthedthreadinfo = _InjectedTIDList.Find(_tthread => _tthread._InjectorPID == item.Injector
                                && _tthread._RemoteThreadID == item.TID && _tthread._ThreadStartAddress == item.StartAddress_of_TID.Split('x')[1].Split('\r')[0]);
                                string _Threadsadd = ((_InjectedThreadDetails_bytes) _injecthedthreadinfo)._ThreadStartAddress.ToString();

                                iList2.SubItems.Add(item.ProcessName_Path +
                                    " Injected by => " +
                                    " (PID:" + item.Injector.ToString()
                                    + ") \nInjector Details:\nInjector-ProcessName: "
                                    + FindingInjectorInfo.ProcessName + "\nInjector-Path: " + FindingInjectorInfo.ProcessName_Path
                                    + "\nInjected ThreadID:" + item.TID.ToString()
                                    + "\nInjected Thread StartAddress:" + _Threadsadd
                                    + "\nInjector " + FindingInjectorInfo.CommandLine);


                                /// ETW Event message for injection which is Description value 
                                _TableofProcess RelatedEvt_Description = Process_Table.Find(x => x.PID == PID && x.ProcessName == ProcessName && x.StartAddress_of_TID.Split('x')[1].Split('\r')[0] == _Threadsadd);
                                //&& x.Description.Contains(":" + item.Injector.ToString() + "[Injected by "));
                                iList2.SubItems.Add(RelatedEvt_Description.Description);
                            }
                            else if (item.SysMonEventId8_25 == 25)
                            {
                                iList2.SubItems.Add("");
                                /// event id 25 has not good description ;)
                                iList2.SubItems.Add(item.Description);
                            }
                            

                            foreach (string ShowItems in showitemsHash)
                            {

                                if (ShowItems == item.ProcessName + ":" + item.PID.ToString() + _des_address_port + _finalresult_Scanned_01[0] +
                               item.ProcessName_Path + " Injected by => " + item.Injector_Path + " (PID:" + item.Injector.ToString() + ") ")
                                {
                                    foundinlist = true;
                                    break;
                                }
                            }
                            if (!foundinlist)
                            {
                                if (Init_to_runPEScanner_01 || Init_to_runPEScanner_02)
                                {
                                   
                                    BeginInvoke(new __Additem(_Additems_toListview2), iList2);

                                    if (iList2.ImageIndex == 1) { Chart_Orange++; }
                                    else if (iList2.ImageIndex == 2) { Chart_Redflag++; }

                                    /// add log to System/Detection_log Tab
                                    System_Detection_Log_events.Invoke((object)iList2, null);

                                }

                                showitemsHash.Add(item.ProcessName + ":" + item.PID.ToString() + _des_address_port + _finalresult_Scanned_01[0] +
                               item.ProcessName_Path + " Injected by => " + item.Injector_Path + " (PID:" + item.Injector.ToString() + ") ");
                                Thread.Sleep(10);

                            }

                            tmplasttcpevent = item.ProcessName + ":" + item.PID + item.ProcessName_Path + item.Injector_Path + item.Injector.ToString();

                            lastshow = item.ProcessName + ":" + item.PID.ToString() + _des_address_port + _finalresult_Scanned_01[0] +
                                item.ProcessName_Path + " Injected by => " + item.Injector_Path + " (PID:" + item.Injector.ToString() + ") ";

                        }
                    }
                }
            }
            catch (Exception err)
            {

                
            }
           
        }


        public string[] executeutilities_01(string pid, string InProcessName_Path, string _injectorPathPid)
        {

            try
            {

                Init_to_runPEScanner_01 = false;
                strOutput = "";

                if (isPEScanonoff)
                {
                    outputs = new System.Diagnostics.Process();

                    List<_TableofProcess_Scanned_01> resultPEScanned = Scanned_PIds.FindAll(PEScan => PEScan.PID == Convert.ToInt32(pid) && PEScan.ProcNameANDPath == InProcessName_Path && PEScan.injectorPathPID == _injectorPathPid);

                    if (resultPEScanned.Count == 0)
                    {
                        /// new pe scan
                        Init_to_runPEScanner_01 = true;
                    }

                    if (ScannerEvery10minMode_Pesieve)
                    {

                        /// check time of last scan >= 10mins or > 1hour + remove + add
                        /// breaking loop for Scanning all PE everytimes ;) not really good code is here but is better than nothing lol
                        int _now_min = DateTime.Now.Minute;
                        int _now_Hour = DateTime.Now.Hour;
                        if (_now_min - resultPEScanned[0].time_min >= 10 || _now_Hour - resultPEScanned[0].time_Hour != 0)
                        {
                            Init_to_runPEScanner_01 = true;
                            Scanned_PIds.Remove(new _TableofProcess_Scanned_01 { PID = Convert.ToInt32(pid) });
                        }
                        else if (_now_min - resultPEScanned[0].time_min < 10 || _now_Hour - resultPEScanned[0].time_Hour == 0)
                        {
                            Init_to_runPEScanner_01 = false;
                        }
                    }

                    if (ScannerMixedMode_Pesieve)
                    {
                        /// remove both for sure make new pe scan
                        foreach (_TableofProcess_Scanned_01 item in resultPEScanned)
                        {
                            Scanned_PIds.Remove(new _TableofProcess_Scanned_01 { PID = item.PID });
                        }
                        Init_to_runPEScanner_01 = true;
                    }

                    string result1 = "";
                    if (Init_to_runPEScanner_01)
                    {
                        if (File.Exists("pe-sieve64.exe"))
                        {
                            try
                            {
                                if (!Process.GetProcessById(Convert.ToInt32(pid)).HasExited)
                                {
                                    outputs.StartInfo.FileName = "pe-sieve64.exe";
                                    outputs.StartInfo.Arguments = "/shellc /iat 2 /pid " + pid;
                                    BeginInvoke(new __AddTextTorichtexhbox1(Update_listbox1_scanner_logs), "[pe-sieve64.exe], Start Scanning => PID:" + pid.ToString());

                                    if (pe_sieve_DumpSwitches == 0) { outputs.StartInfo.Arguments = "/shellc /iat 2 /pid " + pid; }
                                    else if (pe_sieve_DumpSwitches == 1) { outputs.StartInfo.Arguments = "/ofilter 1 /shellc /iat 2 /pid " + pid; }
                                    else if (pe_sieve_DumpSwitches == 2) { outputs.StartInfo.Arguments = "/ofilter 2 /shellc /iat 2 /pid " + pid; }


                                    outputs.StartInfo.CreateNoWindow = true;
                                    outputs.StartInfo.UseShellExecute = false;
                                    outputs.StartInfo.RedirectStandardOutput = true;
                                    outputs.StartInfo.RedirectStandardInput = true;
                                    outputs.StartInfo.RedirectStandardError = true;

                                    outputs.Start();

                                    /// scanner logs
                                    BeginInvoke(new __AddTextTorichtexhbox1(Update_listbox1_scanner_logs), "[pe-sieve64.exe], Scanner Running => " + outputs.StartInfo.FileName + " " + outputs.StartInfo.Arguments);

                                    strOutput = outputs.StandardOutput.ReadToEnd();
                                    string temp1, temp2, temp3, temp4 = "";

                                    try
                                    {
                                        temp1 = strOutput.Substring(strOutput.IndexOf("Implanted PE:")).Split('\n')[0];
                                        temp2 = strOutput.Substring(strOutput.IndexOf("Implanted shc:")).Split('\n')[0];
                                        temp3 = strOutput.Substring(strOutput.IndexOf("Replaced:")).Split('\n')[0];
                                    }
                                    catch (Exception)
                                    {

                                        temp1 = strOutput.Substring(strOutput.IndexOf("Implanted:")).Split('\n')[0];
                                        temp2 = "";
                                        temp3 = strOutput.Substring(strOutput.IndexOf("Replaced:")).Split('\n')[0];
                                    }
                                    try
                                    {
                                        /// find "hooked or patched in report"
                                        temp4 = strOutput.Substring(strOutput.IndexOf("Hooked:")).Split('\n')[0];
                                    }
                                    catch (Exception)
                                    {

                                    }
                                    result1 = "[" + temp1 + "][" + temp2 + "][" + temp3 + "]" + "[" + temp4 + "]";

                                    string result2 = "";
                                    foreach (char item in result1)
                                    {
                                        if (item != ' ')
                                            result2 += item;
                                    }

                                    BeginInvoke(new __AddTextTorichtexhbox1(Update_listbox1_scanner_logs), "[pe-sieve64.exe], Scanner output [ProcessId " + pid.ToString() + "]=> " + result2.Split('\r')[0] + result2.Split('\r')[1] + result2.Split('\r')[2]);

                                    finalresult_Scanned_01[0] = result2;
                                    finalresult_Scanned_01[1] = strOutput;
                                }
                                else
                                {
                                    finalresult_Scanned_01[0] = "[error not found Target Process[not scanned:0]";
                                    finalresult_Scanned_01[1] = "[error not found Target Process[not scanned:0]";
                                }
                            }
                            catch (Exception error)
                            {


                            }
                        }
                        else
                        {
                            finalresult_Scanned_01[0] = "[error not found pe-sieve64.exe[not scanned:0]";
                            finalresult_Scanned_01[1] = "[error not found pe-sieve64.exe[not scanned:0]";
                        }

                        if (!Scanned_PIds.Exists(scanned => scanned.PID == Convert.ToInt32(pid) && scanned.injectorPathPID == _injectorPathPid))
                        {
                            Scanned_PIds.Add(new _TableofProcess_Scanned_01
                            {
                                time_Hour = DateTime.Now.Hour,
                                time_min = DateTime.Now.Minute,
                                PID = Convert.ToInt32(pid),
                                ProcNameANDPath = InProcessName_Path,
                                injectorPathPID = _injectorPathPid
                            });
                        }
                        return finalresult_Scanned_01;
                    }
                    else
                    {
                        finalresult_Scanned_01[0] = "[not scanned:0]";
                        finalresult_Scanned_01[1] = "[not scanned:0]";
                        return finalresult_Scanned_01;
                    }
                }
                else
                {
                    finalresult_Scanned_01[0] = "PEScanner-is-off";
                    finalresult_Scanned_01[1] = strOutput;
                    return finalresult_Scanned_01;
                }
            }
            catch (Exception)
            {
                return finalresult_Scanned_01;

            }



        }


        public string[] executeutilities_02(string pid, string InProcessName_Path, string _injectorPathPid)
        {
            Init_to_runPEScanner_02 = false;
            strOutput2 = "";
            if (isHollowHunteronoff)
            {
                finalresult_Scanned_02[2] = "--";
                string result1 = "";
                outputs2 = new System.Diagnostics.Process();

                List<_TableofProcess_Scanned_02> resultPEScanned = Scanned_PIds2.FindAll(PEScan => PEScan.PID == Convert.ToInt32(pid) && PEScan.ProcNameANDPath == InProcessName_Path && PEScan.injectorPathPID == _injectorPathPid);

                if (resultPEScanned.Count == 0)
                {
                    /// new pe scan
                    Init_to_runPEScanner_02 = true;
                }
                else if (resultPEScanned.Count == 1)
                {
                    /// check time of last scan >= 10mins or > 1hour + remove + add
                    /// breaking loop for Scanning all PE via HollowHunter.exe everytimes ;) not really good code is here but is better than nothing lol
                    int _now_min = DateTime.Now.Minute;
                    int _now_Hour = DateTime.Now.Hour;
                    if (_now_min - resultPEScanned[0].time_min >= 10 || _now_Hour - resultPEScanned[0].time_Hour != 0)
                    {
                        Init_to_runPEScanner_02 = true;
                        Scanned_PIds2.Remove(new _TableofProcess_Scanned_02 { PID = Convert.ToInt32(pid) });
                    }
                    else if (_now_min - resultPEScanned[0].time_min < 10 || _now_Hour - resultPEScanned[0].time_Hour == 0)
                    {
                        Init_to_runPEScanner_02 = false;
                    }
                }
                else if (resultPEScanned.Count >= 2)
                {
                    /// remove both for sure make new pe scan
                    foreach (_TableofProcess_Scanned_02 item in resultPEScanned)
                    {
                        Scanned_PIds2.Remove(new _TableofProcess_Scanned_02 { PID = item.PID });
                    }
                    Init_to_runPEScanner_02 = true;
                }

                if (Init_to_runPEScanner_02)
                {
                    if (File.Exists("hollows_hunter64.exe"))
                    {
                        BeginInvoke(new __AddTextTorichtexhbox1(Update_listbox1_scanner_logs), "[hollows_hunter64.exe], Start Scanning => PID:" + pid.ToString()); ;

                        outputs2.StartInfo.FileName = "hollows_hunter64.exe";
                        if (HollowHunterLevel == 0)
                        {
                            outputs2.StartInfo.Arguments = "/pid " + pid;
                            finalresult_Scanned_02[2] = "Scanned";

                        }
                        else if (HollowHunterLevel == 1)
                        {
                            outputs2.StartInfo.Arguments = "/suspend /pid " + pid;
                            finalresult_Scanned_02[2] = "Scanned";
                        }
                        else if (HollowHunterLevel == 2)
                        {
                            outputs2.StartInfo.Arguments = "/kill /pid " + pid;
                            finalresult_Scanned_02[2] = "Scanned";
                        }

                        if (hollowshunter_DumpSwitches == 1)
                        { outputs2.StartInfo.Arguments = "/ofilter 1 " + outputs2.StartInfo.Arguments; }
                        else if (hollowshunter_DumpSwitches == 2)
                        { outputs2.StartInfo.Arguments = "/ofilter 2 " + outputs2.StartInfo.Arguments; }

                        outputs2.StartInfo.CreateNoWindow = true;
                        outputs2.StartInfo.UseShellExecute = false;
                        outputs2.StartInfo.RedirectStandardOutput = true;
                        outputs2.StartInfo.RedirectStandardInput = true;
                        outputs2.StartInfo.RedirectStandardError = true;

                        outputs2.Start();
                        BeginInvoke(new __AddTextTorichtexhbox1(Update_listbox1_scanner_logs), "[hollows_hunter64.exe], Scanner Running => " + outputs2.StartInfo.FileName + " " + outputs2.StartInfo.Arguments);

                        strOutput2 = outputs2.StandardOutput.ReadToEnd();

                        /// check detection via Hollow_Hunter.exe result ...
                        if (strOutput2.Contains(">> Detected:"))
                        {

                            result1 = "[" + strOutput2.Substring(strOutput2.IndexOf("suspicious")).Split('\n')[0] + " ," +
                                strOutput2.Substring(strOutput2.IndexOf(">> Detected:")).Split('\n')[0]
                                  + " [" + strOutput2.Substring(strOutput2.IndexOf("Finished scan in:") + 8).Split('\n')[0] + "]";

                            if (strOutput2.ToString().Contains(">> Detected:"))
                            {
                                if (HollowHunterLevel == 2)
                                {
                                    Chart_Terminate++;
                                    finalresult_Scanned_02[2] = "Terminated";
                                }
                                else if (HollowHunterLevel == 1)
                                {
                                    Chart_suspend++;
                                    finalresult_Scanned_02[2] = "Suspended";

                                }
                                else if (HollowHunterLevel == 0)
                                {
                                    finalresult_Scanned_02[0] = "";
                                    finalresult_Scanned_02[1] = "";
                                    finalresult_Scanned_02[2] = "Scanned & Found!";
                                }
                            }
                        }
                        else if (!strOutput2.Contains(">> Detected:"))
                        {
                            result1 = "[" + strOutput2.Substring(strOutput2.IndexOf("suspicious")).Split('\n')[0] + " ," +
                              ">> Not Detected:" + pid.ToString()
                                 + " [" + strOutput2.Substring(strOutput2.IndexOf("Finished scan in:") + 8).Split('\n')[0] + "]";
                        }

                        string result2 = "";
                        foreach (char item in result1)
                        {
                            if (item != ' ')
                                result2 += item;
                        }

                        BeginInvoke(new __AddTextTorichtexhbox1(Update_listbox1_scanner_logs), "[hollows_hunter64.exe], Scanner output [ProcessId " + pid.ToString() + "]=> " + result2.Split('\r')[0] + result2.Split('\r')[1] + result2.Split('\r')[2]);

                        if (strOutput2.Contains(">> Detected:") && HollowHunterLevel != 0)
                        {
                            if (HollowHunterLevel == 1) BeginInvoke(new __AddTextTorichtexhbox1(Update_listbox1_scanner_logs),
                                "[hollows_hunter64.exe], ProcessId => " + pid.ToString() + " Suspended!" + " Scanning in {" + result2.Split('\r')[0] + result2.Split('\r')[1] + result2.Split('\r')[2] + "}");

                            if (HollowHunterLevel == 2) BeginInvoke(new __AddTextTorichtexhbox1(Update_listbox1_scanner_logs),
                                "[hollows_hunter64.exe], ProcessId => " + pid.ToString() + " Terminated!" + " Scanning in {" + result2.Split('\r')[0] + result2.Split('\r')[1] + result2.Split('\r')[2] + "}");

                        }

                        finalresult_Scanned_02[0] = result2;
                        finalresult_Scanned_02[1] = strOutput2;
                    }
                    else
                    {
                        finalresult_Scanned_02[0] = "[error not found Hollowhunter.exe[not scanned:0]";
                        finalresult_Scanned_02[1] = "[error not found Hollowhunter.exe[not scanned:0]";
                        finalresult_Scanned_02[2] = "error";

                    }

                    Scanned_PIds2.Add(new _TableofProcess_Scanned_02
                    {
                        time_Hour = DateTime.Now.Hour,
                        time_min = DateTime.Now.Minute,
                        PID = Convert.ToInt32(pid),
                        ProcNameANDPath = InProcessName_Path,
                        injectorPathPID = _injectorPathPid
                    });

                    return finalresult_Scanned_02;
                }
                else
                {
                    finalresult_Scanned_02[0] = "[not scanned:0]";
                    finalresult_Scanned_02[1] = "[not scanned:0]";
                    finalresult_Scanned_02[2] = "[not scanned:0]";

                    return finalresult_Scanned_02;
                }
            }
            else
            {
                finalresult_Scanned_02[0] = "hollowhunter-is-off";
                finalresult_Scanned_02[1] = strOutput2;
                finalresult_Scanned_02[2] = "--";

                return finalresult_Scanned_02;
            }

        }


        public void UpdateRefreshListview1()
        {
            try
            {
                if (i6 != listView1.Items.Count - 1)
                {
                    try
                    {
                        listView1.FocusedItem = listView1.Items[listView1.Items.Count - 1];
                        listView1.BeginInvoke((MethodInvoker)delegate { listView1.FocusedItem.EnsureVisible(); });
                        i6 = listView1.Items.Count - 1;
                       
                    }
                    catch (Exception)
                    {


                    }
                }

            
            }
            catch (Exception)
            {


            }
        }


        private void T_Elapsed(object sender, System.Timers.ElapsedEventArgs e)
        {

            try
            {
                BeginInvoke(new __Updatelistview1(UpdateRefreshListview1));
               

            }
            catch (Exception)
            {


            }


        }


        public void Watcher_EventRecordWritten(object sender, EventRecordWrittenEventArgs e)
        {

            try
            {
                tempMessage2 = e.EventRecord.FormatDescription();

                if (e.EventRecord.Id == 1)
                {
                    if (e.EventRecord.FormatDescription() != string.Empty)
                    {
                        iList = new ListViewItem();
                        string tmp_processname = "";

                        if ((e.EventRecord.FormatDescription().ToString().Split('\n')[10].Split(':')[1].Contains("-")) && (!e.EventRecord.FormatDescription().ToString().Split('\n')[10].Split(':')[1].Contains(".exe")))
                        {

                            string pn1 = e.EventRecord.FormatDescription().ToString().Split('\n')[11];
                            pn1 = pn1.Substring(0, pn1.Length - 1);
                            tmp_processname = pn1.Substring(13);
                        }
                        else
                        {
                            string pn1 = e.EventRecord.FormatDescription().ToString().Split('\n')[10];
                            pn1 = pn1.Substring(0, pn1.Length - 1);
                            tmp_processname = pn1.Substring(18);
                        }

                        iList.Name = e.EventRecord.RecordId.ToString();
                        iList.SubItems.Add(e.EventRecord.TimeCreated.ToString());
                        iList.SubItems.Add(e.EventRecord.Id.ToString());

                        iList.SubItems.Add(tmp_processname
                       + ":" + e.EventRecord.FormatDescription().Substring(e.EventRecord.FormatDescription().IndexOf("ProcessId: ") + 11).Split('\n')[0]);
                        iList.SubItems.Add("[NEW]");
                        iList.SubItems.Add(e.EventRecord.FormatDescription());
                        iList.ImageIndex = 0;
                        LviewItemsX = iList;

                        Thread.Sleep(150);

                        NewProcessAddedtolist_NewProcessEvt.Invoke((object)e.EventRecord.FormatDescription(), null);
                        Chart_NewProcess++;

                        Thread.Sleep(100);

                        NewEventFrom_EventLogsCome.Invoke((object)LviewItemsX, null);
                    }
                }
                if (e.EventRecord.Id == 8)
                {
                    if (e.EventRecord.FormatDescription() != string.Empty)
                    {

                        iList = new ListViewItem();
                        iList.Name = e.EventRecord.RecordId.ToString();
                        iList.SubItems.Add(e.EventRecord.TimeCreated.ToString());
                        iList.SubItems.Add(e.EventRecord.Id.ToString());
                        iList.SubItems.Add(e.EventRecord.FormatDescription().Substring(
                            e.EventRecord.FormatDescription().IndexOf("TargetImage: ") + 13).Split('\n')[0]
                            + ":" + e.EventRecord.FormatDescription().Substring(e.EventRecord.FormatDescription().IndexOf("TargetProcessId: ") + 17).Split('\n')[0]);
                        iList.SubItems.Add("[INJ]");
                        iList.SubItems.Add(e.EventRecord.FormatDescription());
                        iList.ImageIndex = 1;

                        LviewItemsX = iList;
                        Thread.Sleep(250);
                        chart_Inj++;

                        RemoteThreadInjectionDetection_ProcessLists.Invoke(((object)"8" + "@" + e.EventRecord.FormatDescription()), null);

                        Thread.Sleep(100);

                        NewEventFrom_EventLogsCome.Invoke((object)LviewItemsX, null);

                    }
                }
                try
                {


                    if (e.EventRecord.Id == 3)
                    {
                        if (e.EventRecord.FormatDescription() != string.Empty)
                        {
                            iList = new ListViewItem();
                            tempMessage = e.EventRecord.FormatDescription();
                            iList.Name = e.EventRecord.RecordId.ToString();
                            iList.SubItems.Add(e.EventRecord.TimeCreated.ToString());
                            iList.SubItems.Add(e.EventRecord.Id.ToString());

                            iList.SubItems.Add(e.EventRecord.FormatDescription().Substring(e.EventRecord.FormatDescription().IndexOf("Image: ") + 7).Split('\n')[0]
                               + ":" + e.EventRecord.FormatDescription().Substring(e.EventRecord.FormatDescription().IndexOf("ProcessId: ") + 11).Split('\n')[0]);

                            iList.SubItems.Add("[TCP]");

                            iList.SubItems.Add(e.EventRecord.FormatDescription());
                            iList.ImageIndex = 0;

                            LviewItemsX = iList;

                            obj[0] = null;
                            obj[1] = null;

                            Thread.Sleep(150);

                            Chart_Tcp++;

                            string tmp1 = e.EventRecord.FormatDescription().Substring(e.EventRecord.FormatDescription().IndexOf("Image: ") + 7).Split('\n')[0];
                            tmp1 = tmp1.Substring(0, tmp1.Length - 1);
                            string tmp2 = e.EventRecord.FormatDescription().Substring(e.EventRecord.FormatDescription().IndexOf("ProcessId: ") + 10).Split('\n')[0];
                            tmp2 = tmp2.Substring(0, tmp2.Length - 1);

                            obj[0] = tmp1 + ">" + tmp2;
                            obj[1] = e.EventRecord.FormatDescription();

                            objX = obj[0] + "@" + obj[1];
                            NewProcessAddedtolist.Invoke(objX, null);

                            Thread.Sleep(100);

                            NewEventFrom_EventLogsCome.Invoke((object)LviewItemsX, null);

                            Thread.Sleep(5);

                            /// add to Network Connection Tab
                            NewTCP_Connection_Detected.Invoke((object)LviewItemsX, null);
                        }
                    }
                }
                catch (Exception g)
                {

                }

                Chart_Counts++;

            }
            catch (Exception _e)
            {

            }

            if (e.EventRecord.Id == 25)
            {
                try
                {
                   
                    if (e.EventRecord.FormatDescription() != string.Empty)
                    {

                        string tmp1 = e.EventRecord.FormatDescription().Substring(e.EventRecord.FormatDescription().IndexOf("Image: ") + 7).Split('\n')[0];
                        tmp1 = tmp1.Substring(0, tmp1.Length - 1);
                        string tmp2 = e.EventRecord.FormatDescription().Substring(e.EventRecord.FormatDescription().IndexOf("ProcessId: ") + 11).Split('\n')[0];
                        tmp2 = tmp2.Substring(0, tmp2.Length - 1);

                        iList = new ListViewItem();
                        iList.Name = e.EventRecord.RecordId.ToString();
                        iList.SubItems.Add(e.EventRecord.TimeCreated.ToString());
                        iList.SubItems.Add(e.EventRecord.Id.ToString());
                        iList.SubItems.Add(tmp1 + ":" + tmp2);
                        iList.SubItems.Add("[INJ]");
                        iList.SubItems.Add(e.EventRecord.FormatDescription());
                        iList.ImageIndex = 1;

                        LviewItemsX = iList;
                        Thread.Sleep(250);
                        chart_Inj++;

                        RemoteThreadInjectionDetection_ProcessLists.Invoke(((object)"25" + "@" + e.EventRecord.FormatDescription()), null);

                        Thread.Sleep(100);

                        NewEventFrom_EventLogsCome.Invoke((object)LviewItemsX, null);

                    }

                }
                catch (Exception _25)
                {

                 
                }

            }
        }


        private void Form1_FormClosed(object sender, FormClosedEventArgs e)
        {
            try
            {

                EvtWatcher.Enabled = false;
                EvtWatcher.Dispose();
                Process.GetProcessById(_ETWProcess_PID).Kill();
                Process[] p = Process.GetProcessesByName("VirtualMemAllocMon");
                foreach (Process item in p)
                {
                    Process.GetProcessById(item.Id).Kill();
                    Thread.Sleep(100);
                }
            }
            catch (Exception)
            {


            }
        }


        private void StartMonitorToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (!EvtWatcher.Enabled)
                EvtWatcher.Enabled = true;
            toolStripStatusLabel1.Text = "Monitor Status: on";
            i6 = 0;
        }


        private void StoptMonitorToolStripMenuItem_Click(object sender, EventArgs e)
        {
            i6 = 0;
            if (EvtWatcher.Enabled)
            {
                EvtWatcher.Enabled = false;
                EvtWatcher.Dispose();
                toolStripStatusLabel1.Text = "Monitor Status: off";
            }
        }


        public void SaveTheTextFile()
        {
            try
            {
                BeginInvoke(new __Obj_Updater_to_WinForm(UpdateRefreshListview1));


                Task.Factory.StartNew(() =>
                {
                    string fn = "SysmonPM2_RealtimeEvents_" + DateTime.Now.Hour.ToString() + "-" + DateTime.Now.Minute.ToString() + "-" + DateTime.Now.Second.ToString() + ".txt";
                    using (StreamWriter _file = new StreamWriter(fn, false))
                    {
                        _file.WriteLine(richTextBox1.Text);
                    };
                    MessageBox.Show("Texts saved into file: " + fn);
                });
            }
            catch (Exception err)
            {
                MessageBox.Show("Error: " + err.Message);
            }
        }


        private void SaveToolStripMenuItem_Click(object sender, EventArgs e)
        {
            try
            {
                BeginInvoke(new __Obj_Updater_to_WinForm(SaveTheTextFile));

            }
            catch (Exception err)
            {
                MessageBox.Show("Error: " + err.Message);
            }
        }


        private void ExitToolStripMenuItem_Click(object sender, EventArgs e)
        {
            EvtWatcher.Enabled = false;
            EvtWatcher.Dispose();
            this.Close();
        }


        private void AllEventsIDs123ToolStripMenuItem_Click(object sender, EventArgs e)
        {
            //StartQueries_Mon("*");
            ////toolStripStatusLabel2.ForeColor = Color.Red;

            ////toolStripStatusLabel2.Text = "| Filters: Select All EventIDs 1,2,3 [NewProcess , RemoteThreadInjection Detection , TCPIP Send]";

        }


        public void EventID12ToolStripMenuItem_Click(object sender, EventArgs e)
        {
            //string _Query = "<QueryList><Query Id=\"0\" Path=\"ETWPM2\"><Select Path=\"ETWPM2\">*[System[(EventID=1 or EventID=2)]]</Select></Query></QueryList>";

            //StartQueries_Mon(_Query);
            ////toolStripStatusLabel2.ForeColor = Color.Red;
            ////toolStripStatusLabel2.Text = "| Filters: Select All EventIDs 1,2 [NewProcess , RemoteThreadInjection Detection] | " + AlarmsDisabled;

            //MessageBox.Show(AlarmsDisabled);
        }


        public void EventID13ToolStripMenuItem_Click(object sender, EventArgs e)
        {
            //string _Query = "<QueryList><Query Id=\"0\" Path=\"ETWPM2\"><Select Path=\"ETWPM2\">*[System[(EventID=1 or EventID=3)]]</Select></Query></QueryList>";

            //StartQueries_Mon(_Query);
            ////toolStripStatusLabel2.ForeColor = Color.Red;

            ////toolStripStatusLabel2.Text = "| Filters: Select All EventIDs 1,3 [NewProcess , TCPIP Send] | " + AlarmsDisabled;

            //MessageBox.Show(AlarmsDisabled);
        }


        public void EventID23InjectionTCPIPToolStripMenuItem_Click(object sender, EventArgs e)
        {
            //string _Query = "<QueryList><Query Id=\"0\" Path=\"ETWPM2\"><Select Path=\"ETWPM2\">*[System[(EventID=2 or EventID=3)]]</Select></Query></QueryList>";

            //StartQueries_Mon(_Query);
            ////toolStripStatusLabel2.ForeColor = Color.Red;

            ////toolStripStatusLabel2.Text = "| Filters: Select All EventIDs 2,3 [RemoteThreadInjection Detection , TCPIP Send]";

        }


        private void EventID1ToolStripMenuItem_Click(object sender, EventArgs e)
        {
            //string _Query = "<QueryList><Query Id=\"0\" Path=\"ETWPM2\"><Select Path=\"ETWPM2\">*[System[(EventID=1)]]</Select></Query></QueryList>";

            //StartQueries_Mon(_Query);
            ////toolStripStatusLabel2.ForeColor = Color.Red;

            ////toolStripStatusLabel2.Text = "| Filters: Select All EventID 1 [NewProcess] | " + AlarmsDisabled;

            //MessageBox.Show(AlarmsDisabled);

        }


        private void EventID2ToolStripMenuItem_Click(object sender, EventArgs e)
        {
            //string _Query = "<QueryList><Query Id=\"0\" Path=\"ETWPM2\"><Select Path=\"ETWPM2\">*[System[(EventID=2)]]</Select></Query></QueryList>";

            //StartQueries_Mon(_Query);
            ////toolStripStatusLabel2.ForeColor = Color.Red;

            ////toolStripStatusLabel2.Text = "| Filters: Select All EventID 2 [RemoteThreadInjection Detection] | " + AlarmsDisabled;

            //MessageBox.Show(AlarmsDisabled);

        }


        private void EventID3ToolStripMenuItem_Click(object sender, EventArgs e)
        {
            //string _Query = "<QueryList><Query Id=\"0\" Path=\"ETWPM2\"><Select Path=\"ETWPM2\">*[System[(EventID=3)]]</Select></Query></QueryList>";

            //StartQueries_Mon(_Query);
            ////toolStripStatusLabel2.ForeColor = Color.Red;

            ////toolStripStatusLabel2.Text = "| Filters: Select All EventID 3 [TCPIP Send] | " + AlarmsDisabled;
            //MessageBox.Show(AlarmsDisabled);

        }


        private void OnToolStripMenuItem_Click(object sender, EventArgs e)
        {
            t.Enabled = true;
            onToolStripMenuItem.Checked = true;
            offToolStripMenuItem.Checked = false;
            onToolStripMenuItem.Text = "[on]";
            offToolStripMenuItem.Text = "off";
            i6 = 0;

        }


        private void OffToolStripMenuItem_Click(object sender, EventArgs e)
        {
            t.Enabled = false;
            onToolStripMenuItem.Checked = false;
            offToolStripMenuItem.Checked = true;
            onToolStripMenuItem.Text = "on";
            offToolStripMenuItem.Text = "[off]";
            i6 = 0;
        }


        private void ClearAllToolStripMenuItem_Click(object sender, EventArgs e)
        {
            listView1.Items.Clear();
            Thread.Sleep(50);
            //  richTextBox1.Clear();
        }


        private void InjectedTIDMemoryInfoToolStripMenuItem_Click(object sender, EventArgs e)
        {

            try
            {
                ListViewItem listviewitems_wasselected_ihope = listView1.SelectedItems[0];
                EventMessage = listviewitems_wasselected_ihope.SubItems[5].Text;
                string EventMessageRecordId = listviewitems_wasselected_ihope.Name;
                if (listviewitems_wasselected_ihope.SubItems[2].Text == "8")
                {

                    string i32StartAddress = EventMessage.Substring(EventMessage.IndexOf("StartAddress: ") + 14).Split('x')[1].Split('\n')[0];

                    Int64 TID = Convert.ToInt64(EventMessage.Substring(EventMessage.IndexOf("NewThreadId: ") + 12).Split(' ')[1].Split('\n')[0]);

                    Int32 prc = Convert.ToInt32(EventMessage.Substring(EventMessage.IndexOf("TargetProcessId: ") + 16).Split(' ')[1].Split('\n')[0]);

                    buf = new byte[90];
                    IntPtr prch = System.Diagnostics.Process.GetProcessById(prc).Handle;


                    // bool MemoryBytes = Memoryinfo.ReadProcessMemory(prch, (UIntPtr) ((IntPtr)i32StartAddress.Substring(0, i32StartAddress.Length - 1)), buf, buf.Length, IntPtr.Zero);

                    Memoryinfo.NtReadVirtualMemory(prch, (UIntPtr)Convert.ToUInt64(i32StartAddress.Substring(0, i32StartAddress.Length - 1), 16), buf, (uint)buf.Length, ref NTReadTmpRef);


                    MessageBox.Show(EventMessage + "\n\n______________________________________________________________\n[Injected Thread Memory info]\nRemote-Thread-Injection Memory Information:\nTID: " + TID.ToString() + "\nTID StartAddress: " +
                    i32StartAddress.ToString() + "\nTID Win32StartAddress: " + i32StartAddress.ToString() + "\nTarget_Process PID: " + prc.ToString() +
                    "\n\nInjected Memory Bytes: " + BitConverter.ToString(buf).ToString()
                    , "EventID:" + listviewitems_wasselected_ihope.SubItems[2].Text + " EventRecord_ID: " + EventMessageRecordId, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
                else
                {
                    MessageBox.Show("Please Select Events with EventID 8 (only)");
                }
            }
            catch (Exception eee)
            {
                MessageBox.Show(eee.Message);

            }

        }


        private void InjectedTIDMemoryInfoToolStripMenuItem1_Click(object sender, EventArgs e)
        {
            try
            {
                ListViewItem listviewitems_wasselected_ihope = listView1.SelectedItems[0];
                EventMessage = listviewitems_wasselected_ihope.SubItems[5].Text;
                string EventMessageRecordId = listviewitems_wasselected_ihope.Name;
                if (listviewitems_wasselected_ihope.SubItems[2].Text == "8")
                {

                    string i32StartAddress = EventMessage.Substring(EventMessage.IndexOf("StartAddress: ") + 14).Split('x')[1].Split('\n')[0];

                    Int64 TID = Convert.ToInt64(EventMessage.Substring(EventMessage.IndexOf("NewThreadId: ") + 12).Split(' ')[1].Split('\n')[0]);

                    Int32 prc = Convert.ToInt32(EventMessage.Substring(EventMessage.IndexOf("TargetProcessId: ") + 16).Split(' ')[1].Split('\n')[0]);

                    buf = new byte[90];
                    IntPtr prch = System.Diagnostics.Process.GetProcessById(prc).Handle;

                    // bool MemoryBytes = Memoryinfo.ReadProcessMemory(prch, (UIntPtr) ((IntPtr)i32StartAddress.Substring(0, i32StartAddress.Length - 1)), buf, buf.Length, IntPtr.Zero);
                    Memoryinfo.NtReadVirtualMemory(prch, (UIntPtr)Convert.ToUInt64(i32StartAddress.Substring(0, i32StartAddress.Length - 1), 16), buf, (uint)buf.Length, ref NTReadTmpRef);

                    MessageBox.Show(EventMessage + "\n\n______________________________________________________________\n[Injected Thread Memory info]\nRemote-Thread-Injection Memory Information:\nTID: " + TID.ToString() + "\nTID StartAddress: " +
                    i32StartAddress.ToString() + "\nTID Win32StartAddress: " + i32StartAddress.ToString() + "\nTarget_Process PID: " + prc.ToString() +
                    "\n\nInjected Memory Bytes: " + BitConverter.ToString(buf).ToString()
                    , "EventID:" + listviewitems_wasselected_ihope.SubItems[2].Text + " EventRecord_ID: " + EventMessageRecordId, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
                else
                {
                    MessageBox.Show("Please Select Events with EventID 8 (only)");
                }
            }
            catch (Exception eee)
            {
                MessageBox.Show(eee.Message);

            }

        }


        private void EventsPropertiesToolStripMenuItem_Click(object sender, EventArgs e)
        {
            try
            {
                ListViewItem listviewitems_wasselected_ihope = listView1.SelectedItems[0];
                EventMessage = listviewitems_wasselected_ihope.SubItems[5].Text;
                string EventMessageRecordId = listviewitems_wasselected_ihope.Name;
                if (listviewitems_wasselected_ihope.SubItems[2].Text == "2")
                {
                    MessageBox.Show(EventMessage, "Properties for EventID:" + listviewitems_wasselected_ihope.SubItems[2].Text + " ,EventRecord_ID: " + EventMessageRecordId + " ,LogTime:[" + listviewitems_wasselected_ihope.SubItems[1].Text + "]", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
                else
                {
                    MessageBox.Show(EventMessage, "Properties for EventID:" + listviewitems_wasselected_ihope.SubItems[2].Text + " ,EventRecord_ID: " + EventMessageRecordId + " ,LogTime:[" + listviewitems_wasselected_ihope.SubItems[1].Text + "]", MessageBoxButtons.OK, MessageBoxIcon.Information);

                }
            }
            catch (Exception error)
            {

                MessageBox.Show("Please first Select one row/event in listview\n" + error.Message);
            }
        }


        private void AlarmsEventsPropertiesToolStripMenuItem_Click(object sender, EventArgs e)
        {
            try
            {
                ListViewItem listviewitems_wasselected_ihope = listView2.SelectedItems[0];
                string __result01 = "";
                foreach (char item in listviewitems_wasselected_ihope.SubItems[6].Text)
                {
                    if (item != '\r')
                        __result01 += item;
                }
                string __result02 = "";
                foreach (char item in listviewitems_wasselected_ihope.SubItems[7].Text)
                {
                    if (item != '\r')
                        __result02 += item;
                }
                if (listviewitems_wasselected_ihope.ImageIndex == 2)
                {
                    MessageBox.Show("Time: " + listviewitems_wasselected_ihope.SubItems[1].Text + "\n"
                                           + "Process: " + listviewitems_wasselected_ihope.SubItems[2].Text + "\n"
                                              + "Injection-Type: " + listviewitems_wasselected_ihope.SubItems[3].Text + "\n"
                                                 + "TCPSend: " + listviewitems_wasselected_ihope.SubItems[4].Text + "\n"
                                                    + "Status: " + listviewitems_wasselected_ihope.SubItems[5].Text + " (by hollowshunter)" + "\n"
                                                    + "__________________________________________________________\n"
                                                       + "MemoryScanner PE-sieve Result: " + __result01 + "\n\n"
                                                       + "MemoryScanner HollowsHunter Result: " + __result02 + "\n\n"
                                                          + "Description: " + listviewitems_wasselected_ihope.SubItems[8].Text + "\n"
                                                    + "__________________________________________________________\n"
                                                         + "Sysmon Event Message: " + listviewitems_wasselected_ihope.SubItems[9].Text + "\n"

                                , "Properties => " +
                                           listviewitems_wasselected_ihope.SubItems[2].Text + " [" + listviewitems_wasselected_ihope.SubItems[3].Text + "] " +
                                           " " +
                                           ",LogTime:[" + listviewitems_wasselected_ihope.SubItems[1].Text + "]", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                else
                {
                    MessageBox.Show("Time: " + listviewitems_wasselected_ihope.SubItems[1].Text + "\n"
                                           + "Process: " + listviewitems_wasselected_ihope.SubItems[2].Text + "\n"
                                              + "Injection-Type: " + listviewitems_wasselected_ihope.SubItems[3].Text + "\n"
                                                 + "TCPSend: " + listviewitems_wasselected_ihope.SubItems[4].Text + "\n"
                                                    + "Status: " + listviewitems_wasselected_ihope.SubItems[5].Text + " (by hollowshunter)" + "\n"
                                                    + "__________________________________________________________\n"
                                                        + "MemoryScanner PE-sieve Result: " + __result01 + "\n\n"
                                                       + "MemoryScanner HollowsHunter Result: " + __result02 + "\n\n"
                                                          + "Description: " + listviewitems_wasselected_ihope.SubItems[8].Text + "\n"
                                                    + "__________________________________________________________\n"
                                                          + "Sysmon Event Message: " + listviewitems_wasselected_ihope.SubItems[9].Text + "\n"

                               , "Properties => " +
                                           listviewitems_wasselected_ihope.SubItems[2].Text + " [" + listviewitems_wasselected_ihope.SubItems[3].Text + "] " +
                                           " " +
                                           ",LogTime:[" + listviewitems_wasselected_ihope.SubItems[1].Text + "]", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            }
            catch (Exception error)
            {

                MessageBox.Show("Please first Select one row/event in listview\n" + error.Message);
            }
        }


        private void AlarmsEventsPropertiesToolStripMenuItem1_Click(object sender, EventArgs e)
        {
            try
            {
                ListViewItem listviewitems_wasselected_ihope = listView2.SelectedItems[0];
                string __result01 = "";
                foreach (char item in listviewitems_wasselected_ihope.SubItems[6].Text)
                {
                    if (item != '\r')
                        __result01 += item;
                }
                string __result02 = "";
                foreach (char item in listviewitems_wasselected_ihope.SubItems[7].Text)
                {
                    if (item != '\r')
                        __result02 += item;
                }
                if (listviewitems_wasselected_ihope.ImageIndex == 2)
                {
                    MessageBox.Show("Time: " + listviewitems_wasselected_ihope.SubItems[1].Text + "\n"
                                           + "Process: " + listviewitems_wasselected_ihope.SubItems[2].Text + "\n"
                                              + "Injection-Type: " + listviewitems_wasselected_ihope.SubItems[3].Text + "\n"
                                                 + "TCPSend: " + listviewitems_wasselected_ihope.SubItems[4].Text + "\n"
                                                    + "Status: " + listviewitems_wasselected_ihope.SubItems[5].Text + " (by hollowshunter)" + "\n"
                                                    + "__________________________________________________________\n"
                                                       + "MemoryScanner PE-sieve Result: " + __result01 + "\n\n"
                                                       + "MemoryScanner HollowsHunter Result: " + __result02 + "\n\n"
                                                          + "Description: " + listviewitems_wasselected_ihope.SubItems[8].Text + "\n"
                                                    + "__________________________________________________________\n"
                                                         + "Sysmon Event Message: " + listviewitems_wasselected_ihope.SubItems[9].Text + "\n"

                                , "Properties => " +
                                           listviewitems_wasselected_ihope.SubItems[2].Text + " [" + listviewitems_wasselected_ihope.SubItems[3].Text + "] " +
                                           " " +
                                           ",LogTime:[" + listviewitems_wasselected_ihope.SubItems[1].Text + "]", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                else
                {
                    MessageBox.Show("Time: " + listviewitems_wasselected_ihope.SubItems[1].Text + "\n"
                                           + "Process: " + listviewitems_wasselected_ihope.SubItems[2].Text + "\n"
                                              + "Injection-Type: " + listviewitems_wasselected_ihope.SubItems[3].Text + "\n"
                                                 + "TCPSend: " + listviewitems_wasselected_ihope.SubItems[4].Text + "\n"
                                                    + "Status: " + listviewitems_wasselected_ihope.SubItems[5].Text + " (by hollowshunter)" + "\n"
                                                    + "__________________________________________________________\n"
                                                        + "MemoryScanner PE-sieve Result: " + __result01 + "\n\n"
                                                       + "MemoryScanner HollowsHunter Result: " + __result02 + "\n\n"
                                                          + "Description: " + listviewitems_wasselected_ihope.SubItems[8].Text + "\n"
                                                    + "__________________________________________________________\n"
                                                          + "Sysmon Event Message: " + listviewitems_wasselected_ihope.SubItems[9].Text + "\n"

                               , "Properties => " +
                                           listviewitems_wasselected_ihope.SubItems[2].Text + " [" + listviewitems_wasselected_ihope.SubItems[3].Text + "] " +
                                           " " +
                                           ",LogTime:[" + listviewitems_wasselected_ihope.SubItems[1].Text + "]", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            }
            catch (Exception error)
            {

                MessageBox.Show("Please first Select one row/event in listview\n" + error.Message);
            }
        }


        private void AboutToolStripMenuItem1_Click(object sender, EventArgs e)
        {
 
            MessageBox.Show(null, "SysPM2Monitor2 v2.7 [test version 2.7.12.58]\nCode Published by Damon Mohammadbagher , Jan 2022", "About SysPM2Monitor2 v2.7", MessageBoxButtons.OK, MessageBoxIcon.Information);

        }


        private void SaveAllAlarmEventsToolStripMenuItem_Click(object sender, EventArgs e)
        {
            _SaveAlarmsByETW();
        }


        private void TabControl1_SelectedIndexChanged(object sender, EventArgs e)
        {
            if (tabControl1.SelectedIndex != 0) { eventsPropertiesToolStripMenuItem.Enabled = false; injectedTIDMemoryInfoToolStripMenuItem1.Enabled = false; } else { injectedTIDMemoryInfoToolStripMenuItem1.Enabled = true; eventsPropertiesToolStripMenuItem.Enabled = true; }
            if (tabControl1.SelectedIndex != 2) { alarmsEventsPropertiesToolStripMenuItem.Enabled = false; } else { alarmsEventsPropertiesToolStripMenuItem.Enabled = true; }
        }


        private void ETWEventPropertiesToolStripMenuItem_Click(object sender, EventArgs e)
        {

            try
            {


                ListViewItem listviewitems_wasselected_ihope = listView1.SelectedItems[0];
                EventMessage = listviewitems_wasselected_ihope.SubItems[5].Text;
                string EventMessageRecordId = listviewitems_wasselected_ihope.Name;
                if (listviewitems_wasselected_ihope.SubItems[2].Text == "2")
                {
                    MessageBox.Show(EventMessage, "Properties for EventID:" + listviewitems_wasselected_ihope.SubItems[2].Text + " ,EventRecord_ID: " + EventMessageRecordId + " ,LogTime:[" + listviewitems_wasselected_ihope.SubItems[1].Text + "]", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
                else
                {
                    MessageBox.Show(EventMessage, "Properties for EventID:" + listviewitems_wasselected_ihope.SubItems[2].Text + " ,EventRecord_ID: " + EventMessageRecordId + " ,LogTime:[" + listviewitems_wasselected_ihope.SubItems[1].Text + "]", MessageBoxButtons.OK, MessageBoxIcon.Information);

                }
            }
            catch (Exception error)
            {

                MessageBox.Show("Please first Select one row/event in listview\n" + error.Message);
            }
        }


        private void Form1_FormClosing(object sender, FormClosingEventArgs e)
        {
            try
            {

                EvtWatcher.Enabled = false;
                EvtWatcher.Dispose();
                Process.GetProcessById(_ETWProcess_PID).Kill();
                Process[] p = Process.GetProcessesByName("VirtualMemAllocMon");
                foreach (Process item in p)
                {
                    Process.GetProcessById(item.Id).Kill();
                    Thread.Sleep(100);
                }
            }
            catch (Exception)
            {


            }
        }


        public void Update_Richtexbox_7_8_9_ETWDetectionDetails_info()
        {
            try
            {

                richTextBox7.Text = "VirtualMemAllocMon v1.1 Tool , Published by Damon Mohammadbagher , Jun-Jul 2021" + "\n"
                + "VirtualMemAllocMon, ETW VirtualMemAlloc Events Realtime Monitor tool(Payload Detection by ETW Events)\n\n" + listView5.SelectedItems[0].SubItems[7].Text;

                richTextBox10.Text = "VirtualMemAlloc Event Detected by ETW for this Process & this \"Thread Id\" for this Process Detected by Memory Scanner\n\nVirtualMemAlloc Event For This Process:\n"
                    + listView5.SelectedItems[0].SubItems[6].Text + "\n\nMemory Information by Scanner:\n\n" + "VirtualMemAllocMon v1.1 Tool , Published by Damon Mohammadbagher , Jun-Jul 2021" + "\n"
                + "VirtualMemAllocMon, ETW VirtualMemAlloc Events Realtime Monitor tool(Payload Detection by ETW Events)\n\n" + listView5.SelectedItems[0].SubItems[7].Text;

                richTextBox9.Text = "VirtualMemAllocMon v1.1 Tool , Published by Damon Mohammadbagher , Jun-Jul 2021" + "\n"
                + "VirtualMemAllocMon, ETW VirtualMemAlloc Events Realtime Monitor tool(Payload Detection by ETW Events)\n\n" + listView5.SelectedItems[0].SubItems[7].Text;

                richTextBox8.Text = listView5.SelectedItems[0].SubItems[6].Text;

            }
            catch (Exception)
            {


            }
        }


        private void ListView5_SelectedIndexChanged_1(object sender, EventArgs e)
        {
            try
            {
                BeginInvoke(new __Obj_Updater_to_WinForm(Update_Richtexbox_7_8_9_ETWDetectionDetails_info));

            }
            catch (Exception)
            {


            }
        }


        public void Update_Richtexbox11_SystemDetection_SysmonETW_AllDetails_info()
        {
            try
            {
                richTextBox11.Text = listView6.SelectedItems[0].Name;
            }
            catch (Exception)
            {

              
            }
         
        }


        private void ShowNotifyPopupToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (!showNotifyPopupToolStripMenuItem.Checked)
            {
                showNotifyPopupToolStripMenuItem.Checked = true;
                _isNotifyEnabled = true;
            }
            else
            {
                if (showNotifyPopupToolStripMenuItem.Checked)
                    showNotifyPopupToolStripMenuItem.Checked = false;
                _isNotifyEnabled = false;
            }
        }


        private void ListView6_SelectedIndexChanged(object sender, EventArgs e)
        {
            try
            {
               BeginInvoke(new __Obj_Updater_to_WinForm(Update_Richtexbox11_SystemDetection_SysmonETW_AllDetails_info));

            }
            catch (Exception)
            {

               
            }
           
        }


        private void ListView1_Click(object sender, EventArgs e)
        {
            richTextBox6.Text = listView1.SelectedItems[0].SubItems[5].Text;
        }
 

        private void SaveAllAlarmEventsToolStripMenuItem1_Click(object sender, EventArgs e)
        {
            _SaveAlarmsByETW();
        }


        private void DefaultDumpAllToolStripMenuItem_Click(object sender, EventArgs e)
        {
            toolStripStatusLabel3.Text = "| pe-sieve is on";

            pesieve64exeOffToolStripMenuItem.Text = "pe-sieve64.exe off";
            pesieve64exeOffToolStripMenuItem.Checked = false;
            pesieve64exeonToolStripMenuItem.Text = "pe-sieve64.exe [on]";
            pesieve64exeonToolStripMenuItem.Checked = true;
            defaultDumpAllToolStripMenuItem.Text = "Default dump all [on]";
            defaultDumpAllToolStripMenuItem.Checked = true;
            dontDumpTheModifiedPEsButSaveTheReportoffToolStripMenuItem.Text = "don't dump the modified PEs, but save the report [off]";
            dontDumpTheModifiedPEsButSaveTheReportoffToolStripMenuItem.Checked = false;
            dontDumpAnyFilesToolStripMenuItem1.Text = "don't dump any files [off]";
            dontDumpAnyFilesToolStripMenuItem1.Checked = false;

            isPEScanonoff = true;
            pe_sieve_DumpSwitches = 0;
        }


        private void DontDumpTheModifiedPEsButSaveTheReportoffToolStripMenuItem_Click(object sender, EventArgs e)
        {
            toolStripStatusLabel3.Text = "| pe-sieve is on";
            pesieve64exeOffToolStripMenuItem.Text = "pe-sieve64.exe off";
            pesieve64exeonToolStripMenuItem.Text = "pe-sieve64.exe [on]";
            pesieve64exeonToolStripMenuItem.Checked = true;
            pesieve64exeOffToolStripMenuItem.Checked = false;
            dontDumpTheModifiedPEsButSaveTheReportoffToolStripMenuItem.Text = "don't dump the modified PEs, but save the report [on]";
            dontDumpTheModifiedPEsButSaveTheReportoffToolStripMenuItem.Checked = true;
            defaultDumpAllToolStripMenuItem.Text = "Default dump all [off]";
            dontDumpAnyFilesToolStripMenuItem1.Text = "don't dump any files [off]";
            defaultDumpAllToolStripMenuItem.Checked = false;
            dontDumpAnyFilesToolStripMenuItem1.Checked = false;

            isPEScanonoff = true;
            pe_sieve_DumpSwitches = 1;
        }


        private void DontDumpAnyFilesToolStripMenuItem1_Click(object sender, EventArgs e)
        {
            toolStripStatusLabel3.Text = "| pe-sieve is on";
            pesieve64exeOffToolStripMenuItem.Text = "pe-sieve64.exe off";
            pesieve64exeonToolStripMenuItem.Text = "pe-sieve64.exe [on]";
            pesieve64exeonToolStripMenuItem.Checked = true;
            pesieve64exeOffToolStripMenuItem.Checked = false;
            dontDumpTheModifiedPEsButSaveTheReportoffToolStripMenuItem.Text = "don't dump the modified PEs, but save the report [off]";
            dontDumpTheModifiedPEsButSaveTheReportoffToolStripMenuItem.Checked = false;
            defaultDumpAllToolStripMenuItem.Text = "Default dump all [off]";
            dontDumpAnyFilesToolStripMenuItem1.Text = "don't dump any files [on]";
            defaultDumpAllToolStripMenuItem.Checked = false;
            dontDumpAnyFilesToolStripMenuItem1.Checked = true;
            isPEScanonoff = true;
            pe_sieve_DumpSwitches = 2;
        }


        private void DontDumpPEOfilterToolStripMenuItem_Click(object sender, EventArgs e)
        {
            toolStripStatusLabel4.Text = "| hollowshunter is on";
            dumpAllProcessToolStripMenuItem.Checked = false;
            dontDumpAnyFilesToolStripMenuItem.Checked = false;
            dontDumpPEOfilterToolStripMenuItem.Checked = true;
            dumpAllProcessToolStripMenuItem.Text = "Default dump all Process [off]";
            dontDumpPEOfilterToolStripMenuItem.Text = "don't dump the modified PEs, but save the report [on]";
            dontDumpAnyFilesToolStripMenuItem.Text = "don't dump any files [off]";
            hollowshunter_DumpSwitches = 1;
        }


        private void DontDumpAnyFilesToolStripMenuItem_Click(object sender, EventArgs e)
        {
            toolStripStatusLabel4.Text = "| hollowshunter is on";
            dumpAllProcessToolStripMenuItem.Checked = false;
            dontDumpAnyFilesToolStripMenuItem.Checked = true;
            dontDumpPEOfilterToolStripMenuItem.Checked = false;
            dumpAllProcessToolStripMenuItem.Text = "Default dump all Process [off]";
            dontDumpAnyFilesToolStripMenuItem.Text = "don't dump any files [on]";
            dontDumpPEOfilterToolStripMenuItem.Text = "don't dump the modified PEs, but save the report [off]";
            hollowshunter_DumpSwitches = 2;
        }


        private void DumpAllProcessToolStripMenuItem_Click(object sender, EventArgs e)
        {
            toolStripStatusLabel4.Text = "| hollowshunter is on";
            dumpAllProcessToolStripMenuItem.Checked = true;
            dontDumpAnyFilesToolStripMenuItem.Checked = false;
            dontDumpPEOfilterToolStripMenuItem.Checked = false;
            dumpAllProcessToolStripMenuItem.Text = "Default dump all Process [on]";
            dontDumpAnyFilesToolStripMenuItem.Text = "don't dump any files [off]";
            dontDumpPEOfilterToolStripMenuItem.Text = "don't dump the modified PEs, but save the report [off]";
            hollowshunter_DumpSwitches = 0;
        }


        private void Pesieve64exeOffToolStripMenuItem_Click(object sender, EventArgs e)
        {
            toolStripStatusLabel3.Text = "| pe-sieve is off";
            pesieve64exeOffToolStripMenuItem.Text = "pe-sieve64.exe [off]";
            pesieve64exeonToolStripMenuItem.Text = "pe-sieve64.exe on";
            pesieve64exeOffToolStripMenuItem.Checked = true;
            pesieve64exeonToolStripMenuItem.Checked = false;
            isPEScanonoff = false;
            if (isHollowHunteronoff == false && isPEScanonoff == false)
                MessageBox.Show("\"Alarms by Sysmon\" TAB is disable now, because all memory-scanners are OFF\n" + "you need to set \"ON\" at least one of them");

        }


        public void Update_Richtextbox2_3_4_5_SysmonDetectionDetails_info()
        {
            try
            {
                richTextBox2.Text = listView2.SelectedItems[0].Name;
                richTextBox4.Text = listView2.SelectedItems[0].SubItems[9].Text;
                richTextBox5.Text = listView2.SelectedItems[0].SubItems[8].Text;
                string PIDName = listView2.SelectedItems[0].Name.Split('>')[0].Split('\n')[0];
                
                string PID = PIDName.Split(':')[2];
               
                string dumpinfotext = richTextBox1.Text;

                StringBuilder lines = new StringBuilder(dumpinfotext);
                richTextBox3.Text = "";
                richTextBox3.Text += "TargetProcess [" + PIDName + "] Injection History with Debug info:\n";
                richTextBox3.Text += "\n-------------------------------------------------------\n";
                int counter = 0;
                int showtime = 1;
                bool showshowtime = false;

                richTextBox3.Text += "Alarm Description & Injector Details:\n";
                /// injection description
                richTextBox3.Text += listView2.SelectedItems[0].SubItems[8].Text + "\n";
                richTextBox3.Text += "\n-------------------------------------------------------\n";

                //Process_Table.Find()
                //string _SourceImage, _TargetProcessId, _TargetImage, _NewThreadId = "";
                //_TargetImage = "";
                richTextBox3.Text += "Injected Memory Bytes & Injected Thread Details:\n";
                try
                {
                    Query_Reslt1 = _SysmonEventID8_InjectionMemory_Details.FindAll(x => x.TPID == Convert.ToInt32(PID));
                    int _tmpcount = 1;
                    foreach (_TableOfMemoryInjection_Details item in Query_Reslt1)
                    {

                        richTextBox3.Text += "[" + _tmpcount + "] " + "Sysmon EventRecordID for this Injection information: " + item.Sysmon_EventRecord_ID.ToString() + "\n";
                        richTextBox3.Text += "[" + _tmpcount + "] " + "InjectorProcess_Path: " + item.SourceImagePath_or_Injector_Path .ToString() + "\n";
                        richTextBox3.Text += "[" + _tmpcount + "] " + "Injector_PID: " + item.SourceProcessId_or_InjectorPID.ToString() + "\n";
                        richTextBox3.Text += "[" + _tmpcount + "] " + "Target_ProcessID: " + item.TPID.ToString() + "\n";
                        richTextBox3.Text += "[" + _tmpcount + "] " + "Target_ThreadID (Injected TID): " + item.TTID.ToString() + "\n";
                        richTextBox3.Text += "[" + _tmpcount + "] " + "StartAddress: " + item._StartAddress.ToString() + "\n";
                        richTextBox3.Text += "[" + _tmpcount + "] " + "Injected Memory Bytes:\n\n" + item._InjectedMemory_Sbytes.ToString() + "\n";
                        _tmpcount++;
                    }
                   
                }
                catch (Exception)
                {

                   
                }
               

            }
            catch (Exception)
            {


            }
        }


        private void ListView2_SelectedIndexChanged(object sender, EventArgs e)
        {
            try
            {

                ThreadStart __T7_for_show_Details_info = new ThreadStart(delegate
                {
                    BeginInvoke(new __Obj_Updater_to_WinForm(_Run_Async_Changedindexof_listview_2));
                });

                Thread _T7_for_show_Details_info_ = new Thread(__T7_for_show_Details_info);
                _T7_for_show_Details_info_.Priority = ThreadPriority.Highest;
                _T7_for_show_Details_info_.Start();

            }
            catch (Exception)
            {

                
            }
        }


        public async void _Run_Async_Changedindexof_listview_2()
        {
            await _Changedindexof_listview_2();

        }


        public async Task _Changedindexof_listview_2()
        {

            try
            {

                Invoke(new Action(() =>
                {
                    int temp_get_InjectorPID_from_eventmessage = 0;
                    string temp_get_InjectorPN_from_description = "";

                    try
                    {

                        richTextBox2.Text = listView2.SelectedItems[0].Name;
                        richTextBox4.Text = listView2.SelectedItems[0].SubItems[9].Text;
                        richTextBox5.Text = listView2.SelectedItems[0].SubItems[8].Text;
                        temp_get_InjectorPID_from_eventmessage = Convert.ToInt32(listView2.SelectedItems[0].SubItems[9].Text.Split('\n')[4].Split(':')[1].Substring(1).Split('\r')[0]);
                    }
                    catch (Exception)
                    {

                    }


                    try
                    {
                       
                        temp_get_InjectorPN_from_description =
                        listView2.SelectedItems[0].SubItems[9].Text.Split('\n')[5].Substring(13).Split('\r')[0];
                    }
                    catch (Exception)
                    {

                       
                        if (temp_get_InjectorPN_from_description == " ")
                        {
                            temp_get_InjectorPN_from_description = "";
                        }

                    }


                    richTextBox3.Text = "";
                    string ops = listView2.SelectedItems[0].Name;
                    string PIDName = listView2.SelectedItems[0].Name.Split('\n')[0].Split(':')[0] + ":" + listView2.SelectedItems[0].Name.Split('\n')[0].Split(':')[1];
                    string PID = listView2.SelectedItems[0].Name.Split('\n')[1].Split(':')[1];
                    PID = PID.Substring(1, PID.Length - 2);

                    ThreadStart __T7_for_show_Details_info = new ThreadStart(delegate
                    {
                        BeginInvoke(new __Core2(_MemoryScanner_Pesieve_ShowObjects_AsyncRun), (object)PID);
                    });

                    Thread _T7_for_show_Details_info_ = new Thread(__T7_for_show_Details_info);
                    _T7_for_show_Details_info_.Priority = ThreadPriority.Highest;
                    _T7_for_show_Details_info_.Start();

                   

                    string line1 = "TargetProcess [" + PIDName + ":" + PID + "] Injection History with Debug info:\n";
                    line1 += "\n-------------------------------------------------------\n";
                    int counter = 0;
                    line1 += "Target Process & Injector Details:\n";
                    //string last_tid = "";


                    try
                    {


                        line1 += "[" + counter.ToString() + "] " + "Remote Thread Injection Detected!" + "\n";
                        line1 += "[" + counter.ToString() + "] " + "Injection by InjectorPID:" + listView2.SelectedItems[0].SubItems[9].Text.Split('\n')[4].Substring(17).Replace('\r', ' ') + "===>==TID:" +
                        listView2.SelectedItems[0].SubItems[9].Text.Split('\n')[9].Substring(13).Replace('\r', ' ') + "==>==Injected into====>" + listView2.SelectedItems[0].SubItems[9].Text.Split('\n')[8].Substring(13).Replace('\r', ' ') + ":" + PID + "\n";
                        line1 += "InjectorProcessName: " + listView2.SelectedItems[0].SubItems[9].Text.Split('\n')[5].Substring(13).Replace('\r', ' ');
                        line1 += "\n\nTarget Process More Details:"
                        + "\nTarget Process Path:" + listView2.SelectedItems[0].SubItems[9].Text.Split('\n')[8].Substring(13).Replace('\r', ' ')
                        + "\n"
                        + "Injected Bytes:  (TID: " + listView2.SelectedItems[0].SubItems[9].Text.Split('\n')[9].Substring(13).Replace('\r', ' ') + ") ";
                       
                        Thread.Sleep(10);

                        string _tempstartaddress = listView2.SelectedItems[0].SubItems[9].Text.Split('\n')[10].Substring(16).Split('\r')[0];
                        _InjectedThreadDetails_bytes __hex = _InjectedTIDList.Find(y => y._ThreadStartAddress == _tempstartaddress
                        || y._TargetPID == Convert.ToInt32(PID) && y._InjectorPID == temp_get_InjectorPID_from_eventmessage);

                        Thread.Sleep(10);

                       line1 += " (StartAddress: " + __hex._ThreadStartAddress + ")\n" + __hex.Injected_Memory_Bytes_Hex + "\n";

                    }
                    catch (Exception)
                    {


                    }


                    richTextBox3.Text = line1;
 
                }));

            }
            catch (Exception)
            {


            }


        }


        public async void _MemoryScanner_Pesieve_ShowObjects_AsyncRun(object __obj)
        {
            await _MemoryScanner_Pesieve_ShowObjects(__obj);
        }


        /// <summary>
        /// C# Method , this method is for Show Memory scanner 01 details info about Detected process in Listview2 [Alarms by ETW Tab]         
        /// </summary>   
        public async Task _MemoryScanner_Pesieve_ShowObjects(object _PID)
        {
            try
            {
                Invoke(new Action(() =>
                {
                    int PID = Convert.ToInt32(_PID);

                    richTextBox12.Text = "";
                    string module = "";
                    string module_size = "";
                    string filename = "";

                    string dump = "";
                    if (File.Exists(@".\process_" + PID + @"\" + @"dump_report.json"))
                    {

                        foreach (string item in File.ReadAllLines(@".\process_" + PID + @"\" + @"dump_report.json"))
                        {
                            if (item.Contains("\"module\" :") || item.Contains("\"module_size\" :") || item.Contains("\"dump_file\" :")
                                || item.Contains("\"dump_mode\" :") || item.Contains("\"is_shellcode\" :"))
                            {
                                if (item.Contains("\"module\" :"))
                                {
                                    module = item.Split(':')[1];
                                    module = module.Replace("\"", "");
                                    module = module.Replace(" ", "");
                                    module = module.Replace(",", "");

                                }
                                if (item.Contains("module_size"))
                                {
                                    module_size = item.Split(':')[1];
                                    module_size = module_size.Replace("\"", "");
                                    module_size = module_size.Replace(" ", "");
                                    module_size = module_size.Replace(",", "");

                                }
                                if (item.Contains("dump_file"))
                                {
                                    filename = item.Split(':')[1].Substring(2);
                                    filename = filename.Replace("\",", "");

                                }

                                richTextBox12.Text += item + "\n";


                            }

                        }


                    }
                    else
                    {
                        richTextBox12.Text = "";
                    }

                }));
            }
            catch (Exception rr)
            {


            }
        }

        private void HollowHunterexeoffToolStripMenuItem_Click(object sender, EventArgs e)
        {
            toolStripStatusLabel4.Text = "| hollowshunter is off";

            isHollowHunteronoff = false;
            hollowHunterexeoffToolStripMenuItem.Text = "HollowsHunter.exe [off]";
            hollowHunterexeoffToolStripMenuItem.Checked = true;
            hollowHunterexeOnToolStripMenuItem.Text = "HollowsHunter.exe on";
            hollowHunterexeOnToolStripMenuItem.Checked = false;
            scanOnlyModeToolStripMenuItem.Text = "Scan only mode (Default)";
            scanOnlyModeToolStripMenuItem.Checked = false;
            scanSuspendToolStripMenuItem.Text = "Scan + Suspend Suspicious (Run as Admin)";
            scanSuspendToolStripMenuItem.Checked = false;
            scanKillSuspiciousToolStripMenuItem.Text = "Scan + Kill Suspicious (Run as Admin)";
            scanKillSuspiciousToolStripMenuItem.Checked = false;
            if (isHollowHunteronoff == false && isPEScanonoff == false)
                MessageBox.Show("\"Alarms by Sysmon\" TAB is disable now, because all memory-scanners are OFF\n" + "you need to set \"ON\" at least one of them");

        }


        private void ScanOnlyModeToolStripMenuItem_Click(object sender, EventArgs e)
        {
            toolStripStatusLabel4.Text = "| hollowshunter is on";
            isHollowHunteronoff = true;
            HollowHunterLevel = 0;
            hollowHunterexeOnToolStripMenuItem.Text = "HollowsHunter.exe [on]";
            hollowHunterexeOnToolStripMenuItem.Checked = true;
            scanOnlyModeToolStripMenuItem.Text = "Scan only mode (Default) [on]";
            scanOnlyModeToolStripMenuItem.Checked = true;
            scanSuspendToolStripMenuItem.Text = "Scan + Suspend Suspicious (Run as Admin)";
            scanSuspendToolStripMenuItem.Checked = false;
            scanKillSuspiciousToolStripMenuItem.Text = "Scan + Kill Suspicious (Run as Admin)";
            scanKillSuspiciousToolStripMenuItem.Checked = false;
            hollowHunterexeoffToolStripMenuItem.Text = "HollowsHunter.exe off";
            hollowHunterexeoffToolStripMenuItem.Checked = false;

        }


        private void ScanSuspendToolStripMenuItem_Click(object sender, EventArgs e)
        {
            toolStripStatusLabel4.Text = "| hollowshunter is on";

            isHollowHunteronoff = true;
            HollowHunterLevel = 1;
            hollowHunterexeOnToolStripMenuItem.Text = "HollowsHunter.exe [on]";
            hollowHunterexeOnToolStripMenuItem.Checked = true;
            scanSuspendToolStripMenuItem.Text = "Scan + Suspend Suspicious (Run as Admin) [on]";
            scanSuspendToolStripMenuItem.Checked = true;
            scanOnlyModeToolStripMenuItem.Text = "Scan only mode (Default)";
            scanOnlyModeToolStripMenuItem.Checked = false;
            scanKillSuspiciousToolStripMenuItem.Text = "Scan + Kill Suspicious (Run as Admin)";
            scanKillSuspiciousToolStripMenuItem.Checked = false;
            hollowHunterexeoffToolStripMenuItem.Text = "HollowsHunter.exe off";
            hollowHunterexeoffToolStripMenuItem.Checked = false;

        }


        private void ScanKillSuspiciousToolStripMenuItem_Click(object sender, EventArgs e)
        {
            toolStripStatusLabel4.Text = "| hollowshunter is on";

            isHollowHunteronoff = true;
            HollowHunterLevel = 2;
            hollowHunterexeOnToolStripMenuItem.Text = "HollowsHunter.exe [on]";
            hollowHunterexeOnToolStripMenuItem.Checked = true;
            scanOnlyModeToolStripMenuItem.Text = "Scan only mode (Default)";
            scanOnlyModeToolStripMenuItem.Checked = false;
            scanKillSuspiciousToolStripMenuItem.Text = "Scan + Kill Suspicious (Run as Admin) [on]";
            scanKillSuspiciousToolStripMenuItem.Checked = true;
            scanSuspendToolStripMenuItem.Text = "Scan + Suspend Suspicious (Run as Admin)";
            scanSuspendToolStripMenuItem.Checked = false;
            hollowHunterexeoffToolStripMenuItem.Text = "HollowsHunter.exe off";
            hollowHunterexeoffToolStripMenuItem.Checked = false;


        }


        private void DGreyToolStripMenuItem_Click(object sender, EventArgs e)
        {
            listView1.BackColor = Color.Beige;
            listView1.HeaderStyle = ColumnHeaderStyle.Nonclickable;
            listView1.BorderStyle = BorderStyle.FixedSingle;
            listView1.ForeColor = Color.Black;

            listView2.BackColor = Color.Beige;
            listView2.HeaderStyle = ColumnHeaderStyle.Nonclickable;
            listView2.BorderStyle = BorderStyle.FixedSingle;
            listView2.ForeColor = Color.Black;           

            listView5.BackColor = Color.Beige; 
            listView5.HeaderStyle = ColumnHeaderStyle.Nonclickable;
            listView5.BorderStyle = BorderStyle.FixedSingle;
            listView5.ForeColor = Color.Black;

            listView6.BackColor = Color.Beige;
            listView6.HeaderStyle = ColumnHeaderStyle.Nonclickable;
            listView6.BorderStyle = BorderStyle.FixedSingle;
            listView6.ForeColor = Color.Black;

            richTextBox1.BackColor = Control.DefaultBackColor;
            toolStripSeparator1.BackColor = Control.DefaultBackColor;
            statusStrip1.BackColor = Control.DefaultBackColor;
            menuStrip3.BackColor = Control.DefaultBackColor;
            toolStripSeparator1.BackColor = Color.Black;
        }


        public void InjectionMemoryInfoDetails_torichtextbox(string etwEvtMessage, string _EventMessageRecordId)
        {

            try
            {
                string EventMessage = etwEvtMessage;
                string EventMessageRecordId = _EventMessageRecordId;
                string[] chunk_data = EventMessage.Split('\r');

 
                string i32StartAddress = chunk_data[10].Split(':')[1].Substring(1);

                Int64 TID = Convert.ToInt64(chunk_data[9].Split(':')[1].Substring(1));
                Int32 prc = Convert.ToInt32(chunk_data[7].Split(':')[1].Substring(1));

                buf = new byte[208];
                IntPtr prch = System.Diagnostics.Process.GetProcessById(prc).Handle;
                string XStartAddress = chunk_data[10].Split(':')[1].Substring(1);

                //bool MemoryBytes = Memoryinfo.ReadProcessMemory(prch, (UIntPtr)i32StartAddress, buf, buf.Length, IntPtr.Zero);

                Memoryinfo.NtReadVirtualMemory(prch, (UIntPtr)Convert.ToUInt64(i32StartAddress, 16), buf, (uint)buf.Length, ref NTReadTmpRef);

                var temp_Injected_bytes = Memoryinfo.HexDump(buf);

                BeginInvoke(new __Additem(_Additems_str_toRichtextbox1), EventMessage + "\n\nEventID: " + "8" + "\nEventRecord_ID: " + EventMessageRecordId + "\n\n[Remote-Thread-Injection Memory Information]\n\tTID: " + TID.ToString() + "\n\tTID StartAddress: " +
                XStartAddress.ToString() + "\n\tTID Win32StartAddress: " + i32StartAddress.ToString() + "\n\tTarget_Process PID: " + prc.ToString() +
                "\n\nInjected Memory Bytes: " + BitConverter.ToString(buf).ToString() + "\n\n" + temp_Injected_bytes + "\n_____________________\n");

                _SysmonEventID8_InjectionMemory_Details.Add(new _TableOfMemoryInjection_Details()
                {
                    Sysmon_EventRecord_ID = Convert.ToInt64(EventMessageRecordId),
                    TPID = prc,
                    TTID = TID.ToString(),
                    _StartAddress = i32StartAddress,
                    _InjectedMemory_Sbytes = temp_Injected_bytes,
                    SourceImagePath_or_Injector_Path = chunk_data[5].Substring(13),
                    SourceProcessId_or_InjectorPID = Convert.ToInt32(chunk_data[4].Split(':')[1])

                });
                
            }
            catch (Exception ohwoOwwtfk)
            {
                BeginInvoke(new __Additem(_Additems_str_toRichtextbox1), etwEvtMessage + "\n\nEventID: " + "8" + "\n");
                BeginInvoke(new __Additem(_Additems_str_toRichtextbox1), "EventID: 8, Read Target_Process Memory via API::ReadProcessMemory [ERROR] => " + ohwoOwwtfk.Message + "\n[Remote-Thread-Injection Memory Information]\n_____________________________error______________________________\n");
            }
        }


        public void _SaveAlarmsByETW()
        {

            StringBuilder st = new StringBuilder();
            string dumpinfotext = richTextBox1.Text;

            foreach (ListViewItem xitem in listView6.Items)
            {

                st.AppendLine("\n[#] Time: " + xitem.SubItems[1].Text + ", Process: " + xitem.SubItems[2].Text
                    + "\nStatus: " + xitem.SubItems[3].Text + "\nDetection by Sysmon/ETW: " + xitem.SubItems[4].Text +
                    "\nAction Scanned/Suspended/Terminated: " + xitem.SubItems[5].Text + "\nMemory Scanners Pe-sieve/VirtualMemAllowMon:" + xitem.SubItems[6].Text);
                st.AppendLine("\nMemory Scanner Results:");
                st.AppendLine(xitem.Name);
                st.AppendLine(" ");
                st.AppendLine("-------------------------------------------------------------------------");
                st.AppendLine(" ");
            }

            logfilewrite("Sysmon_ETW_AlarmEvents.txt", st.ToString());
            MessageBox.Show("Alarms ETW Events Saved into Text File: \n \"Sysmon_ETW_AlarmEvents.txt\"");
        }


        public void logfilewrite(string filename, string text)
        {
            using (StreamWriter _file = new StreamWriter(filename))
            {
                _file.WriteLine(text);
            };
        }

        public static class Memoryinfo
        {
            [DllImport("kernelbase.dll")]
            public static extern bool CloseHandle(IntPtr hObject);

            [DllImport("kernelbase.dll")]
            public static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, bool bInheritHandle, Int32 dwProcessId);

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
                return result.ToString();
            }

            public static string HexDump2(byte[] bytes, int bytesPerLine = 16)
            {
                /// hexdump output ... 
                ///00000000   48 83 EC 28 E8 2B FF FF  FF 48 83 C4 28 EB 15 90   Hì(è+ÿÿÿHÄ(ë·
                ///00000010   90 90 90 90 90 90 90 90  90 90 90 90 90 90 90 90   
                ///00000020   90 90 90 90 48 8B C4 48  89 58 08 48 89 78 10 4C   HÄHX·Hx·L

                if (bytes == null) return "<null>";
                int bytesLength = 208;

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
                return result.ToString();
            }

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool ReadProcessMemory(IntPtr hProcess, UIntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, IntPtr lpNumberOfBytesRead);

            [DllImport("ntdll.dll", SetLastError = true)]
            public static extern NtStatus NtReadVirtualMemory(IntPtr ProcessHandle, UIntPtr BaseAddress, byte[] Buffer, UInt32 NumberOfBytesToRead, ref UInt32 NumberOfBytesRead);

            [DllImport("kernel32.dll", SetLastError = true)]
            static extern bool CloseHandle(UIntPtr hObject);

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
        }
    }
}
