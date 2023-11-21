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
using System.Management;
using System.Security.Cryptography;
using System.Reflection;
using System.Runtime.Serialization.Formatters.Binary;

namespace ETWPM2Monitor2
{
    public partial class Form1 : Form
    {
         
        /// <summary>
        /// ETWPM2Monitor v2.1 [test version] Code Published by Damon Mohammadbagher , 31 Jul 2021 
        /// Console App for Realtime monitor ETW Events "ETWPM2" which made by ETWProcessMon2
        /// this app will monitor events in windows event log [logname = ETWPM2].
        /// NewProcess events + RemoteThreadInjection events + TCPIP Send events will monitor by ETWProcessMon2 with logname ETWPM2 which by this tool "ETWPM2Monitor" you can watch them "realtime"
        /// also RemoteThreadInjection events + VirtualMemAlloc events will save by ETWProcessMon2 into text logfile "ETWProcessMonlog.txt" at the same time.
        /// Note: in this version some Memory Scanner will add to code which made by others ...
        /// </summary>         

        /// this System.Management should add to "References" in the project

        public static bool is_system4_excluded = true;
        public Int64 i6 = 0;
        public static System.Timers.Timer t = new System.Timers.Timer(10000);
        public static System.Timers.Timer t2 = new System.Timers.Timer(5000);
        public static System.Timers.Timer t3 = new System.Timers.Timer(10000);
        public static System.Timers.Timer t4 = new System.Timers.Timer(500);
        public static System.Timers.Timer t4_1 = new System.Timers.Timer(1500);
        public static System.Timers.Timer t5 = new System.Timers.Timer(10000);
        public static System.Timers.Timer t6 = new System.Timers.Timer(10000);
        public static System.Timers.Timer t7 = new System.Timers.Timer(20000);
        public static System.Timers.Timer t8 = new System.Timers.Timer(5000);
        public static System.Timers.Timer t9 = new System.Timers.Timer(2000);
        public static System.Timers.Timer t10 = new System.Timers.Timer(10000);
        public static System.Timers.Timer t11 = new System.Timers.Timer(5000);
        public static System.Timers.Timer t12 = new System.Timers.Timer(7000);
        public static System.Timers.Timer t13 = new System.Timers.Timer(2000);
        public static System.Timers.Timer t14 = new System.Timers.Timer(10000);
        public static System.Timers.Timer t15 = new System.Timers.Timer(10000);
        public static System.Timers.Timer t16 = new System.Timers.Timer(10000);
        public static System.Timers.Timer t17 = new System.Timers.Timer(2700);
        public static System.Timers.Timer t18 = new System.Timers.Timer(1500);
        public static System.Timers.Timer t19 = new System.Timers.Timer(5000);
        //public static System.Timers.Timer t20 = new System.Timers.Timer(15000);

       
        public static TimeSpan tt = new TimeSpan();
        public static uint NTReadTmpRef = 0;
        public static EventLog ETW2MON;
        public static EventLogQuery ETWPM2Query;
        public ListViewItem iList = new ListViewItem();
        public ListViewItem iList2 = new ListViewItem();
        public ListViewItem iList3 = new ListViewItem();
        public ListViewItem iList4 = new ListViewItem();
        public static EventLogWatcher EvtWatcher = null;
        public string tempMessage, tempMessage2, EventMessage = "";
        public static byte[] buf = new byte[90];
        public static BackgroundWorker bgw = new BackgroundWorker();
        public static ListViewItem LviewItemsX = null;
        public static string evtstring, tmplasttcpevent = "";
        public static bool isPEScanonoff = true;
        public static bool isHollowHunteronoff = true;
        public static bool init_savedumpinfo = false;
        public static bool init_removeItems = false;

        public delegate void __MyDelegate_LogFileReader_Method();
        public delegate void __MyDelegate_showdatagrid();
        public delegate void __LogReader();
        public delegate void __Additem(object itemsOfListview1_2_5_6);
        public delegate void __AddTextTorichtexhbox1(object str);
        public delegate void __core2(object str);
        public delegate void __core5(object str,int id);
        public delegate void __Updatelistview1();
        public delegate void __Obj_Updater_to_WinForm();
        public delegate void __Obj_Updater_to_WinForm2(TreeView ResultTreeview, string obj1, TreeView obj2);
        public delegate void __Obj_Updater_to_WinForm3(string obj1, int obj2);
        public delegate void __FSWatch_Object_Add(System.IO.FileSystemEventArgs _e);
        public delegate void __AsyncScanner01(List<_TableofProcess> __Table_of_Process_to_Scan, Int32 PID, string _des_address_port, string ProcessName);
        public delegate void __core6(string str, string date);
        public struct _TCPConnection_Struc
        {
            private DateTime Time;
            public DateTime _Time { get { return Time; } set { Time = value; } }

            private string Process;
            public string _Process { get { return Process; } set { Process = value; } }

            private string Status;
            public string _Status { get { return Status; } set { Status = value; } }

            private string SIP;
            public string _SIP { get { return SIP; } set { SIP = value; } }

            private string DIP;
            public string _DIP { get { return DIP; } set { DIP = value; } }

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

            private Int32 Update_Events;
            public Int32 _Update_Events { get { return Update_Events; } set { Update_Events = value; } }


        }

        public static List<_TCPConnection_Struc> TCPConnectionTable_To_Show = new List<_TCPConnection_Struc>();


        public static List<_All_Injection_Details_info_Filter_withoutSystem4> _List_All_Injection_Details_info_Filter_withoutSystem4 = new List<_All_Injection_Details_info_Filter_withoutSystem4>();
        public struct _All_Injection_Details_info_Filter_withoutSystem4
        {
            private bool flag_to_NoRemove_FromList;
            public string _time_evt { set; get; }
            public string _ThreadStartAddress { set; get; }
            public Int32 _RemoteThreadID { set; get; }
            public Int32 _TargetPID { set; get; }
            public string _TargetPID_Path { set; get; }
            public Int32 _InjectorPID { set; get; }
            public string _InjectorPID_Path { set; get; }

            public bool _flag_to_Dont_Remove_FromList { get { return flag_to_NoRemove_FromList; } set { flag_to_NoRemove_FromList = value; } }

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
            //private string _TCPDetails2;
            //public string TCPDetails2 { get { return _TCPDetails2; } set { _TCPDetails2 = value; } }

            //public string TCPDetails;
            //public string Description;
            //public int PID;
            //public int Injector;
            //public string Injector_Path;
            //public string ProcessName;
            //public string ProcessName_Path;
            //public bool IsLive { set; get; }
            //public bool IsShow_Alarm { set; get; }
            //public DateTime Detection_EventTime;
            //public string Detection_Status;
            //public string MemoryScanner01_Result;
            //public string MemoryScanner02_Result;
            //public string InjectionType;
            //public string Descripton_Details;
            //public string SubItems_Name_Property;
            //public int SubItems_ImageIndex;
            private string _TCPDetails2;
            public string TCPDetails2 { get { return _TCPDetails2; } set { _TCPDetails2 = value; } }

            public string TCPDetails { set; get; }
            public string Description { set; get; }
            public int PID { set; get; }
            public int Injector { set; get; }
            public string Injector_Path { set; get; }
            public string ProcessName { set; get; }
            public string ProcessName_Path { set; get; }
            public bool IsLive { set; get; }
            public bool IsShow_Alarm { set; get; }
            public DateTime Detection_EventTime { set; get; }
            public string Detection_Status { set; get; }
            public string MemoryScanner01_Result { set; get; }
            public string MemoryScanner02_Result { set; get; }
            public string InjectionType { set; get; }
            public string Descripton_Details { set; get; }
            public string SubItems_Name_Property { set; get; }
            public int SubItems_ImageIndex { set; get; }
        }
        public static List<_TableofProcess_NewProcess_evt> NewProcess_Table = new List<_TableofProcess_NewProcess_evt>();
        public static List<string> showitemsHash = new List<string>();
        public static List<_TableofProcess> Process_Table = new List<_TableofProcess>();
        public static List<_InjectedThreadDetails_bytes> _InjectedTIDList = new List<_InjectedThreadDetails_bytes>();
        public static List<string> List_ofProcess_inListview2 = new List<string>();
        public static List<Int32> temptids = new List<int>();
        public static List<string> ActiveTCP = new List<string>();


        public string Tempops, Injectortmp = "";
        public string[] finalresult_Scanned_01 = new string[2];
        public string[] _finalresult_Scanned_01 = new string[2];
        public string[] finalresult_Scanned_02 = new string[3];
        public string[] _finalresult_Scanned_02 = new string[3];

        /// <summary>
        /// table/list for pe-sieve64.exe
        /// </summary>
        public struct _TableofProcess_Scanned_01
        {

            public string injectorPathPID { set; get; }
            public int time_min { set; get; }
            public int time_Hour { set; get; }
            public string ProcNameANDPath { set; get; }
            public int PID { set; get; }
            /// <summary>
            /// needs to change sync to async scanning target process ;)
            /// </summary>
            public bool ScannerResult_IsDetected { set; get; }
            public string Scanner01_RESULT_Int32_outputstr { set; get; }
            public string InjectionType { set; get; }
            public string Action { set; get; }
        }

        /// <summary>
        /// table/list for hollowshunter.exe
        /// </summary>
        public struct _TableofProcess_Scanned_02
        {

            public string injectorPathPID { set; get; }
            public int time_min { set; get; }
            public int time_Hour { set; get; }
            public string ProcNameANDPath { set; get; }
            public int PID { set; get; }
            /// <summary>
            /// needs to change sync to async scanning target process ;)
            /// </summary>
            public bool ScannerResult_IsDetected { set; get; }
            public string Scanner02_RESULT_Int32_outputstr { set; get; }
            public string ScannerStatus { set; get; }
        }

        public static List<_TableofProcess_Scanned_01> Scanned_PIds = new List<_TableofProcess_Scanned_01>();
        public static string strOutput = "";
        public static System.Diagnostics.Process outputs = new System.Diagnostics.Process();
        public bool Init_to_runPEScanner_01 = false;

        public static List<_TableofProcess_Scanned_02> Scanned_PIds2 = new List<_TableofProcess_Scanned_02>();
        public static string strOutput2 = "";
        public static System.Diagnostics.Process outputs2 = new System.Diagnostics.Process();
        public static bool Init_to_runPEScanner_02 = false;
        public static int HollowHunterLevel = 0;
        public static int Pe_sieveLevel = 0;
        public static bool AlarmsByETW_onoff_WithoutScanners = false;


        /// <summary>
        /// Adding Process which had RemoteThreadInjection to the list for monitoring their TCP Connections etc...
        /// </summary>
        public event EventHandler RemoteThreadInjectionDetection_ProcessLists;

        /// <summary>
        /// C# event, when new tcp Event ID 3 detected then this event will invoke [NewProcessAddedtolist.Invoke(objX, null)]
        /// for check process via process table [_Table = Process_Table] and memory scanners (if needed), 
        /// that means if this process has tcp connection event which had some related injection event 
        /// then should have true flag for scanning by memory scanners and add to "Alarms by ETW Tab"
        /// so this process had remotethread injectioh event plus tcp connection event so maybe should has true flag for scanning in memory ...
        /// </summary>   
        public event EventHandler NewProcessAddedtolist;

        public object[] obj = new object[2];
        public object objX = null;
        public string AlarmsDisabled = "Warning: Alarms by ETW \"Tab\", is \"disabled\" by selecting this Filter, [All Memory Scanners are OFF]";

        /// <summary>
        /// event for New Process Detection & Adding NEW Process info to the list [Event ID 1]
        /// </summary>
        public event EventHandler NewProcessAddedtolist_NewProcessEvt;
        public object[] obj2 = new object[8];


        /// <summary>
        /// v0 => new process
        /// v1 => injection count
        /// v2 => tcp count
        /// v3 => alarms by etw red count
        /// v4 => alarms by etw orange count
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
        public static int pe_sieve_DumpSwitches = 0;
        /// <summary>
        /// hollowshunter_DumpSwitches =  /ofilter  & , 0 dump all , 1 dump some files , 2 Dont Dump any Process to disk (if detected something)
        /// </summary>
        public static int hollowshunter_DumpSwitches = 0;
        public int _1, _2, _3, _4, _5, _6, _7, _8, time4t = 0;
        public string subitemX = "";
        public static string[] temp_str = null;
        public static string tmpitemListview2 = "";

        /// <summary> event for refresh/update events in listView1 for (real-time events), these events read from windows event log name "ETWPM2" and added to listview1 (real_time)  </summary>
        public event EventHandler NewEventFrom_EventLogsCome;

        /// <summary> event for add all detection events to System_Detection_logs Tab </summary>  
        public event EventHandler System_Detection_Log_events;

        /// <summary> event for add tcp/new events which was for Shell or Meterpreter Session detection events to System_Detection_logs Tab </summary>  
        public event EventHandler System_Detection_Log_events2;

        /// <summary> event for add tcp events to Network Tab  </summary>  
        public event EventHandler NewTCP_Connection_Detected;

        /// <summary> event for change Listview4 colors </summary>        
        public event EventHandler ChangeColorstoDefault;       

        public struct _TableofProcess_ETW_Event_Counts
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

        public struct _Table_of_FileSystem_for_Processes_Watcher
        {
            private string _File_MD5;
            public string Eventtime { set; get; }
            public string FileName { set; get; }
            public string FileName_Path { set; get; }

            public string ProcessCommandLine { set; get; }
            public string File_MD5 { get { return _File_MD5; } set { _File_MD5 = value; } }

        }
        public static List<_Table_of_FileSystem_for_Processes_Watcher> Processes_FileSystemList = new List<_Table_of_FileSystem_for_Processes_Watcher>();

        public static List<_TableofProcess_ETW_Event_Counts> _ETW_Events_Counts = new List<_TableofProcess_ETW_Event_Counts>();
        public static _TableofProcess_ETW_Event_Counts Temp_Table_structure;

        public struct _ListProcessObjects
        {
            private bool _flag;
            public DateTime Eventtime { set; get; }
            public bool flag { get { return _flag; } set { _flag = value; } }
            public object obj { set; get; }
            public ulong counter { set; get; }

        }

        public static string evtstring2, evtstring3 = "";
        public static Int32 ListiveItemCount = 1000;
        public static Int32 counter_for_tcp_packets_filter = 0;
        public static bool IsSearchFormActived = false;
        public static bool show_tcp_packets_filter = false;
        public static bool _StopLoopingScan_Exec_01 = false;
        public static bool ScannerEvery10minMode_Pesieve = false;
        // public static bool _StopLoopingScan_Exec_02 = false;
        // public static bool ScannerMixedMode_Pesieve = false;
        // public static bool ScannerMixedMode_Hollowh = false;
        // public static bool ScannerEvery10minMode_Hollowh = false;
        public static string eventstring_tmp3 = "";
        public static bool NetworkConection_found = false;
        public static Int64 NetworkConection_TCP_counts = 0;
        public static bool IsTargetProcessTerminatedbyETWPM2monitor = false;
        public static string _windir = Environment.GetEnvironmentVariable("windir").ToLower();
        public static NotifyIcon ico = new NotifyIcon();
        public static bool _isNotifyEnabled = true;
        public static string _ProcessName;
        public static bool _IsProcessTab_Enabled = false;
        /// <summary>
        /// ETWPM2Realt_timeShowMode_Level => 1 and 0
        /// 0 is mode to show all event also in this mode tool will detect shell process via Red Background
        /// 1 is besr performance to show last events [events will overwrite to relative listview items] , 
        /// in this mode 1 , we have bug to show shell process with red background , will fix in the future...
        /// </summary>
        public static int ETWPM2Realt_timeShowMode_Level = 0;
        public static string SearchInjector, SearchInjector2 = "";
        public static int _PPID_For_TimerScanner01 = -1;
        public static string _PPIDPath_For_TimerScanner01 = "";
        public static int _Imgindex, _Imgindex2 = 0;
        public ListViewItem xiList2 = new ListViewItem();
        public static List<string> _ExcludeProcessList = new List<string>();
        public static bool IsDontShow_ETWPM2_Realt_time_Enabled = false;
        public static bool IsDontShow_NetworkConnection_Enabled = false;
        public static List<string> System_DeveloperLogsList = new List<string>();
        public static Int64 System_DeveloperLogsListIndex = 0;
        public static bool IsSystemDeveloperLogs_on = true;
        public List<_ListProcessObjects> ProcessListTabObject = new List<_ListProcessObjects>();
        public ulong ProcessListTabObject_itemscounter01 = 0;
        public string lastETW_Alarms_Detection = "";
        public string lastETW_Alarms_Detection2 = "";
        public static List<string> _List_of_Alarm_Events_Raised = new List<string>();
        public int _orangeDetection = 0;
        public int _RedflagDetection = 0;
        public List<string> _List_of__RedflagDetection_Raised = new List<string>();
        public bool IsFilterSystem4Enabled_ETWPM2_Realtime = true;
        public static List<ListViewItem> _DetectedItemsByETWAlarms = new List<ListViewItem>();
        public static List<ListViewItem> _DetectedItemsByWindowEventLogSaved = new List<ListViewItem>();
        public static int TCPConnectionDelay_for_RefreshList = 100;
        public ETW_Alarms_to_WinEventLog SaveETWLogs = new ETW_Alarms_to_WinEventLog();
        public static bool Isinit_Time_To_Start_Timer10_ProcessTabTimer = false;
        public static DateTime _Time_To_Start_Timer10_ProcessTabTimer = DateTime.Now;
        public static List<ListViewItem> _ETW_Network_Events_FalsePositiveChecking_Records = new List<ListViewItem>();
        public static List<ListViewItem> _Listview3_Items_NetworkConnection_Apis = new List<ListViewItem>();
        public static List<ListViewItem> _Listview7_Items_NetworkConnection_history = new List<ListViewItem>();
        /// <summary>
        ///  last update 9 june 2023 [v2.1.50.528] 
        ///  New Memory Scanner called [Hunt_Sleeping_Beacons] added
        /// </summary>
        public static string Main_lastMemoryScannerIIResult = "";
        public static List<ListViewItem> Main_DetectedItemsByMemoryScannerII_Alarms = new List<ListViewItem>();
        public static ListViewItem Main_xiList3 = new ListViewItem();
        public static string Main_MemoryScanner_Hunt_Sleeping_Beacons_Details = "";
        public static string Main_DetectedPID_via__Hunt_Sleeping_Beacons = "";
        public static string Main_DetectedProcess_via__Hunt_Sleeping_Beacons = "";
        public string[] Main__Results_for__Hunt_Sleeping_Beacons = new string[1];
        public static string Main_Result__in_background__Hunt_Sleeping_Beacons = "";
        public static int Main_SearchProcessinNetHistoryListview7 = -1;
        public static bool _IsMemoryScanner_PeSieve_isBusy = false;
        public static string movjmp_info = "\n\n";



        public async Task _Add_SystemDeveloperLogs(string logmessage)
        {
            try
            {
                await Task.Run(() =>
                {
                    System_DeveloperLogsList.Add(DateTime.Now.Hour + ":" + DateTime.Now.Minute + ":" + DateTime.Now.Second + "." + DateTime.Now.Millisecond + " " + logmessage);
                    listBox5.BeginInvoke((MethodInvoker)delegate
                    {                        
                        listBox5.Items.Add(DateTime.Now.Hour + ":" + DateTime.Now.Minute + ":" + DateTime.Now.Second + "." + DateTime.Now.Millisecond + " " + logmessage);
                    });
                });
            }
            catch (Exception)
            {


            }
        }
        public async void AsyncRun__Add_SystemDeveloperLogs(object obj)
        {
            await _Add_SystemDeveloperLogs(obj.ToString());
        }
        public static string _Get_MD5(string filenamePath)
        {
            string result = "";

            try
            {

                if (filenamePath != null)
                {
                    byte[] myHash;
                    using (var md5 = MD5.Create())
                    using (var stream = File.OpenRead(filenamePath))
                        myHash = md5.ComputeHash(stream);

                    for (int i = 0; i < myHash.Length; i++)
                    {
                        result += myHash[i].ToString("x2");
                    }
                }
                return result;
            }
            catch (Exception)
            {


            }

            return result;
        }
        public async void _Show_Notify_Ico_Popup(object obj)
        {
            try
            {
                if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [_Show_Notify_Ico_Popup] Method Call: Started");
                //if(IsSystemDeveloperLogIson) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [_Show_Notify_Ico_Popup] Method Call: error1 => " + ee.Message);

                await Task.Run(() =>
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
                         + "\n" + _value4 + "\n" + _value5 + "\n" + _value6, _value2 + "\n" + _value5, ToolTipIcon.Error);
                });
            }
            catch (Exception ee)
            {
                if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [_Show_Notify_Ico_Popup] Method Call: error1 => " + ee.Message);

            }
        }
        public static int _percent(int count, int total)
        {
            if (total != 0)
            {
                try
                {
                    return (count * 100) / total;
                }
                catch (Exception)
                {
                    return (count * 100) / total;

                }
            }
            else
            {
                return 0;
            }

        }
        public IEnumerable<TreeNode> _FindSubsNode(TreeNodeCollection nodes, string Search)
        {
            foreach (TreeNode node in nodes)
            {

                if (node.Text.IndexOf(Search, StringComparison.CurrentCultureIgnoreCase) >= 0)
                {
                    yield return node;
                }
                else
                {
                    foreach (var subNode in _FindSubsNode(node.Nodes, Search)) yield return subNode;
                }
            }
        }
        public void __SearchStrings_in_ProcessesTab(TreeView SearchResultTreeView, string search, TreeView targetProcesses)
        {

            try
            {

                foreach (TreeNode node in targetProcesses.Nodes)
                {

                    if (node.Text.IndexOf(search, StringComparison.CurrentCultureIgnoreCase) >= 0)
                    {
                        object mainobj = node.Clone();

                        SearchResultTreeView.Nodes.Add((TreeNode)mainobj);
                    }
                    else
                    {
                        string lastnode = "";
                        foreach (var subNode in _FindSubsNode(node.Nodes, search))
                        {

                            object obj = subNode.Parent.Clone();

                            ((TreeNode)obj).ForeColor = Color.Black;
                            ((TreeNode)obj).ExpandAll();

                            if (((TreeNode)obj).Text != lastnode)
                                SearchResultTreeView.Nodes.Add((TreeNode)obj);

                            lastnode = ((TreeNode)obj).Text;

                        }
                    }
                }

            }
            catch (Exception r)
            {


            }


        }
        public void __Additems_toListview1__2_Method(object _obj)
        {
            ListViewItem _obj_ = (ListViewItem)_obj;

            listView1.BeginInvoke((MethodInvoker)delegate
            {
                if (IsFilterSystem4Enabled_ETWPM2_Realtime == false)
                {

                    if (listView1.Items.Count > 0)
                    {

                        bool _found = false;

                        for (int i = 0; i < listView1.Items.Count; i++)
                        {

                            if (listView1.Items[i].SubItems[3].Text == _obj_.SubItems[3].Text)
                            {
                                listView1.Items[i].SubItems[0] = _obj_.SubItems[0];
                                listView1.Items[i].SubItems[1] = _obj_.SubItems[1];
                                listView1.Items[i].SubItems[2] = _obj_.SubItems[2];
                                listView1.Items[i].SubItems[3] = _obj_.SubItems[3];
                                listView1.Items[i].SubItems[4] = _obj_.SubItems[4];
                                listView1.Items[i].SubItems[5] = _obj_.SubItems[5];
                                listView1.Items[i].Name = _obj_.Name;
                                listView1.Items[i].ImageIndex = _obj_.ImageIndex;
                                _found = true;
                                listView1.Items[i].ForeColor = Color.OrangeRed;
                                break;
                            }
                        }

                        if (!_found)
                        {
                            listView1.Items.Add(_obj_).ForeColor = Color.OrangeRed;
                            Thread.Sleep(5);
                        }

                    }
                    else
                    {
                        listView1.Items.Add(_obj_).ForeColor = Color.OrangeRed;
                    }
                }

                if (IsFilterSystem4Enabled_ETWPM2_Realtime == true)
                {
                    if (!_obj_.SubItems[5].Text.Split('\n')[5].Contains(":4[Injected by System]"))
                    {
                        if (listView1.Items.Count > 0)
                        {

                            bool _found = false;

                            for (int i = 0; i < listView1.Items.Count; i++)
                            {

                                if (listView1.Items[i].SubItems[3].Text == _obj_.SubItems[3].Text)
                                {
                                    listView1.Items[i].SubItems[0] = _obj_.SubItems[0];
                                    listView1.Items[i].SubItems[1] = _obj_.SubItems[1];
                                    listView1.Items[i].SubItems[2] = _obj_.SubItems[2];
                                    listView1.Items[i].SubItems[3] = _obj_.SubItems[3];
                                    listView1.Items[i].SubItems[4] = _obj_.SubItems[4];
                                    listView1.Items[i].SubItems[5] = _obj_.SubItems[5];
                                    listView1.Items[i].Name = _obj_.Name;
                                    listView1.Items[i].ImageIndex = _obj_.ImageIndex;
                                    _found = true;
                                    listView1.Items[i].ForeColor = Color.OrangeRed;
                                    break;
                                }
                            }

                            if (!_found)
                            {
                                listView1.Items.Add(_obj_).ForeColor = Color.OrangeRed;
                                Thread.Sleep(5);
                            }

                        }
                        else
                        {
                            listView1.Items.Add(_obj_).ForeColor = Color.OrangeRed;
                        }

                    }
                }
            });
        }
        public void _Additems_toListview1__2(object obj)
        {
            try
            {

                ListViewItem MyLviewItemsX1 = (ListViewItem)obj;
                Thread.Sleep(5);

                if (MyLviewItemsX1 != null)
                {
                    if (_IsProcessTab_Enabled)
                    {

                        // BeginInvoke(new __Additem(_Additems_toTreeview1), MyLviewItemsX1);

                        /// filter: show all injection (exclude injection by system PID 4)
                        if (!MyLviewItemsX1.SubItems[5].Text.Contains("Injected by Process Exited (PID:4)")
                            && !MyLviewItemsX1.SubItems[5].Text.Contains("4[Injected by System]"))
                        {
                            ProcessListTabObject_itemscounter01 = ProcessListTabObject_itemscounter01 + 1;

                            ProcessListTabObject.Add(new _ListProcessObjects
                            {
                                Eventtime = DateTime.Now,
                                flag = false,
                                obj = MyLviewItemsX1,
                                counter = ProcessListTabObject_itemscounter01
                            });
                        }
                    }
                    /// EventID 3 = TCP Send Event
                    if (MyLviewItemsX1.SubItems[2].Text == "3")
                    {
                        /// size 160 , 192 was about Meterpreter traffic which will send send for each 1 min [sleep(1000) default] 
                        /// also 192 will send before every command packets  meterpreter backdoor
                        /// that was my test ;)
                        if ((MyLviewItemsX1.SubItems[5].Text.Split('\n')[6].Contains("[size:160]")) || (MyLviewItemsX1.SubItems[5].Text.Split('\n')[6].Contains("[size:192]")))
                        {
                            MyLviewItemsX1.BackColor = Color.LightGray;
                            // MyLviewItemsX1.ForeColor = Color.White;

                            if (MyLviewItemsX1.SubItems[5].Text.Split('\n')[6].Contains("[dport:4444]"))
                            {
                                MyLviewItemsX1.BackColor = Color.Gainsboro;
                            }

                            MyLviewItemsX1.SubItems[5].Text += "\n\n#This Description Added by ETWPM2Monitor2 tool#\n##Warning Description: Packet with [size:160] maybe was for Meterpreter Session which will send every 1 min between Client/Server##\n" +
                            "##Warning Description: Packet with [size:192] is for meterpreter session which will send before every command excution from/to server##\n" +
                            "##Warning Description: DestinationPort [dport:4444] is Default port for Meterpreter session##";

                            System_Detection_Log_events2.Invoke((object)MyLviewItemsX1, null);

                        }
                        else if (MyLviewItemsX1.SubItems[5].Text.Split('\n')[6].Contains("[dport:4444]"))
                        {
                            MyLviewItemsX1.BackColor = Color.Gainsboro;

                            MyLviewItemsX1.SubItems[5].Text += "\n\n#This Description Added by ETWPM2Monitor2 tool#\n##Warning Description: Packet with [size:160] maybe was for Meterpreter Session which will send every 1 min between Client/Server##\n" +
                               "##Warning Description: Packet with [size:192] is for meterpreter session which will send before every command excution from/to server##\n" +
                               "##Warning Description: DestinationPort [dport:4444] is Default port for Meterpreter session##";
                            System_Detection_Log_events2.Invoke((object)MyLviewItemsX1, null);
                        }
                        if (!IsDontShow_ETWPM2_Realt_time_Enabled)
                        {
                            BeginInvoke(new __Additem(__Additems_toListview1__2_Method), MyLviewItemsX1);
                        }

                    }

                    /// EventID 1 = Create New Process
                    if (MyLviewItemsX1.SubItems[2].Text == "1")
                    {
                        string commandline = MyLviewItemsX1.SubItems[5].Text.Split('\n')[4].ToLower();
                        string parentid = MyLviewItemsX1.SubItems[5].Text.Split('\n')[6].ToLower();
                        if (commandline.Contains("[commandline: \"" + _windir + "\\system32\\cmd.exe\"") || commandline.Contains("[commandline: " + _windir + "\\system32\\cmd.exe") || commandline.Contains("[commandline: cmd"))
                        {
                           
                            if (parentid != "[parentid path: " + _windir + "\\explorer.exe]")
                            {
                                MyLviewItemsX1.BackColor = Color.Red;
                                MyLviewItemsX1.ForeColor = Color.Black;
                                MyLviewItemsX1.ImageIndex = 2;
                                MyLviewItemsX1.SubItems[5].Text += "\n\n#This Description Added by ETWPM2Monitor2 tool#\n##Warning Description: [ParentID Path] & [PPID] for this New Process is not Normal! (maybe Shell Activated?)##\n";
                                System_Detection_Log_events2.Invoke((object)MyLviewItemsX1, null);
                            }
                        }
                        else
                        {
                            MyLviewItemsX1.ForeColor = Color.Black;
                            MyLviewItemsX1.ImageIndex = 0;
                        }

                        if (!IsDontShow_ETWPM2_Realt_time_Enabled)
                        {
                            BeginInvoke(new __Additem(__Additems_toListview1__2_Method), MyLviewItemsX1);
                        }

                    }

                    /// EventID 2 = Injection
                    if (MyLviewItemsX1.SubItems[2].Text == "2")
                    {
                        if (!IsDontShow_ETWPM2_Realt_time_Enabled)
                        {
                            BeginInvoke(new __Additem(__Additems_toListview1__2_Method), MyLviewItemsX1);
                        }
                    }

                    evtstring = MyLviewItemsX1.Name;
                }

            }
            catch (Exception)
            {


            }

        }

        /// <summary>
        /// Add ETW items to listview1 [events ID 1 : new process] [even ID 2 : injection detection] [event ID 3 : tcp send,connect connections] 
        /// </summary>
        /// <param name="obj"></param>
        public void _Additems_toListview1(object obj)
        {

            try
            {

                ListViewItem MyLviewItemsX1 = (ListViewItem)obj;
                Thread.Sleep(5);

                if (MyLviewItemsX1 != null)
                {
                    /// just for test for better detection via events ;)
                    /// simple example.

                    if (_IsProcessTab_Enabled)
                    {

                        /// filter: show all injection (exclude injection by system PID 4)
                        if (!MyLviewItemsX1.SubItems[5].Text.Contains("Injected by Process Exited (PID:4)")
                            && !MyLviewItemsX1.SubItems[5].Text.Contains("4[Injected by System]"))
                        {
                            ProcessListTabObject_itemscounter01 = ProcessListTabObject_itemscounter01 + 1;

                            ProcessListTabObject.Add(new _ListProcessObjects
                            {
                                Eventtime = DateTime.Now,
                                flag = false,
                                obj = MyLviewItemsX1,
                                counter = ProcessListTabObject_itemscounter01
                            });
                        }
                    }

                    /// EventID 3 = TCP Send Event
                    if (MyLviewItemsX1.SubItems[2].Text == "3")
                    {

                        /// size 160 , 192 was about Meterpreter traffic wich will send send for each 1 min [sleep(1000) default] 
                        /// also 192 will send before every command packets  meterpreter backdoor
                        /// that was my test ;)
                        if ((MyLviewItemsX1.SubItems[5].Text.Split('\n')[6].Contains("[size:160]")) || (MyLviewItemsX1.SubItems[5].Text.Split('\n')[6].Contains("[size:192]")))
                        {
                            MyLviewItemsX1.BackColor = Color.LightGray;
                            MyLviewItemsX1.ForeColor = Color.White;

                            if (MyLviewItemsX1.SubItems[5].Text.Split('\n')[6].Contains("[dport:4444]"))
                            {
                                MyLviewItemsX1.BackColor = Color.Gainsboro;
                                MyLviewItemsX1.ForeColor = Color.Black;

                            }

                            MyLviewItemsX1.SubItems[5].Text += "\n\n#This Description Added by ETWPM2Monitor2 tool#\n##Warning Description: Packet with [size:160] maybe was for Meterpreter Session which will send every 1 min between Client/Server##\n" +
                            "##Warning Description: Packet with [size:192] is for meterpreter session which will send before every command excution from/to server##\n" +
                            "##Warning Description: DestinationPort [dport:4444] is Default port for Meterpreter session##";

                            System_Detection_Log_events2.Invoke((object)MyLviewItemsX1, null);

                        }
                        else if (MyLviewItemsX1.SubItems[5].Text.Split('\n')[6].Contains("[dport:4444]"))
                        {
                            MyLviewItemsX1.BackColor = Color.LightSlateGray;
                            MyLviewItemsX1.ForeColor = Color.White;

                            MyLviewItemsX1.SubItems[5].Text += "\n\n#This Description Added by ETWPM2Monitor2 tool#\n##Warning Description: Packet with [size:160] maybe was for Meterpreter Session which will send every 1 min between Client/Server##\n" +
                               "##Warning Description: Packet with [size:192] is for meterpreter session which will send before every command excution from/to server##\n" +
                               "##Warning Description: DestinationPort [dport:4444] is Default port for Meterpreter session##";
                            System_Detection_Log_events2.Invoke((object)MyLviewItemsX1, null);
                        }

                        if (!IsDontShow_ETWPM2_Realt_time_Enabled)
                        {
                            try
                            {
                                /// Delta time Detection in Show Event Details [Mode1].
                                /// 

                                if (listView1.Items.Count > 0)
                                {
                                   
                                    string lastprocess = listView1.Items[listView1.Items.Count - 1].SubItems[3].Text;
                                   
                                    if (lastprocess.ToLower() == MyLviewItemsX1.SubItems[3].Text.ToLower())
                                    {
                                        try
                                        {
                                            DateTime lastdt = Convert.ToDateTime(listView1.Items[listView1.Items.Count - 1].SubItems[5].Text.Split('\n')[4].Split('=')[1]);
                                            DateTime currentdt = Convert.ToDateTime(MyLviewItemsX1.SubItems[5].Text.Split('\n')[4].Split('=')[1]);
                                            TimeSpan ts = currentdt - lastdt;
                                            string delta = ts.TotalSeconds.ToString();

                                            listView1.Items[listView1.Items.Count - 1].SubItems[4].Text += " " + "▼";

                                            Int32 deltalast = -1;

                                            if (listView1.Items[listView1.Items.Count - 1].SubItems[4].Text.Contains("DeltaTime:"))
                                            {
                                                deltalast = Convert.ToInt32(string.Join("", ("0" + listView1.Items[listView1.Items.Count - 1].SubItems[4].Text)
                                                   .ToCharArray().Where(char.IsDigit)).ToString());
                                            }

                                            listView1.Items.Add(MyLviewItemsX1);

                                            listView1.Items[listView1.Items.Count - 1].SubItems[4].Text += " " + "▲" + " (DeltaTime: " + delta + " Sec)";



                                            Int32 deltacurrent = Convert.ToInt32(ts.TotalSeconds);

                                            /// show tcp events for process. those Events which has/had same Delta Time.
                                            if (deltalast == deltacurrent)
                                            {
                                                listView1.Items[listView1.Items.Count - 2].BackColor = Color.LightGoldenrodYellow;
                                                listView1.Items[listView1.Items.Count - 1].BackColor = Color.LightGoldenrodYellow;
                                                listView1.Items[listView1.Items.Count - 2].ForeColor = Color.Black;
                                                listView1.Items[listView1.Items.Count - 1].ForeColor = Color.Black;
                                            }

                                           
                                        }
                                        catch (Exception ee)
                                        {
                                          //  MessageBox.Show(ee.Message);

                                        }


                                    }
                                    else
                                    {
                                        listView1.Items.Add(MyLviewItemsX1);
                                    }
                                }
                                else
                                {
                                    listView1.Items.Add(MyLviewItemsX1);
                                   
                                }
                            }
                            catch (Exception)
                            {

                                
                            }                                                     

                        }



                    }

                    /// EventID 1 = Create New Process
                    if (MyLviewItemsX1.SubItems[2].Text == "1")
                    {
                        string commandline = MyLviewItemsX1.SubItems[5].Text.Split('\n')[4].ToLower();
                        string parentid = MyLviewItemsX1.SubItems[5].Text.Split('\n')[6].ToLower();
                        
                        if (commandline.Contains("[commandline: \"" + _windir + "\\system32\\cmd.exe\"") 
                            || commandline.Contains("[commandline: " + _windir + "\\system32\\cmd.exe") || commandline.Contains("[commandline: cmd")
                              || commandline.Contains("[commandline: " + _windir + "\\system32\\windowspowershell\\")
                        || commandline.Contains("[commandline: powershell.exe"))
                        {
                           
                            if (parentid != "[parentid path: " + _windir + "\\explorer.exe]")
                            {
                                MyLviewItemsX1.BackColor = Color.Red;
                                MyLviewItemsX1.ForeColor = Color.Black;
                                MyLviewItemsX1.ImageIndex = 2;
                                MyLviewItemsX1.SubItems[5].Text += "\n\n#This Description Added by ETWPM2Monitor2 tool#\n##Warning Description: [ParentID Path] & [PPID] for this New Process is not Normal! (maybe Shell Activated?)##\n";
                                System_Detection_Log_events2.Invoke((object)MyLviewItemsX1, null);
                            }
                        }
                        else
                        {
                            MyLviewItemsX1.ForeColor = Color.Black;
                            MyLviewItemsX1.ImageIndex = 0;
                        }
                        if (!IsDontShow_ETWPM2_Realt_time_Enabled)
                        {
                            listView1.Items.Add(MyLviewItemsX1);
                        }
                    }
                    /// EventID 2 = Injection
                    if (MyLviewItemsX1.SubItems[2].Text == "2")
                    {
                        if (!IsDontShow_ETWPM2_Realt_time_Enabled)
                        {
                            if (IsFilterSystem4Enabled_ETWPM2_Realtime == false)
                            {
                                listView1.Items.Add(MyLviewItemsX1);
                            }

                            if (IsFilterSystem4Enabled_ETWPM2_Realtime == true)
                            {
                                if (!MyLviewItemsX1.SubItems[5].Text.Split('\n')[5].Contains(":4[Injected by System]"))
                                {
                                    listView1.Items.Add(MyLviewItemsX1);
                                }
                            }
                        }
                    }

                    evtstring = MyLviewItemsX1.Name;

                }


            }
            catch (Exception ee)
            {


            }
        }
        
        /// <summary>
        /// add items to listview2 Alarms by ETW like Scanned,Scannedfound,Suspended,Terminated etc
        /// </summary>
        /// <param name="obj"></param>
        public void _Additems_toListview2(object obj)
        {
            ListViewItem MyLviewItemsX2 = (ListViewItem)obj;

            if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [_Additems_toListview2] Method Call: Started");
            //if(IsSystemDeveloperLogIson) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [_Additems_toListview2] Method Call: error1 => " + ee.Message);


            try
            {
                if (MyLviewItemsX2 != null)
                {
                    string[] allDetails_EventMessage = MyLviewItemsX2.SubItems[9].Text.Split('\n');

                    string xDetection_EventTime = allDetails_EventMessage[17].Split('>')[1];
                    Int32 xpid = Convert.ToInt32(allDetails_EventMessage[8].Split('>')[1]);
                    string xProcessName = allDetails_EventMessage[15].Split('>')[1].Substring(1);
                    string xDescription_is_EventMessage = MyLviewItemsX2.SubItems[9].Text;
                    string xInjector_Path = allDetails_EventMessage[16].Split('>')[1].Substring(1);
                    Int32 xInjectorPID = Convert.ToInt32(allDetails_EventMessage[12].Split('>')[1].Substring(1));
                    string xProcessName_Path = allDetails_EventMessage[3].Substring(20);
                    string xTCPDetails2 = MyLviewItemsX2.SubItems[4].Text;
                    string xDetection_Status = MyLviewItemsX2.SubItems[5].Text;
                    string xInjectionType = MyLviewItemsX2.SubItems[3].Text;
                    string xMemoryScanner01_Result = MyLviewItemsX2.SubItems[6].Text;
                    string xMemoryScanner02_Result = MyLviewItemsX2.SubItems[7].Text;
                    string xDescription2 = MyLviewItemsX2.SubItems[8].Text;
                    string xSubItems_Name_Property = MyLviewItemsX2.Name.ToString();
                    int xSubItems_ImageIndex = MyLviewItemsX2.ImageIndex;

                    int obj_index = Process_Table.ToList<_TableofProcess>().FindIndex(process => process.Detection_EventTime == Convert.ToDateTime(xDetection_EventTime)
                    && process.ProcessName.ToLower() + ":" + process.PID == MyLviewItemsX2.SubItems[2].Text.ToLower());

                    if (obj_index == -1)
                    {
                        if (_ExcludeProcessList.FindIndex(index => index.ToLower() == xProcessName.ToLower()) == -1)
                        {
                            Process_Table.Add(new _TableofProcess
                            {
                                PID = xpid,
                                ProcessName = xProcessName,
                                Description = xDescription_is_EventMessage,
                                Injector_Path = xInjector_Path,
                                Injector = xInjectorPID,
                                ProcessName_Path = xProcessName_Path,
                                IsLive = true,
                                TCPDetails = "null",
                                IsShow_Alarm = true,
                                TCPDetails2 = xTCPDetails2,
                                Detection_EventTime = Convert.ToDateTime(xDetection_EventTime),
                                Detection_Status = xDetection_Status,
                                InjectionType = xInjectionType,
                                MemoryScanner01_Result = xMemoryScanner01_Result,
                                MemoryScanner02_Result = xMemoryScanner02_Result,
                                Descripton_Details = xDescription2,
                                SubItems_Name_Property = xSubItems_Name_Property,
                                SubItems_ImageIndex = xSubItems_ImageIndex

                            });
                        }
                        else
                        {
                            Process_Table.Add(new _TableofProcess
                            {
                                PID = xpid,
                                ProcessName = xProcessName,
                                Description = xDescription_is_EventMessage,
                                Injector_Path = xInjector_Path,
                                Injector = xInjectorPID,
                                ProcessName_Path = xProcessName_Path,
                                IsLive = true,
                                TCPDetails = "null",
                                IsShow_Alarm = false,
                                TCPDetails2 = xTCPDetails2,
                                Detection_EventTime = Convert.ToDateTime(xDetection_EventTime),
                                Detection_Status = xDetection_Status,
                                InjectionType = xInjectionType,
                                MemoryScanner01_Result = xMemoryScanner01_Result,
                                MemoryScanner02_Result = xMemoryScanner02_Result,
                                Descripton_Details = xDescription2,
                                SubItems_Name_Property = xSubItems_Name_Property,
                                SubItems_ImageIndex = xSubItems_ImageIndex

                            });
                        }
                    }
                    else
                    {

                        _TableofProcess TempStruc = new _TableofProcess();
                        TempStruc.TCPDetails2 = xTCPDetails2;
                        TempStruc.TCPDetails = Process_Table[obj_index].TCPDetails;
                        TempStruc.ProcessName_Path = Process_Table[obj_index].ProcessName_Path;
                        TempStruc.ProcessName = Process_Table[obj_index].ProcessName;
                        TempStruc.PID = Process_Table[obj_index].PID;
                        TempStruc.IsLive = Process_Table[obj_index].IsLive;
                        TempStruc.Injector_Path = Process_Table[obj_index].Injector_Path;
                        TempStruc.Injector = Process_Table[obj_index].Injector;
                        TempStruc.Description = Process_Table[obj_index].Description;
                        TempStruc.IsShow_Alarm = true;
                        TempStruc.Detection_Status = xDetection_Status;
                        TempStruc.Detection_EventTime = Convert.ToDateTime(xDetection_EventTime);
                        TempStruc.InjectionType = xInjectionType;
                        TempStruc.MemoryScanner01_Result = xMemoryScanner01_Result;
                        TempStruc.MemoryScanner02_Result = xMemoryScanner02_Result;
                        TempStruc.Descripton_Details = xDescription2;
                        TempStruc.SubItems_Name_Property = xSubItems_Name_Property;
                        TempStruc.SubItems_ImageIndex = xSubItems_ImageIndex;

                        Process_Table[obj_index] = TempStruc;

                    }
                }
            }
            catch (Exception ee)
            {
                if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [_Additems_toListview2] Method Call: error1 => " + ee.Message);


            }

            try
            {
                Thread.Sleep(20);
                bool found = false;
                if (MyLviewItemsX2 != null)
                {
                    if (MyLviewItemsX2.SubItems[9].Text == "")
                    {
                        if (MyLviewItemsX2.SubItems[5].Text.Contains("Terminated") || MyLviewItemsX2.SubItems[5].Text.Contains("Suspended"))
                        {
                            

                            Thread.Sleep(20);                            
                            
                            BeginInvoke(new __core2(SaveETWLogs.AsyncRun__SaveNewETW_Alarms_to_WinEventLog), MyLviewItemsX2);

                            Thread.Sleep(20);

                            tmpitemListview2 = MyLviewItemsX2.Name;
                        }

                    }
                    else
                    {
                        

                        Thread.Sleep(20);

                        BeginInvoke(new __core2(SaveETWLogs.AsyncRun__SaveNewETW_Alarms_to_WinEventLog), MyLviewItemsX2);

                        Thread.Sleep(20);

                        tmpitemListview2 = MyLviewItemsX2.Name;
                    }

                    if (MyLviewItemsX2.SubItems[9].Text != "")
                    {
                        InjectionMemoryInfoDetails_torichtectbox(MyLviewItemsX2.SubItems[9].Text);
                    }


                    Thread.Sleep(25);

                    List_ofProcess_inListview2.Add(MyLviewItemsX2.Name.Split(':')[0] + ":" + MyLviewItemsX2.Name.Split(':')[1].Split('>')[0]);

                    evtstring2 = MyLviewItemsX2.Name;

                    /// time to search in list of injected thread for showing Hex one by one for all injector to target pid....
                    /// 
                    List<_All_Injection_Details_info_Filter_withoutSystem4> _TidDetails =
                    _List_All_Injection_Details_info_Filter_withoutSystem4.FindAll(_y =>
                    _y._TargetPID == Convert.ToInt32(MyLviewItemsX2.Name.Split(':')[1].Split('>')[0]));

                    foreach (_All_Injection_Details_info_Filter_withoutSystem4 _itemX in _TidDetails.ToList<_All_Injection_Details_info_Filter_withoutSystem4>())
                    {
                        _All_Injection_Details_info_Filter_withoutSystem4 tmpstruc = new _All_Injection_Details_info_Filter_withoutSystem4();
                        tmpstruc._flag_to_Dont_Remove_FromList = true;
                        tmpstruc._InjectorPID = _itemX._InjectorPID;
                        tmpstruc._InjectorPID_Path = _itemX._InjectorPID_Path;
                        tmpstruc._RemoteThreadID = _itemX._RemoteThreadID;
                        tmpstruc._TargetPID = _itemX._TargetPID;
                        tmpstruc._TargetPID_Path = _itemX._TargetPID_Path;
                        tmpstruc._ThreadStartAddress = _itemX._ThreadStartAddress;
                        tmpstruc._time_evt = _itemX._time_evt;

                        _List_All_Injection_Details_info_Filter_withoutSystem4[_List_All_Injection_Details_info_Filter_withoutSystem4.FindIndex
                            (x => x._TargetPID == _itemX._TargetPID && x._TargetPID_Path == _itemX._TargetPID_Path
                            && x._InjectorPID == _itemX._InjectorPID && x._RemoteThreadID == _itemX._RemoteThreadID
                            && x._ThreadStartAddress == _itemX._ThreadStartAddress)] = tmpstruc;


                        _DumpMemoryInfo_Injected_Bytes(_itemX._ThreadStartAddress, _itemX._RemoteThreadID, _itemX._TargetPID, _itemX._InjectorPID.ToString());

                    }
                }
            }
            catch (Exception ee)
            {

            }
        }

        /// <summary>
        /// add items to Processes Tab (Process List)
        /// </summary>
        /// <param name="obj"></param>
        public async void _Additems_toTreeview1(object obj)
        {
            await Task.Run(() =>
            {
                try
                {

                    if (obj != null)
                    {
                        treeView1.BeginInvoke((MethodInvoker)delegate
                        {
                            if (obj != null)
                            {
                                ListViewItem MyLviewItemsX5 = (ListViewItem)obj;

                                bool xfound = false;
                                foreach (TreeNode item in treeView1.Nodes)
                                {
                                    Task.Delay(10);

                                    if (item.Text.ToLower() == MyLviewItemsX5.SubItems[3].Text.ToLower())
                                    {
                                        _Imgindex2 = 0;
                                        if (MyLviewItemsX5.SubItems[2].Text == "1") { _Imgindex2 = 0; }
                                        if (MyLviewItemsX5.SubItems[2].Text == "2") { _Imgindex2 = 1; }
                                        if (MyLviewItemsX5.SubItems[2].Text == "3") { _Imgindex2 = 3; }

                                        if(MyLviewItemsX5.SubItems[2].Text != "3"){

                                            item.Nodes.Add("", "[EventID:" + MyLviewItemsX5.SubItems[2].Text + "]" 
                                            + MyLviewItemsX5.SubItems[4].Text + " { " + MyLviewItemsX5.SubItems[5].Text + " }", _Imgindex2);
                                        }
                                        else
                                        {
                                            item.Nodes.Add("", "[EventID:" + MyLviewItemsX5.SubItems[2].Text + "]" +
                                           "[" + "TCP" + "] { " + MyLviewItemsX5.SubItems[5].Text + " }", _Imgindex2);
                                        }

                                        if (MyLviewItemsX5.SubItems[2].Text == "3")
                                        {
                                            try
                                            {

                                                int last = item.Nodes.Count;
                                                if (item.LastNode.PrevNode.Text.Contains("[EventID:3]"))
                                                {
                                                    DateTime xdt_prev = Convert.ToDateTime(item.LastNode.PrevNode.Text.Split('\n')[4].Substring(12));
                                                    DateTime xdt_current = Convert.ToDateTime(item.LastNode.Text.Split('\n')[4].Substring(12));

                                                    item.Nodes.Add("", ">> Delta time (Total-Seconds) between last two Network Events is >> " + Delta_Time(xdt_current, xdt_prev), 3).ForeColor = Color.MediumBlue;

                                                }
                                            }
                                            catch (Exception)
                                            {


                                            }
                                        }


                                        if (MyLviewItemsX5.SubItems[2].Text == "2")
                                        {
                                            try
                                            {

                                                SearchInjector = MyLviewItemsX5.SubItems[5].Text.Substring(MyLviewItemsX5.SubItems[5].Text.IndexOf("[Injected by ") + 13).Split(']')[0];
                                                SearchInjector2 = "";

                                                if (SearchInjector.Contains(':')) { SearchInjector2 = SearchInjector.Split(':')[0]; } else { SearchInjector2 = SearchInjector; }

                                                if (SearchInjector2.ToLower() != "system")
                                                {

                                                    _TableofProcess _ToP = Process_Table.Find(Proc => Proc.Injector ==
                                                    Convert.ToInt32(MyLviewItemsX5.SubItems[5].Text.Split('\n')[12].Split('>')[1])
                                                    && Proc.Injector_Path.Contains(SearchInjector2));

                                                    if (_ToP.PID > 0)
                                                    {

                                                        item.Nodes.Add("", ">>>> " + _ToP.Injector_Path + " was injector for EventID2\n [Injector_ProcessID: "
                                                        + _ToP.Injector + "]\n [TargetPID with (EventID2): " + _ToP.ProcessName + ":" + _ToP.PID + "]", 1).ForeColor = Color.MediumBlue;

                                                    }
                                                }
                                            }
                                            catch (Exception)
                                            {


                                            }
                                        }

                                        item.ForeColor = Color.Red;
                                        xfound = true;

                                        break;
                                    }
                                }

                                if (!xfound)
                                {
                                    _Imgindex = 0;
                                    if (MyLviewItemsX5.SubItems[2].Text == "1") { _Imgindex = 0; }
                                    if (MyLviewItemsX5.SubItems[2].Text == "2") { _Imgindex = 1; }
                                    if (MyLviewItemsX5.SubItems[2].Text == "3") { _Imgindex = 3; }

                                    if (MyLviewItemsX5.SubItems[2].Text != "3")
                                    {
                                        treeView1.Nodes.Add("", MyLviewItemsX5.SubItems[3].Text, _Imgindex).Nodes.Add("", "[EventID:" + MyLviewItemsX5.SubItems[2].Text + "]"
                                    +  MyLviewItemsX5.SubItems[4].Text + " { " + MyLviewItemsX5.SubItems[5].Text + " }", _Imgindex).Parent.ImageIndex = _Imgindex;
                                    }
                                    else
                                    {
                                        treeView1.Nodes.Add("", MyLviewItemsX5.SubItems[3].Text, _Imgindex).Nodes.Add("", "[EventID:" + MyLviewItemsX5.SubItems[2].Text + "]"
                                     + "[" + "TCP" + "] { " + MyLviewItemsX5.SubItems[5].Text + " }", _Imgindex).Parent.ImageIndex = _Imgindex;
                                    }

                                  
                                }
                            }
                        });
                    }


                }
                catch (Exception err)
                {


                }
            });
        }
        public async void _Additems_toTreeview2(object obj)
        {
            try
            {
                try
                {
                    string ClosedProcName = ((TreeNode)obj).Text.Split('<')[0];
                    ClosedProcName = ClosedProcName.Substring(0, ClosedProcName.Length - 1);
                    Processes_FileSystemList.Remove(Processes_FileSystemList.Find(x => x.FileName == ClosedProcName));

                    Int32 closed_pid = Convert.ToInt32(ClosedProcName.Split(':')[1]);
                    string _ClosedProcessname = ClosedProcName.Split(':')[0];


                    Int32 ClosedPID_Index = Process_Table.FindIndex(index => index.ProcessName.ToLower() == _ClosedProcessname.ToLower()
                    && index.PID == closed_pid);


                    _TableofProcess TempStruc = new _TableofProcess();
                    TempStruc.IsLive = false;
                    TempStruc.TCPDetails2 = Process_Table[ClosedPID_Index].TCPDetails2;
                    TempStruc.TCPDetails = Process_Table[ClosedPID_Index].TCPDetails;
                    TempStruc.ProcessName_Path = Process_Table[ClosedPID_Index].ProcessName_Path;
                    TempStruc.ProcessName = Process_Table[ClosedPID_Index].ProcessName;
                    TempStruc.PID = Process_Table[ClosedPID_Index].PID;
                    TempStruc.Injector_Path = Process_Table[ClosedPID_Index].Injector_Path;
                    TempStruc.Injector = Process_Table[ClosedPID_Index].Injector;
                    TempStruc.Description = Process_Table[ClosedPID_Index].Description;
                    TempStruc.IsShow_Alarm = Process_Table[ClosedPID_Index].IsShow_Alarm;
                    TempStruc.Detection_Status = Process_Table[ClosedPID_Index].Detection_Status;
                    TempStruc.Detection_EventTime = Process_Table[ClosedPID_Index].Detection_EventTime;
                    TempStruc.InjectionType = Process_Table[ClosedPID_Index].InjectionType;
                    TempStruc.MemoryScanner01_Result = Process_Table[ClosedPID_Index].MemoryScanner01_Result;
                    TempStruc.MemoryScanner02_Result = Process_Table[ClosedPID_Index].MemoryScanner02_Result;
                    TempStruc.Descripton_Details = Process_Table[ClosedPID_Index].Descripton_Details;
                    TempStruc.SubItems_Name_Property = Process_Table[ClosedPID_Index].SubItems_Name_Property;
                    TempStruc.SubItems_ImageIndex = Process_Table[ClosedPID_Index].SubItems_ImageIndex;
                    Process_Table[ClosedPID_Index] = TempStruc;


                }
                catch (Exception)
                {


                }


                bool found = false;
                await new TaskFactory().StartNew(() =>
                {

                    treeView2.BeginInvoke((MethodInvoker)delegate
                    {
                        foreach (TreeNode item in treeView2.Nodes)
                        {
                            Task.Delay(1);
                            if (item.Text == ((TreeNode)obj).Text)
                            {
                                found = true;
                                break;
                            }
                        }
                    });
                });

                if (!found)
                {
                    treeView2.BeginInvoke((MethodInvoker)delegate
                    {
                        object _obj = ((TreeNode)obj).Clone();

                        treeView2.Nodes.Add(((TreeNode)_obj));
                    });

                }

            }
            catch (Exception r)
            {

            }
        }
        private async void T3_Elapsed(object sender, System.Timers.ElapsedEventArgs e)
        {

            if (_IsProcessTab_Enabled)
            {
                await Task.Run(() =>
                {

                    Thread.Sleep(25);
                    foreach (TreeNode item in treeView1.Nodes)
                    {

                        try
                        {
                            if (item != null)
                            {
                                if (!item.Text.Contains("Process Exited!?"))
                                {
                                    item.ForeColor = Color.Black;
                                    if (item.Nodes.Count > 0)
                                    {
                                        item.ImageIndex = item.Nodes[item.Nodes.Count - 1].ImageIndex;
                                    }
                                    else
                                    {

                                    }

                                    bool found_prc = false;

                                    try
                                    {

                                        if (Process.GetProcesses().ToList().FindIndex(x => x.Id == Convert.ToInt32(item.Text.Split(':')[1])) != -1)
                                        {
                                            Thread.Sleep(2);
                                            found_prc = true;
                                        }

                                    }
                                    catch (Exception)
                                    {


                                    }

                                    if (!found_prc)
                                    {

                                        if (!item.Text.Contains("Process Exited!?"))
                                        {

                                            item.Text = item.Text + " <<Process Exited!?>>";
                                            item.BackColor = Color.LightGoldenrodYellow;

                                            var _Delay = Task.Delay(TimeSpan.FromSeconds(2));
                                            do
                                            {
                                                Thread.Sleep(2);

                                                item.BackColor = Color.LightGoldenrodYellow;

                                                if (_Delay.IsCompleted)
                                                {
                                                    item.ForeColor = Color.DarkBlue;
                                                    item.BackColor = Color.White;                                                   

                                                    break;
                                                }

                                            } while (!_Delay.IsCompleted);

                                            BeginInvoke(new __Additem(_Additems_toTreeview2), item);

                                            item.Remove();

                                        }
                                    }
                                }
                            }
                        }
                        catch (Exception)
                        {

                        }

                    }


                });
            }

        }

        //public void Update_Richtexbox8_SystemDetection_ETW_AllDetails_info()
        //{
        //    try
        //    {
        //        richTextBox8.Text = listView3.SelectedItems[0].Name;
        //    }
        //    catch (Exception)
        //    {


        //    }

        //}

        /// <summary>
        /// dump all details info about Injected ThreadId , StartAddress , Hex bytes and more also add them to richtextbox1 Realtime text Tab
        /// </summary>       
        public void _DumpMemoryInfo_Injected_Bytes(string _i32StartAddress, Int32 _InjectedTID, Int32 _TPID, string _InjectorPID)
        {

            string d = _i32StartAddress.Substring(2);
            ulong i32StartAddress = Convert.ToUInt64(_i32StartAddress.Substring(3), 16);

            if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [_DumpMemoryInfo_Injected_Bytes] Method Call: Started");
            //if(IsSystemDeveloperLogIson) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [_DumpMemoryInfo_Injected_Bytes] Method Call: error1 => " + ee.Message);


            Int64 TID = Convert.ToInt64(_InjectedTID);
            Int32 prc = _TPID;
            buf = new byte[208];
            buf = new byte[208];
            try
            {
                IntPtr prch = System.Diagnostics.Process.GetProcessById(prc).Handle;
                string pname = System.Diagnostics.Process.GetProcessById(prc).ProcessName;
                string XStartAddress = _i32StartAddress.Substring(1);
                string _injector = _InjectorPID;
                bool MemoryBytes = Memory_info.ReadProcessMemory(prch, (UIntPtr)i32StartAddress, buf, buf.Length, IntPtr.Zero);
                string _buf = Memory_info.HexDump(buf);
                string _bytes = BitConverter.ToString(buf).ToString();

                if (_InjectedTIDList.FindIndex(startaddress => startaddress._ThreadStartAddress == XStartAddress
                 && startaddress._InjectorPID == Convert.ToInt32(_injector)) == -1)
                {
                    if (Convert.ToInt32(_injector) != 4)
                    {
                        _InjectedTIDList.Add(new _InjectedThreadDetails_bytes
                        {
                            _TargetPID = prc,
                            _ThreadStartAddress = XStartAddress.ToString(),
                            _RemoteThreadID = Convert.ToInt32(TID),
                            Injected_Memory_Bytes = _bytes,
                            Injected_Memory_Bytes_Hex = _buf,
                            _InjectorPID = Convert.ToInt32(_injector),
                            _TargetPIDName = pname

                        });
                    }
                }

            }
            catch (Exception ee)
            {
                if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [_DumpMemoryInfo_Injected_Bytes] Method Call: error1 => " + ee.Message);

                BeginInvoke(new __Additem(_Additems_str_toRichtextbox1),
               EventMessage + "\n\nEventID: " + "2" + "\n" + "EventID: 2, Read Target_Process Memory via API::ReadProcessMemory [ERROR] => " + "Access Error or Process Exited" + "\n[Remote-Thread-Injection Memory Information]\n_____________________________error______________________________\n");

            }

        }
        public Form1()
        {
            InitializeComponent();
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

            return "D:" + Setinputs(_ts.TotalDays) + " or "
                + "H:" + Setinputs(_ts.TotalHours) + " or "
                + "M:" + _ts.TotalMinutes.ToString()
                + " (Sec:" + _ts.Seconds.ToString() + ")"
                + " (TSec:" + _ts.TotalSeconds.ToString() + ")";
        }
        public void StartQueries_Mon(string queries)
        {
            if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [StartQueries_Mon] Method Call: Started");
            //if(IsSystemDeveloperLogIson) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [StartQueries_Mon] Method Call: error1 => " + ee.Message);

            ThreadStart Core2 = new ThreadStart(delegate { BeginInvoke(new __core2(_Core2), queries); });
            Thread _T1_Core2 = new Thread(Core2);
            _T1_Core2.Priority = ThreadPriority.Highest;
            _T1_Core2.Start();

        }

        /// <summary>
        /// core code for realtime monitoring Windows eventlog "ETWPM2".
        /// </summary>
        public void _Core2(object queries)
        {
            try
            {
                if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [_Core2] Method Call: Started");
                //if(IsSystemDeveloperLogIson) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [StartQueries_Mon] Method Call: error1 => " + ee.Message);

                string _Query = queries.ToString();
                EvtWatcher.Dispose();
                ETWPM2Query = new EventLogQuery("ETWPM2", PathType.LogName, _Query);

                EvtWatcher = new EventLogWatcher(ETWPM2Query);
                EvtWatcher.EventRecordWritten += Watcher_EventRecordWritten;
                EvtWatcher.Enabled = true;
                toolStripStatusLabel1.Text = "Monitor Status: on";
            }
            catch (Exception ee)
            {
                if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [_Core2] Method Call: error1 => " + ee.Message);
            }
        }

        /// <summary>
        /// core code for realtime monitoring Windows eventlog "ETWPM2".
        /// </summary>
        
        public void _Core()
        {
            try
            {
                if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [_Core] Method Call: Started");
               

                ETWPM2Query = new EventLogQuery("ETWPM2", PathType.LogName);

                EvtWatcher = new EventLogWatcher(ETWPM2Query);
                EvtWatcher.EventRecordWritten += Watcher_EventRecordWritten;

                EvtWatcher.Enabled = true;
                toolStripStatusLabel1.Text = "Monitor Status: on";
            }
            catch (Exception ee)
            {
                if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [_Core] Method Call: error1 => " + ee.Message);

            }

        }
        public void _MonitorWindowsEventLog_ETWPM2Monitor2()
        {
            try
            {
                if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [_MonitorWindowsEventLog_ETWPM2Monitor2] Method Call: Started");

                EventLogQuery ETWPM2Monitor2Query = new EventLogQuery("ETWPM2Monitor2", PathType.LogName);

                EventLogWatcher EvtWatcher_ETWPM2Monitor2Query = new EventLogWatcher(ETWPM2Monitor2Query);
                EvtWatcher_ETWPM2Monitor2Query.EventRecordWritten += EvtWatcher_ETWPM2Monitor2Query_EventRecordWritten; ;

                EvtWatcher_ETWPM2Monitor2Query.Enabled = true;

            }
            catch (Exception ee)
            {
                if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [_MonitorWindowsEventLog_ETWPM2Monitor2] Method Call: error1 => " + ee.Message);

            }

        }
        private async void EvtWatcher_ETWPM2Monitor2Query_EventRecordWritten(object sender, EventRecordWrittenEventArgs e)
        {

            await Task.Run(() =>
            {
                Thread.Sleep(250);
                string evtmsg = "";
                string[] EventMessageDetails = null;

                if (e != null)
                {
                    try
                    {
                        evtmsg = e.EventRecord.FormatDescription().ToString();
                        EventMessageDetails = evtmsg.Split('\n');
                    }
                    catch (Exception)
                    {


                    }



                    if (e.EventRecord.Id == 1)
                    {
                        try
                        {
                            /// Showing Not Detected Events is off ;)
                            // tabPage15.Text = "Windows Event Logs" + "(" + listView6.Items.Count.ToString() + ")";
                            // toolStripStatusLabel9.Text = "| Windows Event Logs " + "(" + listView6.Items.Count.ToString() + ")";
                        }
                        catch (Exception)
                        {


                        }

                    }

                    if (e.EventRecord.Id == 2)
                    {
                        try
                        {
                            Thread.Sleep(400);
                            Task.Delay(500);
                            listView6.BeginInvoke((MethodInvoker)delegate
                            {
                                try
                                {


                                    string _ProcessInfo = EventMessageDetails[1].Substring(9);
                                    string _Time = e.EventRecord.TimeCreated.ToString();
                                    string _Level = e.EventRecord.LevelDisplayName;
                                    string _EventId = "2";
                                    string _Status = EventMessageDetails[3].Split(':')[9].Substring(1);
                                    ListViewItem iList6 = new ListViewItem();

                                    iList6.ImageIndex = 2;
                                    iList6.Name = evtmsg;
                                    iList6.SubItems.Add(_Time);
                                    iList6.SubItems.Add(_Level);
                                    iList6.SubItems.Add(_EventId);
                                    iList6.SubItems.Add(_Status);
                                    iList6.SubItems.Add(_ProcessInfo);

                                    listView6.Items.Add(iList6);

                                    tabPage3.Text = "System/Detection Logs " + "(" + listView6.Items.Count.ToString() + ")";
                                    tabPage15.Text = "ETWPM2Monitor2 Detection Event Logs " + "(" + listView6.Items.Count.ToString() + ")";
                                    toolStripStatusLabel9.Text = "| ETWPM2Monitor2 Detection Event Logs " + "(" + listView6.Items.Count.ToString() + ")";

                                    if (listView6.Items.Count > 0) tabPage3.ImageIndex = 19; else tabPage3.ImageIndex = 23;

                                //if (_isNotifyEnabled)
                                //{
                                //    if (_Status.Contains("Scanned & Found")
                                //        || _Status.Contains("Suspended")
                                //        || _Status.Contains("Terminated"))
                                //        BeginInvoke(new __Additem(_Show_Notify_Ico_Popup), MyLviewItemsX6);
                                //}

                            }
                                catch (Exception)
                                {


                                }

                            });

                        }
                        catch (Exception)
                        {


                        }
                    }

                    if (e.EventRecord.Id == 3)
                    {
                        try
                        {
                            Thread.Sleep(500);
                            Task.Delay(500);
                            listView6.BeginInvoke((MethodInvoker)delegate
                            {
                                try
                                {


                                    string _ProcessInfo = EventMessageDetails[1].Substring(51);
                                    string _Time = e.EventRecord.TimeCreated.ToString();
                                    string _Level = e.EventRecord.LevelDisplayName;
                                    string _EventId = "3";
                                    string _Status = EventMessageDetails[3].Split(':')[6].Substring(1);
                                    ListViewItem iList6 = new ListViewItem();

                                    iList6.ImageIndex = 1;
                                    iList6.Name = evtmsg;
                                    iList6.SubItems.Add(_Time);
                                    iList6.SubItems.Add(_Level);
                                    iList6.SubItems.Add(_EventId);
                                    iList6.SubItems.Add(_Status);
                                    iList6.SubItems.Add(_ProcessInfo);

                                    listView6.Items.Add(iList6);

                                    tabPage3.Text = "System/Detection Logs " + "(" + listView6.Items.Count.ToString() + ")";
                                    tabPage15.Text = "ETWPM2Monitor2 Detection Event Logs " + "(" + listView6.Items.Count.ToString() + ")";
                                    toolStripStatusLabel9.Text = "| ETWPM2Monitor2 Detection Event Logs " + "(" + listView6.Items.Count.ToString() + ")";
                                }
                                catch (Exception)
                                {

                                }
                            });


                        }
                        catch (Exception)
                        {


                        }
                    }

                    if (e.EventRecord.Id == 4)
                    {
                        try
                        {
                            Thread.Sleep(400);
                            Task.Delay(500);
                            listView6.BeginInvoke((MethodInvoker)delegate
                            {
                                try
                                {


                                    string _ProcessInfo = EventMessageDetails[1].Substring(29);
                                    string _Time = e.EventRecord.TimeCreated.ToString();
                                    string _Level = e.EventRecord.LevelDisplayName;
                                    string _EventId = "4";
                                    string _Status = EventMessageDetails[3].Split(':')[8].Substring(1);
                                    ListViewItem iList6 = new ListViewItem();

                                    iList6.ImageIndex = 2;
                                    iList6.Name = evtmsg;
                                    iList6.SubItems.Add(_Time);
                                    iList6.SubItems.Add(_Level);
                                    iList6.SubItems.Add(_EventId);
                                    iList6.SubItems.Add(_Status);
                                    iList6.SubItems.Add(_ProcessInfo);

                                    listView6.Items.Add(iList6);

                                    tabPage3.Text = "System/Detection Logs " + "(" + listView6.Items.Count.ToString() + ")";
                                    tabPage15.Text = "ETWPM2Monitor2 Detection Event Logs " + "(" + listView6.Items.Count.ToString() + ")";
                                    toolStripStatusLabel9.Text = "| ETWPM2Monitor2 Detection Event Logs " + "(" + listView6.Items.Count.ToString() + ")";

                                    if (listView6.Items.Count > 0) tabPage3.ImageIndex = 19; else tabPage3.ImageIndex = 23;
                                }
                                catch (Exception)
                                {


                                }

                            });


                        }
                        catch (Exception)
                        {


                        }

                    }
                }

            });

        }
        public async Task RealtimeWatchProcess()
        {
            await Task.Run(() =>
            {
                bool init = false;

                if (!init)
                {
                    try
                    {
                        var wmiQueryString = "SELECT ProcessId, ExecutablePath, CommandLine FROM Win32_Process";
                        /// this System.Management should add to "References" in the project
                        using (var searcher = new ManagementObjectSearcher(wmiQueryString))
                        using (var results = searcher.Get())
                        {
                            var query = from _Process in Process.GetProcesses()
                                        join Obj in results.Cast<ManagementObject>()
                                        on _Process.Id equals (int)(uint)Obj["ProcessId"]
                                        select new
                                        {
                                            Process = _Process,
                                            Path = (string)Obj["ExecutablePath"],
                                            CommandLine = (string)Obj["CommandLine"],

                                        };
                            foreach (var item in query)
                            {
                                try
                                {

                                    //Task.Delay(10);
                                    Thread.Sleep(10);
                                    Processes_FileSystemList.Add(new _Table_of_FileSystem_for_Processes_Watcher
                                    {
                                        Eventtime = DateTime.Now.ToString(),
                                        FileName = item.Process.ProcessName + ":" + item.Process.Id,
                                        FileName_Path = item.Path,
                                        File_MD5 = _Get_MD5(item.Path),
                                        ProcessCommandLine = item.CommandLine
                                    });
                                }
                                catch (Exception)
                                {


                                }

                            }
                        }

                        init = true;

                    }
                    catch (Exception)
                    {

                     //   throw;
                    }

                }

                step1:
                Thread.Sleep(500);
                try
                {

                    var wmiQueryString2 = "SELECT ProcessId, ExecutablePath, CommandLine FROM Win32_Process";
                    using (var searcher = new ManagementObjectSearcher(wmiQueryString2))
                    using (var results = searcher.Get())
                    {
                        /// this System.Management should add to "References" in the project
                        var query = from _Process in Process.GetProcesses()
                                    join Obj in results.Cast<ManagementObject>()
                                    on _Process.Id equals (int)(uint)Obj["ProcessId"]
                                    select new
                                    {
                                        Process = _Process,
                                        Path = (string)Obj["ExecutablePath"],
                                        CommandLine = (string)Obj["CommandLine"],

                                    };

                        foreach (var item in query)
                        {
                            Thread.Sleep(50);
                            if (Processes_FileSystemList.ToList().FindIndex(x => x.FileName == item.Process.ProcessName + ":" + item.Process.Id) == -1)
                            {
                                Processes_FileSystemList.Add(new _Table_of_FileSystem_for_Processes_Watcher
                                {
                                    Eventtime = DateTime.Now.ToString(),
                                    FileName = item.Process.ProcessName + ":" + item.Process.Id,
                                    FileName_Path = item.Path,
                                    File_MD5 = _Get_MD5(item.Path),
                                    ProcessCommandLine = item.CommandLine
                                });
                            }
                        }
                    }

                    goto step1;
                }
                catch (Exception)
                {


                }

            });
        }
        public async Task RealtimeWatchProcess_run()
        {
            if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [RealtimeWatchProcess_run] Method Call: Started");
            //if(IsSystemDeveloperLogIson) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [RealtimeWatchProcess_run] Method Call: error1 => " + ee.Message);

            await RealtimeWatchProcess();
        }

        public void _Set_iListview_Properties(ListView TargetListView, string[] _ColumnsText,int[] _widthColumns , ImageList imglist)
        {

            TargetListView.SmallImageList = imglist;
            /// Set the view to show details.
            TargetListView.View = View.Details;
            /// Allow the user to edit item text.
            TargetListView.LabelEdit = false;
            /// Allow the user to rearrange columns.
            TargetListView.AllowColumnReorder = true;
            /// Display check boxes.
            TargetListView.CheckBoxes = false;
            /// Select the item and subitems when selection is made.
            TargetListView.FullRowSelect = true;
            /// Display grid lines.
            TargetListView.GridLines = false;
            
            TargetListView.Sorting = SortOrder.Ascending;

            int icounter = 0;

            foreach (string item in _ColumnsText)
            {
                TargetListView.Columns.Add(item, _widthColumns[icounter], HorizontalAlignment.Left);
                icounter++;
            }
            
        }
        private void Form1_Load(object sender, EventArgs e)
        {
            try
            {
                /// very important  
                Form.CheckForIllegalCrossThreadCalls = false;

                IsSystemDeveloperLogs_on = false;
                onToolStripMenuItem1.Checked = false;
                offToolStripMenuItem1.Checked = true;

                showEventDetailsToolStripMenuItem.Checked = true;
                showEventDetails2ToolStripMenuItem.Checked = false;
                ETWPM2Realt_timeShowMode_Level = 0;

                _ExcludeProcessList.AddRange(new string[4] { "msedge", "firefox", "chrome", "iexplorer" });

                //BeginInvoke(new __Obj_Updater_to_WinForm(RealtimeWatchProcess_run));

                ///fix bug here
                new Task(() => { RealtimeWatchProcess_run().GetAwaiter(); }).Start();


                /// New Memory ScannerII Added to code Hunt-Sleeping-Beacons] , 
                /// for detecting Sleep-mask and suspicious callstacks etc 9 june 2023
                ThreadStart Core4 = new ThreadStart(delegate { BeginInvoke(new __LogReader(ExtendedMemoryScanners_Info._Invoke_Every_1_min_RunAsyn_Hunt_Sleeping_Beacons)); });
                Thread _T1_Core4 = new Thread(Core4);
                _T1_Core4.Priority = ThreadPriority.Highest;
                _T1_Core4.Start();               

                ThreadStart Core = new ThreadStart(delegate { BeginInvoke(new __Obj_Updater_to_WinForm(_Core)); });
                Thread _T1_Core1 = new Thread(Core);
                _T1_Core1.Priority = ThreadPriority.Highest;
                _T1_Core1.Start();

                /// add to System/Detection Tab ---> Windows Event Logs Tab
                ThreadStart Core3 = new ThreadStart(delegate { BeginInvoke(new __Obj_Updater_to_WinForm(_MonitorWindowsEventLog_ETWPM2Monitor2)); });
                Thread _T1_Core3 = new Thread(Core3);
                _T1_Core3.Priority = ThreadPriority.AboveNormal;
                _T1_Core3.Start();

                try
                {
                    if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), 
                        (object)" ==> [Form1_Load::CreateEventSource] Method Call: Started");

                    /// added in v2.1 => All Alarms will save to Windows EventLog "ETWPM2Monitor2" (run as admin)
                    if (!EventLog.Exists("ETWPM2Monitor2"))
                    {
                        EventSourceCreationData ESCD = new EventSourceCreationData("ETWPM2Monitor2.1", "ETWPM2Monitor2");
                        System.Diagnostics.EventLog.CreateEventSource(ESCD);

                    }

                    ETW2MON = new EventLog("ETWPM2Monitor2", ".", "ETWPM2Monitor2.1");
                    ETW2MON.WriteEntry("ETWPM2Monitor2 v2.1 Started", EventLogEntryType.Information, 255);
                }
                catch (Exception ee)
                {
                    if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs),
                        (object)" ==> [Form1_Load::CreateEventSource] Method Call: error1 => " + ee.Message);
                }

                listView1.SmallImageList = imageList1;
                listView4.SmallImageList = imageList1;
                treeView1.ImageList = imageList1;
                treeView2.ImageList = imageList1;
                tabControl5.SelectedIndex = 1;

                try
                {
                    Process[] AllProcess = Process.GetProcesses();
                    foreach (Process item in AllProcess.ToList())
                    {
                        treeView1.Nodes.Add(item.ProcessName + ":" + item.Id.ToString());
                    }
                }
                catch (Exception)
                {
                }

                listView2.HeaderStyle = ColumnHeaderStyle.Nonclickable;
                listView2.BorderStyle = BorderStyle.FixedSingle;
                listView1.HeaderStyle = ColumnHeaderStyle.Nonclickable;
                listView1.BorderStyle = BorderStyle.FixedSingle;

                t.Elapsed += T_Elapsed;
                t.Enabled = true;

                t2.Elapsed += T2_Elapsed;
                t2.Enabled = true;

                t4.Elapsed += T4_Elapsed;
                t4.Enabled = true;
                t4.Start();

                t4_1.Elapsed += T4_1_Elapsed;
                t4_1.Enabled = true;
                t4_1.Start();

                t5.Elapsed += T5_Elapsed;
                t5.Enabled = true;
                t5.Start();

                t3.Elapsed += T3_Elapsed;
                t3.Enabled = true;
                t3.Start();

                t6.Elapsed += T6_Elapsed;
                t6.Enabled = false;
                //t6.Start();

                t7.Elapsed += T7_Elapsed;
                t7.Enabled = true;
                t7.Start();

                t8.Elapsed += T8_Elapsed;
                t8.Enabled = false;

                t9.Elapsed += T9_Elapsed; ;
                t9.Enabled = true;
                t9.Start();

                t10.Elapsed += T10_Elapsed;
                t10.Enabled = false;

                t11.Elapsed += T11_Elapsed;
                t11.Enabled = true;
                t11.Start();

                t12.Elapsed += T12_Elapsed;
                t12.Enabled = true;
                t12.Start();

                t13.Elapsed += T13_Elapsed1;
                t13.Enabled = true;
                t13.Start();

                new Task(() =>
                {

                    /// Network Monitor Timer : checking TCP Connections via C# Codes or Native APIs to compare to ETW TCP Events
                    /// this will help to detect those Connections which has/had not ETW Events but Connection was Established or Send ....
                    System.Runtime.CompilerServices.TaskAwaiter tx = Network_Info._Run_Core_Method().GetAwaiter();
                    tx.GetResult();

                }).Start();

                t14.Elapsed += T14_Elapsed;
                t14.Enabled = true;
                t14.Start();

                t15.Elapsed += T15_Elapsed;
                t15.Enabled = true;
                t15.Start();

                //t16.Elapsed += T16_Elapsed;
                //t16.Enabled = true;
                //t16.Start();

                BeginInvoke((MethodInvoker)delegate { _AsyncRun_checking_false_positive_events(); });
               

                t17.Elapsed += T17_Elapsed;
                t17.Enabled = true;
                t17.Start();

                t18.Elapsed += T18_Elapsed;
                t18.Enabled = false;

                t19.Elapsed += T19_Elapsed;
                t19.Enabled = true;                
                t19.Start();

                

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
                listView1.Columns.Add(" ", 20, HorizontalAlignment.Left);
                listView1.Columns.Add("Time", 130, HorizontalAlignment.Left);
                listView1.Columns.Add("EventID", 55, HorizontalAlignment.Left);
                listView1.Columns.Add("Process", 170, HorizontalAlignment.Left);
                listView1.Columns.Add("Evt-Type", 160, HorizontalAlignment.Left);               

                _Set_iListview_Properties(listView2, new string[] { " ", "LocalTime", "Process", "Injection-Type", "Tcp Sends"
                ,"Status", "PE-Sieve Pe:Shell:Replaced", "Extended Memory Scanners","Description", "EventMessage"  }
                , new int[] { 20, 130, 140, 100, 120, 100, 250, 100, 250, 1000 }, imageList1);
               
                _Set_iListview_Properties(listView4, new string[] { " ", "Time", "Process", "Status", "Source IP:Port"
                ,"Destination IP:Port", "Delta Time (Days or Hours or Minutes)", "Event Count","Event TTL (D:H:Minutes)", "Event First Time"  }
                , new int[] { 20, 124, 180, 64, 120, 120, 187, 77, 135, 130 }, imageList1);               

                _Set_iListview_Properties(listView5, new string[] { " ", "Target Process", "Injector Process", "MZ Header Detection", "Time of Detection" }
                , new int[] { 5, 110, 110, 110, 120 }, imageList1);

                _Set_iListview_Properties(listView10, new string[] { " ", "Time", "Process", "PID","Tcp Sends" ,"Detection Score",
                    "Memory Scanner 1 Details", "Memory Scanner 2 Details" }
               , new int[] { 20, 110, 110, 110,110,120,300,300 }, imageList1);

                /// Set the view to show details.
                listView9.View = View.Details;
                /// Allow the user to edit item text.
                listView9.LabelEdit = false;
                /// Allow the user to rearrange columns.
                listView9.AllowColumnReorder = true;
                /// Display check boxes.
                listView9.CheckBoxes = false;
                /// Select the item and subitems when selection is made.
                listView9.FullRowSelect = true;
                /// Display grid lines.
                listView9.GridLines = false;
                listView9.Columns.Add(" ", 5, HorizontalAlignment.Left);
                listView9.Columns.Add("Target Process", 110, HorizontalAlignment.Left);
                listView9.Columns.Add("Injector Process", 110, HorizontalAlignment.Left);
                listView9.Columns.Add("MZ Header Detection", 110, HorizontalAlignment.Left);
                listView9.Columns.Add("Time of Detection", 120, HorizontalAlignment.Left);

                _Set_iListview_Properties(listView6, new string[] { " ", "Time", "Level", "ETWPM2Monitor2 EventID", "Status", "Process Information" }
                , new int[] { 20, 130, 80, 150, 100,600 }, imageList1);

                _Set_iListview_Properties(listView3, new string[] { " ", "Time", "Process Name", "PID", "State"
                ,"Local IP", "Port", "Remote IP","Port", "Process Info (File Path)"  }
                , new int[] { 1, 130, 100, 50, 100, 100, 45, 100, 45, 520 }, imageList1);

                listView7.View = View.Details;
                // Allow the user to edit item text.
                listView7.LabelEdit = false;
                // Allow the user to rearrange columns.
                listView7.AllowColumnReorder = true;
                // Display check boxes.
                listView7.CheckBoxes = false;
                // Select the item and subitems when selection is made.
                listView7.FullRowSelect = true;
                // Display grid lines.
                listView7.GridLines = false;
                                 
                listView7.Columns.Add(" ", 1, HorizontalAlignment.Left);
                listView7.Columns.Add("Time", 130, HorizontalAlignment.Left);
                listView7.Columns.Add("Process Name", 100, HorizontalAlignment.Left);
                listView7.Columns.Add("PID", 50, HorizontalAlignment.Left);
                listView7.Columns.Add("State", 100, HorizontalAlignment.Left);
                listView7.Columns.Add("Local IP", 100, HorizontalAlignment.Left);
                listView7.Columns.Add("Port", 45, HorizontalAlignment.Left);
                listView7.Columns.Add("Remote IP", 100, HorizontalAlignment.Left);
                listView7.Columns.Add("Port", 45, HorizontalAlignment.Left);
                listView7.Columns.Add("Process Info (File Path)", 520, HorizontalAlignment.Left);
                listView7.Columns.Add("ETW Detection Code", 120, HorizontalAlignment.Left);           

                _Set_iListview_Properties(listView8, new string[] { " ", "Time", "Process Name", "PID", "State"
                ,"Local IP", "Port", "Remote IP","Port", "Process Info (File Path)","ETW Detection Code","Sysmon Detection Code"  }
                , new int[] { 1, 130, 100, 50, 100, 100, 45, 100, 45, 520, 120, 120 }, imageList1);

                /// event for add Process to Alarm-Tab by ETW & Scanning Target Process by Memory Scanners
                /// event is ready ...
                NewProcessAddedtolist += Form1_NewProcessAddedtolist1;

                /// event for add Process to list of New Process
                NewProcessAddedtolist_NewProcessEvt += Form1_NewProcessAddedtolist_NewProcessEvt;

                /// event for add target Process to list of Injected Process which had RemoteThreadInjection
                RemoteThreadInjectionDetection_ProcessLists += Form1_RemoteThreadInjectionDetection_ProcessLists;

                /// event for refresing listviw real-time events
                NewEventFrom_EventLogsCome += Form1_NewEventFrom_EventLogsCome;

                /// event for add all detection events to System_Detection_logs Tab
                // System_Detection_Log_events += Form1_System_Detection_Log_events;
                /// this removed from code , instead new Detection log Tab Added....
                /// now ETWPM2Monitor2 Windows EventLog Monitored Realtime by code 
                /// and Listview6 (New Detection eventLog Tab) will show Detection records etc.

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

                removeRealtimeRecordsAfter1000RecordsToolStripMenuItem.Checked = true;
            }
            catch (EventLogReadingException err)
            {

            }
        }
                
        private void T19_Elapsed(object sender, System.Timers.ElapsedEventArgs e)
        {
            /// checking Result for Memory Scan by Hunt-Sleeping-Beacons.exe
            /// 
            try
            {
                if (Main_lastMemoryScannerIIResult != ExtendedMemoryScanners_Info.Result__in_background__Hunt_Sleeping_Beacons)
                {
                    richTextBox14.Text = "Time of Last Scan: " + DateTime.Now.ToString() + "\n\n" + ExtendedMemoryScanners_Info.Result__in_background__Hunt_Sleeping_Beacons;
                    Main_lastMemoryScannerIIResult = ExtendedMemoryScanners_Info.Result__in_background__Hunt_Sleeping_Beacons;
                    BeginInvoke(new __LogReader(_RunAsync__Refresh_Lsitview10_ExtendedMemScannerResults));
                }
            }
            catch (Exception)
            {


            }
           
        }

        public async void _RunAsync__Refresh_Lsitview10_ExtendedMemScannerResults()
        {
           await _Refresh_Lsitview10_ExtendedMemScannerResults();
        }
        public async Task _Refresh_Lsitview10_ExtendedMemScannerResults()
        {

            await Task.Run(() =>
            {
                try
                {
                    t19.Stop();
                    while (true)
                    {
                        for (int i = 0; i < ExtendedMemoryScanners_Info._DetectedItemsByMemoryScannerII_Alarms.Count; i++)
                        {
                            Thread.Sleep(2000);
                            var FoundItems_MemoryScannerII_Alarms = Main_DetectedItemsByMemoryScannerII_Alarms.Find(x => 
                            x == ExtendedMemoryScanners_Info._DetectedItemsByMemoryScannerII_Alarms[i]);

                            if (FoundItems_MemoryScannerII_Alarms == null)
                            {
                                Main_DetectedItemsByMemoryScannerII_Alarms.Add(ExtendedMemoryScanners_Info._DetectedItemsByMemoryScannerII_Alarms[i]);
                                Thread.Sleep(10);
                                BeginInvoke(new __Additem(_RunAsync_AddingExtendedMemoryScannerResults_toListview10),
                                        ExtendedMemoryScanners_Info._DetectedItemsByMemoryScannerII_Alarms[i]);
                                Thread.Sleep(1000);

                            }
                            else { }

                        }

                        Thread.Sleep(5000);
                        richTextBox14.Text = "Time of Last Scan: " + DateTime.Now.ToString() + "\n\n" 
                        + ExtendedMemoryScanners_Info.Result__in_background__Hunt_Sleeping_Beacons;
                    }
                }
                catch (Exception)
                {


                }
            });
           


        }
        public async void _RunAsync_AddingExtendedMemoryScannerResults_toListview10(object AlarmsItems)
        {
            await AddingExtendedMemoryScannerResults_toListview10(AlarmsItems);
        }

        public async Task AddingExtendedMemoryScannerResults_toListview10(object AlarmsItems_obj)
        {
            await Task.Run(() =>
            {
               /// action needed, not async ;D here
               new Action(() =>
                {
                    Thread.Sleep(20);
                    object _clone = ((ListViewItem)AlarmsItems_obj).Clone();
                    Thread.Sleep(5);
                    listView10.Items.Add((ListViewItem)_clone);
                    tabPage21.Text = "Alarms by Memory Scanner" + " (" + listView10.Items.Count.ToString() + ")";
                    
                }).Invoke();
            });
        }
        private void T18_Elapsed(object sender, System.Timers.ElapsedEventArgs e)
        {
            /// checking Result for Memory Scan by CobaltStrikeScan.exe
            /// 
            string Result = ExtendedMemoryScanners_Info.Task_RESULT_for_CobaltstrikeScanner;
            string[] _Results_via_CobaltStrikeScan = Result.Split('\n');
            if(Result!="" && Result!= null)
            {
                string _Result2 = "";
                try
                {
                    t18.Enabled = false;
                    if (!Result.Contains("Didn't find"))
                    {
                       
                        for (int i = 0; i < 11; i++)
                        {
                            _Result2 += _Results_via_CobaltStrikeScan[i] + "\n";
                        }
                    }
                    else { _Result2 = Result; }
                    MessageBox.Show(_Result2, "Extended MemoryScanner Result:" , MessageBoxButtons.OK, MessageBoxIcon.Warning);                    
                    listView2.SelectedItems[0].SubItems[7].Text = _Results_via_CobaltStrikeScan[0] + " (Scanned by CobaltstrikeScan.exe)";
                    t18.Stop();
                }
                catch (Exception)
                {
                    t18.Enabled = false;
                    t18.Stop();
                }
              
            }
        }

        ///some filter added to Network TCP Connections via Native APIs (Real-time)
        /// Timer for loading Listview3 Items
        private async void T17_Elapsed(object sender, System.Timers.ElapsedEventArgs e)
        {
            await Task.Run(() =>
            {
                try
                {
                    ///some filter added to Network TCP Connections via Native APIs (Real-time)

                    if (_Listview3_Items_NetworkConnection_Apis.Count > 0)
                    {
                        /// .GroupBy(j2 => j2.SubItems[7]).FirstOrDefault()
                        /// FirstOrDefault() will show all remoteips (kind of No-Filter) 
                        /// First() will filter/show only one of them ;)

                        foreach (ListViewItem item in _Listview3_Items_NetworkConnection_Apis.ToList<ListViewItem>()
                        .GroupBy(j => j.SubItems[2]).First().GroupBy(j2 => j2.SubItems[7].Text).FirstOrDefault().ToList().ToArray())
                        {
                            if (item.SubItems[2].Text.ToLower() != "system")
                            {
                                try
                                {
                                    listView3.Items.Add(item);

                                    /// fixed

                                    int index = _Listview7_Items_NetworkConnection_history.ToList().FindIndex(x =>
                                      x.SubItems[2].Text + x.SubItems[3].Text
                                    + x.SubItems[7].Text + x.SubItems[9].Text ==
                                      item.SubItems[2].Text + item.SubItems[3].Text
                                    + item.SubItems[7].Text + item.SubItems[9].Text);

                                    if (index == -1)
                                    {
                                        object tmp = item.Clone();
                                        listView7.Items.Add((ListViewItem)tmp).SubItems.Add("1");

                                        _Listview7_Items_NetworkConnection_history.Add((ListViewItem)tmp);
                                    }
                                }
                                catch (Exception)
                                {

                                    
                                }
                            }

                            Task.Delay(250);
                             
                        }

                        _Listview3_Items_NetworkConnection_Apis.Clear();
                       
                    }

                    _CheckTruePositiveList_Again();
                }
                catch (Exception)
                {


                }
            });
        }
        public void _CheckTruePositiveList_Again()
        {
           
                /// event detected after Minutes so that means your process has/had Network
                /// connection which detected by Native API but "for minutes" not detected by ETW events which is Suspicious ....
                /// here can detect Time to Live TTL for this type of Events very simple with check delta time 
                /// between Event which made by Native API and Event time which made by ETW Events after Minutes ....
                try
                {
                    List<ListViewItem> list1 = listView8.Items.Cast<ListViewItem>().ToList();
                    List<ListViewItem> list2 = listView4.Items.Cast<ListViewItem>().ToList();
                    int count = 0;

                    foreach (ListViewItem item1 in list1.ToList<ListViewItem>())
                    {

                        int index = list2.FindIndex(x => x.SubItems[2].Text.ToLower() == item1.SubItems[2].Text.ToLower() + ":" + item1.SubItems[3].Text
                        && x.SubItems[5].Text == item1.SubItems[7].Text);

                    if (index != -1)
                    {
                        try
                        {
 
                            if (!listView8.Items[count].SubItems[9].Text.Contains("This Process For ("))
                            {
                                listView8.Items[count].BackColor = Color.DarkOrange;
                                TimeSpan _dt = Convert.ToDateTime(list2[index].SubItems[1].Text) - Convert.ToDateTime(item1.SubItems[1].Text);
                                listView8.Items[count].SubItems[9].Text = $"This Process For ({_dt.TotalSeconds.ToString()} Seconds ) Not Detected By ETW Events, TTL For This Event Was => Min:{_dt.TotalMinutes.ToString()} or Sec:{_dt.TotalSeconds.ToString()}";
                                listView8.Items[count].SubItems[10].Text = "0+1";
                            }
                            
                        }
                        catch (Exception ee)
                        {

                            MessageBox.Show(ee.Message);
                        }
                    }
                        count++;

                    }

                }
                catch (Exception)
                {


                }


 
        }

        public async void _AsyncRun_checking_false_positive_events()
        {
            await checking_false_positive_events();
        }
        public async Task checking_false_positive_events()
        {
            await Task.Run((Action)delegate 
            {

                while (true)
                {
                    Thread.Sleep(10000);
                    try
                    {
                        List<ListViewItem> NativeApiNetworkConnectionList = _ETW_Network_Events_FalsePositiveChecking_Records.ToList<ListViewItem>()
                       .FindAll(x => x.SubItems[10].Text == "0" && x.SubItems[2].Text.ToLower() != "system" && x.SubItems[3].Text != "4")
                       .GroupBy(x1 => x1.SubItems[3]).Select(xx => xx.First()).ToList();

                        if (NativeApiNetworkConnectionList != null)
                        {
                            int count = NativeApiNetworkConnectionList.Count;
                            ListView.ListViewItemCollection _listxx = listView4.Items;
                            List<ListViewItem> list2 = _listxx.Cast<ListViewItem>().ToList();

                            //List<ListViewItem> list2 = listView4.Items.Cast<ListViewItem>().ToList();

                            if (list2.Count > 0)
                            {

                                foreach (ListViewItem _item in NativeApiNetworkConnectionList.ToList<ListViewItem>())
                                {
                                    //Task.Delay(10);
                                    Thread.Sleep(20);
                                    try
                                    {
                                        for (int i = 0; i < count; i++)
                                        {
                                            Thread.Sleep(20);
                                            int index = list2.FindIndex(x => x.SubItems[2].Text == _item.SubItems[2].Text + ":" + _item.SubItems[3].Text);

                                            if (index == -1)
                                            {
                                                /// cpu usage awful ;(
                                                /// bug is here
                                                listView8.BeginInvoke((MethodInvoker)delegate
                                                {
                                                    //Thread.Sleep(5);
                                                    ListView.ListViewItemCollection _listx = listView8.Items;
                                                    List<ListViewItem> _list = _listx.Cast<ListViewItem>().ToList();
                                                    //List<ListViewItem> _list = listView8.Items.Cast<ListViewItem>().ToList();

                                                    /// if == -1 then those records was true positive error...
                                                    /// in this time will show only true positive records to the listview8
                                                    if (_list.FindIndex(x => x.SubItems[2].Text + x.SubItems[3].Text + x.SubItems[7].Text
                                                        == _item.SubItems[2].Text + _item.SubItems[3].Text + _item.SubItems[7].Text) == -1)
                                                    {
                                                        listView8.Items.Add(_item).BackColor = Color.DarkRed;
                                                    }
                                                });

                                            }
                                            else
                                            {
                                                /// false positive
                                            }
                                        }

                                    }
                                    catch (Exception)
                                    {

                                    }
                                }
                            }
                            else
                            {
                                try
                                {
                                    List<ListViewItem> _list = listView8.Items.Cast<ListViewItem>().ToList();
                                    /// bug fixed
                                    foreach (ListViewItem item in NativeApiNetworkConnectionList.ToList<ListViewItem>())
                                    {
                                        if (_list.FindIndex(x => x.SubItems[2].Text + x.SubItems[3].Text + x.SubItems[7].Text
                                         == item.SubItems[2].Text + item.SubItems[3].Text + item.SubItems[7].Text) == -1)
                                        {
                                            listView8.Items.Add(item).BackColor = Color.DarkRed;
                                        }
                                    }

                                }
                                catch (Exception)
                                {


                                }

                            }
                        }
                    }
                    catch (Exception t)
                    {

                    }
                }

            });
        }

        /// <summary>  remove those Process items in Network Connections via Native APIs 
        /// </summary>  
        private void T15_Elapsed(object sender, System.Timers.ElapsedEventArgs e)
        {
            /// remove those Process items in Network Connections via Native APIs
            /// which Process Closed or TCP Connection was closed .... (real-time)
            /// Method Network_Info._DeleteItems(object id)

            try
            {


                if (Network_Info.Before_after == 1)
                {
                    try
                    {
                        ///bug fixed
                        //ListView.ListViewItemCollection _listView3_Items_coll = listView3.Items;
                        ListViewItem[] _listView3_Items = listView3.Items.Cast<ListViewItem>().ToList().ToArray<ListViewItem>();

                        for (int w = 0; w < listView3.Items.Count;w++)
                        {
                            int found = -1;
                            found = Network_Info.Table2_x64.ToList().FindIndex(f => f.FullSTR == _listView3_Items[w].Name);
                            Thread.Sleep(15);
                           
                            if (found == -1)
                            {
                                try
                                {
                                    listView3.Items[w].Remove();
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
                else if (Network_Info.Before_after == 0)
                {
                    try
                    {

                        ///bug fixed
                        //ListView.ListViewItemCollection _listView3_Items_coll = listView3.Items;
                        //List<ListViewItem> _listView3_Items = listView3.Items.Cast<ListViewItem>().ToList();
                        ListViewItem[] _listView3_Items = listView3.Items.Cast<ListViewItem>().ToList().ToArray<ListViewItem>();

                        for (int w = 0; w < listView3.Items.Count;w++)
                        {
                            //int found = 0;
                            int found = -1;
                            found = Network_Info.Table2_x64.ToList().FindIndex(f => f.FullSTR == _listView3_Items[w].Name);
                            Thread.Sleep(15);                          

                            if (found == -1)
                            {
                                try
                                {
                                    listView3.Items[w].Remove();
                                }
                                catch (Exception)
                                {

                                    //throw;
                                }



                            }
                            
                        }
                    }
                    catch (Exception)
                    {


                    }
                }



            }
            catch (Exception em)
            {


            }
        }

        /// <summary>  checking Network Connection records which made by ETW Events  
        /// </summary>  
        private void T14_Elapsed(object sender, System.Timers.ElapsedEventArgs e)
        {
            /// checking Network Connection records which made by ETW Events 
            /// and compare with Network Connection records Which Made Native APIs
            /// this will help you you to detect those Processes which has/had Network Connection Activity but Does Not Detected by ETW
            /// That means ETW Bypassed by those Processes probably ;) or ETW has/had bug for detect this process etc.

            try
            {
                if (listView3.Items.Count > 0)
                {
                  
                    try
                    {
                        ///bug fixed
                        //ListView.ListViewItemCollection _listView3_Items_coll = listView3.Items;                        
                        //List<ListViewItem> __Items3 = listView3.Items.Cast<ListViewItem>().ToList();

                        ListViewItem[] __Items3 = listView3.Items.Cast<ListViewItem>().ToList().ToArray();

                        foreach (ListViewItem item3 in __Items3)
                        {                                                       
                            Task.Delay(TCPConnectionDelay_for_RefreshList);
                            try
                            {

                                bool found = false;
                                if (listView4.Items.Count > 0)
                                {
                                                                     
                                    ListViewItem[] __Items4 = new ListViewItem[1];
                                    __Items4 = listView4.Items.Cast<ListViewItem>().ToList().ToArray<ListViewItem>();

                                    foreach (ListViewItem item4 in __Items4)
                                    {
                                        try
                                        {
                                            if (item3.SubItems[2].Text + ":" + item3.SubItems[3].Text == item4.SubItems[2].Text)
                                            {
                                                if (item3.SubItems[7].Text == item4.SubItems[5].Text) found = true;
                                            }
                                            Task.Delay(100);
                                        }
                                        catch (Exception)
                                        {


                                        }

                                    }

                                    if (found == false)
                                    {

                                        item3.BackColor = Color.Red;
                                        item3.ForeColor = Color.White;

                                        int indexx = Network_Info.Processes_FileSystemList2.FindIndex(x => x.PID == Convert.ToInt32(item3.SubItems[3].Text));

                                        if (indexx != -1)
                                        {
                                            if (!item3.SubItems[9].Text.Contains("Network Connection Event for This Process Not Detected by ETW Events! => "))
                                                item3.SubItems[9].Text = "Network Connection Event for This Process Not Detected by ETW Events! => " + Network_Info.Processes_FileSystemList2[indexx].FileName_Path;

                                            if (listView7.Items.Count > 0)
                                            {
                                                bool item7fouand = false;

                                                ListViewItem[] __Items7 = new ListViewItem[1];
                                                __Items7 = listView7.Items.Cast<ListViewItem>().ToList().ToArray<ListViewItem>();

                                                foreach (ListViewItem item7 in __Items7)
                                                {
                                                    string h7 = item7.SubItems[2].Text
                                                 + item7.SubItems[3].Text
                                                 + item7.SubItems[4].Text
                                                 + item7.SubItems[7].Text
                                                 + item7.SubItems[9].Text;

                                                    string h3 = item3.SubItems[2].Text
                                                      + item3.SubItems[3].Text
                                                      + item3.SubItems[4].Text
                                                      + item3.SubItems[7].Text
                                                      + item3.SubItems[9].Text;

                                                    if (h7 == h3)
                                                    {
                                                        item7fouand = true;
                                                        break;
                                                    }
                                                }

                                                if (!item7fouand)
                                                {
                                                    object tmp = item3.Clone();

                                                    listView7.Items.Add((ListViewItem)tmp).SubItems.Add("0");
                                                    object tmp2 = ((ListViewItem)tmp).Clone();
                                                    _ETW_Network_Events_FalsePositiveChecking_Records.Add((ListViewItem)tmp2);

                                                }
                                            }
                                            else
                                            {
                                                object tmp = item3.Clone();

                                                listView7.Items.Add((ListViewItem)tmp).SubItems.Add("0");
                                                object tmp2 = ((ListViewItem)tmp).Clone();
                                                _ETW_Network_Events_FalsePositiveChecking_Records.Add((ListViewItem)tmp2);
                                            }

                                        }
                                        else
                                        {

                                            if (!item3.SubItems[9].Text.Contains("Network Connection Event for This Process Not Detected by ETW Events! => "))
                                                item3.SubItems[9].Text = "Network Connection Event for This Process Not Detected by ETW Events! => " + Process.GetProcessById(Convert.ToInt32(item3.SubItems[3].Text)).ProcessName;

                                            if (listView7.Items.Count > 0)
                                            {
                                                bool item7fouand = false;

                                                ListViewItem[] __Items7 = new ListViewItem[1];
                                                __Items7 = listView7.Items.Cast<ListViewItem>().ToList().ToArray<ListViewItem>();

                                                foreach (ListViewItem item7 in __Items7)
                                                {
                                                    string h7 = item7.SubItems[2].Text
                                                 + item7.SubItems[3].Text
                                                 + item7.SubItems[4].Text
                                                 + item7.SubItems[7].Text
                                                 + item7.SubItems[9].Text;

                                                    string h3 = item3.SubItems[2].Text
                                                      + item3.SubItems[3].Text
                                                      + item3.SubItems[4].Text
                                                      + item3.SubItems[7].Text
                                                      + item3.SubItems[9].Text;

                                                    if (h7 == h3)
                                                    {
                                                        item7fouand = true;
                                                        break;
                                                    }
                                                }

                                                if (!item7fouand)
                                                {
                                                    object tmp = item3.Clone();
                                                    listView7.Items.Add((ListViewItem)tmp).SubItems.Add("0");
                                                    object tmp2 = ((ListViewItem)tmp).Clone();
                                                    _ETW_Network_Events_FalsePositiveChecking_Records.Add((ListViewItem)tmp2);

                                                }
                                            }
                                            else
                                            {
                                                object tmp = item3.Clone();

                                                listView7.Items.Add((ListViewItem)tmp).SubItems.Add("0");
                                                object tmp2 = ((ListViewItem)tmp).Clone();
                                                _ETW_Network_Events_FalsePositiveChecking_Records.Add((ListViewItem)tmp2);
                                            }
                                        }

                                    }
                                    else
                                    {
                                        try
                                        {

                                            item3.BackColor = Color.White;
                                            item3.ForeColor = Color.Black;

                                            if (item3.SubItems[9].Text.Contains("This Process Not Detected by ETW Events! =>"))
                                            {

                                                int indexx = Network_Info.Processes_FileSystemList2.FindIndex(x => x.PID == Convert.ToInt32(item3.SubItems[3].Text));

                                                if (indexx != -1)
                                                {
                                                    item3.SubItems[9].Text = Network_Info.Processes_FileSystemList2[indexx].FileName_Path;

                                                }
                                                else
                                                {
                                                    item3.SubItems[9].Text = "";
                                                }


                                            }
                                        }
                                        catch (Exception)
                                        {

                                            
                                        }
                                    }

                                }
                                else
                                {

                                    item3.BackColor = Color.Red;
                                    item3.ForeColor = Color.White;


                                    int indexx = Network_Info.Processes_FileSystemList2.FindIndex(x => x.PID == Convert.ToInt32(item3.SubItems[3].Text));

                                    if (indexx != -1)
                                    {
                                        item3.SubItems[9].Text = "Network Connection Event for This Process Not Detected by ETW Events! => " + Network_Info.Processes_FileSystemList2[indexx].FileName_Path;

                                        if (listView7.Items.Count > 0)
                                        {
                                            bool item7fouand = false;

                                            ListViewItem[] __Items7 = new ListViewItem[1];
                                            __Items7 = listView7.Items.Cast<ListViewItem>().ToList().ToArray<ListViewItem>();

                                            foreach (ListViewItem item7 in __Items7)
                                            {
                                                string h7 = item7.SubItems[2].Text
                                                 + item7.SubItems[3].Text
                                                 + item7.SubItems[4].Text
                                                 + item7.SubItems[7].Text
                                                 + item7.SubItems[9].Text;

                                                string h3 = item3.SubItems[2].Text
                                                  + item3.SubItems[3].Text
                                                  + item3.SubItems[4].Text
                                                  + item3.SubItems[7].Text
                                                  + item3.SubItems[9].Text;

                                                if (h7 == h3)
                                                {
                                                    item7fouand = true;
                                                    break;
                                                }
                                            }

                                            if (!item7fouand)
                                            {
                                                object tmp = item3.Clone();
                                                listView7.Items.Add((ListViewItem)tmp).SubItems.Add("0");
                                                object tmp2 = ((ListViewItem)tmp).Clone();
                                                _ETW_Network_Events_FalsePositiveChecking_Records.Add((ListViewItem)tmp2);

                                            }
                                        }
                                        else
                                        {
                                            object tmp = item3.Clone();

                                            listView7.Items.Add((ListViewItem)tmp).SubItems.Add("0");
                                            object tmp2 = ((ListViewItem)tmp).Clone();
                                            _ETW_Network_Events_FalsePositiveChecking_Records.Add((ListViewItem)tmp2);
                                        }
                                    }
                                    else
                                    {

                                        item3.SubItems[9].Text = "Network Connection Event for This Process Not Detected by ETW Events! => " + Process.GetProcessById(Convert.ToInt32(item3.SubItems[3].Text)).ProcessName;

                                        if (listView7.Items.Count > 0)
                                        {
                                            bool item7fouand = false;
                                            ListViewItem[] __Items7 = new ListViewItem[1];
                                            __Items7 = listView7.Items.Cast<ListViewItem>().ToList().ToArray<ListViewItem>();

                                            foreach (ListViewItem item7 in __Items7)
                                            {
                                                string h7 = item7.SubItems[2].Text
                                                  + item7.SubItems[3].Text
                                                  + item7.SubItems[4].Text
                                                  + item7.SubItems[7].Text
                                                  + item7.SubItems[9].Text;

                                                string h3 = item3.SubItems[2].Text
                                                  + item3.SubItems[3].Text
                                                  + item3.SubItems[4].Text
                                                  + item3.SubItems[7].Text
                                                  + item3.SubItems[9].Text;

                                                if (h7 == h3)
                                                {
                                                    item7fouand = true;
                                                    break;
                                                }
                                            }

                                            if (!item7fouand)
                                            {
                                                object tmp = item3.Clone();
                                                listView7.Items.Add((ListViewItem)tmp).SubItems.Add("0");
                                                object tmp2 = ((ListViewItem)tmp).Clone();
                                                _ETW_Network_Events_FalsePositiveChecking_Records.Add((ListViewItem)tmp2);

                                            }
                                        }
                                        else
                                        {
                                            object tmp = item3.Clone();

                                            listView7.Items.Add((ListViewItem)tmp).SubItems.Add("0");
                                            object tmp2 = ((ListViewItem)tmp).Clone();
                                            _ETW_Network_Events_FalsePositiveChecking_Records.Add((ListViewItem)tmp2);


                                        }
                                    }
                                }
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
            }
            catch (Exception)
            {


            }

            try
            {

                Task.Run(() =>
                {
                    int _found = 0;
                    for (int i = 0; i < listView7.Items.Count; i++)
                    {
                        Thread.Sleep(10);
                        if (listView7.Items[i].SubItems[10] != null)
                        {
                            if (listView7.Items[i].SubItems[10].Text == "0")
                            {
                                _found++;
                            }
                        }
                    }

                    tabPage16.Text = "Network Connections History (Detection Error: " + _found.ToString() + " of " + listView7.Items.Count.ToString() + ")";
                    tabPage13.Text = "Network Connections (" + listView3.Items.Count.ToString() + ")";
                });

            }
            catch (Exception)
            {


            }

        }
        private void T13_Elapsed1(object sender, System.Timers.ElapsedEventArgs e)
        {
             
                List<Network_Info._Table> TPClist = Network_Info.Table2_x64.ToList<Network_Info._Table>().FindAll
                    (x => x.IsLive == 1 && (x.states_String.ToString() == "ESTABLISHED" || x.states_String.ToString() == "CLOSEWAIT"));

            foreach (Network_Info._Table item in TPClist.ToList<Network_Info._Table>())
            {

                if (listView3.Items.Count <= 0)
                {
                    try
                    {
                        Thread.Sleep(TCPConnectionDelay_for_RefreshList);
                        ListViewItem iList3x = new ListViewItem();

                        iList3x.SubItems.Add(DateTime.Now.ToString());
                        iList3x.SubItems.Add(item.ProcessName.ToString());
                        iList3x.SubItems.Add(item.PID.ToString());
                        iList3x.SubItems.Add(item.states_String.ToString());
                        iList3x.SubItems.Add(item.LocalIP.ToString());
                        iList3x.SubItems.Add(item.LPORT.ToString());
                        iList3x.SubItems.Add(item.RemoteIP.ToString());
                        iList3x.SubItems.Add(item.RPORT.ToString());

                        int indexx = Network_Info.Processes_FileSystemList2.FindIndex(x => x.PID == item.PID);

                        if (indexx != -1)
                        {
                            iList3x.SubItems.Add(Network_Info.Processes_FileSystemList2[indexx].FileName_Path);
                        }
                        else
                        {
                            iList3x.SubItems.Add(" ");
                        }

                        iList3x.Name = item.FullSTR;

                        ////if (listView7.Items.Count > 0)
                        ////{
                        ////    bool item7fouand = false;

                        ////    ListViewItem[] __Items7 = listView7.Items.Cast<ListViewItem>().ToList().ToArray();

                        ////    foreach (ListViewItem item7 in __Items7)
                        ////    {
                        ////        string h7 = item7.SubItems[2].Text
                        ////                  + item7.SubItems[3].Text
                        ////                  + item7.SubItems[4].Text
                        ////                  + item7.SubItems[7].Text
                        ////                  + item7.SubItems[9].Text;

                        ////        string h3 = iList3x.SubItems[2].Text
                        ////          + iList3x.SubItems[3].Text
                        ////          + iList3x.SubItems[4].Text
                        ////          + iList3x.SubItems[7].Text
                        ////          + iList3x.SubItems[9].Text;

                        ////        Thread.Sleep(10);

                        ////        if (h7 == h3)
                        ////        {
                        ////            item7fouand = true;
                        ////            break;
                        ////        }
                        ////    }

                        ////    if (!item7fouand)
                        ////    {
                        ////        object tmp = iList3x.Clone();
                        ////        listView7.Items.Add((ListViewItem)tmp).SubItems.Add("1");

                        ////    }
                        ////}
                        ////else
                        ////{
                        ////    object tmp = iList3x.Clone();
                        ////    listView7.Items.Add((ListViewItem)tmp).SubItems.Add("1");
                        ////}




                        if (iList3x != null)
                        {
                            //listView3.Items.Add(iList3x);
                            _Listview3_Items_NetworkConnection_Apis.Add(iList3x);

                        }

                    }
                    catch (Exception)
                    {


                    }
                }

                if (listView3.Items.Count > 0)
                {
                    try
                    {


                        bool found = false;

                        if (listView3.Items.Count > 0)
                        {
                            ListViewItem[] __Items = listView3.Items.Cast<ListViewItem>().ToArray();

                            foreach (ListViewItem _item in __Items)
                            {
                                if (_item.Name == item.FullSTR)
                                {
                                    found = true;
                                    break;
                                }
                            }


                            if (!found)
                            {
                                ListViewItem iList3x = new ListViewItem();
                                iList3x.SubItems.Add(DateTime.Now.ToString());
                                iList3x.SubItems.Add(item.ProcessName.ToString());
                                iList3x.SubItems.Add(item.PID.ToString());
                                iList3x.SubItems.Add(item.states_String.ToString());
                                iList3x.SubItems.Add(item.LocalIP.ToString());
                                iList3x.SubItems.Add(item.LPORT.ToString());
                                iList3x.SubItems.Add(item.RemoteIP.ToString());
                                iList3x.SubItems.Add(item.RPORT.ToString());

                                int indexx = Network_Info.Processes_FileSystemList2.FindIndex(x => x.PID == item.PID);

                                if (indexx != -1)
                                {
                                    iList3x.SubItems.Add(Network_Info.Processes_FileSystemList2[indexx].FileName_Path);
                                }
                                else
                                {
                                    iList3x.SubItems.Add(" ");
                                }

                                iList3x.Name = item.FullSTR;

                                ////if (listView7.Items.Count > 0)
                                ////{
                                ////    bool item7fouand = false;

                                ////    ListViewItem[] __Items2 = listView7.Items.Cast<ListViewItem>().ToList().ToArray();

                                ////    foreach (ListViewItem item7 in __Items2)
                                ////    {
                                ////        string h7 = item7.SubItems[2].Text
                                ////            + item7.SubItems[3].Text
                                ////            + item7.SubItems[4].Text
                                ////            + item7.SubItems[7].Text
                                ////            + item7.SubItems[9].Text;

                                ////        string h3 = iList3x.SubItems[2].Text
                                ////          + iList3x.SubItems[3].Text
                                ////          + iList3x.SubItems[4].Text
                                ////          + iList3x.SubItems[7].Text
                                ////          + iList3x.SubItems[9].Text;

                                ////        Thread.Sleep(10);

                                ////        if (h7 == h3)
                                ////        {
                                ////            item7fouand = true;
                                ////            break;
                                ////        }
                                ////    }

                                ////    if (!item7fouand)
                                ////    {
                                ////        object tmp = iList3x.Clone();


                                ////        listView7.Items.Add((ListViewItem)tmp).SubItems.Add("1");

                                ////    }
                                ////}
                                ////else
                                ////{
                                ////    object tmp = iList3x.Clone();

                                ////    listView7.Items.Add((ListViewItem)tmp).SubItems.Add("1");

                                ////}


                                if (iList3x != null)
                                {
                                    //listView3.Items.Add(iList3x);
                                    _Listview3_Items_NetworkConnection_Apis.Add(iList3x);
                                }

                            }

                        }
                    }
                    catch (Exception)
                    {


                    }

                }

            }

        }
        private void T12_Elapsed(object sender, System.Timers.ElapsedEventArgs e)
        {
            try
            {

                Detection_Info.Detection_Compare_to_WinEventLogSaved(_DetectedItemsByETWAlarms, _DetectedItemsByWindowEventLogSaved);
            }
            catch (Exception)
            {


            }



        }
        private async void T11_Elapsed(object sender, System.Timers.ElapsedEventArgs e)
        {
            await Task.Run(() =>
            {
                Thread.Sleep(250);
                _orangeDetection = 0;
                _RedflagDetection = 0;
                if (listView6.Items.Count > 0)
                {
                    foreach (ListViewItem _info_item in listView6.Items)
                    {
                        Thread.Sleep(100);
                        if (_info_item.SubItems[2].Text.ToLower() == "information") _orangeDetection++;

                        Task.Delay(40);

                        if (_info_item.SubItems[2].Text.ToLower() == "warning" && _info_item.SubItems[3].Text.ToLower() == "4")
                        {
                            string _hash = _info_item.SubItems[2].Text.ToLower()
                                + _info_item.SubItems[3].Text.ToLower()
                                + _info_item.SubItems[4].Text.ToLower()
                                + _info_item.SubItems[5].Text.ToLower();

                            if (_List_of__RedflagDetection_Raised.FindIndex(h => h.ToLower() == _hash) == -1)
                                _List_of__RedflagDetection_Raised.Add(_hash);
                        }

                    }

                    _RedflagDetection = _List_of__RedflagDetection_Raised.Count;

                    Chart_Redflag = Process_Table.ToList<_TableofProcess>().FindAll(high => high.SubItems_ImageIndex == 2).Count + _RedflagDetection;

                    Chart_Orange = _orangeDetection;
                }
            });
        }

        public void _StopTimer7_10()
        {
           
            processesToolStripMenuItem.Checked = false;
            for30minToolStripMenuItem.Checked = false;
            for60MinToolStripMenuItem.Checked = false;
            for90MinToolStripMenuItem.Checked = false;
            for120MinToolStripMenuItem.Checked = false;

            groupBox12.ForeColor = Color.Black;
            groupBox12.Refresh();

            Isinit_Time_To_Start_Timer10_ProcessTabTimer = false;
            _IsProcessTab_Enabled = false;
            stopListRefreshingToolStripMenuItem.Checked = true;
            startRefreshingToolStripMenuItem.Checked = false;
            processesToolStripMenuItem.Checked = false;
            groupBox12.Text = "Live Processes";
            t7.Enabled = false;
            t7.Stop();
            t10.Enabled = false;
            t10.Stop();
        }
        private async void T10_Elapsed(object sender, System.Timers.ElapsedEventArgs e)
        {
            await Task.Run(() =>
            {
                if (!Isinit_Time_To_Start_Timer10_ProcessTabTimer)
                {
                    _Time_To_Start_Timer10_ProcessTabTimer = DateTime.Now;
                    Isinit_Time_To_Start_Timer10_ProcessTabTimer = true;
                    groupBox12.Text = "Live Processes" + " (Refresh Timer is on: 0"  + "/" + "Min)";
                    groupBox12.ForeColor = Color.DarkGreen;
                 
                }

                TimeSpan ts = DateTime.Now - _Time_To_Start_Timer10_ProcessTabTimer;
              
                if (for30minToolStripMenuItem.Checked)
                {
                    if(ts.TotalMinutes.ToString().Split('.')[0].ToString() != groupBox12.Text.Split(':')[1].Split('/')[0])
                    groupBox12.Text = "Live Processes" + " (Refresh Timer is on: " + ts.TotalMinutes.ToString().Split('.')[0].ToString() + "/" + "30Min)";

                    if (ts.TotalMinutes >= 30)
                    {
                        for30minToolStripMenuItem.Checked = false;

                        _StopTimer7_10();
                        t10.Enabled = false;
                        t10.Stop();
                    }
                }

                if (for60MinToolStripMenuItem.Checked)
                {
                    if (ts.TotalMinutes.ToString().Split('.')[0].ToString() != groupBox12.Text.Split(':')[1].Split('/')[0])
                        groupBox12.Text = "Live Processes" + " (Refresh Timer is on: " + ts.TotalMinutes.ToString().Split('.')[0].ToString() + "/" + "60Min)";

                    if (ts.TotalMinutes >= 60)
                    {
                        for60MinToolStripMenuItem.Checked = false;
                      
                        _StopTimer7_10();
                        t10.Enabled = false;
                        t10.Stop();
                    }
                }

                if (for90MinToolStripMenuItem.Checked)
                {
                    if (ts.TotalMinutes.ToString().Split('.')[0].ToString() != groupBox12.Text.Split(':')[1].Split('/')[0])
                        groupBox12.Text = "Live Processes" + " (Refresh Timer is on: " + ts.TotalMinutes.ToString().Split('.')[0].ToString() + "/" + "90Min)";

                    if (ts.TotalMinutes >= 90)
                    {
                        for90MinToolStripMenuItem.Checked = false;
                      
                        _StopTimer7_10();
                        t10.Enabled = false;
                        t10.Stop();
                    }
                }

                if (for120MinToolStripMenuItem.Checked)
                {
                    if (ts.TotalMinutes.ToString().Split('.')[0].ToString() != groupBox12.Text.Split(':')[1].Split('/')[0])
                        groupBox12.Text = "Live Processes" + " (Refresh Timer is on: " + ts.TotalMinutes.ToString().Split('.')[0].ToString() + "/" + "120Min)";

                    if (ts.TotalMinutes >= 120)
                    {
                        for120MinToolStripMenuItem.Checked = false;
                        _StopTimer7_10();
                        t10.Enabled = false;
                        t10.Stop();
                    }
                }


                try
                {
                    List<_ListProcessObjects> tmp = new List<_ListProcessObjects>();

                    do
                    {
                        Task.Delay(20);

                        if (_IsProcessTab_Enabled)
                        {
                            ProcessListTabObject.RemoveAll(xx => xx.flag == true);

                            tmp = ProcessListTabObject.ToList<_ListProcessObjects>().FindAll(index => index.flag == false);

                            foreach (_ListProcessObjects item in tmp.ToList<_ListProcessObjects>())
                            {
                                if (!_IsProcessTab_Enabled) break;

                                try
                                {
                                    Task.Delay(5);
                                    BeginInvoke(new __Additem(_Additems_toTreeview1), item.obj);
                                    _ListProcessObjects tmpstru = new _ListProcessObjects();
                                    tmpstru.counter = item.counter;
                                    tmpstru.Eventtime = item.Eventtime;
                                    tmpstru.flag = true;
                                    tmpstru.obj = item.obj;
                                    ProcessListTabObject[ProcessListTabObject.ToList<_ListProcessObjects>().FindIndex(x => x.counter == item.counter)] = tmpstru;
                                    
                                }
                                catch (Exception)
                                {


                                }

                              
                            }

                            break;
                        }

                      

                    } while (_IsProcessTab_Enabled);
                }
                catch (Exception)
                {


                }

            });
        }

        /// <summary>
        /// this timer is for Update items for listView2 (Alarms by ETW Tab)
        /// </summary>       
        private async void T9_Elapsed(object sender, System.Timers.ElapsedEventArgs e)
        {
            await Task.Run(() =>
            {                         
                try
                {
                   

                    List<_TableofProcess> TerminatedProcess = Process_Table.ToList<_TableofProcess>().FindAll(Terminate => Terminate.Detection_Status == "Terminated")
                    .GroupBy(x1 => x1.PID).Select(j => j.First()).ToList();

                    if (Chart_Terminate != TerminatedProcess.Count) Chart_Terminate = TerminatedProcess.Count;


                    List<_TableofProcess> SuspendedProcess = Process_Table.ToList<_TableofProcess>().FindAll(Suspended => Suspended.Detection_Status == "Suspended")
                    .GroupBy(x1 => x1.PID).Select(j => j.First()).ToList();

                    if (Chart_suspend != SuspendedProcess.Count) Chart_suspend = SuspendedProcess.Count;

                    Task.Delay(10);
                    List<_TableofProcess> AllDettectionItems = new List<_TableofProcess>();
                    Int32 AllDettectionItemsIndex = 0;

                    /// bug fixed here omg [ null exception ] 9 june 2023
                    /// null value removed i will fix this with another code but for fix code this simple code needed ;(
                    Process_Table.RemoveAll(x => x.MemoryScanner01_Result == null);

                    try
                    {
                        if (-1 != Process_Table.ToList<_TableofProcess>().FindIndex(process => process.IsShow_Alarm == true
                                               && !process.MemoryScanner01_Result.Contains("[not scanned:0:0:0]")
                                               && !process.MemoryScanner01_Result.Contains("Skipped:[not scanned:0:0:0]")))
                        {

                            AllDettectionItems = Process_Table.ToList<_TableofProcess>().FindAll(process => process.IsShow_Alarm == true
                                                   && !process.MemoryScanner01_Result.Contains("[not scanned:0:0:0]") && !process.MemoryScanner01_Result.Contains("Skipped:[not scanned:0:0:0]"));

                            AllDettectionItemsIndex = Process_Table.ToList<_TableofProcess>().FindIndex(process => process.IsShow_Alarm == true
                                 && !process.MemoryScanner01_Result.Contains("Skipped:[not scanned:0:0:0]") && !process.MemoryScanner01_Result.Contains("[not scanned:0:0:0]"));
                        }

                    }
                    catch (Exception)
                    {

                        /// bug fixed here omg [ null exception ]
                        /// null value removed i will fix this with another code but for fix code this simple code needed ;(
                        Process_Table.RemoveAll(x => x.MemoryScanner01_Result == null);
                    }

                    Task.Delay(10);

                    xiList2 = new ListViewItem();
                    bool _xfound = false;

                    if (listView2.Items.Count > 0)
                    {
                        if (AllDettectionItemsIndex != -1)
                        {
                            foreach (var _main in AllDettectionItems.ToList<_TableofProcess>())
                            {
                                _xfound = false;
                                Task.Delay(2);

                                foreach (ListViewItem item in listView2.Items)
                                {
                                    if (item.SubItems[2].Text.ToLower() == _main.ProcessName.ToString().ToLower() + ":" + _main.PID.ToString()
                                    && Convert.ToDateTime(item.SubItems[1].Text) == Convert.ToDateTime(_main.Detection_EventTime))
                                    {
                                        _xfound = true;
                                        break;
                                    }

                                    Task.Delay(2);
                                }


                                if (!_xfound)
                                {
                                    try
                                    {

                                        int obj_index = Process_Table.ToList<_TableofProcess>().FindIndex(process => process.ProcessName.ToLower() + ":"
                                        + process.PID == _main.ProcessName + ":" + _main.PID.ToString());

                                        /// bug fixed for -1 result...
                                        /// 
                                        if (obj_index != -1)
                                        {
                                            _TableofProcess_Scanned_01 xResult = Scanned_PIds.ToList<_TableofProcess_Scanned_01>().FindLast(scannedproc => scannedproc.PID == _main.PID
                                            && scannedproc.ProcNameANDPath == _main.ProcessName_Path);



                                            _TableofProcess TempStruc = new _TableofProcess();
                                            TempStruc.TCPDetails2 = Process_Table[obj_index].TCPDetails2;
                                            TempStruc.TCPDetails = Process_Table[obj_index].TCPDetails;
                                            TempStruc.ProcessName_Path = Process_Table[obj_index].ProcessName_Path;
                                            TempStruc.ProcessName = Process_Table[obj_index].ProcessName;
                                            TempStruc.PID = Process_Table[obj_index].PID;
                                            TempStruc.IsLive = Process_Table[obj_index].IsLive;
                                            TempStruc.Injector_Path = Process_Table[obj_index].Injector_Path;
                                            TempStruc.Injector = Process_Table[obj_index].Injector;
                                            TempStruc.Description = Process_Table[obj_index].Description;
                                            TempStruc.IsShow_Alarm = true;
                                            TempStruc.Detection_Status = xResult.Action;
                                            TempStruc.Detection_EventTime = Process_Table[obj_index].Detection_EventTime;

                                            TempStruc.MemoryScanner01_Result = xResult.Scanner01_RESULT_Int32_outputstr;
                                            TempStruc.MemoryScanner02_Result = "Disabled";

                                            string temp_InjectionType_Recheck = "";
                                            try
                                            {
                                                /// bug fixed
                                                string replacestr = xResult.Scanner01_RESULT_Int32_outputstr.Substring(Memory_info._FindAllIndex("replaced:", _finalresult_Scanned_01[0], 0)[0])
                                                .Split(']')[0];

                                                int count = Convert.ToInt32(replacestr.Split(':')[1]);
                                                if (count > 0)
                                                {
                                                    /// injection type
                                                    temp_InjectionType_Recheck = "Process-Hollowing";
                                                    TempStruc.InjectionType = "Process-Hollowing";
                                                }
                                                else
                                                {
                                                    /// injection type
                                                    temp_InjectionType_Recheck = "Injection";
                                                    TempStruc.InjectionType = "Injection";
                                                }

                                            }
                                            catch (Exception)
                                            {


                                            }

                                            _TableofProcess_NewProcess_evt xFindingInjectorInfo = NewProcess_Table.ToList<_TableofProcess_NewProcess_evt>().Find(x => x.PID == Process_Table[obj_index].Injector
                                            || x.ProcessName_Path == Process_Table[obj_index].Injector_Path);

                                            TempStruc.Descripton_Details = TempStruc.ProcessName + " Injected by => " + TempStruc.Injector_Path + " (PID:" + TempStruc.Injector.ToString()
                                            + ") \nInjector Details:\nInjector-ProcessName: "
                                            + xFindingInjectorInfo.ProcessName + "\nInjector-Path: " + xFindingInjectorInfo.ProcessName_Path
                                            + "\nInjector-CommandLine: " + xFindingInjectorInfo.CommandLine;

                                            TempStruc.SubItems_Name_Property = Process_Table[obj_index].ProcessName + ":" + Process_Table[obj_index].PID + ">\n" + xResult.Action;

                                            if (xResult.Action == "Scanned & Found!" || xResult.Action == "Terminated" || xResult.Action == "Suspended")
                                            {
                                                TempStruc.SubItems_ImageIndex = 2;
                                            }
                                            else
                                            {
                                                TempStruc.SubItems_ImageIndex = 1;
                                            }

                                            Process_Table[obj_index] = TempStruc;


                                            xiList2.SubItems.Add(_main.Detection_EventTime.ToString());
                                            xiList2.SubItems.Add(_main.ProcessName + ":" + _main.PID.ToString());

                                            xiList2.SubItems.Add(temp_InjectionType_Recheck);

                                            xiList2.SubItems.Add(_main.TCPDetails2.ToString());
                                            xiList2.SubItems.Add(xResult.Action);

                                            xiList2.SubItems.Add(xResult.Scanner01_RESULT_Int32_outputstr);

                                            xiList2.SubItems.Add("Disabled");
                                            xiList2.SubItems.Add(TempStruc.Descripton_Details);
                                            xiList2.SubItems.Add(_main.Description);

                                            if (_main.SubItems_Name_Property.Length > TempStruc.SubItems_Name_Property.Length)
                                            {
                                                xiList2.Name = _main.SubItems_Name_Property;
                                            }
                                            else if (_main.SubItems_Name_Property.Length < TempStruc.SubItems_Name_Property.Length)
                                            {
                                                xiList2.Name = TempStruc.SubItems_Name_Property;
                                            }

                                            xiList2.ImageIndex = TempStruc.SubItems_ImageIndex;

                                            if (xResult.Action != "Skipped" && xResult.Scanner01_RESULT_Int32_outputstr.ToString() != string.Empty)
                                            {
                                                //object cloner_xiList2 = xiList2.Clone();
                                                //listView2.Items.Add((ListViewItem)cloner_xiList2);
                                                try
                                                {
                                                    listView2.Items.Add(xiList2);

                                                    _DetectedItemsByETWAlarms.Add(xiList2);
                                                }
                                                catch (Exception)
                                                {

                                                    
                                                }
                                                

                                            }

                                            tabPage4.Text = "Alarms by ETW " + "(" + listView2.Items.Count.ToString() + ")";
                                            toolStripStatusLabel6.Text = "| Alarms by ETW " + "(" + listView2.Items.Count.ToString() + ")";
                                        }
                                    }
                                    catch (Exception ee)
                                    {
                                        if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [_Additems_toListview2_timer] Method Call: error1 => " + ee.Message);


                                    }
                                }


                            }
                        }
                    }
                    else
                    {
                        if (AllDettectionItemsIndex != -1)
                        {
                            foreach (var _item in AllDettectionItems.ToList<_TableofProcess>())
                            {
                                try
                                {
                                    Task.Delay(2);

                                    _TableofProcess_Scanned_01 xResult = Scanned_PIds.ToList<_TableofProcess_Scanned_01>().FindLast(scannedproc => scannedproc.PID == _item.PID
                                    && scannedproc.ProcNameANDPath == _item.ProcessName_Path);

                                    int obj_index = Process_Table.ToList<_TableofProcess>().FindIndex(process => process.ProcessName.ToLower() + ":"
                                     + process.PID == _item.ProcessName.ToLower() + ":" + _item.PID.ToString());


                                    _TableofProcess TempStruc = new _TableofProcess();
                                    TempStruc.TCPDetails2 = Process_Table[obj_index].TCPDetails2;
                                    TempStruc.TCPDetails = Process_Table[obj_index].TCPDetails;
                                    TempStruc.ProcessName_Path = Process_Table[obj_index].ProcessName_Path;
                                    TempStruc.ProcessName = Process_Table[obj_index].ProcessName;
                                    TempStruc.PID = Process_Table[obj_index].PID;
                                    TempStruc.IsLive = Process_Table[obj_index].IsLive;
                                    TempStruc.Injector_Path = Process_Table[obj_index].Injector_Path;
                                    TempStruc.Injector = Process_Table[obj_index].Injector;
                                    TempStruc.Description = Process_Table[obj_index].Description;
                                    TempStruc.IsShow_Alarm = true;
                                    TempStruc.Detection_Status = xResult.Action;
                                    TempStruc.Detection_EventTime = Process_Table[obj_index].Detection_EventTime;

                                    TempStruc.MemoryScanner01_Result = xResult.Scanner01_RESULT_Int32_outputstr;
                                    TempStruc.MemoryScanner02_Result = "Disabled";
                                    string temp_InjectionType_Recheck = "";
                                    try
                                    {
                                        /// bug fixed
                                        string replacestr = xResult.Scanner01_RESULT_Int32_outputstr.Substring(Memory_info._FindAllIndex("replaced:", _finalresult_Scanned_01[0], 0)[0])
                                        .Split(']')[0];

                                        int count = Convert.ToInt32(replacestr.Split(':')[1]);
                                        if (count > 0)
                                        {
                                            /// injection type
                                            temp_InjectionType_Recheck = "Process-Hollowing";
                                            TempStruc.InjectionType = "Process-Hollowing";
                                        }
                                        else
                                        {
                                            /// injection type
                                            temp_InjectionType_Recheck = "Injection";
                                            TempStruc.InjectionType = "Injection";
                                        }

                                    }
                                    catch (Exception)
                                    {


                                    }

                                    _TableofProcess_NewProcess_evt xFindingInjectorInfo = NewProcess_Table.ToList<_TableofProcess_NewProcess_evt>().Find(x => x.PID == Process_Table[obj_index].Injector
                                    || x.ProcessName_Path == Process_Table[obj_index].Injector_Path);

                                    TempStruc.Descripton_Details = TempStruc.ProcessName + " Injected by => " + TempStruc.Injector_Path + " (PID:" + TempStruc.Injector.ToString()
                                    + ") \nInjector Details:\nInjector-ProcessName: "
                                    + xFindingInjectorInfo.ProcessName + "\nInjector-Path: " + xFindingInjectorInfo.ProcessName_Path
                                    + "\nInjector-CommandLine: " + xFindingInjectorInfo.CommandLine;

                                    TempStruc.SubItems_Name_Property = Process_Table[obj_index].ProcessName + ":" + Process_Table[obj_index].PID + ">\n" + xResult.Action;

                                    if (xResult.Action == "Scanned & Found!" || xResult.Action == "Terminated" || xResult.Action == "Suspended")
                                    {
                                        TempStruc.SubItems_ImageIndex = 2;
                                    }
                                    else
                                    {
                                        TempStruc.SubItems_ImageIndex = 1;
                                    }

                                    Process_Table[obj_index] = TempStruc;


                                    xiList2.SubItems.Add(_item.Detection_EventTime.ToString());
                                    xiList2.SubItems.Add(_item.ProcessName + ":" + _item.PID.ToString());

                                    xiList2.SubItems.Add(temp_InjectionType_Recheck);

                                    xiList2.SubItems.Add(_item.TCPDetails2.ToString());
                                    xiList2.SubItems.Add(xResult.Action);

                                    xiList2.SubItems.Add(xResult.Scanner01_RESULT_Int32_outputstr);

                                    xiList2.SubItems.Add("Disabled");
                                    xiList2.SubItems.Add(TempStruc.Descripton_Details);
                                    xiList2.SubItems.Add(_item.Description);

                                    if (_item.SubItems_Name_Property.Length > TempStruc.SubItems_Name_Property.Length)
                                    {
                                        xiList2.Name = _item.SubItems_Name_Property;
                                    }
                                    else if (_item.SubItems_Name_Property.Length < TempStruc.SubItems_Name_Property.Length)
                                    {
                                        xiList2.Name = TempStruc.SubItems_Name_Property;
                                    }

                                    xiList2.ImageIndex = TempStruc.SubItems_ImageIndex;

                                    if (xResult.Action != "Skipped" && xResult.Scanner01_RESULT_Int32_outputstr.ToString() != string.Empty)
                                    {
                                        //object cloner_xiList2 = xiList2.Clone();
                                        //listView2.Items.Add((ListViewItem)cloner_xiList2);                                       
                                        //_DetectedItemsByETWAlarms.Add(xiList2);

                                        try
                                        {
                                            listView2.Items.Add(xiList2);

                                            _DetectedItemsByETWAlarms.Add(xiList2);
                                        }
                                        catch (Exception)
                                        {


                                        }
                                    }

                                    tabPage4.Text = "Alarms by ETW " + "(" + listView2.Items.Count.ToString() + ")";
                                    toolStripStatusLabel6.Text = "| Alarms by ETW " + "(" + listView2.Items.Count.ToString() + ")";

                                }
                                catch (Exception ee)
                                {
                                    if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [_Additems_toListview2_timer] Method Call: error0 => " + ee.Message);
                                }

                            }
                        }
                    }


                }
                catch (Exception)
                {


                }
            });
        }

        /// <summary>
        /// this timer will check child processes of target process to terminate after (delay 2 sec) 
        /// </summary>       
        private void T8_Elapsed(object sender, System.Timers.ElapsedEventArgs e)
        {
            try
            {


                for (int i = 0; i < 2; i++)
                {


                    /// check sub processes                                              
                    foreach (_TableofProcess_NewProcess_evt ___item in NewProcess_Table.ToList().FindAll(SubProc =>
                    SubProc.PPID == _PPID_For_TimerScanner01))
                    {
                        ///"[ParentID Path: C:\\Windows\\SysWOW64\\notepad.exe]"

                        if (___item.PPID_Path.ToLower().Substring(16).Split(']')[0] ==
                            _PPIDPath_For_TimerScanner01.ToLower())
                        {
                            try
                            {
                                if (Process.GetProcesses().ToList().FindIndex(x => x.Id == ___item.PID) != -1)
                                {
                                    //Process.GetProcessById(___item.PID).Kill();

                                    IntPtr TintPtr = Process.GetProcessById(___item.PID).Handle;
                                    uint ExitCode = 0;

                                    Memory_info.GetExitCodeProcess(TintPtr, out ExitCode);

                                    Memory_info.TerminateProcess(TintPtr, ExitCode);
                                }
                            }
                            catch (Exception)
                            {


                            }

                        }
                    }

                    Thread.Sleep(2000);
                }
            }
            catch (Exception)
            {


            }
            _PPID_For_TimerScanner01 = -1;
            _PPIDPath_For_TimerScanner01 = "";
            t8.Enabled = false;
            t8.Stop();
        }
        private async void T7_Elapsed(object sender, System.Timers.ElapsedEventArgs e)
        {
            await Task.Run(() =>
            {
                try
                {
                    
                    foreach (var item in _List_All_Injection_Details_info_Filter_withoutSystem4.ToList())
                    {
                        Task.Delay(5);
                        if (item._TargetPID != 4)
                        {
                            bool found = false;
                            if (listBox3.Items.Count > 0)
                            {
                                foreach (var _item in listBox3.Items)
                                {
                                    Task.Delay(5);
                                    if (_item.ToString() == "(StartAddr:" + item._ThreadStartAddress.ToString() + ") [TID:" + item._RemoteThreadID.ToString() + "] " + "[Time:" + item._time_evt
                                  + "] [Target PID:" + item._TargetPID + "] [Target PIDName:" + item._TargetPID_Path + "]"
                                  + " [Injector:" + item._InjectorPID + "] [InjectorPath:" + item._InjectorPID_Path + "]")
                                    {
                                        found = true;
                                        break;
                                    }
                                }
                                if (!found)
                                {
                                    listBox3.Items.Add("(StartAddr:" + item._ThreadStartAddress.ToString() + ") [TID:" + item._RemoteThreadID.ToString() + "] " + "[Time:" + item._time_evt
                                  + "] [Target PID:" + item._TargetPID + "] [Target PIDName:" + item._TargetPID_Path + "]"
                                  + " [Injector:" + item._InjectorPID + "] [InjectorPath:" + item._InjectorPID_Path + "]");
                                }
                            }
                            else
                            {

                                listBox3.Items.Add("(StartAddr:" + item._ThreadStartAddress.ToString() + ") [TID:" + item._RemoteThreadID.ToString() + "] " + "[Time:" + item._time_evt
                                  + "] [Target PID:" + item._TargetPID + "] [Target PIDName:" + item._TargetPID_Path + "]"
                                  + " [Injector:" + item._InjectorPID + "] [InjectorPath:" + item._InjectorPID_Path + "]");

                            }
                        }
                    }

                    listBox3.SelectedIndex = listBox3.Items.Count - 1;

                    /// this will remove all useless info and make free memory also cpu usage will be low too...
                    _List_All_Injection_Details_info_Filter_withoutSystem4.RemoveAll(xx => xx._flag_to_Dont_Remove_FromList == false);

                    foreach (var item in _InjectedTIDList.ToList())
                    {
                        Task.Delay(5);
                        bool found = false;
                        if (listBox4.Items.Count > 0)
                        {
                            foreach (var _item in listBox4.Items)
                            {
                                Task.Delay(5);
                                _TableofProcess_ETW_Event_Counts TCP_Process = _ETW_Events_Counts.Find(process => process.PID == item._TargetPID && process.ProcNameANDPath.ToLower() == item._TargetPIDName.ToLower());

                                if (_item.ToString() == "(StartAddr:" + item._ThreadStartAddress.ToString() + ") [TID:" + item._RemoteThreadID.ToString() + "] "
                                    + "[Bytes:" + item.Injected_Memory_Bytes.Substring(0, 50) + "...."
                              + "] [Target PID:" + item._TargetPID + "] [Target PIDName:" + item._TargetPIDName + "]"
                              + " [Injector:" + item._InjectorPID + "] [TCP: " + TCP_Process._LastTCP_Details + "]")
                                {
                                    found = true;
                                    break;
                                }
                            }
                            if (!found)
                            {
                                _TableofProcess_ETW_Event_Counts TCP_Process = _ETW_Events_Counts.Find(process => process.PID == item._TargetPID && process.ProcNameANDPath.ToLower() == item._TargetPIDName.ToLower());

                                listBox4.Items.Add("(StartAddr:" + item._ThreadStartAddress.ToString() + ") [TID:" + item._RemoteThreadID.ToString() + "] "
                                    + "[Bytes:" + item.Injected_Memory_Bytes.Substring(0, 50) + "...."
                              + "] [Target PID:" + item._TargetPID + "] [Target PIDName:" + item._TargetPIDName + "]"
                              + " [Injector:" + item._InjectorPID + "] [TCP: " + TCP_Process._LastTCP_Details + "]");
                            }
                        }
                        else
                        {
                            _TableofProcess_ETW_Event_Counts TCP_Process = _ETW_Events_Counts.Find(process => process.PID == item._TargetPID
                            && process.ProcNameANDPath.ToLower() == item._TargetPIDName.ToLower());

                            listBox4.Items.Add("(StartAddr:" + item._ThreadStartAddress.ToString() + ") [TID:" + item._RemoteThreadID.ToString() + "] "
                                    + "[Bytes:" + item.Injected_Memory_Bytes.Substring(0, 50) + "...."
                              + "] [Target PID:" + item._TargetPID + "] [Target PIDName:" + item._TargetPIDName + "]"
                              + " [Injector:" + item._InjectorPID + "] [TCP: " + TCP_Process._LastTCP_Details + "]");

                        }
                    }
                    // listBox4.SelectedIndex = listBox4.Items.Count - 1;
                }
                catch (Exception)
                {


                }
            });
        }
        private void T6_Elapsed(object sender, System.Timers.ElapsedEventArgs e)
        {
            try
            {

                listView4.BeginInvoke((MethodInvoker)delegate
                {
                    Process[] p = Process.GetProcesses();
                    foreach (ListViewItem item in listView1.Items)
                    {
                        try
                        {
                            if (p.ToList().FindIndex(pid => pid.Id == Convert.ToInt32(item.SubItems[3].Text.Split(':')[1])
                        && pid.ProcessName.ToLower() == item.SubItems[3].Text.Split(':')[0].ToLower()) == -1)
                            {

                                item.Remove();
                            }
                        }
                        catch (Exception)
                        {


                        }

                    }
                });
            }
            catch (Exception)
            {


            }

        }

        /// <summary>
        /// time for refresh listview4 [network connections Tab] items and verfiy tcp connection for each items [realtime] to change their imageindex (refresh every 10sec) 
        /// </summary>        
        private async void T5_Elapsed(object sender, System.Timers.ElapsedEventArgs e)
        {
            try
            {
                await Task.Run(() =>
                {
                    listView4.BeginInvoke((MethodInvoker)delegate
                    {
                        try
                        {

                            ActiveTCP.Clear();
                            IPGlobalProperties _GetIPGlobalProperties = IPGlobalProperties.GetIPGlobalProperties();
                            TcpConnectionInformation[] _TCPConnections = _GetIPGlobalProperties.GetActiveTcpConnections();

                            foreach (TcpConnectionInformation t in _TCPConnections.ToList())
                            {

                                ActiveTCP.Add(t.LocalEndPoint.Address.ToString() + ":" + t.LocalEndPoint.Port.ToString() + ">" + t.RemoteEndPoint.Address.ToString()
                                    + ":" + t.RemoteEndPoint.Port.ToString() + "@" + t.State.ToString());

                            }

                            for (int i = 0; i < listView4.Items.Count; i++)
                            {
                                string __find = ActiveTCP.Find(_tcp => _tcp.Split('>')[0] == listView4.Items[i].SubItems[4].Text && _tcp.Split('>')[1].Split('@')[0]
                                == listView4.Items[i].SubItems[5].Text);

                                if (__find != null)
                                {
                                    if (__find.Split('@')[1].ToLower().Contains("established"))
                                    {
                                        listView4.Items[i].ImageIndex = 7;
                                    }
                                    else
                                    {
                                        listView4.Items[i].ImageIndex = 6;
                                    }

                                }
                                else
                                {
                                    listView4.Items[i].ImageIndex = 6;

                                }
                            }

                            listView4.Refresh();
                        }
                        catch (Exception)
                        {


                        }
                    });
                });
            }
            catch (Exception)
            {


            }
        }

        /// <summary>
        /// timer to refresh listview4 [network connection Tab] and change colors to white (delay 25millisec) 
        /// </summary>        
        private async void T4_1_Elapsed(object sender, System.Timers.ElapsedEventArgs e)
        {
            await Task.Run(() =>
            {
                try
                {
                    Task.Delay(25);

                    /// for sure check all index ;)
                    listView4.BeginInvoke((MethodInvoker)delegate
                    {
                        for (int ii = 0; ii < listView4.Items.Count; ii++)
                        {
                            try
                            {
                                listView4.Items[ii].BackColor = Color.White;
                                Task.Delay(5);
                            }
                            catch (Exception)
                            {


                            }

                        }
                        listView4.Refresh();
                    });

                }
                catch (Exception)
                {


                }

                t4_1.Enabled = false;
            });
        }
        private void Form1_ChangeColorstoDefault(object sender, EventArgs e)
        {
            /// time to change/refresh listview4 colors (1500) delay
            t4_1.Enabled = true;

        }

        /// <summary>
        /// add all tcp events to networ connection Tab
        /// </summary>       
        private void Form1_NewTCP_Connection_Detected(object sender, EventArgs e)
        {
            BeginInvoke(new __Additem(Run_Async_Refresh_NetworkConection_in_Network_Tab), sender);
        }
        public async void Run_Async_Refresh_NetworkConection_in_Network_Tab(object _obj)
        {
            await Refresh_NetworkConection_in_Network_Tab(_obj);
        }

        /// <summary>
        /// add and refresh all tcp events to network connection Tab
        /// </summary>
        public async Task Refresh_NetworkConection_in_Network_Tab(object obj)
        {
            await Task.Run(() =>
            {

                try
                {
                    ListViewItem NetworkTCP = (ListViewItem)obj;
                    ListViewItem __obj = (ListViewItem)obj;
                    string sip = __obj.SubItems[5].Text.Split('\n')[6].Split(']')[2].Split(':')[1];
                    string sip_port = __obj.SubItems[5].Text.Split('\n')[6].Split(']')[4].Split(':')[1];
                    string dip = __obj.SubItems[5].Text.Split('\n')[6].Split(']')[1].Split(':')[1];
                    string dip_port = __obj.SubItems[5].Text.Split('\n')[6].Split(']')[3].Split(':')[1];
                    NetworkTCP.Name = __obj.SubItems[3].Text + sip + dip + dip_port;
                    iList4 = new ListViewItem();
                    init_removeItems = false;

                    if (listView4.Items.Count > 0)
                    {
                        for (int i = 0; i < listView4.Items.Count; i++)
                        {

                            string __TargetProcess = "";

                            if (listView4.Items[i].Name != __obj.SubItems[3].Text + sip + dip + dip_port)
                            {
                                NetworkConection_found = false;
                               
                            }
                            else if (listView4.Items[i].Name == __obj.SubItems[3].Text + sip + dip + dip_port)
                            {
                                try
                                {
                                    Task.Delay(2);
                                    Int32 IndexofTCPRecord = TCPConnectionTable_To_Show.ToList<_TCPConnection_Struc>().FindIndex(index => index._SUID == __obj.SubItems[3].Text + sip + dip + dip_port);
                                    bool timetoshow = false;
                                    Task.Delay(2);
                                    if (IndexofTCPRecord != -1)
                                    {
                                        TimeSpan _1min = TCPConnectionTable_To_Show[IndexofTCPRecord]._Time - Convert.ToDateTime(listView4.Items[i].SubItems[1].Text);

                                        if (_1min.Minutes >= 1) timetoshow = true;

                                        _TCPConnection_Struc TempTCPstruc = new _TCPConnection_Struc();

                                        TempTCPstruc._Time = Convert.ToDateTime(NetworkTCP.SubItems[1].Text);
                                        TempTCPstruc._Process = TCPConnectionTable_To_Show[IndexofTCPRecord]._Process;
                                        TempTCPstruc._Status = "Connected";
                                        TempTCPstruc._SIP = sip + ":" + sip_port;
                                        TempTCPstruc._DIP = TCPConnectionTable_To_Show[IndexofTCPRecord]._DIP;
                                        TempTCPstruc._DeltaTime = Delta_Time(Convert.ToDateTime(NetworkTCP.SubItems[1].Text), TCPConnectionTable_To_Show[IndexofTCPRecord]._Time);

                                        Int64 __Tempcount = Convert.ToInt64(TCPConnectionTable_To_Show[IndexofTCPRecord]._EventCount);
                                        __Tempcount++;
                                        TempTCPstruc._EventCount = __Tempcount;

                                        TimeSpan __ttl = Convert.ToDateTime(NetworkTCP.SubItems[1].Text) - TCPConnectionTable_To_Show[IndexofTCPRecord]._Event_FirstTime;
                                        TempTCPstruc._EventTTL = "D:" + __ttl.Days.ToString() + " , H:" + __ttl.Hours.ToString() + " , M:" + __ttl.Minutes.ToString();

                                        TempTCPstruc._Event_FirstTime = TCPConnectionTable_To_Show[IndexofTCPRecord]._Event_FirstTime;
                                        TempTCPstruc._SUID = TCPConnectionTable_To_Show[IndexofTCPRecord]._SUID;

                                        Int32 _tempupdate = Convert.ToInt32(TCPConnectionTable_To_Show[IndexofTCPRecord]._Update_Events);

                                        if (_tempupdate <= 4)
                                        {
                                            _tempupdate++;
                                            TempTCPstruc._Update_Events = _tempupdate;
                                            TCPConnectionTable_To_Show[IndexofTCPRecord] = TempTCPstruc;
                                        }
                                        else if (_tempupdate > 4)
                                        {
                                            if (_1min.Minutes >= 1)
                                            {
                                                timetoshow = true;

                                                _tempupdate = 1;

                                            }

                                            TempTCPstruc._Update_Events = _tempupdate;
                                            TCPConnectionTable_To_Show[IndexofTCPRecord] = TempTCPstruc;
                                        }


                                        if (_1min.Minutes >= 1) timetoshow = true;

                                    }


                                    if (timetoshow)
                                    {
                                        try
                                        {

                                            listView4.Items[i].SubItems[6].Text = TCPConnectionTable_To_Show[IndexofTCPRecord]._DeltaTime;
                                            listView4.Items[i].SubItems[1].Text = TCPConnectionTable_To_Show[IndexofTCPRecord]._Time.ToString();
                                            listView4.Items[i].SubItems[4].Text = TCPConnectionTable_To_Show[IndexofTCPRecord]._SIP;

                                            NetworkConection_TCP_counts = Convert.ToInt64(listView4.Items[i].SubItems[7].Text);
                                            NetworkConection_TCP_counts++;

                                            listView4.Items[i].SubItems[7].Text = TCPConnectionTable_To_Show[IndexofTCPRecord]._EventCount.ToString();
                                            listView4.Items[i].SubItems[8].Text = TCPConnectionTable_To_Show[IndexofTCPRecord]._EventTTL;
                                            __TargetProcess = TCPConnectionTable_To_Show[IndexofTCPRecord]._Process;
                                        }
                                        catch (Exception ee)
                                        {
                                            if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [Refresh_NetworkConection_in_Network_Tab] Method Call: error1 => " + ee.Message);
                                        }

                                        listView4.Refresh();
                                        BeginInvoke(new __Additem(_Run_ChangeColor_for_listview4), i);
                                        NetworkConection_found = true;
                                        tabPage9.Text = "Network Connections (" + listView4.Items.Count.ToString() + ")";
                                        toolStripStatusLabel7.Text = "| Network Connections (" + listView4.Items.Count.ToString() + ")";
                                    }
                                }
                                catch (Exception ee)
                                {
                                    if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [Refresh_NetworkConection_in_Network_Tab] Method Call: error3 => " + ee.Message);

                                }

                                break;
                            }
                        }

                        if (!NetworkConection_found)
                        {
                            try
                            {
                                Task.Delay(2);
                                int IndexofTCPRecord2 = TCPConnectionTable_To_Show.ToList<_TCPConnection_Struc>().FindIndex(index => index._SUID == __obj.SubItems[3].Text + sip + dip + dip_port);
                                Task.Delay(2);
                                if (IndexofTCPRecord2 == -1)
                                {
                                    TCPConnectionTable_To_Show.Add(new _TCPConnection_Struc
                                    {
                                        _Time = Convert.ToDateTime(__obj.SubItems[1].Text),
                                        _Process = __obj.SubItems[3].Text,
                                        _Status = "Connected",
                                        _SIP = sip + ":" + sip_port,
                                        _DIP = dip + ":" + dip_port,
                                        _DeltaTime = "0",
                                        _EventCount = 1,
                                        _EventTTL = "0",
                                        _Event_FirstTime = Convert.ToDateTime(NetworkTCP.SubItems[1].Text),
                                        _SUID = __obj.SubItems[3].Text + sip + dip + dip_port,
                                        _Update_Events = 1

                                    });
                                }
                            }
                            catch (Exception ee)
                            {
                                if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [Refresh_NetworkConection_in_Network_Tab] Method Call: error4 => " + ee.Message);


                            }


                            try
                            {

                                bool founditem = false;

                                for (int j = 0; j < listView4.Items.Count; j++)
                                {
                                    if (listView4.Items[j].Name == NetworkTCP.SubItems[3].Text + sip + dip + dip_port)
                                    {
                                        founditem = true;
                                        break;
                                    }
                                }

                                Task.Delay(2);

                                if (!founditem)
                                {
                                    try
                                    {

                                        iList4 = new ListViewItem();
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
                                        string __TargetProcess = __obj.SubItems[3].Text;


                                    }
                                    catch (Exception ee)
                                    {
                                        if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [Refresh_NetworkConection_in_Network_Tab] Method Call: error5 => " + ee.Message);


                                    }
                                    

                                    if (iList4.SubItems[2].Text.Contains(':') && iList4.SubItems[3].Text == "Connected")
                                    {
                                       
                                        bool xfound = false;
                                        if (listView4.Items.Count > 0)
                                        {
                                            for (int i = 0; i < listView4.Items.Count; i++)
                                            {
                                                /// bug was here, fixed
                                                if (listView4.Items[i].SubItems[2].Text == iList4.SubItems[2].Text 
                                                && listView4.Items[i].SubItems[5].Text == iList4.SubItems[5].Text)
                                                {
                                                    xfound = true;
                                                    break;
                                                }

                                                Task.Delay(2);
                                            }


                                            if (!xfound)
                                            {
                                                int _i1 = listView4.Items.Add(iList4).Index;                                                
                                                BeginInvoke(new __Additem(_Run_ChangeColor_for_listview4), _i1);
                                            }
                                        }
                                        else
                                        {
                                            int _i2 = listView4.Items.Add(iList4).Index;
                                            BeginInvoke(new __Additem(_Run_ChangeColor_for_listview4), _i2);

                                        }
                                    }

                                    tabPage9.Text = "Network Connections (" + listView4.Items.Count.ToString() + ")";
                                    toolStripStatusLabel7.Text = "| Network Connections (" + listView4.Items.Count.ToString() + ")";
                                }
                            }
                            catch (Exception ee)
                            {
                                if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [Refresh_NetworkConection_in_Network_Tab] Method Call: error6 => " + ee.Message);

                            }
                        }
                    }
                    else if (listView4.Items.Count <= 0)
                    {
                        try
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
                            int _i = 0;
                            Task.Delay(2);

                            if (iList4.SubItems[2].Text.Contains(':') && iList4.SubItems[3].Text == "Connected")
                            {
                                bool xfound = false;
                                foreach (ListViewItem xitem in listView4.Items)
                                {
                                    if (xitem.SubItems[2].Text == iList4.SubItems[2].Text)
                                    {
                                        xfound = true;
                                        break;
                                    }
                                }

                                if (!xfound)
                                {
                                    _i = listView4.Items.Add(iList4).Index;

                                    BeginInvoke(new __Additem(_Run_ChangeColor_for_listview4), _i);
                                }
                            }

                            tabPage9.Text = "Network Connections (" + listView4.Items.Count.ToString() + ")";
                            toolStripStatusLabel7.Text = "| Network Connections (" + listView4.Items.Count.ToString() + ")";
                        }
                        catch (Exception ee)
                        {
                            if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [Refresh_NetworkConection_in_Network_Tab] Method Call: error7 => " + ee.Message);
                        }
                    }
                }
                catch (Exception ee)
                {
                    if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [Refresh_NetworkConection_in_Network_Tab] Method Call: error8 => " + ee.Message);
                }
                
                init_removeItems = true;
            });

        }
        public async Task _ChangedProperty_Color_changed_delay(object itemid)
        {
            try
            {

                await Task.Run(() =>
                {
                    init_removeItems = false;
                    listView4.Items[Convert.ToInt32(itemid)].BackColor = Color.Red;
                    listView4.Refresh();
                    ChangeColorstoDefault.Invoke((object)itemid, null);

                    Task.Delay(25);

                    init_removeItems = true;

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
        /// add detected events to System_Detection_Logs Tab , for TCP Meterpreter events and Found Shell events (only)
        /// </summary>        
        private void Form1_System_Detection_Log_events2(object sender, EventArgs e)
        {
            try
            {
                if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [Form1_System_Detection_Log_events2] Event/Method Call: Started");
                //if(IsSystemDeveloperLogIson) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [Form1_System_Detection_Log_events2] Event/Method Call: error1 => " + ee.Message);


                ListViewItem tmp2 = (ListViewItem)sender;

                if (tmp2.SubItems[2].Text == "3")
                {
                    if ((tmp2.SubItems[5].Text.Split('\n')[6].Contains("[size:160]")) || (tmp2.SubItems[5].Text.Split('\n')[6].Contains("[size:192]")))
                    {

                        iList3 = new ListViewItem();
                        /// add event message to name value
                        iList3.Name = tmp2.SubItems[5].Text;
                        iList3.SubItems.Add(tmp2.SubItems[1].Text);
                        iList3.SubItems.Add(tmp2.SubItems[3].Text);

                        iList3.SubItems.Add("[!] Suspicious Traffic [Meterpreter!]");
                        iList3.SubItems.Add("ETW [Tcp] event");
                        iList3.SubItems.Add("Event Detected!");


                        iList3.SubItems.Add("--");
                        iList3.ImageIndex = 1;
                        if (tmp2.Name != eventstring_tmp3)
                        {
                             
                           
                            BeginInvoke(new __core2(SaveETWLogs.AsyncRun___Save_New_DetectionLogs_TCP_Shell_Events_to_WinEventLog), iList3);
                            eventstring_tmp3 = tmp2.Name;

                        }

                    }
                    else if (tmp2.SubItems[5].Text.Split('\n')[6].Contains("[dport:4444]"))
                    {

                        //tmp2.SubItems[5].Text += "\n\n#This Description Added by ETWPM2Monitor2 tool#\n##Warning Description: Packet with [size:160] maybe was for Meterpreter Session which will send every 1 min between Client/Server##\n" +
                        //   "##Warning Description: Packet with [size:192] is for meterpreter session which will send before every command excution from/to  server##\n" +
                        //   "##Warning Description: DestinationPort [dport:4444] is Default port for Meterpreter session##";
                        iList3 = new ListViewItem();
                        iList3.Name = tmp2.SubItems[5].Text;
                        iList3.SubItems.Add(tmp2.SubItems[1].Text);
                        iList3.SubItems.Add(tmp2.SubItems[3].Text);

                        iList3.SubItems.Add("[!] Suspicious Traffic [Meterpreter!]");
                        iList3.SubItems.Add("ETW [Tcp] event");
                        iList3.SubItems.Add("Event Detected!");


                        iList3.SubItems.Add("--");
                        iList3.ImageIndex = 1;
                        if (tmp2.Name != eventstring_tmp3)
                        {
                            

                            BeginInvoke(new __core2(SaveETWLogs.AsyncRun___Save_New_DetectionLogs_TCP_Shell_Events_to_WinEventLog), iList3);
                            eventstring_tmp3 = tmp2.Name;
                        }
                    }
                }

                if (tmp2.SubItems[2].Text == "1")
                {
                    string commandline = tmp2.SubItems[5].Text.Split('\n')[4].ToLower();
                    string parentid = tmp2.SubItems[5].Text.Split('\n')[5].ToLower();
                    string parentidPath = tmp2.SubItems[5].Text.Split('\n')[6].Substring(16);
                    parentidPath = parentidPath.Substring(0, parentidPath.Length - 1);
                    string Shell_Pid = tmp2.SubItems[5].Text.Split('\n')[2].Substring(6).Split(' ')[0];

                    if (commandline.Contains("[commandline: \"" + _windir + "\\system32\\cmd.exe\"")
                        || commandline.Contains("[commandline: " + _windir + "\\system32\\cmd.exe") 
                        || commandline.Contains("[commandline: cmd")
                        || commandline.Contains("[commandline: " + _windir + "\\system32\\windowspowershell\\")
                        || commandline.Contains("[commandline: powershell.exe"))
                    {

                        if (parentid != "[parentid path: " + _windir + "\\explorer.exe]")
                        {
                            iList3 = new ListViewItem();
                            iList3.Name = tmp2.SubItems[5].Text;
                            iList3.SubItems.Add(tmp2.SubItems[1].Text);
                            iList3.SubItems.Add(tmp2.SubItems[3].Text + " (with ParentId [" + parentidPath + ":" + parentid.Split(':')[1] + ")");

                            iList3.SubItems.Add("[!] Found Shell");
                            iList3.SubItems.Add("ETW [New] event");
                            iList3.SubItems.Add("Event Detected!");


                            iList3.SubItems.Add("--");
                            iList3.ImageIndex = 2;
                            if (tmp2.Name != eventstring_tmp3)
                            {
                               


                                BeginInvoke(new __core2(SaveETWLogs.AsyncRun___Save_New_DetectionLogs_TCP_Shell_Events_to_WinEventLog), iList3);
                                eventstring_tmp3 = tmp2.Name;
                            }
                        }
                    }
                    else
                    {

                    }


                }
            }
            catch (Exception ee)
            {

                if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [Form1_System_Detection_Log_events2] Event/Method Call: error1 => " + ee.Message);


            }
        }

        public async void _RunRemoveItemsLisview1()
        {
            await Listview1__Removeitems();
        }

        /// <summary>
        /// C# method for remove listview1 items, default is 500
        /// </summary>      
        public async Task Listview1__Removeitems()
        {

            await Task.Run(() =>
            {
                while (true)
                {
                    if (ETWPM2Realt_timeShowMode_Level == 1) break;

                    try
                    {
                        Thread.Sleep(10000);
                        int _counter = 0;

                        if (listView1.Items.Count >= ListiveItemCount)
                        {
                            for (int i = 0; i < listView1.Items.Count - 1; i++)
                            {
                                Thread.Sleep(1000);
                                listView1.Items.RemoveAt(0);
                                _counter++;

                                if (_counter > _percent(40, ListiveItemCount))
                                {
                                    _counter = 0;
                                    break;
                                }
                            }
                        }
                    }
                    catch (Exception)
                    {


                    }
                }
            });
        }
        private async void T4_Elapsed(object sender, System.Timers.ElapsedEventArgs e)
        {
            await Task.Run(() =>
            {
                if (init_removeItems)
                {
                    try
                    {


                        foreach (ListViewItem item in listView4.Items)
                        {
                            if (item.SubItems[2].Text.StartsWith(":"))
                            {
                                item.Remove();
                            }

                            if (!item.SubItems[2].Text.Contains(':') || item.SubItems[3].Text != "Connected")
                            {
                                if (!init_removeItems)
                                    break;

                                if (init_removeItems)
                                    item.Remove();
                            }
                        }
                    }
                    catch (Exception)
                    {


                    }
                }
            });

        }

        /// <summary>
        /// C# event for add all ETW events from windows evet log real_time to listview1
        /// </summary>       
        private void Form1_NewEventFrom_EventLogsCome(object sender, EventArgs e)
        {
            //if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [Form1_NewEventFrom_EventLogsCome] Event/Method Call: Started");
            //if(IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [Form1_NewEventFrom_EventLogsCome] Event/Method Call: error1 => " + ee.Message);


            ListViewItem MyLviewItemsX = (ListViewItem)sender;
            try
            {
                /// Filter added for system:4 injection 
                if (is_system4_excluded)
                {
                    if (MyLviewItemsX.SubItems[3].Text.ToString().ToUpper() != "SYSTEM:4")
                    {
                        if (ETWPM2Realt_timeShowMode_Level == 0)
                        {
                            BeginInvoke(new __Additem(_Additems_toListview1), MyLviewItemsX);
                        }
                        else
                        {
                            BeginInvoke(new __Additem(_Additems_toListview1__2), MyLviewItemsX);

                        }

                    }
                }
                else
                {
                    if (ETWPM2Realt_timeShowMode_Level == 0)
                    {
                        BeginInvoke(new __Additem(_Additems_toListview1), MyLviewItemsX);
                    }
                    else
                    {
                        BeginInvoke(new __Additem(_Additems_toListview1__2), MyLviewItemsX);

                    }

                }
            }
            catch (Exception ee)
            {
                if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [Form1_NewEventFrom_EventLogsCome] Event/Method Call: error1 => " + ee.Message);

            }
        }

        /// <summary>
        /// C# event for add RemoteThreadInjection Detection to the list of process [Process_Table table], [_ETW_Events_Counts table] , Event ID 2
        /// </summary>       
        public void Form1_RemoteThreadInjectionDetection_ProcessLists(object sender, EventArgs e)
        {
            try
            {
                //if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [Form1_RemoteThreadInjectionDetection_ProcessLists] Event/Method Call: Started");
                //if(IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [Form1_RemoteThreadInjectionDetection_ProcessLists] Event/Method Call: error1 => " + ee.Message);

                string EventMessage = sender.ToString().Split('@')[1];
                string PName_PID = sender.ToString().Split('@')[0];

                Injectortmp = "";
                Tempops = "";

                if (EventMessage.Substring(EventMessage.IndexOf(") Injected by") + 13).Split(':')[0].Contains("Process Exited"))
                {
                    Tempops = EventMessage.Substring(EventMessage.IndexOf("[Injected by ") + 12).Split(']')[0];
                    Injectortmp = EventMessage.Substring(EventMessage.IndexOf(") Injected by") + 13).Split('(')[0] + "[" + Tempops + "]";
                }
                else
                {
                    int a = EventMessage.IndexOf(") Injected by ") + 14;
                    Injectortmp = EventMessage.Substring(a).Split('\n')[0];
                }

                /// bug here ;)
                // string InjectorPID = EventMessage.Substring(EventMessage.IndexOf("[Injected by ") - 7).Split(':')[1].Split('[')[0];
                string InjectorPID = EventMessage.Split('\n')[12].Split('>')[1];

                if (!is_system4_excluded)
                {
                    if (!Process_Table.Exists(NewProcess => NewProcess.PID == Convert.ToInt32(PName_PID.Split(':')[1])
                     && NewProcess.ProcessName_Path == EventMessage.Substring(EventMessage.IndexOf("Target_ProcessPath:") + 20).Split('\n')[0]
                     && NewProcess.Injector == Convert.ToInt32(InjectorPID)))
                    {
                        Process_Table.Add(new _TableofProcess
                        {
                            PID = Convert.ToInt32(PName_PID.Split(':')[1]),
                            ProcessName = PName_PID.Split(':')[0],
                            Description = EventMessage,
                            Injector_Path = Injectortmp,
                            Injector = Convert.ToInt32(InjectorPID),
                            ProcessName_Path = EventMessage.Substring(EventMessage.IndexOf("Target_ProcessPath:") + 20).Split('\n')[0],
                            IsLive = true,
                            TCPDetails = "null",
                            IsShow_Alarm = false,
                            TCPDetails2 = "null",
                            Detection_EventTime = Convert.ToDateTime(EventMessage.Split('\n')[17].Split('>')[1]),
                            Detection_Status = "",
                            MemoryScanner01_Result = "",
                            MemoryScanner02_Result = "",
                            InjectionType = "",
                            Descripton_Details = "",
                            SubItems_Name_Property = "",
                            SubItems_ImageIndex = 0

                        });
                    }
                }
                else
                {
                    /// filter for system:4 events & injections
                    if (Convert.ToInt32(InjectorPID) != 4)
                    {
                        if (!Process_Table.Exists(NewProcess => NewProcess.PID == Convert.ToInt32(PName_PID.Split(':')[1])
                       && NewProcess.ProcessName_Path == EventMessage.Substring(EventMessage.IndexOf("Target_ProcessPath:") + 20).Split('\n')[0]
                       && NewProcess.Injector == Convert.ToInt32(InjectorPID)))
                        {
                            Process_Table.Add(new _TableofProcess
                            {
                                PID = Convert.ToInt32(PName_PID.Split(':')[1]),
                                ProcessName = PName_PID.Split(':')[0],
                                Description = EventMessage,
                                Injector_Path = Injectortmp,
                                Injector = Convert.ToInt32(InjectorPID),
                                ProcessName_Path = EventMessage.Substring(EventMessage.IndexOf("Target_ProcessPath:") + 20).Split('\n')[0],
                                IsLive = true,
                                TCPDetails = "null",
                                IsShow_Alarm = false,
                                TCPDetails2 = "null",
                                Detection_EventTime = Convert.ToDateTime(EventMessage.Split('\n')[17].Split('>')[1]),
                                Detection_Status = "",
                                MemoryScanner01_Result = "",
                                MemoryScanner02_Result = "",
                                Descripton_Details = "",
                                SubItems_Name_Property = "",
                                SubItems_ImageIndex = 0,
                                InjectionType = ""
                            });
                        }
                    }
                }

                if (_ETW_Events_Counts.Exists(_xPID => _xPID.PID == Convert.ToInt32(PName_PID.Split(':')[1])))
                {
                    if (Convert.ToInt32(InjectorPID) != 4)
                    {
                        string Procesname_path = EventMessage.Substring(EventMessage.IndexOf("Target_ProcessPath:") + 20).Split('\n')[0];
                        Int32 Pid = Convert.ToInt32(PName_PID.Split(':')[1]);
                        string evt_time = DateTime.Now.ToString();
                        Temp_Table_structure = new _TableofProcess_ETW_Event_Counts();
                        Temp_Table_structure.PID = Pid;
                        Temp_Table_structure.lastEventtime = evt_time;
                        Temp_Table_structure.ProcNameANDPath = Procesname_path;
                        Temp_Table_structure._LastTCP_Details = _ETW_Events_Counts[_ETW_Events_Counts.FindIndex(__PID => __PID.PID == Pid)]._LastTCP_Details;
                        Temp_Table_structure._RemoteThreadInjection_count = _ETW_Events_Counts[_ETW_Events_Counts.FindIndex(__PID => __PID.PID == Pid)]._RemoteThreadInjection_count + 1;
                        Temp_Table_structure._TCPSend_count = _ETW_Events_Counts[_ETW_Events_Counts.FindIndex(__PID => __PID.PID == Pid)]._TCPSend_count;
                        Temp_Table_structure.CommandLine = _ETW_Events_Counts[_ETW_Events_Counts.FindIndex(__PID => __PID.PID == Pid)].CommandLine;

                        _ETW_Events_Counts[_ETW_Events_Counts.FindIndex(__PID => __PID.PID == Pid)] = Temp_Table_structure;
                    }
                }
                else
                {
                    if (Convert.ToInt32(InjectorPID) != 4)
                    {
                        string Procesname_path = EventMessage.Substring(EventMessage.IndexOf("Target_ProcessPath:") + 20).Split('\n')[0];
                        Int32 Pid = Convert.ToInt32(PName_PID.Split(':')[1]);
                        string evt_time = DateTime.Now.ToString();
                        Temp_Table_structure = new _TableofProcess_ETW_Event_Counts();
                        Temp_Table_structure.PID = Pid;
                        Temp_Table_structure.lastEventtime = evt_time;
                        Temp_Table_structure.ProcNameANDPath = Procesname_path;
                        Temp_Table_structure._LastTCP_Details = "";
                        Temp_Table_structure._RemoteThreadInjection_count = 1;
                        Temp_Table_structure._TCPSend_count = 0;
                        Temp_Table_structure.CommandLine = "";
                        _ETW_Events_Counts.Add(Temp_Table_structure);
                    }
                }


            }
            catch (Exception ee)
            {
                if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [Form1_RemoteThreadInjectionDetection_ProcessLists] Event/Method Call: error1 => " + ee.Message);

            }
        }

        /// <summary>
        /// C# event for add New Process events to the list of process [NewProcess_Table table], Event ID 1
        /// </summary>        
        private void Form1_NewProcessAddedtolist_NewProcessEvt(object sender, EventArgs e)
        {

            //if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [Form1_NewProcessAddedtolist_NewProcessEvt] Event/Method Call: Started");
            //if(IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [Form1_NewProcessAddedtolist_NewProcessEvt] Event/Method Call: error1 => " + ee.Message);


            var evt_time = "";

            try
            {
                //[ETW]
                //[MEM]NewProcess Started           
                //PID = 4928  PIDPath = C:\Windows\System32\dllhost.exe
                //ProcessName = dllhost
                //[CommandLine: C:\Windows\system32\DllHost.exe / Processid:{E10F6C3A - F1AE - 4ADC - AA9D - 2FE655E}]
                //[ParentID: 612]
                //[ParentID Path: C:\Windows\System32\svchost.exe]
                //EventTime = 8/11/2021 10:15:32 AM]

                string[] all = sender.ToString().Split('\n');

                NewProcess_Table.Add(new _TableofProcess_NewProcess_evt
                {
                    ProcessName = all[3].Split('=')[1]
                    ,
                    ProcessName_Path = all[2].Split('=')[2]
                    ,
                    PID = Convert.ToInt32(all[2].Split(' ')[2])
                    ,
                    CommandLine = all[4]
                    ,
                    PPID = Convert.ToInt32(all[5].Split(':')[1].Split(']')[0])
                    ,
                    PPID_Path = all[6]
                });


                string Procesname_path = all[2].Split('=')[2];
                Int32 Pid = Convert.ToInt32(all[2].Split(' ')[2]);
                evt_time = all[7].Split('=')[1].ToString();
                Temp_Table_structure = new _TableofProcess_ETW_Event_Counts();
                Temp_Table_structure.PID = Pid;
                Temp_Table_structure.lastEventtime = evt_time;
                Temp_Table_structure.ProcNameANDPath = Procesname_path;
                Temp_Table_structure._LastTCP_Details = "--";
                Temp_Table_structure._RemoteThreadInjection_count = 0;
                Temp_Table_structure._TCPSend_count = 0;
                Temp_Table_structure.CommandLine = all[4];
                _ETW_Events_Counts.Add(Temp_Table_structure);


            }
            catch (Exception ee)
            {
                if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [Form1_NewProcessAddedtolist_NewProcessEvt] Event/Method Call: error1 => " + ee.Message);

            }

        }
        public void Update_Charts_info()
        {
            try
            {
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
                Thread.Sleep(10);
                /// <summary>
                /// v0 => new process
                /// v1 => injection count
                /// v2 => tcp count
                /// v3 => alarms by etw red count
                /// v4 => alarms by etw orange count
                /// v5 => suspended process by memory scanner
                /// v6 => terminated proesses by memory scanner
                /// v7 => All realtime events which made by ETWProcessMon2 in Windows Event logs (but this tool will not show all of them ;D because of filter for same/dublicated events etc...)
                /// </summary>
            }
            catch (Exception)
            {


            }
        }

        /// <summary>
        /// timer to refresh chart tab ETW events info
        /// </summary>        
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
        /// C# event, when new tcp Event ID 3 detected then this event will invoke [NewProcessAddedtolist.Invoke(objX, null)]
        /// for check process via process table [_Table = Process_Table] and memory scanners (if needed), 
        /// that means if this process has tcp connection event which had some related injection event 
        /// then should have true flag for scanning by memory scanners and add to "Alarms by ETW Tab"
        /// so this process had remotethread injectioh event plus tcp connection event so maybe should has true flag for scanning in memory ...
        /// </summary>     
        private void Form1_NewProcessAddedtolist1(object sender, EventArgs e)
        {
            try
            {
                if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [Form1_NewProcessAddedtolist1] Event/Method Call: Started");
                //if(IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [Form1_NewProcessAddedtolist1] Event/Method Call: error1 => " + ee.Message);


                string PName_PID = sender.ToString().Split('@')[0];
                string tcpdetails = sender.ToString().Split('@')[1];

                subitemX = "Injection";
                //bool foundinlist = false;
                //string lastshow = "";
                Int32 PID = Convert.ToInt32(PName_PID.Split(':')[1]);

                string ProcessName = PName_PID.Split(':')[0];
                string _des_address_port = tcpdetails.Substring(tcpdetails.IndexOf("daddr:") + 6).Split(']')[0] + ":" + tcpdetails.Substring(tcpdetails.IndexOf("dport:") + 6).Split(']')[0];

                // "[ETW] \n[TCPIP] TcpIpSend Detected\nTarget_Process: mspaint:3044  TID(-1) TaskName(TcpIp) \nPIDPath = C:\\Windows\\System32\\mspaint.exe\nEventTime = 4/21/2022 3:10:57 PM\n\n[size:0][daddr:192.168.56.101][saddr:192.168.56.1][dport:80][sport:51039][mss:1460][sackopt:1][tsopt:0][wsopt:1][rcvwin:262144][rcvwinscale:8][sndwinscale:7][seqnum:0][connid:68719476736]"
                string Procesname_path = ProcessName;
                string Procesname_path2 = tcpdetails.Split('\n')[3].Substring(10);
                Int32 Pid = PID;
                string evt_time = DateTime.Now.ToString();
                Temp_Table_structure = new _TableofProcess_ETW_Event_Counts();
                if (_ETW_Events_Counts.Exists(_xPID => _xPID.PID == PID))
                {
                    Temp_Table_structure.PID = Pid;
                    Temp_Table_structure.lastEventtime = evt_time;
                    Temp_Table_structure.ProcNameANDPath = Procesname_path;
                    Temp_Table_structure._LastTCP_Details = _des_address_port;
                    Temp_Table_structure._RemoteThreadInjection_count = _ETW_Events_Counts[_ETW_Events_Counts.FindIndex(__PID => __PID.PID == Pid)]._RemoteThreadInjection_count;
                    Temp_Table_structure._TCPSend_count = _ETW_Events_Counts[_ETW_Events_Counts.FindIndex(__PID => __PID.PID == Pid)]._TCPSend_count + 1;
                    Temp_Table_structure.CommandLine = _ETW_Events_Counts[_ETW_Events_Counts.FindIndex(__PID => __PID.PID == Pid)].CommandLine;

                    _ETW_Events_Counts[_ETW_Events_Counts.FindIndex(__PID => __PID.PID == Pid)] = Temp_Table_structure;
                }
                else
                {
                    Temp_Table_structure.PID = Pid;
                    Temp_Table_structure.lastEventtime = evt_time;
                    Temp_Table_structure.ProcNameANDPath = Procesname_path;
                    Temp_Table_structure._LastTCP_Details = _des_address_port;
                    Temp_Table_structure._RemoteThreadInjection_count = 0;
                    Temp_Table_structure._TCPSend_count = 1;
                    Temp_Table_structure.CommandLine = "";

                    _ETW_Events_Counts.Add(Temp_Table_structure);
                }

                if (Process_Table.Find(x => x.PID == PID && x.ProcessName == ProcessName).TCPDetails == "null")
                {

                    List<_TableofProcess> _Table = Process_Table.FindAll(x => x.PID == PID && x.ProcessName == ProcessName);

                    if (Process_Table.Exists(_processname => _processname.PID == PID && _processname.ProcessName == ProcessName))
                    {
                        _TableofProcess TempStruc = new _TableofProcess();
                        TempStruc.TCPDetails2 = _des_address_port;
                        TempStruc.TCPDetails = Process_Table[Process_Table
                            .FindLastIndex(_processname => _processname.PID == PID && _processname.ProcessName == ProcessName)].TCPDetails;
                        TempStruc.ProcessName_Path = Process_Table[Process_Table
                            .FindLastIndex(_processname => _processname.PID == PID && _processname.ProcessName == ProcessName)].ProcessName_Path;
                        TempStruc.ProcessName = Process_Table[Process_Table
                            .FindLastIndex(_processname => _processname.PID == PID && _processname.ProcessName == ProcessName)].ProcessName;
                        TempStruc.PID = Process_Table[Process_Table
                            .FindLastIndex(_processname => _processname.PID == PID && _processname.ProcessName == ProcessName)].PID;
                        TempStruc.IsLive = Process_Table[Process_Table
                            .FindLastIndex(_processname => _processname.PID == PID && _processname.ProcessName == ProcessName)].IsLive;
                        TempStruc.Injector_Path = Process_Table[Process_Table
                          .FindLastIndex(_processname => _processname.PID == PID && _processname.ProcessName == ProcessName)].Injector_Path;
                        TempStruc.Injector = Process_Table[Process_Table
                          .FindLastIndex(_processname => _processname.PID == PID && _processname.ProcessName == ProcessName)].Injector;
                        TempStruc.Description = Process_Table[Process_Table
                        .FindLastIndex(_processname => _processname.PID == PID && _processname.ProcessName == ProcessName)].Description;
                        if (_ExcludeProcessList.FindIndex(index => index.ToLower() == ProcessName.ToLower()) == -1)
                        {
                            TempStruc.IsShow_Alarm = true;
                        }
                        else
                        {
                            TempStruc.IsShow_Alarm = false;
                        }
                        TempStruc.Detection_Status = Process_Table[Process_Table
                        .FindLastIndex(_processname => _processname.PID == PID && _processname.ProcessName == ProcessName)].Detection_Status;
                        TempStruc.Detection_EventTime = Process_Table[Process_Table
                        .FindLastIndex(_processname => _processname.PID == PID && _processname.ProcessName == ProcessName)].Detection_EventTime;
                        TempStruc.InjectionType = Process_Table[Process_Table
                        .FindLastIndex(_processname => _processname.PID == PID && _processname.ProcessName == ProcessName)].InjectionType;
                        TempStruc.MemoryScanner01_Result = Process_Table[Process_Table
                        .FindLastIndex(_processname => _processname.PID == PID && _processname.ProcessName == ProcessName)].MemoryScanner01_Result;
                        TempStruc.MemoryScanner02_Result = Process_Table[Process_Table
                        .FindLastIndex(_processname => _processname.PID == PID && _processname.ProcessName == ProcessName)].MemoryScanner02_Result;
                        TempStruc.Descripton_Details = Process_Table[Process_Table
                       .FindLastIndex(_processname => _processname.PID == PID && _processname.ProcessName == ProcessName)].Descripton_Details;
                        TempStruc.SubItems_Name_Property = Process_Table[Process_Table
                      .FindLastIndex(_processname => _processname.PID == PID && _processname.ProcessName == ProcessName)].SubItems_Name_Property;
                        TempStruc.SubItems_ImageIndex = Process_Table[Process_Table
                     .FindLastIndex(_processname => _processname.PID == PID && _processname.ProcessName == ProcessName)].SubItems_ImageIndex;

                        Process_Table[Process_Table.FindLastIndex(_processname => _processname.PID == PID && _processname.ProcessName == ProcessName)] = TempStruc;
                    }

                    _StopLoopingScan_Exec_01 = false;
                     

                    int _IndexScannedPids = Scanned_PIds.FindIndex(TargetPid => TargetPid.PID == PID
                    && TargetPid.ProcNameANDPath.ToLower() == Procesname_path2.ToLower());

                    bool initScan = false;
                    initScan = _IndexScannedPids != -1 ? initScan = Scanned_PIds[_IndexScannedPids].ScannerResult_IsDetected == false ? true : false : true;

                    /// check processes before scan by memory scanner 
                    /// if process was scanned and Detected before, then ignore new scan.
                    if (initScan && isPEScanonoff)
                    {
                        ThreadStart _CoreScanThread = new ThreadStart(delegate
                        {
                            BeginInvoke(new __AsyncScanner01(Async_Run_Scanner0102_Run), _Table, PID, _des_address_port, ProcessName);                           
                        });

                        Thread _T8__CoreScanThread = new Thread(_CoreScanThread);
                        _T8__CoreScanThread.Priority = ThreadPriority.Highest;
                        _T8__CoreScanThread.Start();

                        
                    }

                }
            }
            catch (Exception ee)
            {
                if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [Form1_NewProcessAddedtolist1] Event/Method Call: error1 => " + ee.Message);


            }
        }
        public async void Async_Run_Scanner0102_Run(List<_TableofProcess> __Table_of_Process_to_Scan, Int32 PID, string _des_address_port, string ProcessName)
        {
           
            await Async_Run_Scanner0102_Method(__Table_of_Process_to_Scan, PID, _des_address_port, ProcessName);
        }
        public async Task Async_Run_Scanner0102_Method(List<_TableofProcess> __Table_of_Process_to_Scan, Int32 PID, string _des_address_port, string ProcessName)
        {
            if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [Async_Run_Scanner0102_Method] Method Call: Started");

            await Task.Run(() =>
            {
                try
                {
                    subitemX = "Injection";
                    bool foundinlist = false;
                    string lastshow = "";
                    string result2 = "";
                    string _injtype = "Injection";
                    string _lastTargetProcessScannedInfo = "";
                    bool _Isdetected = false;
                    _IsMemoryScanner_PeSieve_isBusy = true;

                    foreach (_TableofProcess item in __Table_of_Process_to_Scan.ToList<_TableofProcess>())
                    {
                        if (item.ProcessName + ":" + item.PID + item.ProcessName_Path + item.Injector_Path + item.Injector.ToString() != tmplasttcpevent)
                        {
                            _finalresult_Scanned_02[2] = "--";
                            iList2 = new ListViewItem();

                            /// check target pids to "stop looping scan" , injectorID_PATH may be should add to this ....
                            Int32 IsScannedBefore = Scanned_PIds.ToList().FindIndex(x => x.PID == item.PID && x.ProcNameANDPath.ToLower() == item.ProcessName_Path.ToLower());

                            /// && changed to ||
                            if (!_StopLoopingScan_Exec_01 || IsScannedBefore == -1)
                            {
                                /// pe-sieve64.exe scanner

                                try
                                {
                                    /// pe-sieve64.exe scanner

                                    string _InjectorPathPID = "";

                                    if (item.Injector_Path.Contains(" Process Exited [ "))
                                    {
                                        _InjectorPathPID = item.Injector_Path.Split('[')[1].Split(']')[0].Substring(1);
                                    }
                                    else
                                    {
                                        _InjectorPathPID = item.Injector_Path + ":" + item.Injector.ToString();
                                    }

                                    Init_to_runPEScanner_01 = false;

                                    strOutput = "";

                                    if (isPEScanonoff)
                                    {
                                        outputs = new System.Diagnostics.Process();

                                        int _resultPEScanned01 = Scanned_PIds.ToList().FindIndex(PEScan => PEScan.PID == Convert.ToInt32(item.PID.ToString()) && PEScan.ProcNameANDPath == item.ProcessName_Path
                                       && PEScan.injectorPathPID == _InjectorPathPID);


                                        if (_resultPEScanned01 == -1)
                                        {
                                            Init_to_runPEScanner_01 = true;
                                        }

                                        Thread.Sleep(100);

                                        string result1 = "";

                                        if (Init_to_runPEScanner_01 || -1 == Scanned_PIds.ToList().FindIndex(PEScan => PEScan.PID == Convert.ToInt32(item.PID.ToString()) && PEScan.ProcNameANDPath == item.ProcessName_Path
                                       && PEScan.injectorPathPID == _InjectorPathPID))
                                        {
                                            result2 = "";
                                            if (File.Exists("pe-sieve64.exe"))
                                            {
                                                if (toolStripStatusLabel3.Text != "| pe-sieve is on")
                                                {
                                                    toolStripStatusLabel3.Text = "| pe-sieve is on";
                                                    toolStripStatusLabel3.ForeColor = Color.GhostWhite;
                                                }

                                                try
                                                {


                                                    if (!Process.GetProcessById(Convert.ToInt32(item.PID.ToString())).HasExited)
                                                    {

                                                        try
                                                        {


                                                            /// Check Live Processes, if MemoryScanners Was not Running for this Pid (real-time) 
                                                            /// [stop looping to async scan same PID at the same time]
                                                            if ((!_ExcludeProcessList.ToList().Exists(index => index.Contains(Process.GetProcessById(item.PID).ProcessName.ToLower())))
                                                            && (!_lastTargetProcessScannedInfo.ToLower().Contains("/shellc /iat 2 /pid " + item.PID.ToString())))
                                                            {
                                                                outputs.StartInfo.FileName = "pe-sieve64.exe";
                                                                outputs.StartInfo.Arguments = "/shellc /iat 2 /pid " + item.PID.ToString();
                                                                BeginInvoke(new __AddTextTorichtexhbox1(Update_listbox1_scanner_logs), "[pe-sieve64.exe], Start Scanning => PID:" + item.PID.ToString());

                                                                if (pe_sieve_DumpSwitches == 0) { outputs.StartInfo.Arguments = "/shellc /iat 2 /pid " + item.PID.ToString(); }
                                                                else if (pe_sieve_DumpSwitches == 1) { outputs.StartInfo.Arguments = "/ofilter 1 /shellc /iat 2 /pid " + item.PID.ToString(); }
                                                                else if (pe_sieve_DumpSwitches == 2) { outputs.StartInfo.Arguments = "/ofilter 2 /shellc /iat 2 /pid " + item.PID.ToString(); }

                                                                _lastTargetProcessScannedInfo = outputs.StartInfo.Arguments;

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

                                                                result2 = "";

                                                                foreach (char xxitem in result1)
                                                                {
                                                                    if (xxitem != ' ')
                                                                        result2 += xxitem;
                                                                }

                                                                BeginInvoke(new __AddTextTorichtexhbox1(Update_listbox1_scanner_logs), "[pe-sieve64.exe], Scanner output [ProcessId " + item.PID.ToString() + "]=> " + result2.Split('\r')[0] + result2.Split('\r')[1] + result2.Split('\r')[2]);

                                                                finalresult_Scanned_01[0] = result2;
                                                                finalresult_Scanned_01[1] = strOutput;
                                                            }
                                                            else
                                                            {
                                                                finalresult_Scanned_01[0] = "[Skipped[not scanned:0:0:0]";
                                                                finalresult_Scanned_01[1] = "[Skipped[not scanned:0:0:0]";
                                                            }
                                                        }
                                                        catch (Exception)
                                                        {


                                                        }

                                                    }
                                                    else
                                                    {
                                                        finalresult_Scanned_01[0] = "[error not found Target Process[not scanned:0]";
                                                        finalresult_Scanned_01[1] = "[error not found Target Process[not scanned:0]";
                                                    }

                                                }
                                                catch (Exception ee)
                                                {
                                                    if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [Async_Run_Scanner0102_Method] Method Call: error1 => " + ee.Message);


                                                }
                                            }
                                            else
                                            {
                                                finalresult_Scanned_01[0] = "[error not found pe-sieve.exe[not scanned:0]";
                                                finalresult_Scanned_01[1] = "[not scanned:0]";
                                                toolStripStatusLabel3.Text = "| error not found pe-sieve64.exe";
                                                toolStripStatusLabel3.ForeColor = Color.Red;
                                            }

                                          

                                            if (Convert.ToInt32(string.Join("", ("0" + result2).Where(char.IsDigit)).ToString()) > 0) { _Isdetected = true; }
                                            else { _Isdetected = false; }

                                            string Scanner_Action = "Scanned & Found!";

                                            if (Pe_sieveLevel == 0)
                                            {
                                                if (_Isdetected)
                                                {
                                                    Scanner_Action = "Scanned & Found!";
                                                    iList2.ImageIndex = 2;
                                                }
                                                else
                                                {
                                                    /// fixed,  bad bug was here ;)
                                                    Scanner_Action = "Scanned & Not Found!";
                                                    iList2.ImageIndex = 1;
                                                }

                                            }

                                            if (Pe_sieveLevel == 1)
                                            {
                                                if (_Isdetected)
                                                {
                                                    Scanner_Action = "Suspended";
                                                    iList2.ImageIndex = 2;
                                                }
                                                else
                                                {
                                                    /// fixed
                                                    Scanner_Action = "Scanned & Not Found!";
                                                    iList2.ImageIndex = 1;
                                                }
                                            }

                                            if (Pe_sieveLevel == 2)
                                            {
                                                if (_Isdetected)
                                                {
                                                    Scanner_Action = "Terminated";
                                                    iList2.ImageIndex = 2;
                                                }
                                                else
                                                {
                                                    /// fixed
                                                    Scanner_Action = "Scanned & Not Found!";
                                                    iList2.ImageIndex = 1;
                                                }
                                            }

                                            if (finalresult_Scanned_01[0].ToLower().Contains("skipped"))
                                            {
                                                Scanner_Action = "Skipped";
                                                iList2.ImageIndex = 1;
                                            }

                                            if (!Scanned_PIds.ToList<_TableofProcess_Scanned_01>().Exists(scanned => scanned.PID == Convert.ToInt32(item.PID.ToString()) 
                                            && scanned.ProcNameANDPath == item.ProcessName_Path
                                             && scanned.injectorPathPID == _InjectorPathPID))
                                            {
                                               

                                                try
                                                {
                                                    /// bug fixed
                                                    string replacestr = _finalresult_Scanned_01[0].Substring(Memory_info._FindAllIndex("replaced:", _finalresult_Scanned_01[0], 0)[0])
                                                    .Split(']')[0];

                                                    int count = Convert.ToInt32(replacestr.Split(':')[1]);
                                                    if (count > 0)
                                                    {
                                                        /// injection type
                                                         subitemX = "Process-Hollowing";
                                                        _injtype = "Process-Hollowing";
                                                    }
                                                    else
                                                    {
                                                        /// injection type
                                                         subitemX = "Injection";
                                                        _injtype = "Injection";
                                                    }

                                                }
                                                catch (Exception)
                                                {


                                                }

                                                Scanned_PIds.Add(new _TableofProcess_Scanned_01
                                                {
                                                    time_Hour = DateTime.Now.Hour,
                                                    time_min = DateTime.Now.Minute,
                                                    PID = Convert.ToInt32(item.PID.ToString()),
                                                    ProcNameANDPath = item.ProcessName_Path,
                                                    injectorPathPID = _InjectorPathPID,
                                                    Scanner01_RESULT_Int32_outputstr = result2,
                                                    ScannerResult_IsDetected = _Isdetected,
                                                    InjectionType = subitemX,
                                                    Action = Scanner_Action

                                                });
                                            }
                                            _finalresult_Scanned_01 = finalresult_Scanned_01;
                                        }
                                        else
                                        {

                                            /// bug here
                                            finalresult_Scanned_01[0] = "[not scanned:0:0:0]";
                                            finalresult_Scanned_01[1] = "[not scanned:0:0:0]";
                                            _finalresult_Scanned_01 = finalresult_Scanned_01;

                                        }
                                    }
                                    else
                                    {
                                        finalresult_Scanned_01[0] = "PEScanner-is-off";
                                        finalresult_Scanned_01[1] = strOutput;
                                        _finalresult_Scanned_01 = finalresult_Scanned_01;
                                    }
                                }
                                catch (Exception ee)
                                {
                                    if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [Async_Run_Scanner0102_Method] Method Call: error2 => " + ee.Message);

                                    _finalresult_Scanned_01 = finalresult_Scanned_01;

                                }

                            }

                            Thread.Sleep(100);

                           

                            iList2.Name = item.ProcessName + ":" + item.PID + ">\n" + _finalresult_Scanned_01[1] + _finalresult_Scanned_02[1]
                               + "\n-------------------\nScanner Result/Status: " + _finalresult_Scanned_01[0];

                            iList2.SubItems.Add(DateTime.Now.ToString());
                            iList2.SubItems.Add(item.ProcessName + ":" + item.PID.ToString());
                            int ResultNumbers_of__finalresult_Scanned_01 = 0;

                            if (isPEScanonoff != false)
                            {

                                try
                                {

                                    ResultNumbers_of__finalresult_Scanned_01 = Convert.ToInt32(
                                        string.Join("", ("0" + _finalresult_Scanned_01[0]).ToCharArray().Where(char.IsDigit)).ToString());

                                    if (ResultNumbers_of__finalresult_Scanned_01 > 0)
                                    {
                                        /// break loops for scanning target process again (if detected in first scan)
                                        _StopLoopingScan_Exec_01 = true;

                                    }

                                }
                                catch (Exception ee)
                                {
                                    if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [Async_Run_Scanner0102_Method] Method Call: error9 => " + ee.Message);
                                }


                            }


                            if (Convert.ToInt32(string.Join("", ("0" + _finalresult_Scanned_01[0]).ToCharArray().Where(char.IsDigit))) == 0)
                            {
                                subitemX = "Injection";
                                iList2.ImageIndex = 1;
                            }
                            else
                            if (Convert.ToInt32(string.Join("", ("0" + _finalresult_Scanned_01[0]).ToCharArray().Where(char.IsDigit))) > 0)
                            {
                                iList2.ImageIndex = 2;

                                try
                                {
                                    string replacestr = _finalresult_Scanned_01[0].Substring(Memory_info._FindAllIndex("replaced:", _finalresult_Scanned_01[0], 0)[0])
                                    .Split(']')[0];

                                    int count = Convert.ToInt32(replacestr.Split(':')[1]);
                                    if (count > 0)
                                    {
                                        subitemX = "Process-Hollowing";
                                        _injtype = "Process-Hollowing";

                                    }
                                    else
                                    {
                                        /// injection type
                                        subitemX = "Injection";
                                        _injtype = "Injection";
                                    }

                                }
                                catch (Exception)
                                {


                                }
                            }

                            IsTargetProcessTerminatedbyETWPM2monitor = false;
                            string Detection_Status_Action = "";
                            //iList2.ImageIndex = 1;

                            if (Convert.ToInt32(string.Join("", ("0" + _finalresult_Scanned_01[0]).ToCharArray().Where(char.IsDigit))) > 0)
                            {

                                iList2.ImageIndex = 2;

                                if (Pe_sieveLevel == 0)
                                {
                                    if (_Isdetected)
                                    {
                                        iList2.ImageIndex = 2;
                                        Detection_Status_Action = "Scanned & Found!";
                                    }
                                    else
                                    {
                                        /// fixed
                                        iList2.ImageIndex = 1;
                                        Detection_Status_Action = "Scanned & Not Found!";
                                    }
                                }
                                else
                                if (Pe_sieveLevel == 1)
                                {
                                    try
                                    {
                                        if (_Isdetected)
                                        {
                                            iList2.ImageIndex = 2;
                                            Detection_Status_Action = "Suspended";
                                            int _tpid = PID;
                                            Memory_info.NtSuspendProcess(Process.GetProcessById(_tpid).Handle);
                                        }
                                        else
                                        {
                                            /// fixed
                                            iList2.ImageIndex = 1;
                                            Detection_Status_Action = "Scanned & Not Found!";
                                        }
                                    }
                                    catch (Exception)
                                    {


                                    }
                                }
                                else
                                if (Pe_sieveLevel == 2)
                                {
                                    if (_Isdetected)
                                    {
                                        iList2.ImageIndex = 2;
                                        try
                                        {
                                            try
                                            {
                                                try
                                                {
                                                    _PPID_For_TimerScanner01 = PID;
                                                    _PPIDPath_For_TimerScanner01 = Process.GetProcessById(PID).MainModule.FileName.ToLower();
                                                }
                                                catch (Exception ee)
                                                {
                                                    if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [Async_Run_Scanner0102_Method] Method Call: error10 => " + ee.Message);

                                                }

                                                /// timer to terminate sub processes     
                                                t8.Enabled = true;
                                                t8.Start();

                                                /// check sub processes                                              
                                                foreach (_TableofProcess_NewProcess_evt ___item in NewProcess_Table.ToList().FindAll(SubProc =>
                                                SubProc.PPID == PID).ToList<_TableofProcess_NewProcess_evt>())
                                                {
                                                    ///"[ParentID Path: C:\\Windows\\SysWOW64\\notepad.exe]"

                                                    if (___item.PPID_Path.ToLower().Substring(16).Split(']')[0] ==
                                                        Process.GetProcessById(PID).MainModule.FileName.ToLower())
                                                    {
                                                        if (Process.GetProcesses().ToList().FindIndex(x => x.Id == ___item.PID) != -1)
                                                        {
                                                            try
                                                            {
                                                                IntPtr TintPtr = Process.GetProcessById(___item.PID).Handle;
                                                                uint ExitCode = 0;

                                                                Memory_info.GetExitCodeProcess(TintPtr, out ExitCode);

                                                                Memory_info.TerminateProcess(TintPtr, ExitCode);
                                                            }
                                                            catch (Exception j)
                                                            {


                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            catch (Exception ee)
                                            {
                                                if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [Async_Run_Scanner0102_Method] Method Call: error11 => " + ee.Message);
                                            }


                                            try
                                            {
                                                /// check sockets for shutdown
                                                List<IntPtr> TP_Socket_intptrs = SocketClass.SocketHijacking.GetSocketsTargetProcess
                                                    (Process.GetProcessById(PID));

                                                foreach (IntPtr _____item in TP_Socket_intptrs.ToList())
                                                {
                                                    SocketClass.SocketHijacking.shutdown(_____item, 2);
                                                }

                                                /// check target process                                          
                                                try
                                                {
                                                    if (Process.GetProcesses().ToList().FindIndex(x => x.Id == PID) != -1)
                                                    {
                                                        try
                                                        {
                                                            IntPtr TintPtr = Process.GetProcessById(PID).Handle;
                                                            uint ExitCode = 0;

                                                            Memory_info.GetExitCodeProcess(TintPtr, out ExitCode);

                                                            Memory_info.TerminateProcess(TintPtr, ExitCode);
                                                        }
                                                        catch (Exception j)
                                                        {


                                                        }

                                                    }

                                                    int obj_index = Process_Table.FindIndex(process => process.ProcessName.ToLower() + ":" + process.PID == item.ProcessName.ToLower() + ":" + item.PID);


                                                    _TableofProcess TempStruc = new _TableofProcess();
                                                    TempStruc.TCPDetails2 = Process_Table[obj_index].TCPDetails2;
                                                    TempStruc.TCPDetails = Process_Table[obj_index].TCPDetails;
                                                    TempStruc.ProcessName_Path = Process_Table[obj_index].ProcessName_Path;
                                                    TempStruc.ProcessName = Process_Table[obj_index].ProcessName;
                                                    TempStruc.PID = Process_Table[obj_index].PID;
                                                    TempStruc.IsLive = Process_Table[obj_index].IsLive;
                                                    TempStruc.Injector_Path = Process_Table[obj_index].Injector_Path;
                                                    TempStruc.Injector = Process_Table[obj_index].Injector;
                                                    TempStruc.Description = Process_Table[obj_index].Description;
                                                    TempStruc.IsShow_Alarm = true;
                                                    TempStruc.Detection_Status = "Terminated";
                                                    TempStruc.Detection_EventTime = Process_Table[obj_index].Detection_EventTime;
                                                    TempStruc.InjectionType = _injtype;
                                                    TempStruc.MemoryScanner01_Result = result2;
                                                    TempStruc.MemoryScanner02_Result = "Disabled";

                                                    int _indexNewProcess = NewProcess_Table.FindIndex(x => x.PID == item.Injector || x.ProcessName_Path == item.Injector_Path);

                                                    if (_indexNewProcess != -1)
                                                    {
                                                        _TableofProcess_NewProcess_evt xFindingInjectorInfo = NewProcess_Table.Find(x => x.PID == item.Injector || x.ProcessName_Path == item.Injector_Path);

                                                        TempStruc.Descripton_Details = item.ProcessName_Path + " Injected by => " + item.Injector_Path + " (PID:" + item.Injector.ToString()
                                                        + ") \nInjector Details:\nInjector-ProcessName: "
                                                        + xFindingInjectorInfo.ProcessName + "\nInjector-Path: " + xFindingInjectorInfo.ProcessName_Path
                                                        + "\nInjector-CommandLine: " + xFindingInjectorInfo.CommandLine;
                                                    }
                                                    else
                                                    {

                                                        TempStruc.Descripton_Details = item.ProcessName_Path + " Injected by => " + item.Injector_Path + " (PID:" + item.Injector.ToString()
                                                        + ") \nInjector Details:\nInjector-ProcessName: "
                                                        + "\nInjector-Path: "
                                                        + "\nInjector-CommandLine: ";
                                                    }

                                                    TempStruc.SubItems_Name_Property = item.ProcessName + ":" + item.PID + ">\n" + _finalresult_Scanned_01[1];
                                                    TempStruc.SubItems_ImageIndex = 2;

                                                    Process_Table[obj_index] = TempStruc;

                                                }
                                                catch (Exception ee)
                                                {
                                                    if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [Async_Run_Scanner0102_Method] Method Call: error12 => " + ee.Message);
                                                }

                                            }
                                            catch (Exception err)
                                            {


                                            }

                                        }
                                        catch (Exception ee)
                                        {
                                            if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [Async_Run_Scanner0102_Method] Method Call: error13 => " + ee.Message);


                                        }

                                        iList2.ImageIndex = 2;
                                        Detection_Status_Action = "Terminated";
                                        IsTargetProcessTerminatedbyETWPM2monitor = true;
                                    }
                                    else
                                    {
                                        /// fixed
                                        iList2.ImageIndex = 1;
                                        Detection_Status_Action = "Scanned & Not Found!";
                                    }

                                }

                            }


                            
                            /// injection type
                            iList2.SubItems.Add(subitemX);
                            /// tcp send info
                            iList2.SubItems.Add(_des_address_port);

                            /// status for suspend/terminate by hollowshunter
                            //iList2.SubItems.Add(_finalresult_Scanned_02[2]);

                            iList2.SubItems.Add(Detection_Status_Action);
                            /// detection info by pe-sieve64
                            iList2.SubItems.Add(_finalresult_Scanned_01[0]);
                            /// detection info by hollowshunter
                            iList2.SubItems.Add("Disabled");

                            /// injection description && / || [bug]
                            _TableofProcess_NewProcess_evt FindingInjectorInfo = NewProcess_Table.Find(x => x.PID == item.Injector || x.ProcessName_Path == item.Injector_Path);

                            iList2.SubItems.Add(item.ProcessName_Path + " Injected by => " + item.Injector_Path + " (PID:" + item.Injector.ToString() + ") \nInjector Details:\nInjector-ProcessName: "
                                + FindingInjectorInfo.ProcessName + "\nInjector-Path: " + FindingInjectorInfo.ProcessName_Path +
                                "\nInjector-CommandLine: " + FindingInjectorInfo.CommandLine);

                            /// ETW Event message for injection which is decription value 
                            _TableofProcess RelatedEvt_Description = Process_Table.Find(x => x.PID == PID && x.ProcessName == ProcessName
                            && x.Description.Contains(":" + item.Injector.ToString() + "[Injected by "));
                            iList2.SubItems.Add(RelatedEvt_Description.Description);


                            foreach (string ShowItems in showitemsHash)
                            {

                                if (ShowItems == item.ProcessName + ":" + item.PID.ToString() + _des_address_port + _finalresult_Scanned_01[0] +
                               item.ProcessName_Path + " Injected by => " + item.Injector_Path + " (PID:" + item.Injector.ToString() + ") " + HollowHunterLevel.ToString())
                                {
                                    if (_finalresult_Scanned_01[0] != "[not scanned:0]")
                                    {
                                        foundinlist = true;
                                        break;
                                    }
                                }
                            }

                            if (!foundinlist)
                            {
                                if (Init_to_runPEScanner_01)
                                {
                                    BeginInvoke(new __Additem(_Additems_toListview2), iList2);

                                    /// this code & method/event removed from source code
                                    //System_Detection_Log_events.Invoke((object)iList2, null);

                                }

                                bool found_obj = false;

                                foreach (string Objitem in showitemsHash)
                                {
                                    if (Objitem == item.ProcessName + ":" + item.PID.ToString() + _des_address_port + _finalresult_Scanned_01[0] +
                                       item.ProcessName_Path + " Injected by => " + item.Injector_Path + " (PID:" + item.Injector.ToString() + ") "
                                       + HollowHunterLevel.ToString())
                                    {
                                        found_obj = true;
                                    }
                                }
                                if (!found_obj)
                                {
                                    showitemsHash.Add(item.ProcessName + ":" + item.PID.ToString() + _des_address_port + _finalresult_Scanned_01[0] +
                                   item.ProcessName_Path + " Injected by => " + item.Injector_Path + " (PID:" + item.Injector.ToString() + ") " + HollowHunterLevel.ToString());
                                }

                                Thread.Sleep(10);
                            }

                            tmplasttcpevent = item.ProcessName + ":" + item.PID + item.ProcessName_Path + item.Injector_Path + item.Injector.ToString();

                            lastshow = item.ProcessName + ":" + item.PID.ToString() + _des_address_port + _finalresult_Scanned_01[0] +
                                item.ProcessName_Path + " Injected by => " + item.Injector_Path + " (PID:" + item.Injector.ToString() + ") ";


                        }
                    }
                }
                catch (Exception)
                {
                    _IsMemoryScanner_PeSieve_isBusy = false;

                }
                _IsMemoryScanner_PeSieve_isBusy = false;
            });

        }
        public void Update_listbox1_scanner_logs(object str)
        {
            try
            {


                if (str.ToString().Contains("Suspended") || str.ToString().Contains("Terminated"))
                {
                    listBox1.Items.Add("[#] " + DateTime.Now.ToString() + " " + str.ToString());

                }
                else
                {
                    listBox1.Items.Add("[!!] " + DateTime.Now.ToString() + " " + str.ToString());
                }

                listBox1.SelectedIndex = listBox1.Items.Count - 1;
            }
            catch (Exception)
            {


            }

        }
        public async Task UpdateRefreshListview1()
        {
            await Task.Run(() =>
            {
                if (ETWPM2Realt_timeShowMode_Level == 0)
                {
                    t.Interval = 10000;
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
                else if (ETWPM2Realt_timeShowMode_Level == 1)
                {

                    listView1.BeginInvoke((MethodInvoker)delegate
                    {

                        t.Interval = 6000;
                        foreach (ListViewItem item in listView1.Items)
                        {
                            try
                            {


                                if (item.ForeColor != Color.Black)
                                {
                                    if (item.ForeColor == Color.OrangeRed)
                                        item.ForeColor = Color.Black;
                                }
                                else if (item.ForeColor == Color.Black)
                                {
                                    tt = DateTime.Now - Convert.ToDateTime(item.SubItems[1].Text);

                                    if (tt.TotalSeconds <= 120)
                                    {
                                        item.ForeColor = Color.Black;
                                    }
                                    else
                                    {
                                        item.ForeColor = Color.LightSlateGray;
                                    }

                                }
                            }
                            catch (Exception)
                            {


                            }
                        }
                        listView1.Refresh();
                    });

                }
            });
        }
        private void T_Elapsed(object sender, System.Timers.ElapsedEventArgs e)
        {

            BeginInvoke(new __Updatelistview1(Run_Async_UpdateRefreshListview1));

        }
        public async void Run_Async_UpdateRefreshListview1()
        {
            await UpdateRefreshListview1();
        }
        public static void _Updater__List_All_Injection_Details_info_Filter_withoutSystem4(object obj)
        {
            try
            {

                temp_str = obj.ToString().Split('\n');

                ///[ETW]
                ///[MEM] Injected ThreadStart Detected,
                ///Target_Process: msedge:10932   TID(11688) Injected by C:\Program Files(x86)\Microsoft\Edge\Application\msedge.exe
                ///Target_ProcessPath: C:\Program Files(x86)\Microsoft\Edge\Application\msedge.exe

                ///Debug info: [2/5/2022 8:25:26 PM] PID: (10932)(msedge) 11688::0x7ff6a1c20220:12676:1256[Injected by msedge]
                ///---------------------------------------------
                ///Debug Integers : TargetProcessPID,InjectedTID:StartAddress:ParentThreadID:InjectorPID
                ///TPID > 10932
                ///InjectedTID > 11688
                ///StartAddress > 0x7ff6a1c20220
                ///PTID > 12676
                ///InjectorPID > 1256
                ///---------------------------------------------
                ///Debug Process_Names : TargetProcessName,InjectorProcessName
                ///TargetProcessName > msedge
                ///InjectorProcessName > C:\Program Files(x86)\Microsoft\Edge\Application\msedge.exe
                ///EventTime > 2/5/2022 8:25:26 PM 

                if (Convert.ToInt32(temp_str[12].Split('>')[1]) != 4)
                {
                    _List_All_Injection_Details_info_Filter_withoutSystem4.Add(new _All_Injection_Details_info_Filter_withoutSystem4
                    {
                        _time_evt = temp_str[17].Split('>')[1],
                        _InjectorPID = Convert.ToInt32(temp_str[12].Split('>')[1]),
                        _InjectorPID_Path = temp_str[16].Split('>')[1],
                        _RemoteThreadID = Convert.ToInt32(temp_str[9].Split('>')[1]),
                        _ThreadStartAddress = temp_str[10].Split('>')[1],
                        _TargetPID = Convert.ToInt32(temp_str[8].Split('>')[1]),
                        _TargetPID_Path = temp_str[15].Split('>')[1],
                        _flag_to_Dont_Remove_FromList = false
                    });
                }
            }
            catch (Exception)
            {


            }

        }

        /// <summary>
        /// realtime monitoring events IDs 1,2,3 from windows event log "ETWPM2"  
        /// </summary>         
        public void Watcher_EventRecordWritten(object sender, EventRecordWrittenEventArgs e)
        {


            try
            {

                if (e.EventRecord.FormatDescription() != tempMessage2)
                {

                    if (e.EventRecord.Id == 2)
                    {
                        BeginInvoke(new __core2(_Updater__List_All_Injection_Details_info_Filter_withoutSystem4), e.EventRecord.FormatDescription().ToString());
                    }

                }

            }
            catch (Exception)
            {

            }

            try
            {
                tempMessage2 = e.EventRecord.FormatDescription();

                if (e.EventRecord.Id == 1)
                {
                    if (e.EventRecord.FormatDescription() != string.Empty)
                    {
                        iList = new ListViewItem();

                        iList.Name = e.EventRecord.RecordId.ToString();
                        iList.SubItems.Add(e.EventRecord.TimeCreated.ToString());
                        iList.SubItems.Add(e.EventRecord.Id.ToString());
                        _ProcessName = e.EventRecord.FormatDescription().Substring(e.EventRecord.FormatDescription().IndexOf("ProcessName = ") + 14).Split('[')[0];
                        _ProcessName = _ProcessName.Substring(0, _ProcessName.Length - 1);
                        iList.SubItems.Add(_ProcessName + ":" + e.EventRecord.FormatDescription().Split('\n')[2].Substring(6).Split(' ')[0]);

                        iList.SubItems.Add("[NEW]");
                        iList.SubItems.Add(e.EventRecord.FormatDescription());
                        iList.ImageIndex = 0;
                        LviewItemsX = iList;

                        Thread.Sleep(10);

                        NewProcessAddedtolist_NewProcessEvt.Invoke((object)e.EventRecord.FormatDescription(), null);
                        Chart_NewProcess++;

                        Thread.Sleep(10);

                        NewEventFrom_EventLogsCome.Invoke((object)LviewItemsX, null);
                    }
                }
                if (e.EventRecord.Id == 2)
                {
                    if (e.EventRecord.FormatDescription() != string.Empty)
                    {

                        iList = new ListViewItem();
                        iList.Name = e.EventRecord.RecordId.ToString();
                        iList.SubItems.Add(e.EventRecord.TimeCreated.ToString());
                        iList.SubItems.Add(e.EventRecord.Id.ToString());
                        iList.SubItems.Add(e.EventRecord.FormatDescription()
                            .Substring(e.EventRecord.FormatDescription().IndexOf(":")).Split(' ')[1]);
                        iList.SubItems.Add("[INJ]");
                        iList.SubItems.Add(e.EventRecord.FormatDescription());
                        iList.ImageIndex = 1;

                        LviewItemsX = iList;
                        Thread.Sleep(25);
                        chart_Inj++;

                        RemoteThreadInjectionDetection_ProcessLists.Invoke((object)(e.EventRecord.FormatDescription()
                            .Substring(e.EventRecord.FormatDescription().IndexOf(":")).Split(' ')[1].Replace('\n', ' ')
                        + "@" + e.EventRecord.FormatDescription()), null);

                        Thread.Sleep(10);

                        NewEventFrom_EventLogsCome.Invoke((object)LviewItemsX, null);

                    }
                }
                if ((e.EventRecord.Id == 3) && (e.EventRecord.FormatDescription() != tempMessage))
                {
                    if (e.EventRecord.FormatDescription() != string.Empty)
                    {
                        iList = new ListViewItem();
                        tempMessage = e.EventRecord.FormatDescription();
                        iList.Name = e.EventRecord.RecordId.ToString();
                        iList.SubItems.Add(e.EventRecord.TimeCreated.ToString());
                        iList.SubItems.Add(e.EventRecord.Id.ToString());
                        iList.SubItems.Add(e.EventRecord.FormatDescription().Substring(e.EventRecord.FormatDescription().IndexOf(":")).Split(' ')[1]);
                        iList.SubItems.Add("[TCP]");

                        iList.SubItems.Add(e.EventRecord.FormatDescription());
                        iList.ImageIndex = 0;

                        LviewItemsX = iList;

                        obj[0] = null;
                        obj[1] = null;

                        Thread.Sleep(15);

                        Chart_Tcp++;

                        obj[0] = e.EventRecord.FormatDescription().Substring(e.EventRecord.FormatDescription().IndexOf(":")).Split(' ')[1];
                        obj[1] = e.EventRecord.FormatDescription();
                        objX = obj[0] + "@" + obj[1];


                        NewProcessAddedtolist.Invoke(objX, null);

                        Thread.Sleep(10);

                        NewEventFrom_EventLogsCome.Invoke((object)LviewItemsX, null);

                        /// add to Network Connection Tab
                        if (!IsDontShow_NetworkConnection_Enabled)
                            NewTCP_Connection_Detected.Invoke((object)LviewItemsX, null);



                    }
                }

                Chart_Counts++;

            }
            catch (Exception _e)
            {

            }



        }
        private void Form1_FormClosed(object sender, FormClosedEventArgs e)
        {
            if (!IsSearchFormActived)
            {
                try
                {

                
                EvtWatcher.Enabled = false;
                EvtWatcher.Dispose();

                /// exit Core Thread for Monitoring TCP/UDP Connections
                Network_Info_DataTables.StopThread = true;
                Network_Info.Core.Abort();
                }
                catch (Exception)
                {                 
                }
            }
        }
        private void StartMonitorToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [StartMonitorToolStripMenuItem_Click] Method Call: Started");
            //if(IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [StartMonitorToolStripMenuItem_Click] Method Call: error1 => " + ee.Message);

            if (!EvtWatcher.Enabled)
            {
                EvtWatcher.Enabled = true;
                toolStripStatusLabel1.Text = "Monitor Status: on";
                i6 = 0;
                try
                {
                    if (Network_Info.Core.IsAlive || Network_Info.Core.IsBackground)
                        Network_Info.Core.Resume();
                }
                catch (Exception)
                {

                    //throw;
                }
            }
         
        }
        private void StoptMonitorToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [StoptMonitorToolStripMenuItem_Click] Method Call: Started");
            //if(IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [StoptMonitorToolStripMenuItem_Click] Method Call: error1 => " + ee.Message);
            if (Network_Info.Core.IsAlive)
                Network_Info.Core.Suspend();

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
                if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [SaveTheTextFile] Method Call: Started");
                //if(IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [SaveTheTextFile] Method Call: error1 => " + ee.Message);

                string fn = "ETWPM2_RealtimeEvents_" + DateTime.Now.Hour.ToString() + "-" + DateTime.Now.Minute.ToString() + "-" + DateTime.Now.Second.ToString() + ".txt";
                Task.Factory.StartNew(() =>
                {

                    using (StreamWriter _file = new StreamWriter(fn, false))
                    {
                        _file.WriteLine(richTextBox1.Text);
                    };
                });
                MessageBox.Show("Texts saved into file: " + fn);
            }
            catch (Exception ee)
            {
                if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [SaveTheTextFile] Method Call: error1 => " + ee.Message);

                MessageBox.Show("Error: " + ee.Message);

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
            StartQueries_Mon("*");
            toolStripStatusLabel2.ForeColor = Color.Red;

            eventID12ToolStripMenuItem.Checked = false;
            eventID13ToolStripMenuItem.Checked = false;
            eventID1ToolStripMenuItem.Checked = false;
            eventID23InjectionTCPIPToolStripMenuItem.Checked = false;
            eventID2ToolStripMenuItem.Checked = false;
            eventID3ToolStripMenuItem.Checked = false;
            //allEventsIDs123ToolStripMenuItem.Checked = true;

            toolStripStatusLabel2.Text = "| Filters: Select All EventIDs 1,2,3 [NewProcess , RemoteThreadInjection Detection , TCPIP Send]";

        }
        public void EventID12ToolStripMenuItem_Click(object sender, EventArgs e)
        {
            string _Query = "<QueryList><Query Id=\"0\" Path=\"ETWPM2\"><Select Path=\"ETWPM2\">*[System[(EventID=1 or EventID=2)]]</Select></Query></QueryList>";

            eventID12ToolStripMenuItem.Checked = true;
            eventID13ToolStripMenuItem.Checked = false;
            eventID1ToolStripMenuItem.Checked = false;
            eventID23InjectionTCPIPToolStripMenuItem.Checked = false;
            eventID2ToolStripMenuItem.Checked = false;
            eventID3ToolStripMenuItem.Checked = false;
            allEventsIDs123ToolStripMenuItem.Checked = false;

            StartQueries_Mon(_Query);
            toolStripStatusLabel2.ForeColor = Color.Red;
            toolStripStatusLabel2.Text = "| Filters: Select All EventIDs 1,2 [NewProcess , RemoteThreadInjection Detection] | " + AlarmsDisabled;

            MessageBox.Show(AlarmsDisabled);
        }
        public void EventID13ToolStripMenuItem_Click(object sender, EventArgs e)
        {
            string _Query = "<QueryList><Query Id=\"0\" Path=\"ETWPM2\"><Select Path=\"ETWPM2\">*[System[(EventID=1 or EventID=3)]]</Select></Query></QueryList>";

            eventID12ToolStripMenuItem.Checked = false;
            eventID13ToolStripMenuItem.Checked = true;
            eventID1ToolStripMenuItem.Checked = false;
            eventID23InjectionTCPIPToolStripMenuItem.Checked = false;
            eventID2ToolStripMenuItem.Checked = false;
            eventID3ToolStripMenuItem.Checked = false;
            allEventsIDs123ToolStripMenuItem.Checked = false;

            StartQueries_Mon(_Query);
            toolStripStatusLabel2.ForeColor = Color.Red;

            toolStripStatusLabel2.Text = "| Filters: Select All EventIDs 1,3 [NewProcess , TCPIP Send] | " + AlarmsDisabled;

            MessageBox.Show(AlarmsDisabled);
        }
        public void EventID23InjectionTCPIPToolStripMenuItem_Click(object sender, EventArgs e)
        {
            string _Query = "<QueryList><Query Id=\"0\" Path=\"ETWPM2\"><Select Path=\"ETWPM2\">*[System[(EventID=2 or EventID=3)]]</Select></Query></QueryList>";

            eventID12ToolStripMenuItem.Checked = false;
            eventID13ToolStripMenuItem.Checked = false;
            eventID1ToolStripMenuItem.Checked = false;
            eventID23InjectionTCPIPToolStripMenuItem.Checked = true;
            eventID2ToolStripMenuItem.Checked = false;
            eventID3ToolStripMenuItem.Checked = false;
            allEventsIDs123ToolStripMenuItem.Checked = false;

            StartQueries_Mon(_Query);
            toolStripStatusLabel2.ForeColor = Color.Red;

            toolStripStatusLabel2.Text = "| Filters: Select All EventIDs 2,3 [RemoteThreadInjection Detection , TCPIP Send]";

        }
        private void EventID1ToolStripMenuItem_Click(object sender, EventArgs e)
        {
            string _Query = "<QueryList><Query Id=\"0\" Path=\"ETWPM2\"><Select Path=\"ETWPM2\">*[System[(EventID=1)]]</Select></Query></QueryList>";

            eventID12ToolStripMenuItem.Checked = false;
            eventID13ToolStripMenuItem.Checked = false;
            eventID1ToolStripMenuItem.Checked = true;
            eventID23InjectionTCPIPToolStripMenuItem.Checked = false;
            eventID2ToolStripMenuItem.Checked = false;
            eventID3ToolStripMenuItem.Checked = false;
            allEventsIDs123ToolStripMenuItem.Checked = false;

            StartQueries_Mon(_Query);
            toolStripStatusLabel2.ForeColor = Color.Red;

            toolStripStatusLabel2.Text = "| Filters: Select All EventID 1 [NewProcess] | " + AlarmsDisabled;

            MessageBox.Show(AlarmsDisabled);

        }
        private void EventID2ToolStripMenuItem_Click(object sender, EventArgs e)
        {
            string _Query = "<QueryList><Query Id=\"0\" Path=\"ETWPM2\"><Select Path=\"ETWPM2\">*[System[(EventID=2)]]</Select></Query></QueryList>";

            eventID12ToolStripMenuItem.Checked = false;
            eventID13ToolStripMenuItem.Checked = false;
            eventID1ToolStripMenuItem.Checked = false;
            eventID23InjectionTCPIPToolStripMenuItem.Checked = false;
            eventID2ToolStripMenuItem.Checked = true;
            eventID3ToolStripMenuItem.Checked = false;
            allEventsIDs123ToolStripMenuItem.Checked = false;

            StartQueries_Mon(_Query);
            toolStripStatusLabel2.ForeColor = Color.Red;

            toolStripStatusLabel2.Text = "| Filters: Select All EventID 2 [RemoteThreadInjection Detection] | " + AlarmsDisabled;

            MessageBox.Show(AlarmsDisabled);

        }

        private void EventID3ToolStripMenuItem_Click(object sender, EventArgs e)
        {
            string _Query = "<QueryList><Query Id=\"0\" Path=\"ETWPM2\"><Select Path=\"ETWPM2\">*[System[(EventID=3)]]</Select></Query></QueryList>";

            eventID12ToolStripMenuItem.Checked = false;
            eventID13ToolStripMenuItem.Checked = false;
            eventID1ToolStripMenuItem.Checked = false;
            eventID23InjectionTCPIPToolStripMenuItem.Checked = false;
            eventID2ToolStripMenuItem.Checked = false;
            eventID3ToolStripMenuItem.Checked = true;
            allEventsIDs123ToolStripMenuItem.Checked = false;

            StartQueries_Mon(_Query);
            toolStripStatusLabel2.ForeColor = Color.Red;

            toolStripStatusLabel2.Text = "| Filters: Select All EventID 3 [TCPIP Send] | " + AlarmsDisabled;
            MessageBox.Show(AlarmsDisabled);

        }

        public void Update_Richtexbox6_RealtimeETW_AllDetails_info()
        {
            try
            {
                richTextBox6.Text = listView1.SelectedItems[0].SubItems[5].Text;
            }
            catch (Exception)
            {


            }

        }

        private void ListView1_SelectedIndexChanged(object sender, EventArgs e)
        {
            try
            {
                BeginInvoke(new __Obj_Updater_to_WinForm(Update_Richtexbox6_RealtimeETW_AllDetails_info));

            }
            catch (Exception)
            {


            }
        }

        private void OnToolStripMenuItem_Click(object sender, EventArgs e)
        {
            t.Enabled = true;
            onToolStripMenuItem.Text = "[on]";
            offToolStripMenuItem.Text = "off";
            i6 = 0;

        }

        private void OffToolStripMenuItem_Click(object sender, EventArgs e)
        {
            t.Enabled = false;
            onToolStripMenuItem.Text = "on";
            offToolStripMenuItem.Text = "[off]";
            i6 = 0;
        }

        private void ClearAllToolStripMenuItem_Click(object sender, EventArgs e)
        {
            listView1.Items.Clear();
            Thread.Sleep(50);

        }

        private void InjectedTIDMemoryInfoToolStripMenuItem_Click(object sender, EventArgs e)
        {

            try
            {
                ListViewItem listviewitems_wasselected_ihope = listView1.SelectedItems[0];
                EventMessage = listviewitems_wasselected_ihope.SubItems[5].Text;
                string EventMessageRecordId = listviewitems_wasselected_ihope.Name;
                if (listviewitems_wasselected_ihope.SubItems[2].Text == "2")
                {
                    ulong i32StartAddress = Convert.ToUInt64(EventMessage.Substring(EventMessage.IndexOf("::") + 2).Split(':')[0].Substring(2), 16);

                    Int64 TID = Convert.ToInt64(EventMessage.Substring(EventMessage.IndexOf("::") - 8).Split(')', ':')[1]);
                    Int32 prc = Convert.ToInt32(EventMessage.Substring(EventMessage.IndexOf("PID: (") + 6).Split(')')[0]);

                    buf = new byte[90];
                    IntPtr prch = System.Diagnostics.Process.GetProcessById(prc).Handle;
                    string XStartAddress = EventMessage.Substring(EventMessage.IndexOf("::") + 2).Split(':')[0];
                    bool MemoryBytes = Memory_info.ReadProcessMemory(prch, (UIntPtr)i32StartAddress, buf, buf.Length, IntPtr.Zero);

                    //Memoryinfo.NtReadVirtualMemory(prch, (IntPtr)i32StartAddress, buf,(uint) buf.Length, ref NTReadTmpRef);

                    MessageBox.Show(EventMessage + "\n\n______________________________________________________________\n[Injected Thread Memory info]\nRemote-Thread-Injection Memory Information:\nTID: " + TID.ToString() + "\nTID StartAddress: " +
                    XStartAddress.ToString() + "\nTID Win32StartAddress: " + i32StartAddress.ToString() + "\nTarget_Process PID: " + prc.ToString() +
                    "\n\nInjected Memory Bytes: " + BitConverter.ToString(buf).ToString()
                    , "EventID:" + listviewitems_wasselected_ihope.SubItems[2].Text + " EventRecord_ID: " + EventMessageRecordId, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
                else
                {
                    MessageBox.Show("Please Select Events with EventID 2 (only)");
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
                if (listviewitems_wasselected_ihope.SubItems[2].Text == "2")
                {
                    ulong i32StartAddress = Convert.ToUInt64(EventMessage.Substring(EventMessage.IndexOf("::") + 2).Split(':')[0].Substring(2), 16);

                    Int64 TID = Convert.ToInt64(EventMessage.Substring(EventMessage.IndexOf("::") - 8).Split(')', ':')[1]);
                    Int32 prc = Convert.ToInt32(EventMessage.Substring(EventMessage.IndexOf("PID: (") + 6).Split(')')[0]);

                    buf = new byte[90];
                    IntPtr prch = System.Diagnostics.Process.GetProcessById(prc).Handle;
                    string XStartAddress = EventMessage.Substring(EventMessage.IndexOf("::") + 2).Split(':')[0];

                    bool MemoryBytes = Memory_info.ReadProcessMemory(prch, (UIntPtr)i32StartAddress, buf, buf.Length, IntPtr.Zero);

                    MessageBox.Show(EventMessage + "\n\n______________________________________________________________\n[Injected Thread Memory info]\nRemote-Thread-Injection Memory Information:\nTID: " + TID.ToString() + "\nTID StartAddress: " +
                    XStartAddress.ToString() + "\nTID Win32StartAddress: " + i32StartAddress.ToString() + "\nTarget_Process PID: " + prc.ToString() +
                    "\n\nInjected Memory Bytes: " + BitConverter.ToString(buf).ToString()
                    , "EventID:" + listviewitems_wasselected_ihope.SubItems[2].Text + " EventRecord_ID: " + EventMessageRecordId, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
                else
                {
                    MessageBox.Show("Please Select Events with EventID 2 (only)");
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
                                                       + "Extended MemoryScanner Result: " + __result02 + "\n\n"
                                                          + "Description: " + listviewitems_wasselected_ihope.SubItems[8].Text + "\n"
                                                    + "__________________________________________________________\n"
                                                         + "ETW Event Message: " + listviewitems_wasselected_ihope.SubItems[9].Text + "\n"

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
                                                       + "Extended MemoryScanner Result: " + __result02 + "\n\n"
                                                          + "Description: " + listviewitems_wasselected_ihope.SubItems[8].Text + "\n"
                                                    + "__________________________________________________________\n"
                                                          + "ETW Event Message: " + listviewitems_wasselected_ihope.SubItems[9].Text + "\n"

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
                    try
                    {


                        MessageBox.Show("Time: " + listviewitems_wasselected_ihope.SubItems[1].Text + "\n"
                                               + "Process: " + listviewitems_wasselected_ihope.SubItems[2].Text + "\n"
                                                  + "Injection-Type: " + listviewitems_wasselected_ihope.SubItems[3].Text + "\n"
                                                     + "TCPSend: " + listviewitems_wasselected_ihope.SubItems[4].Text + "\n"
                                                        + "Status: " + listviewitems_wasselected_ihope.SubItems[5].Text + "\n"
                                                        + "__________________________________________________________\n"
                                                           + "MemoryScanner PE-sieve Result: " + __result01 + "\n\n"
                                                           + "Extended MemoryScanner Result: " + __result02 + "\n\n"
                                                              + "Description: " + listviewitems_wasselected_ihope.SubItems[8].Text + "\n"
                                                        + "__________________________________________________________\n"
                                                             + "ETW Event Message: " + listviewitems_wasselected_ihope.SubItems[9].Text + "\n"

                                    , "Properties => " +
                                               listviewitems_wasselected_ihope.SubItems[2].Text + " [" + listviewitems_wasselected_ihope.SubItems[3].Text + "] " +
                                               " " +
                                               ",LogTime:[" + listviewitems_wasselected_ihope.SubItems[1].Text + "]", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                    catch (Exception)
                    {


                    }
                }
                else
                {
                    try
                    {


                        MessageBox.Show("Time: " + listviewitems_wasselected_ihope.SubItems[1].Text + "\n"
                                               + "Process: " + listviewitems_wasselected_ihope.SubItems[2].Text + "\n"
                                                  + "Injection-Type: " + listviewitems_wasselected_ihope.SubItems[3].Text + "\n"
                                                     + "TCPSend: " + listviewitems_wasselected_ihope.SubItems[4].Text + "\n"
                                                        + "Status: " + listviewitems_wasselected_ihope.SubItems[5].Text + "\n"
                                                        + "__________________________________________________________\n"
                                                            + "MemoryScanner PE-sieve Result: " + __result01 + "\n\n"
                                                           + "Extended MemoryScanner Result: " + __result02 + "\n\n"
                                                              + "Description: " + listviewitems_wasselected_ihope.SubItems[8].Text + "\n"
                                                        + "__________________________________________________________\n"
                                                              + "ETW Event Message: " + listviewitems_wasselected_ihope.SubItems[9].Text + "\n"

                                   , "Properties => " +
                                               listviewitems_wasselected_ihope.SubItems[2].Text + " [" + listviewitems_wasselected_ihope.SubItems[3].Text + "] " +
                                               " " +
                                               ",LogTime:[" + listviewitems_wasselected_ihope.SubItems[1].Text + "]", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    }
                    catch (Exception)
                    {


                    }
                }
            }
            catch (Exception error)
            {

                MessageBox.Show("Please first Select one row/event in listview\n" + error.Message);
            }
        }

        private void AboutToolStripMenuItem1_Click(object sender, EventArgs e)
        {
            MessageBox.Show(null, "ETWPM2Monitor2 v2.1 [test version 2.1.52.628]\nCode Published by Damon Mohammadbagher , Jul 2021", "About ETWPM2Monitor2 v2.1", MessageBoxButtons.OK, MessageBoxIcon.Information);

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

        private void SaveAllAlarmEventsToolStripMenuItem1_Click(object sender, EventArgs e)
        {
            _SaveAlarmsByETW();
        }

        private void DefaultDumpAllToolStripMenuItem_Click(object sender, EventArgs e)
        {
            toolStripStatusLabel3.Text = "| pe-sieve is on";

            pesieve64exeOffToolStripMenuItem.Text = "pe-sieve64.exe off";
            pesieve64exeonToolStripMenuItem.Text = "pe-sieve64.exe [on]";
            defaultDumpAllToolStripMenuItem.Text = "Default dump all [on]";
            dontDumpTheModifiedPEsButSaveTheReportoffToolStripMenuItem.Text = "don't dump the modified PEs, but save the report [off]";
            dontDumpAnyFilesToolStripMenuItem1.Text = "don't dump any files [off]";

            isPEScanonoff = true;
            pe_sieve_DumpSwitches = 0;
        }

        private void RemoveRealtimeRecordsAfter500RecordsToolStripMenuItem_Click(object sender, EventArgs e)
        {
            ListiveItemCount = 500;
            removeRealtimeRecordsAfter1000RecordsToolStripMenuItem.Checked = false;
            removeRealtimeRecordsAfter2000RecordsToolStripMenuItem.Checked = false;
            removeRealtimeRecordsAfter3000RecordsToolStripMenuItem.Checked = false;
            removeRealtimeRecordsAfter5000RecordsToolStripMenuItem.Checked = false;


        }

        private void RemoveRealtimeRecordsAfter1000RecordsToolStripMenuItem_Click(object sender, EventArgs e)
        {
            ListiveItemCount = 1000;
            removeRealtimeRecordsAfter500RecordsToolStripMenuItem.Checked = false;
            removeRealtimeRecordsAfter2000RecordsToolStripMenuItem.Checked = false;
            removeRealtimeRecordsAfter3000RecordsToolStripMenuItem.Checked = false;
            removeRealtimeRecordsAfter5000RecordsToolStripMenuItem.Checked = false;
        }

        private void RemoveRealtimeRecordsAfter2000RecordsToolStripMenuItem_Click(object sender, EventArgs e)
        {
            ListiveItemCount = 2000;
            removeRealtimeRecordsAfter1000RecordsToolStripMenuItem.Checked = false;
            removeRealtimeRecordsAfter500RecordsToolStripMenuItem.Checked = false;
            removeRealtimeRecordsAfter3000RecordsToolStripMenuItem.Checked = false;
            removeRealtimeRecordsAfter5000RecordsToolStripMenuItem.Checked = false;
        }

        private void RemoveRealtimeRecordsAfter3000RecordsToolStripMenuItem_Click(object sender, EventArgs e)
        {
            ListiveItemCount = 3000;
            removeRealtimeRecordsAfter1000RecordsToolStripMenuItem.Checked = false;
            removeRealtimeRecordsAfter2000RecordsToolStripMenuItem.Checked = false;
            removeRealtimeRecordsAfter500RecordsToolStripMenuItem.Checked = false;
            removeRealtimeRecordsAfter5000RecordsToolStripMenuItem.Checked = false;
        }

        private void RemoveRealtimeRecordsAfter5000RecordsToolStripMenuItem_Click(object sender, EventArgs e)
        {
            ListiveItemCount = 5000;
            removeRealtimeRecordsAfter1000RecordsToolStripMenuItem.Checked = false;
            removeRealtimeRecordsAfter2000RecordsToolStripMenuItem.Checked = false;
            removeRealtimeRecordsAfter3000RecordsToolStripMenuItem.Checked = false;
            removeRealtimeRecordsAfter500RecordsToolStripMenuItem.Checked = false;
        }

        private void DontDumpTheModifiedPEsButSaveTheReportoffToolStripMenuItem_Click(object sender, EventArgs e)
        {
            toolStripStatusLabel3.Text = "| pe-sieve is on";
            pesieve64exeOffToolStripMenuItem.Text = "pe-sieve64.exe off";
            pesieve64exeonToolStripMenuItem.Text = "pe-sieve64.exe [on]";
            dontDumpTheModifiedPEsButSaveTheReportoffToolStripMenuItem.Text = "don't dump the modified PEs, but save the report [on]";
            defaultDumpAllToolStripMenuItem.Text = "Default dump all [off]";
            dontDumpAnyFilesToolStripMenuItem1.Text = "don't dump any files [off]";

            isPEScanonoff = true;
            pe_sieve_DumpSwitches = 1;
        }

        private void DontDumpAnyFilesToolStripMenuItem1_Click(object sender, EventArgs e)
        {
            toolStripStatusLabel3.Text = "| pe-sieve is on";
            pesieve64exeOffToolStripMenuItem.Text = "pe-sieve64.exe off";
            pesieve64exeonToolStripMenuItem.Text = "pe-sieve64.exe [on]";
            dontDumpTheModifiedPEsButSaveTheReportoffToolStripMenuItem.Text = "don't dump the modified PEs, but save the report [off]";
            defaultDumpAllToolStripMenuItem.Text = "Default dump all [off]";
            dontDumpAnyFilesToolStripMenuItem1.Text = "don't dump any files [on]";
            isPEScanonoff = true;
            pe_sieve_DumpSwitches = 2;
        }

        private void ScanOnlyModeDefaultToolStripMenuItem_Click(object sender, EventArgs e)
        {
            Pe_sieveLevel = 0;
            scanKillSuspiciousRunAsAdminToolStripMenuItem.Checked = false;
            scanOnlyModeDefaultToolStripMenuItem.Checked = true;
            scanSuspendToolStripMenuItem.Checked = false;
        }

        private void ScanSuspendToolStripMenuItem_Click_1(object sender, EventArgs e)
        {
            Pe_sieveLevel = 1;
            scanKillSuspiciousRunAsAdminToolStripMenuItem.Checked = false;
            scanOnlyModeDefaultToolStripMenuItem.Checked = false;
            scanSuspendToolStripMenuItem.Checked = true;
        }

        private void ScanKillSuspiciousRunAsAdminToolStripMenuItem_Click(object sender, EventArgs e)
        {
            Pe_sieveLevel = 2;
            scanKillSuspiciousRunAsAdminToolStripMenuItem.Checked = true;
            scanOnlyModeDefaultToolStripMenuItem.Checked = false;
            scanSuspendToolStripMenuItem.Checked = false;
        }

        private void RealTimeSearchFiltersToolStripMenuItem_Click(object sender, EventArgs e)
        {
            SearchForm_Realtime _NewForm = new SearchForm_Realtime();
            IsSearchFormActived = true;
            _NewForm.Show();

        }

        private void Form1_FormClosing(object sender, FormClosingEventArgs e)
        {
            if (!IsSearchFormActived)
            {

            }
            else
            {
                MessageBox.Show("Please first exit from Search/Filter Form!");
                e.Cancel = true;
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

        private void TreeView1_AfterSelect(object sender, TreeViewEventArgs e)
        {
            richTextBox9.Text = treeView1.SelectedNode.Text;
        }

        private void TreeView2_AfterSelect(object sender, TreeViewEventArgs e)
        {
            richTextBox9.Text = treeView2.SelectedNode.Text;
        }

        public void Button1_Click(object sender, EventArgs e)
        {
            richTextBox9.Clear();
            treeView3.Nodes.Clear();
            treeView3.ImageList = imageList1;
            BeginInvoke(new __Obj_Updater_to_WinForm2(__SearchStrings_in_ProcessesTab),treeView3, textBox1.Text, treeView1);

        }

        public void Button2_Click(object sender, EventArgs e)
        {
            richTextBox9.Clear();
            treeView3.Nodes.Clear();
            treeView3.ImageList = imageList1;
            BeginInvoke(new __Obj_Updater_to_WinForm2(__SearchStrings_in_ProcessesTab),treeView3, textBox1.Text, treeView2);

        }

        private void Refresh5SecToolStripMenuItem_Click(object sender, EventArgs e)
        {
            t3.Interval = 15000;
            refresh5SecToolStripMenuItem.Checked = true;
            refresh10SecToolStripMenuItem.Checked = false;
            t10.Interval = 15000;
        }

        private void Refresh10SecToolStripMenuItem_Click(object sender, EventArgs e)
        {
            t3.Interval = 10000;
            refresh5SecToolStripMenuItem.Checked = false;
            refresh10SecToolStripMenuItem.Checked = true;
            t10.Interval = 10000;
        }

        private void AllToolStripMenuItem_Click(object sender, EventArgs e)
        {
            bool __init1 = false;
            bool __init2 = false;

            if (t7.Enabled)
            {
                t7.Enabled = false;
                t7.Stop();
                t10.Enabled = false;
                t10.Stop();
                __init1 = true;
            }

            if (_IsProcessTab_Enabled)
            {
                _IsProcessTab_Enabled = false;
                __init2 = true;
            }

            treeView1.Nodes.Clear();
            treeView2.Nodes.Clear();

            GC.Collect();
            try
            {
                Process[] AllProcess = Process.GetProcesses();
                foreach (Process item in AllProcess.ToList())
                {
                    treeView1.Nodes.Add(item.ProcessName + ":" + item.Id.ToString());
                }
            }
            catch (Exception)
            {


            }

            if (__init1)
            {

                t7.Enabled = true;
                t7.Start();
                t10.Enabled = true;
                t10.Start();
            }

            if (__init2)
                _IsProcessTab_Enabled = true;

        }

        private void LiveProcessesToolStripMenuItem_Click(object sender, EventArgs e)
        {
            bool __init1 = false;
            bool __init2 = false;

            if (t7.Enabled)
            {
                t7.Enabled = false;
                t7.Stop();
                t10.Enabled = false;
                t10.Stop();
                __init1 = true;
            }

            if (_IsProcessTab_Enabled)
            {
                _IsProcessTab_Enabled = false;
                __init2 = true;
            }

            treeView1.Nodes.Clear();
            GC.Collect();

            try
            {
                Process[] AllProcess = Process.GetProcesses();
                foreach (Process item in AllProcess.ToList())
                {
                    treeView1.Nodes.Add(item.ProcessName + ":" + item.Id.ToString());
                }
            }
            catch (Exception)
            {


            }

            if (__init1)
            {

                t7.Enabled = true;
                t7.Start();
                t10.Enabled = true;
                t10.Start();
            }

            if (__init2)
                _IsProcessTab_Enabled = true;
        }

        private void ClosedProcessesToolStripMenuItem_Click(object sender, EventArgs e)
        {
            treeView2.Nodes.Clear();
        }

        private void StopListRefreshingToolStripMenuItem_Click(object sender, EventArgs e)
        {
            _IsProcessTab_Enabled = false;
            stopListRefreshingToolStripMenuItem.Checked = true;
            startRefreshingToolStripMenuItem.Checked = false;
            processesToolStripMenuItem.Checked = false;
            for30minToolStripMenuItem.Checked = false;
            for60MinToolStripMenuItem.Checked = false;
            for90MinToolStripMenuItem.Checked = false;
            for120MinToolStripMenuItem.Checked = false;

            groupBox12.ForeColor = Color.Black;
            groupBox12.Refresh();

            t7.Enabled = false;
            t7.Stop();
            t10.Enabled = false;
            t10.Stop();

            Isinit_Time_To_Start_Timer10_ProcessTabTimer = false;
            groupBox12.Text = "Live Processes";

        }

        //private void StartRefreshingToolStripMenuItem_Click(object sender, EventArgs e)
        //{
        //    //_IsProcessTab_Enabled = true;
        //    //processesToolStripMenuItem.Checked = true;
        //    //stopListRefreshingToolStripMenuItem.Checked = false;
        //    //startRefreshingToolStripMenuItem.Checked = true;
        //    //t7.Enabled = true;
        //    //t7.Start();
        //    //t10.Enabled = true;
        //    //t10.Start();
        //}

        private void ShowEventDetails2ToolStripMenuItem_Click(object sender, EventArgs e)
        {
            listView1.Items.Clear();
            ETWPM2Realt_timeShowMode_Level = 1;
            showEventDetailsToolStripMenuItem.Checked = false;
            showEventDetails2ToolStripMenuItem.Checked = true;
            t6.Enabled = true;
            t6.Start();
        }

        private void ShowEventDetailsToolStripMenuItem_Click(object sender, EventArgs e)
        {
            listView1.Items.Clear();
            ETWPM2Realt_timeShowMode_Level = 0;
            showEventDetailsToolStripMenuItem.Checked = true;
            showEventDetails2ToolStripMenuItem.Checked = false;
            t6.Enabled = false;
            t6.Stop();
            BeginInvoke(new __Obj_Updater_to_WinForm(_RunRemoveItemsLisview1));
        }

        private void TreeView3_AfterSelect(object sender, TreeViewEventArgs e)
        {
            richTextBox9.Text = treeView3.SelectedNode.Text;
        }

        private void ToolStripMenuItem2_Click(object sender, EventArgs e)
        {
            try
            {
                ListViewItem listviewitems_wasselected_ihope = listView4.SelectedItems[0];
                string __TargetProcess = listviewitems_wasselected_ihope.SubItems[2].Text;


                List<IntPtr> TP_Socket_intptrs = SocketClass.SocketHijacking.GetSocketsTargetProcess
                    (Process.GetProcessById(Convert.ToInt32(__TargetProcess.Split(':')[1])));

                foreach (IntPtr item in TP_Socket_intptrs.ToList())
                {
                    SocketClass.SocketHijacking.shutdown(item, 2);

                }

            }
            catch (Exception err)
            {

                MessageBox.Show(err.Message);


            }
            try
            {
                /// Checking TCP Connections....
                IPGlobalProperties _GetIPGlobalProperties = IPGlobalProperties.GetIPGlobalProperties();
                TcpConnectionInformation[] _TCPConnections = _GetIPGlobalProperties.GetActiveTcpConnections();

                ListViewItem listviewitems_wasselected_ihope2 = listView4.SelectedItems[0];
                string __TargetProcess2 = listviewitems_wasselected_ihope2.SubItems[2].Text;
                string sip_port = listviewitems_wasselected_ihope2.SubItems[4].Text;
                string dip_port = listviewitems_wasselected_ihope2.SubItems[5].Text;
                foreach (TcpConnectionInformation t in _TCPConnections.ToList())
                {
                    if (t.LocalEndPoint.Address.ToString() + ":" + t.LocalEndPoint.Port.ToString() + t.RemoteEndPoint.Address.ToString()
                                + ":" + t.RemoteEndPoint.Port.ToString() == sip_port + dip_port && t.State == TcpState.Established)
                    {

                        MessageBox.Show("Warning\nConnection Not Closed!\nmaybe this Connection made by some dll/modules (in background) for this process?", "Connection Not Closed!?", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    }
                }
            }
            catch (Exception)
            {


            }

        }

        private void KillProcessToolStripMenuItem_Click(object sender, EventArgs e)
        {


            try
            {
                /// check sub processes 
                ListViewItem listviewitems_wasselected_ihope = listView4.SelectedItems[0];
                string __TargetProcess = listviewitems_wasselected_ihope.SubItems[2].Text;

                foreach (_TableofProcess_NewProcess_evt item in NewProcess_Table.ToList().FindAll(SubProc =>
                SubProc.PPID == Convert.ToInt32(__TargetProcess.Split(':')[1])))
                {
                    ///"[ParentID Path: C:\\Windows\\SysWOW64\\notepad.exe]"
                    string g = item.PPID_Path;
                    if (item.PPID_Path.ToLower().Substring(16).Split(']')[0] ==
                        Process.GetProcessById(Convert.ToInt32(__TargetProcess.Split(':')[1])).MainModule.FileName.ToLower())
                    {
                        if (Process.GetProcesses().ToList().FindIndex(x => x.Id == item.PID) != -1)
                        {
                            try
                            {
                                //   Process.GetProcessById(item.PID).Kill();

                                IntPtr TintPtr = Process.GetProcessById(item.PID).Handle;
                                uint ExitCode = 0;

                                Memory_info.GetExitCodeProcess(TintPtr, out ExitCode);

                                Memory_info.TerminateProcess(TintPtr, ExitCode);
                            }
                            catch (Exception j)
                            {


                            }


                        }
                    }
                }
            }
            catch (Exception)
            {


            }


            try
            {
                /// check sockets for shutdown
                ListViewItem listviewitems_wasselected_ihope = listView4.SelectedItems[0];
                string __TargetProcess = listviewitems_wasselected_ihope.SubItems[2].Text;

                List<IntPtr> TP_Socket_intptrs = SocketClass.SocketHijacking.GetSocketsTargetProcess
                    (Process.GetProcessById(Convert.ToInt32(__TargetProcess.Split(':')[1])));

                foreach (IntPtr item in TP_Socket_intptrs.ToList())
                {
                    SocketClass.SocketHijacking.shutdown(item, 2);
                }

                try
                {
                    if (Process.GetProcesses().ToList().FindIndex(x => x.Id == Convert.ToInt32(__TargetProcess.Split(':')[1])) != -1)
                    {
                        try
                        {
                            //    Process.GetProcessById(Convert.ToInt32(__TargetProcess.Split(':')[1])).Kill();
                            IntPtr TintPtr = Process.GetProcessById(Convert.ToInt32(__TargetProcess.Split(':')[1])).Handle;
                            uint ExitCode = 0;

                            Memory_info.GetExitCodeProcess(TintPtr, out ExitCode);

                            Memory_info.TerminateProcess(TintPtr, ExitCode);
                        }
                        catch (Exception j)
                        {


                        }

                    }
                }
                catch (Exception err2)
                {


                }

            }
            catch (Exception err)
            {


            }

            try
            {
                /// Checking TCP Connections....
                IPGlobalProperties _GetIPGlobalProperties = IPGlobalProperties.GetIPGlobalProperties();
                TcpConnectionInformation[] _TCPConnections = _GetIPGlobalProperties.GetActiveTcpConnections();

                ListViewItem listviewitems_wasselected_ihope2 = listView4.SelectedItems[0];
                string __TargetProcess2 = listviewitems_wasselected_ihope2.SubItems[2].Text;
                string sip_port = listviewitems_wasselected_ihope2.SubItems[4].Text;
                string dip_port = listviewitems_wasselected_ihope2.SubItems[5].Text;
                foreach (TcpConnectionInformation t in _TCPConnections.ToList())
                {
                    if (t.LocalEndPoint.Address.ToString() + ":" + t.LocalEndPoint.Port.ToString() + t.RemoteEndPoint.Address.ToString()
                                + ":" + t.RemoteEndPoint.Port.ToString() == sip_port + dip_port && t.State == TcpState.Established)
                    {
                        MessageBox.Show("Warning\nProcess Killed but Connection Not Closed!\nmaybe this Connection made by some dll/modules (in background) for this process?", "Connection Not Closed!?", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    }
                }
            }
            catch (Exception)
            {


            }
        }

        public async void _Run_Async_Changedindexof_listview_5()
        {
            await _Run_Async_Changedindexof_listview_5_method();
        }

        public async Task _Run_Async_Changedindexof_listview_5_method()
        {
            try
            {
                await Task.Run(() =>
                {
                    Invoke(new Action(() =>
                    {
                        richTextBox1.Text = listView5.SelectedItems[0].Name.ToString();
                        try
                        {
                            if (!listView5.SelectedItems[0].Name.ToString().Contains("Read Target_Process Memory via API::ReadProcessMemory [ERROR] =>"))
                            {
                                string payload = listView5.SelectedItems[0].Name.ToString().Split('\n')[28].Split(':')[1].Substring(1).Split('\n')[0];

                                ImageBitmap_Info.MakeImageBMP(payload, "LastInjectedPayloadDetected.bmp");
                                ImageBitmap_Info.Lines(payload);
                                Task.Delay(10);

                                pictureBox1.ImageLocation = "LastInjectedPayloadDetected.bmp";
                                pictureBox2.ImageLocation = "LastInjectedPayloadDetected2.png";
                            }
                            else
                            {
                                pictureBox1.ImageLocation = "";
                                pictureBox2.ImageLocation = "";
                            }
                        }
                        catch (Exception)
                        {


                        }
                    }));
                });
            }
            catch (Exception)
            {


            }
        }

        public async void _Run_Async_Changedindexof_listview_9()
        {
            await _Run_Async_Changedindexof_listview_9_method();
        }

        public async Task _Run_Async_Changedindexof_listview_9_method()
        {
            try
            {
                await Task.Run(() =>
                {
                    Invoke(new Action(() =>
                    {
                        richTextBox12.Text = listView9.SelectedItems[0].Name.ToString();
                        try
                        {
                             
                            if (!listView9.SelectedItems[0].Name.ToString().Contains("Read Target_Process Memory via API::ReadProcessMemory [ERROR] =>"))
                            {
                                string payload = listView9.SelectedItems[0].Name.ToString().Split('\n')[28].Split(':')[1].Substring(1).Split('\n')[0];

                                ImageBitmap_Info.MakeImageBMP(payload, "Snapshot_LastInjectedPayloadDetected.bmp");
                               
                                Task.Delay(10);

                                pictureBox3.ImageLocation = "Snapshot_LastInjectedPayloadDetected.bmp";
                                
                            }
                            else
                            {
                                pictureBox3.ImageLocation = "";
                                 
                            }
                        }
                        catch (Exception)
                        {


                        }
                    }));
                });
            }
            catch (Exception)
            {


            }
        }

        private void ToolStripStatusLabel7_Click(object sender, EventArgs e)
        {
            tabControl1.SelectedIndex = 3;
            tabControl2.SelectedIndex = 3;
            tabControl5.SelectedIndex = 1;
        }

        private void ToolStripStatusLabel5_Click(object sender, EventArgs e)
        {

            tabControl1.SelectedIndex = 4;
            tabControl4.SelectedIndex = 0;

        }

        private void ToolStripStatusLabel6_Click(object sender, EventArgs e)
        {
            tabControl2.SelectedIndex = 2;
            tabControl1.SelectedIndex = 3;
        }

        private void DontShowEventsToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (dontShowEventsToolStripMenuItem.Checked == false)
            {
                dontShowEventsToolStripMenuItem.Checked = true;
                IsDontShow_ETWPM2_Realt_time_Enabled = true;

                t6.Enabled = false;
                t6.Stop();
                listView1.Items.Clear();
                eTWPM2RealtimeToolStripMenuItem.Checked = false;

            }
            else if (dontShowEventsToolStripMenuItem.Checked == true)
            {
                dontShowEventsToolStripMenuItem.Checked = false;
                IsDontShow_ETWPM2_Realt_time_Enabled = false;
                t6.Enabled = true;
                t6.Start();
                eTWPM2RealtimeToolStripMenuItem.Checked = true;
            }
        }

        private void ShowEventsToolStripMenuItem_Click(object sender, EventArgs e)
        {

            IsDontShow_NetworkConnection_Enabled = false;
            showEventsToolStripMenuItem.Checked = true;
            dontShowEventsToolStripMenuItem1.Checked = false;
            networkConnectionsToolStripMenuItem.Checked = true;

        }

        private void DontShowEventsToolStripMenuItem1_Click(object sender, EventArgs e)
        {
            IsDontShow_NetworkConnection_Enabled = true;
            dontShowEventsToolStripMenuItem1.Checked = true;
            showEventsToolStripMenuItem.Checked = false;
            networkConnectionsToolStripMenuItem.Checked = false;
        }

        private void ListView6_SelectedIndexChanged(object sender, EventArgs e)
        {
            try
            {
                BeginInvoke(new __Obj_Updater_to_WinForm(Update_Richtexbox10_WindowsEventLogTab_Details_Info));

            }
            catch (Exception)
            {


            }
        }

        public void Update_Richtexbox10_WindowsEventLogTab_Details_Info()
        {

            try
            {
                richTextBox10.Text = listView6.SelectedItems[0].Name;
            }
            catch (Exception)
            {


            }

        }

        private void RefreshNetworkConnectionsToolStripMenuItem_Click(object sender, EventArgs e)
        {
            listView3.Items.Clear();
        }

        private void For30minToolStripMenuItem_Click(object sender, EventArgs e)
        {
            _IsProcessTab_Enabled = true;
            processesToolStripMenuItem.Checked = true;
            stopListRefreshingToolStripMenuItem.Checked = false;
            startRefreshingToolStripMenuItem.Checked = true;
            for30minToolStripMenuItem.Checked = true;
            for60MinToolStripMenuItem.Checked = false;
            for90MinToolStripMenuItem.Checked = false;
            for120MinToolStripMenuItem.Checked = false;
            t7.Enabled = true;
            t7.Start();
            t10.Enabled = true;
            t10.Start();
        }

        private void For60MinToolStripMenuItem_Click(object sender, EventArgs e)
        {
            _IsProcessTab_Enabled = true;
            processesToolStripMenuItem.Checked = true;
            stopListRefreshingToolStripMenuItem.Checked = false;
            startRefreshingToolStripMenuItem.Checked = true;
            for30minToolStripMenuItem.Checked = false;
            for60MinToolStripMenuItem.Checked = true;
            for90MinToolStripMenuItem.Checked = false;
            for120MinToolStripMenuItem.Checked = false;
            t7.Enabled = true;
            t7.Start();
            t10.Enabled = true;
            t10.Start();
        }

        private void For90MinToolStripMenuItem_Click(object sender, EventArgs e)
        {
            _IsProcessTab_Enabled = true;
            processesToolStripMenuItem.Checked = true;
            stopListRefreshingToolStripMenuItem.Checked = false;
            startRefreshingToolStripMenuItem.Checked = true;
            for30minToolStripMenuItem.Checked = false;
            for60MinToolStripMenuItem.Checked = false;
            for90MinToolStripMenuItem.Checked = true;
            for120MinToolStripMenuItem.Checked = false;
            t7.Enabled = true;
            t7.Start();
            t10.Enabled = true;
            t10.Start();

        }

        private void For120MinToolStripMenuItem_Click(object sender, EventArgs e)
        {
            _IsProcessTab_Enabled = true;
            processesToolStripMenuItem.Checked = true;
            stopListRefreshingToolStripMenuItem.Checked = false;
            startRefreshingToolStripMenuItem.Checked = true;
            for30minToolStripMenuItem.Checked = false;
            for60MinToolStripMenuItem.Checked = false;
            for90MinToolStripMenuItem.Checked = false;
            for120MinToolStripMenuItem.Checked = true;
            t7.Enabled = true;
            t7.Start();
            t10.Enabled = true;
            t10.Start();
        }

        private void TakeSnapShotToolStripMenuItem_Click(object sender, EventArgs e)
        {
            try
            {                
                Snapshot_Info._ProcessesTab_TakeSnapshot(treeView1, treeView2);
            }
            catch (Exception)
            {

               
            }
        
        }

        private void LoadSnapshotToolStripMenuItem_Click(object sender, EventArgs e)
        {
            try
            {
                
                object[] Return_obj = Snapshot_Info._ProcessesTab_Snapshot1Tab_LoadSnapshot();
                treeView4.Nodes.Clear();
                treeView5.Nodes.Clear();
                treeView4.ImageList = imageList1;
                treeView5.ImageList = imageList1;

                if ((TreeNode[])Return_obj[0] != null)
                    treeView4.Nodes.AddRange((TreeNode[])Return_obj[0]);
                if ((TreeNode[])Return_obj[1] != null)
                    treeView5.Nodes.AddRange((TreeNode[])Return_obj[1]);

                Thread.Sleep(100);
                tabControl3.SelectedIndex = 2;
                Thread.Sleep(10);
                label1.Text = (string)Return_obj[2];
                label2.Text = (string)Return_obj[3];

                MessageBox.Show("Data files loaded in Snapshot1 Tab \n" + (string)Return_obj[2] + "\n" + (string)Return_obj[3]);

            }
            catch (Exception)
            {

              
            }
            
        }

        private void TreeView4_AfterSelect(object sender, TreeViewEventArgs e)
        {
            richTextBox11.Text = treeView4.SelectedNode.Text;
        }

        private void TreeView5_AfterSelect(object sender, TreeViewEventArgs e)
        {
            richTextBox11.Text = treeView5.SelectedNode.Text;
        }

        private void Button4_Click(object sender, EventArgs e)
        {
            richTextBox11.Clear();
            treeView6.Nodes.Clear();
            treeView6.ImageList = imageList1;
            BeginInvoke(new __Obj_Updater_to_WinForm2(__SearchStrings_in_ProcessesTab), treeView6, textBox2.Text, treeView4);
        }

        private void Button3_Click(object sender, EventArgs e)
        {
            richTextBox11.Clear();
            treeView6.Nodes.Clear();
            treeView6.ImageList = imageList1;
            BeginInvoke(new __Obj_Updater_to_WinForm2(__SearchStrings_in_ProcessesTab), treeView6, textBox2.Text, treeView5);
        }

        private void TreeView6_AfterSelect(object sender, TreeViewEventArgs e)
        {
            richTextBox11.Text = treeView6.SelectedNode.Text;
        }

        private void LoadSnapshotToolStripMenuItem1_Click(object sender, EventArgs e)
        {
            //_ProcessesTab_Snapshot1Tab_LoadSnapshot();
            object[] Return_obj = Snapshot_Info._ProcessesTab_Snapshot1Tab_LoadSnapshot();
            treeView4.Nodes.Clear();
            treeView5.Nodes.Clear();
            treeView4.ImageList = imageList1;
            treeView5.ImageList = imageList1;

            if ((TreeNode[])Return_obj[0] != null)
                treeView4.Nodes.AddRange((TreeNode[])Return_obj[0]);
            if ((TreeNode[])Return_obj[1] != null)
                treeView5.Nodes.AddRange((TreeNode[])Return_obj[1]);

            Thread.Sleep(100);
            tabControl3.SelectedIndex = 2;
            Thread.Sleep(10);
            label1.Text = (string)Return_obj[2];
            label2.Text = (string)Return_obj[3];

            MessageBox.Show("Data files loaded in Snapshot1 Tab \n" + (string)Return_obj[2] + "\n" + (string)Return_obj[3]);
        }

        private void TakeSnapshotToolStripMenuItem1_Click(object sender, EventArgs e)
        {
            try
            {
                Snapshot_Info._ProcessesTab_TakeSnapshot(treeView1, treeView2);
            }
            catch (Exception)
            {

                throw;
            }
          
        }

        private void LoadSnapshotToolStripMenuItem2_Click(object sender, EventArgs e)
        {
            try
            {
                object[] Return_obj = Snapshot_Info._ProcessesTab_Snapshot1Tab_LoadSnapshot();
                treeView4.Nodes.Clear();
                treeView5.Nodes.Clear();
                treeView4.ImageList = imageList1;
                treeView5.ImageList = imageList1;

                if ((TreeNode[])Return_obj[0] != null)
                    treeView4.Nodes.AddRange((TreeNode[])Return_obj[0]);
                if ((TreeNode[])Return_obj[1] != null)
                    treeView5.Nodes.AddRange((TreeNode[])Return_obj[1]);

                Thread.Sleep(100);
                tabControl3.SelectedIndex = 2;
                Thread.Sleep(10);
                label1.Text = (string)Return_obj[2];
                label2.Text = (string)Return_obj[3];

                MessageBox.Show("Data files loaded in Snapshot1 Tab \n" + (string)Return_obj[2] + "\n" + (string)Return_obj[3]);
            }
            catch (Exception)
            {


            }
        }

        private void TakeSnapshotToolStripMenuItem2_Click(object sender, EventArgs e)
        {
            try
            {
                //_ETWPM2InjectionTab_TakeSnapshot();
                Snapshot_Info._ETWPM2InjectionTab_TakeSnapshot(listView5);
            }
            catch (Exception)
            {
               
            }           
        }

        private void LoadSnapshotToolStripMenuItem3_Click(object sender, EventArgs e)
        {
            try
            {
                object[] return_obj = Snapshot_Info._ETWPM2InjectionTab_SnapshotTab_LoadSnapshot();

                listView9.Items.Clear();
                ListViewItem[] ilist = ((ListViewItem[])return_obj[0]).ToList().ToArray();

                listView9.Items.AddRange(ilist.ToList().ToArray());
                Thread.Sleep(100);
                tabControl1.SelectedIndex = 2;
                Thread.Sleep(10);
                toolStripStatusLabel8.Text = "";
                toolStripStatusLabel8.Text = ((string)return_obj[1]);
                MessageBox.Show("Data files loaded in Snapshot Tab \n" + ((string)return_obj[1]));
            }
            catch (Exception)
            {


            }
        }

        private void ListView9_SelectedIndexChanged(object sender, EventArgs e)
        {
            try
            {

                ThreadStart __T7_for_show_Details_info = new ThreadStart(delegate
                {
                    BeginInvoke(new __Obj_Updater_to_WinForm(_Run_Async_Changedindexof_listview_9));
                });

                Thread _T7_for_show_Details_info_ = new Thread(__T7_for_show_Details_info);
                _T7_for_show_Details_info_.Start();
            }
            catch (Exception)
            {


            }
        }

        private void ToolStripMenuItem1_Click(object sender, EventArgs e)
        {
            try
            {
                Snapshot_Info._ETWPM2InjectionTab_TakeSnapshot(listView5);
            }
            catch (Exception)
            {

               
            }
         
        }

        private void ToolStripMenuItem3_Click(object sender, EventArgs e)
        {
            try
            {          
            // _ETWPM2InjectionTab_SnapshotTab_LoadSnapshot();

            object[] return_obj = Snapshot_Info._ETWPM2InjectionTab_SnapshotTab_LoadSnapshot();

            listView9.Items.Clear();
            ListViewItem[] ilist = ((ListViewItem[])return_obj[0]).ToList().ToArray();

            listView9.Items.AddRange(ilist.ToList().ToArray());

            Thread.Sleep(100);
            tabControl1.SelectedIndex = 2;
            Thread.Sleep(10);
            toolStripStatusLabel8.Text = "";
            toolStripStatusLabel8.Text = ((string)return_obj[1]);
            MessageBox.Show("Data files loaded in Snapshot Tab \n" + ((string)return_obj[1]));

            }
            catch (Exception)
            {

                
            }
        }

        private void ONToolStripMenuItem2_Click(object sender, EventArgs e)
        {
            offToolStripMenuItem2.Checked = false;
            oNToolStripMenuItem2.Checked = true;
            isPEScanonoff = true;
            toolStripStatusLabel3.Text = "| pe-sieve is on";
            toolStripStatusLabel3.ForeColor = Color.GhostWhite;
        }

        private void OffToolStripMenuItem2_Click(object sender, EventArgs e)
        {
            toolStripStatusLabel3.Text = "| pe-sieve is off";
            toolStripStatusLabel3.ForeColor = Color.Red;
            offToolStripMenuItem2.Checked = true;
            oNToolStripMenuItem2.Checked = false;
            //pesieve64exeonToolStripMenuItem.Text = "pe-sieve64.exe on";
            isPEScanonoff = false;
            if (isPEScanonoff == false)
                MessageBox.Show("\"Alarms by ETW\" TAB is disable now, because Memory Scanner is OFF\n");
        }

        private void ScanProcessMemoryByCobaltStrikeScanBeaconDetectionToolStripMenuItem_Click(object sender, EventArgs e)
        {
            /// scanning Target Process via Extended Memory Scanner CobaltStrikeScan.exe
            /// -t target process added by me to the source for scan target proces (not all processes)
            /// Github source code => https://github.com/Apr4h/CobaltStrikeScan
            /// nice code .... 
            try
            {
                string TargetPID = listView2.SelectedItems[0].SubItems[2].Text.Split(':')[1];
                BeginInvoke(new __core2(ExtendedMemoryScanners_Info.RunAsyn_CobaltstrikeScan), (object)TargetPID);
                t18.Enabled = true;
                t18.Start();
            }
            catch (Exception)
            {


            }
        }

        private void HorizontalToolStripMenuItem_Click(object sender, EventArgs e)
        {
            splitContainer15.Orientation = Orientation.Horizontal;
            splitContainer15.Panel1MinSize = 250;
            splitContainer15.Panel2MinSize = 250;
            splitContainer15.Refresh();
        }

        private void VerticalToolStripMenuItem_Click(object sender, EventArgs e)
        {
            splitContainer15.Orientation = Orientation.Vertical;
            splitContainer15.Panel1MinSize = 250;
            splitContainer15.Panel2MinSize = 250;
            splitContainer15.Refresh();
        }

        public void Update_Richtexbox13_AllDetails_info()
        {
            try
            {
                richTextBox13.Text = "Time: " + listView10.SelectedItems[0].SubItems[1].Text
                    + "\nProcess: " + listView10.SelectedItems[0].SubItems[2].Text
                    + "\nPid: " + listView10.SelectedItems[0].SubItems[3].Text
                    + "\nTcp Sends: " + listView10.SelectedItems[0].SubItems[4].Text
                    + "\nDetection Score: " + listView10.SelectedItems[0].SubItems[5].Text
                    + "\n" + listView10.SelectedItems[0].SubItems[6].Text
                    + "\n\nMemory Scanner CobaltstrikeScan , Result: " + "\n\n" + listView10.SelectedItems[0].SubItems[7].Text + "\n";
            }
            catch (Exception)
            {


            }

        }

        private void ListView10_SelectedIndexChanged(object sender, EventArgs e)
        {
            ThreadStart __T10_for_show_Details_info = new ThreadStart(delegate
            {
                BeginInvoke(new __Obj_Updater_to_WinForm(Update_Richtexbox13_AllDetails_info));
            });

            Thread _T10_for_show_Details_info_ = new Thread(__T10_for_show_Details_info);
            _T10_for_show_Details_info_.Start();
        }

        private void ToolStripStatusLabel9_Click(object sender, EventArgs e)
        {
            tabControl1.SelectedIndex = 5;
            tabControl4.SelectedIndex = 0;
        }

        private void ListBox4_SelectedIndexChanged(object sender, EventArgs e)
        {

            try
            {
                BeginInvoke(new __Obj_Updater_to_WinForm(_ShowProcessDetailsInfo));
            }
            catch (Exception)
            {


            }
        }

        public async void _ShowProcessDetailsInfo()
        {
            await Task.Run(() =>
            {
                try
                {
                    string _ProcessName = listBox4.SelectedItems[0].ToString().Split('[')[4].Substring(15).Split(']')[0];
                    Int32 _PID = Convert.ToInt32(listBox4.SelectedItems[0].ToString().Split('[')[3].Substring(11).Split(']')[0]);

                    Int32 Index = Process_Table.FindIndex(i => i.PID == _PID && i.ProcessName == _ProcessName);

                    richTextBox8.Text = "";
                    richTextBox8.Text += "[#] ProcessName: " + Process_Table[Index].ProcessName;
                    richTextBox8.Text += "\n[#] ProcessName_Path: " + Process_Table[Index].ProcessName_Path;
                    richTextBox8.Text += "\n[#] PID: " + Process_Table[Index].PID;
                    richTextBox8.Text += "\n[#] IsLive: " + Process_Table[Index].IsLive;
                    richTextBox8.Text += "\n-------------------------------------------------------------";
                    richTextBox8.Text += "\n[#] InjectorPID: " + Process_Table[Index].Injector;
                    richTextBox8.Text += "\n[#] Injector_Path: " + Process_Table[Index].Injector_Path;
                    richTextBox8.Text += "\n\n[#] IsShow_Alarm: " + Process_Table[Index].IsShow_Alarm;
                    richTextBox8.Text += "\n-------------------------------------------------------------";
                    richTextBox8.Text += "\n[#] InjectionType: " + Process_Table[Index].InjectionType;
                    richTextBox8.Text += "\n[#] Detection_Status: " + Process_Table[Index].Detection_Status;
                    richTextBox8.Text += "\n[#] Detection_EventTime: " + Process_Table[Index].Detection_EventTime;
                    richTextBox8.Text += "\n-------------------------------------------------------------";
                    richTextBox8.Text += "\n[#] TCPDetails2: " + Process_Table[Index].TCPDetails2;
                    richTextBox8.Text += "\n[#] TCPDetails: " + Process_Table[Index].TCPDetails;
                    richTextBox8.Text += "\n-------------------------------------------------------------";
                    richTextBox8.Text += "\n[#] Description (ETW Event Message):\n" + Process_Table[Index].Description;
                    richTextBox8.Text += "\n\n[#] Descripton_Details:\n" + Process_Table[Index].Descripton_Details;
                    richTextBox8.Text += "\n-------------------------------------------------------------";
                    richTextBox8.Text += "\n[#] Memory Scanner Result: " + Process_Table[Index].MemoryScanner01_Result.Replace('\n', ' ');
                    richTextBox8.Text += "\n-------------------------------------------------------------";
                    richTextBox8.Text += "\n[#] Memory Scanner Result Details:\n" + Process_Table[Index].SubItems_Name_Property;

                    //richTextBox8.Text += Process_Table[Index].SubItems_ImageIndex;

                }
                catch (Exception)
                {


                }
            });
        }

        private void FilterExcludeInjectionBySystem4ToolStripMenuItem_Click(object sender, EventArgs e)
        {

            if (filterExcludeInjectionBySystem4ToolStripMenuItem.Checked == false)
            {
                filterExcludeInjectionBySystem4ToolStripMenuItem.Checked = true;
                IsFilterSystem4Enabled_ETWPM2_Realtime = true;
                toolStripStatusLabel5.Text = "Filter: Exclude Injection by System:4 is on";
                toolStripStatusLabel5.ForeColor = Color.Red;
            }
            else if (filterExcludeInjectionBySystem4ToolStripMenuItem.Checked == true)
            {
                filterExcludeInjectionBySystem4ToolStripMenuItem.Checked = false;
                IsFilterSystem4Enabled_ETWPM2_Realtime = false;
                toolStripStatusLabel5.Text = "Filter: Exclude Injection by System:4 is off";
                toolStripStatusLabel5.ForeColor = Color.Black;
            }
        }

        private void OnToolStripMenuItem1_Click(object sender, EventArgs e)
        {
            IsSystemDeveloperLogs_on = true;
            onToolStripMenuItem1.Checked = true;
            offToolStripMenuItem1.Checked = false;

        }

        private void OffToolStripMenuItem1_Click(object sender, EventArgs e)
        {
            IsSystemDeveloperLogs_on = false;
            onToolStripMenuItem1.Checked = false;
            offToolStripMenuItem1.Checked = true;

        }

        private void CheckProcessHollowingSizeChangingToolStripMenuItem_Click(object sender, EventArgs e)
        {
            try
            {
                ListViewItem listviewitems_wasselected_ihope = listView2.SelectedItems[0];
                if (listviewitems_wasselected_ihope.SubItems[3].Text == "Process-Hollowing")
                {
                    try
                    {
                        string result = Memory_info._CheckSizeChanges(Convert.ToInt32(listviewitems_wasselected_ihope.SubItems[2].Text.Split(':')[1]));

                        MessageBox.Show(result, "Properties => " +
                                               listviewitems_wasselected_ihope.SubItems[2].Text + " [" + listviewitems_wasselected_ihope.SubItems[3].Text + "] " +
                                               " " +
                                               ",LogTime:[" + listviewitems_wasselected_ihope.SubItems[1].Text + "]", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                    catch (Exception)
                    {


                    }
                }
                else
                {
                    MessageBox.Show("Please Select Events with ProcessHollowing Injection-type only");
                }
            }
            catch (Exception)
            {

                // throw;
            }

        }

        private void ListView5_SelectedIndexChanged(object sender, EventArgs e)
        {
            try
            {

                ThreadStart __T7_for_show_Details_info = new ThreadStart(delegate
                {
                    BeginInvoke(new __Obj_Updater_to_WinForm(_Run_Async_Changedindexof_listview_5));
                });

                Thread _T7_for_show_Details_info_ = new Thread(__T7_for_show_Details_info);
                _T7_for_show_Details_info_.Start();
            }
            catch (Exception)
            {


            }
        }

        private void ClearAllProcessesToolStripMenuItem_Click(object sender, EventArgs e)
        {
            //listBox2.Items.Clear();
            listBox3.Items.Clear();
            listBox4.Items.Clear();
        }

        private void ExcludeSYSTEM4EventsFromRealtimeToolStripMenuItem_Click(object sender, EventArgs e)
        {
            is_system4_excluded = true;
            includeSYSTEM4EventsFromRealtimeToolStripMenuItem.Checked = false;
        }

        private void IncludeSYSTEM4EventsFromRealtimeToolStripMenuItem_Click(object sender, EventArgs e)
        {
            is_system4_excluded = false;
            excludeSYSTEM4EventsFromRealtimeToolStripMenuItem.Checked = false;
        }

        private void Pesieve64exeOffToolStripMenuItem_Click(object sender, EventArgs e)
        {
          

        }

        private void ListView2_SelectedIndexChanged(object sender, EventArgs e)
        {

            ThreadStart __T7_for_show_Details_info = new ThreadStart(delegate
            {
                BeginInvoke(new __Obj_Updater_to_WinForm(_Run_Async_Changedindexof_listview_2));
            });

            Thread _T7_for_show_Details_info_ = new Thread(__T7_for_show_Details_info);
            _T7_for_show_Details_info_.Start();

        }

        public async void _Run_Async_Changedindexof_listview_2()
        {
            await _Changedindexof_listview_2();

        }

        /// <summary>
        /// C# Method , this method is for Show details info about Detected process in Listview2 [Alarms by ETW Tab]
        /// </summary>        
        public async Task _Changedindexof_listview_2()
        {

            try
            {

                Invoke(new Action(() =>
                {
                    int temp_get_InjectorPID_from_eventmessage = 0;
                    string temp_get_InjectorPN_from_description = "";

                    bool _error = true;
                    richTextBox4.Text = "";
                    richTextBox5.Text = "";
                    richTextBox7.Text = "";
                    try
                    {
                        string __PIDName = listView2.SelectedItems[0].Name.Split('>')[0].Split(':')[0];
                        string __PID = listView2.SelectedItems[0].Name.Split('>')[0].Split(':')[1];

                        _error = listView2.SelectedItems[0].SubItems[2].Text.ToLower() == __PIDName.ToLower() + ":" + __PID ? false : true;
                    }
                    catch (Exception)
                    {

                        _error = true;

                    }



                    if (!_error)
                    {
                        try
                        {

                            richTextBox2.Text = listView2.SelectedItems[0].Name;
                            richTextBox4.Text = listView2.SelectedItems[0].SubItems[9].Text;
                            richTextBox5.Text = listView2.SelectedItems[0].SubItems[8].Text;
                            temp_get_InjectorPID_from_eventmessage = Convert.ToInt32(listView2.SelectedItems[0].SubItems[9].Text.Split('\n')[12].Split('>')[1]);
                        }
                        catch (Exception)
                        {

                        }


                        try
                        {
                            temp_get_InjectorPN_from_description = listView2.SelectedItems[0].SubItems[8].Text
                          .Split('>')[1].Split('[')[1].Split(']')[0].Split(':')[0].Substring(1);
                        }
                        catch (Exception)
                        {

                            temp_get_InjectorPN_from_description = listView2.SelectedItems[0].SubItems[8].Text
                           .Split('>')[1].Substring(listView2.SelectedItems[0].SubItems[8].Text
                           .Split('>')[1].IndexOf("Injector-CommandLine:")).Substring(21);
                            if (temp_get_InjectorPN_from_description == " ")
                            {
                                temp_get_InjectorPN_from_description = "";
                            }

                        }


                        richTextBox3.Text = "";

                        string PIDName = listView2.SelectedItems[0].Name.Split('>')[0].Split(':')[0];
                        string PID = listView2.SelectedItems[0].Name.Split('>')[0].Split(':')[1];

                        BeginInvoke(new __core2(_MemoryScanner_Pesieve_ShowObjects), (object)PID);

                        richTextBox3.Text += "TargetProcess [" + PIDName + ":" + PID + "] Injection History with Debug info:\n";
                        richTextBox3.Text += "\n-------------------------------------------------------\n";
                        int counter = 0;
                        richTextBox3.Text += "Target Process & Injector Details:\n";
                        string last_tid = "";
                        foreach (_InjectedThreadDetails_bytes item in _InjectedTIDList.ToList<_InjectedThreadDetails_bytes>().FindAll(y => y._TargetPID == Convert.ToInt32(PID) && y._InjectorPID == temp_get_InjectorPID_from_eventmessage))
                        {
                            try
                            {

                                if (!temptids.Exists(___t => ___t == item._RemoteThreadID))
                                {
                                    temptids.Add(item._RemoteThreadID);
                                }
                                Thread.Sleep(1);
                                if (item._RemoteThreadID.ToString() != last_tid)
                                {
                                    if (NewProcess_Table.Exists(_w => _w.PID == item._InjectorPID))
                                    {
                                        bool error = false;
                                        try
                                        {
                                            var a = NewProcess_Table.Find(_w => (_w.PID == item._InjectorPID && _w.CommandLine.Contains(temp_get_InjectorPN_from_description))).CommandLine;
                                            var b = NewProcess_Table.Find(_w => _w.PID == item._InjectorPID).ProcessName_Path;
                                            var c = NewProcess_Table.Find(_w => _w.PID == item._InjectorPID).PPID_Path;
                                            var d = NewProcess_Table.Find(_w => _w.ProcessName.Substring(1) == item._TargetPIDName && _w.PID == item._TargetPID).ProcessName_Path;
                                        }
                                        catch (Exception)
                                        {
                                            error = true;
                                        }

                                        if (!error)
                                        {
                                            string injector_path = "\nInjector Path:" + NewProcess_Table.Find(_w => _w.PID == item._InjectorPID).ProcessName_Path;

                                            if (injector_path.Contains("Process Exited"))
                                            {
                                                if (Processes_FileSystemList.FindIndex(_fs => _fs.FileName_Path != null && _fs.FileName_Path.ToLower().Contains(temp_get_InjectorPN_from_description.ToLower())) != -1)
                                                {
                                                    var FS_FullPath = Processes_FileSystemList.Find(_fs => _fs.FileName_Path != null && _fs.FileName_Path.ToLower().Contains(temp_get_InjectorPN_from_description.ToLower())).FileName_Path;
                                                    injector_path = "\nInjector Path:" + FS_FullPath;
                                                }

                                            }
                                            counter++;
                                            richTextBox3.Text += "[" + counter.ToString() + "] " + "Remote Thread Injection Detected!" + "\n";
                                            richTextBox3.Text += "[" + counter.ToString() + "] " + "Injection by InjectorPID:" + item._InjectorPID.ToString() + "===>==TID:" +
                                           item._RemoteThreadID.ToString() + "==>==Injected into====>" + PIDName + ":" + PID

                                           + "\nInjector More Details:"
                                           + "\n" + NewProcess_Table.Find(_w => (_w.PID == item._InjectorPID && _w.CommandLine.Contains(temp_get_InjectorPN_from_description))).CommandLine
                                           + injector_path
                                           + "\n" + NewProcess_Table.Find(_w => _w.PID == item._InjectorPID).PPID_Path
                                           + "\nTarget Process More Details:"
                                           + "\nTarget Process Path:" + NewProcess_Table.Find(_w => _w.ProcessName.Substring(1) == item._TargetPIDName && _w.PID == item._TargetPID).ProcessName_Path
                                           + "\n"
                                           + "Injected Bytes:  (TID: " + item._RemoteThreadID.ToString() + ") " + " (StartAddress: " + item._ThreadStartAddress.ToString() + ")\n" + item.Injected_Memory_Bytes_Hex + "\n";
                                        }
                                    }
                                    last_tid = item._RemoteThreadID.ToString();
                                }


                            }
                            catch (Exception)
                            {

                            }
                        }

                        temptids.Clear();
                    }
                    else
                    {
                        richTextBox2.Text = "";
                        richTextBox3.Text = "";


                    }
                }));

            }
            catch (Exception)
            {


            }


        }

        /// <summary>
        /// C# Method , this method is for Show Memory scanner 01 details info about Detected process in Listview2 [Alarms by ETW Tab]         
        /// </summary>   
        public void _MemoryScanner_Pesieve_ShowObjects(object _PID)
        {
            try
            {
                Invoke(new Action(() =>
                {
                    int PID = Convert.ToInt32(_PID);

                    richTextBox7.Text = "";
                    string module = "";
                    string module_size = "";
                    string filename = "";
                   
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

                                richTextBox7.Text += item + "\n";
                            }

                        }
                    }
                    else
                    {
                        richTextBox7.Text = "";
                    }

                }));
            }
            catch (Exception rr)
            {

            }
        }

        private void DGreyToolStripMenuItem_Click(object sender, EventArgs e)
        {
            listView1.BackColor = Control.DefaultBackColor;
            listView1.HeaderStyle = ColumnHeaderStyle.Nonclickable;
            listView1.BorderStyle = BorderStyle.FixedSingle;
            listView1.ForeColor = Color.Black;
            listView2.BackColor = Control.DefaultBackColor;
            listView2.HeaderStyle = ColumnHeaderStyle.Nonclickable;
            listView2.BorderStyle = BorderStyle.FixedSingle;
            listView2.ForeColor = Color.Black;

            //richTextBox1.BackColor = Control.DefaultBackColor;
            //toolStripSeparator1.BackColor = Control.DefaultBackColor;
            //statusStrip1.BackColor = Control.DefaultBackColor;
            //menuStrip3.BackColor = Control.DefaultBackColor;
            //toolStripSeparator1.BackColor = Color.Black;
        }

        public void _Additems_str_toRichtextbox1(object str)
        {
            try
            {
                string Eventmessage = str.ToString();
                string[] events = Eventmessage.Split('\n');

                string TargetProcess = events[15].Split('>')[1].Substring(1) + ":" + events[8].Split('>')[1].Substring(1);
                string Injector = events[5].Substring(events[5].IndexOf("[Injected by ") + 13).Split(']')[0];

                if (!Injector.Contains(":"))
                {
                    Injector = events[5].Substring(events[5].IndexOf("[Injected by ") + 13).Split(']')[0]
                         + ":" + events[12].Split('>')[1].Substring(1);
                }

                string evettime = events[17].Split('>')[1].Substring(1);

                ListViewItem iList5 = new ListViewItem();
                
                iList5.SubItems.Add(TargetProcess);
                iList5.SubItems.Add(Injector);
                try
                {
                    if (Convert.ToInt32(events[46].Split(':')[1]) != 0)
                    {
                        iList5.ForeColor = Color.Red;
                        iList5.SubItems.Add(events[46].Split(':')[1].ToString());
                    }
                    else
                    {
                        iList5.SubItems.Add(events[46].Split(':')[1].ToString());
                    }
                }
                catch (Exception)
                {

                    iList5.SubItems.Add("0");
                }
                
                iList5.SubItems.Add(evettime);
                iList5.Name = Eventmessage;
                listView5.Items.Add(iList5);

                Thread.Sleep(20);

                BeginInvoke(new __core2(SaveETWLogs.AsyncRun__SaveNewETW_Alarms_to_WinEventLog2), iList5);

            }
            catch (Exception)
            {

            }
        }

        /// <summary>
        /// only detected proces in Alarms by ETW Tab will send to richtextbox1
        /// details info about remotethreadinjection and hex bytes 
        /// </summary>       
        public void InjectionMemoryInfoDetails_torichtectbox(object etwEvtMessage)
        {

            try
            {

                //324324323[ETW] 
                //[MEM] Injected ThreadStart Detected,

                string EventMessage = etwEvtMessage.ToString();
                string EventMessageRecordId = "0";

                ulong i32StartAddress = Convert.ToUInt64(EventMessage.Substring(EventMessage.IndexOf("::") + 2).Split(':')[0].Substring(2), 16);

                Int64 TID = Convert.ToInt64(EventMessage.Substring(EventMessage.IndexOf("::") - 8).Split(')', ':')[1]);
                Int32 prc = Convert.ToInt32(EventMessage.Substring(EventMessage.IndexOf("PID: (") + 6).Split(')')[0]);
                buf = new byte[208];
                buf = new byte[208];
                try
                {
                    IntPtr prch = System.Diagnostics.Process.GetProcessById(prc).Handle;
                    string pname = System.Diagnostics.Process.GetProcessById(prc).ProcessName;
                    string XStartAddress = EventMessage.Substring(EventMessage.IndexOf("::") + 2).Split(':')[0];
                    string _injector = EventMessage.Substring(EventMessage.IndexOf("::") + 2).Split(':')[2].Split('[')[0];
                    bool MemoryBytes = Memory_info.ReadProcessMemory(prch, (UIntPtr)i32StartAddress, buf, buf.Length, IntPtr.Zero);
                    string _buf = Memory_info.HexDump(buf);
                    string _bytes = BitConverter.ToString(buf).ToString();
                    /// added
                    ThreadStart __T5_info_for_additems_to_Richtextbox1 = new ThreadStart(delegate
                    {
                        BeginInvoke(new __Additem(_Additems_str_toRichtextbox1),
                        EventMessage + "\n\nEventID: " + "2" + "\nEventRecord_ID: " + EventMessageRecordId + "\n\n[Remote-Thread-Injection Memory Information]\n\tTID: " + TID.ToString() + "\n\tTID StartAddress: " +
                         XStartAddress.ToString() + "\n\tTID Win32StartAddress: " + i32StartAddress.ToString() + "\n\tTarget_Process PID: " + prc.ToString() +
                         "\n\nInjected Memory Bytes: " + _bytes + "\n\n" + _buf + "\n_____________________\n");
                    });

                    Thread _T5_for_additems_to_Richtextbox1 = new Thread(__T5_info_for_additems_to_Richtextbox1);
                    _T5_for_additems_to_Richtextbox1.Start();

                    if (_InjectedTIDList.FindIndex(startaddress => startaddress._ThreadStartAddress == XStartAddress
                    && startaddress._InjectorPID == Convert.ToInt32(_injector)) == -1)
                    {
                        if (Convert.ToInt32(_injector) != 4)
                        {
                            _InjectedTIDList.Add(new _InjectedThreadDetails_bytes
                            {
                                _TargetPID = prc,
                                _ThreadStartAddress = XStartAddress.ToString(),
                                _RemoteThreadID = Convert.ToInt32(TID),
                                Injected_Memory_Bytes = _bytes,
                                Injected_Memory_Bytes_Hex = _buf,
                                _InjectorPID = Convert.ToInt32(_injector),
                                _TargetPIDName = pname

                            });
                        }
                    }

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

        public void _SaveAlarmsByETW()
        {

            StringBuilder st = new StringBuilder();
            string dumpinfotext = richTextBox1.Text;
            StringBuilder lines = new StringBuilder(dumpinfotext);
            foreach (ListViewItem xitem in listView2.Items)
            {

                st.AppendLine("[#] Time: " + xitem.SubItems[1].Text + ", Process: " + xitem.SubItems[2].Text
                    + ", Injection-Type: " + xitem.SubItems[3].Text + ", TCP-Send: " + xitem.SubItems[4].Text +
                    ", Status: " + xitem.SubItems[5].Text);
                st.AppendLine("Memory Scanner Results:");
                st.AppendLine("Pe-sieve: " + xitem.SubItems[6].Text.Replace('\r', ' '));
                st.AppendLine("Hollows_Hunter: " + xitem.SubItems[7].Text.Replace('\r', ' '));
                st.AppendLine("Description:");
                st.AppendLine(xitem.SubItems[8].Text);
                st.AppendLine("ETW Event Message:");
                st.AppendLine(xitem.SubItems[9].Text);
                st.AppendLine(" ");
                st.AppendLine("Debug Info & Details:");
                string PIDName = xitem.SubItems[2].Text.Split(':')[0];
                string PID = xitem.SubItems[2].Text.Split(':')[1];
                int counter = 0;

                foreach (string item in lines.ToString().Split('\n'))
                {
                    if (item.Contains("Target_Process: " + PIDName + ":" + PID))
                    {
                        if (!item.Contains("TaskName(TcpIp)"))
                        {
                            st.AppendLine("[" + counter.ToString() + "] " + item);
                            counter++;
                        }
                    }
                    if ((item.Contains("Debug info:") && item.Contains("PID: (" + PID + ")(" + PIDName + ")")) && (!item.Contains("TaskName(TcpIp)")))
                    {
                        //"Debug info: [2/4/2022 5:58:26 PM] PID: (6592)(notepad) 10336::0x7ff7878c3db0:12408:3652[Injected by dotnet.exe:3652]"

                        if (!item.Contains("TaskName(TcpIp)"))
                        {
                            st.AppendLine("[" + counter.ToString() + "] " + item);
                            st.AppendLine("[" + counter.ToString() + "] " + "Injection by " + item.Substring(item.IndexOf("Injected by ")).Split(']')[0].Split(' ')[2] + "===>==TID:" +
                           item.Split(')')[2].Split(':')[0] + "==>==Injected into====>" + PIDName + ":" + PID + "\n\n");

                            st.AppendLine("ETW Event & Injection Details:\n");
                            try
                            {
                                var __tid = Convert.ToInt32(item.Split(')')[2].Split(':')[0]);
                                var _injector = Convert.ToInt32(item.Split('[')[1].Split(':')[7]);
                                _InjectedThreadDetails_bytes details = _InjectedTIDList.Find(_x => _x._RemoteThreadID == __tid && _x._TargetPID == Convert.ToInt32(PID) && _x._InjectorPID == _injector);

                                st.AppendLine("\nInjectorPID: " + details._InjectorPID.ToString() +
                                    "\nTargetPID: " + details._TargetPID.ToString() + "\nInjectedTID: " + details._RemoteThreadID.ToString() +
                                    "\nStartAddress: " + details._ThreadStartAddress + "\n\nInjectedBytes[HEX]:\n" + details.Injected_Memory_Bytes_Hex + "\n");
                            }
                            catch (Exception)
                            {


                            }
                        }
                    }


                }
                st.AppendLine("\nMemory Scanner Result:\n");
                st.AppendLine(xitem.Name);
                st.AppendLine("-------------------------------------------------------------------------");
                st.AppendLine(" ");
            }


            logfilewrite("ETWAlarmEvents.txt", st.ToString());
            MessageBox.Show("Alarms ETW Events Saved into Text File: \n \"ETWAlarmEvents.txt\"");
        }

        public void logfilewrite(string filename, string text)
        {
            if (IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [logfilewrite] Method Call: Started");
            //if(IsSystemDeveloperLogs_on) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [logfilewrite] Method Call: error1 => " + ee.Message);


            using (StreamWriter _file = new StreamWriter(filename))
            {
                _file.WriteLine(text);
            };
        }

        public static class Memory_info
        {
            [DllImport("kernel32.dll")]
            public static extern bool TerminateProcess(IntPtr hprocess, uint uExitCode);

            [DllImport("kernel32.dll")]
            public static extern bool GetExitCodeProcess(IntPtr hprocess, out uint lpExitCode);

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


                string[] Flag_to_detection_Bytes = new string[11];
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

                string NewResult = "";

                string[] tmp = result.ToString().Split('\n');
                string itemx = "";
                int FoundItem = 0;
                foreach (string item in tmp)
                {
                    foreach (string flag in Flag_to_detection_Bytes)
                    {
                        if (item.Contains(flag))
                        {
                            itemx = item.Replace('\r', ' ') + "        <====== Detected!" + "\n";
                            FoundItem++;
                            break;
                        }
                        else
                        {
                            itemx = item + "\n";
                        }
                    }

                    NewResult += itemx;
                }

                NewResult = NewResult + "\n-----------------------------------\nMZ Header Detection:" + FoundItem.ToString() 
                    + "\n----------------------------------------------------------------------\n";
                movjmp_info = "\n\n";
                for (int i = 0; i < bytes.Length; i++)
                {
                    // Search for mov instructions
                    if (i + 4 < bytes.Length && bytes[i] == 0xB8)
                    {
                        int value = BitConverter.ToInt32(bytes, i + 1);
                        string bytestr = BitConverter.ToString(bytes, i,20);
                        int destAddr =/* i +*/ value;
                        movjmp_info += 
                       ($"MOV instruction found at position {i} with source {value} and destination 0x{destAddr:x}") + $"\n=> {bytestr}\n";
                    }

                    // Search for jmp instructions
                    if (i + 4 < bytes.Length && bytes[i] == 0xE9)
                    {
                        int offset = BitConverter.ToInt32(bytes, i + 1);
                        string bytestr = BitConverter.ToString(bytes, i, 20);
                        int destAddr = i + 5 + offset;
                        movjmp_info += ($"JMP instruction found at position {i} with destination 0x{destAddr:x}") + $"\n=> {bytestr}\n";
                    }
                }

                return NewResult.ToString() + movjmp_info;

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

            public static int[] _FindAllIndex(string match ,string Source_to_Search, int StartIndex)
            {
                int found = -1;
                int count = 0;
                List<int> founditems = new List<int>();
                try
                {
                                   
                    Source_to_Search = Source_to_Search.ToUpper();
                    match = match.ToUpper();

                    do
                    {

                        found = Source_to_Search.IndexOf(match, StartIndex);
                        if (found > -1)
                        {
                            StartIndex = found + match.Length;
                            count++;
                            founditems.Add(found);
                        }

                    } while (found > -1 && StartIndex < Source_to_Search.Length);
                }
                catch (Exception)
                {


                }
                return ((int[])founditems.ToArray());
            } 

            public static string _Get_Arguments(Process Prcs)
            {
                string Prcs_args = "";

                try
                {
                    using (ManagementObjectSearcher _ExecutablePath = new ManagementObjectSearcher("SELECT ExecutablePath FROM Win32_Process WHERE ProcessId = " + Prcs.Id))
                    {
                        foreach (ManagementObject obj in _ExecutablePath.Get())
                        {
                            Prcs_args += obj["ExecutablePath"];
                        }
                    }
                    return Prcs_args;
                }
                catch (Exception) { return ""; }
            }

            public static byte[] Scan_Process_Memory(Process Prcs)
            {

                List<byte> memory = new List<byte>();
                try
                {
                    if (Prcs.HasExited)
                    {
                        buff = null;
                        return null;
                    }
                    try
                    {
                        IntPtr Addy = new IntPtr();
                        List<MEMORY_BASIC_INFORMATION> MemReg = new List<MEMORY_BASIC_INFORMATION>();
                        while (true)
                        {
                            if (!Prcs.HasExited)
                            {
                                MEMORY_BASIC_INFORMATION MemInfo = new MEMORY_BASIC_INFORMATION();
                                int MemDump = VirtualQueryEx(Prcs.Handle, Addy, out MemInfo, Marshal.SizeOf(MemInfo));
                                if (MemDump == 0) break;
                                if (0 != (MemInfo.State & MEM_COMMIT) && 0 != (MemInfo.Protect & WRITABLE) && 0 == (MemInfo.Protect & PAGE_GUARD))
                                {
                                    MemReg.Add(MemInfo);
                                }
                                Addy = new IntPtr(MemInfo.BaseAddress.ToInt64() + MemInfo.RegionSize.ToInt64());
                            }
                            if (Prcs.HasExited)
                            {

                                break;

                            }
                        }

                        for (int i = 0; i < MemReg.Count; i++)
                        {
                            if (Prcs.HasExited) { break; }
                            if (!Prcs.HasExited)
                            {
                                buff = new byte[MemReg[i].RegionSize.ToInt64()];
                                ReadProcessMemory(Prcs.Handle, MemReg[i].BaseAddress, buff, MemReg[i].RegionSize.ToInt32(), IntPtr.Zero);


                                for (int j = 0; j < buff.Length; j++)
                                {
                                    memory.Add((byte)(buff[j]));
                                    // buff[j] = (byte)(buff[j] ^ 0xFF);

                                }

                            }
                            if (Prcs.HasExited) { break; }
                        }

                        return memory.ToArray();

                    }
                    catch (Exception ee)
                    {


                    }

                }
                catch (Exception)
                {
                    return null;
                }

                return memory.ToArray();

            }

            public static string _CheckSizeChanges(int ProcessID)
            {

                string result = "";

                try
                {
                    string filename = _Get_Arguments(Process.GetProcessById(ProcessID));

                    // STARTUPINFO _STARTUPINFO = new STARTUPINFO();

                    // PROCESS_INFORMATION _ROCESS_INFORMATION = new PROCESS_INFORMATION();
                    // bool success = CreateProcess(filename, null,IntPtr.Zero, IntPtr.Zero, false,
                    // ProcessCreationFlags.CREATE_SUSPENDED,IntPtr.Zero, null, ref _STARTUPINFO, out _ROCESS_INFORMATION);


                    result += filename + "\n";
                    byte[] targetprocessbytes = Scan_Process_Memory(Process.GetProcessById(ProcessID));
                    long vms64 = Process.GetProcessById(Convert.ToInt32(ProcessID)).PrivateMemorySize64 / 1024;
                    long vms64p = Process.GetProcessById(Convert.ToInt32(ProcessID)).PagedMemorySize64 / 1024;

                    result += $"Target Process PID: {Convert.ToInt32(ProcessID).ToString()} Bytes:\n" + HexDump2(targetprocessbytes);

                    ProcessStartInfo _NewProcess_WithSameSourcePath = new ProcessStartInfo(filename);
                    _NewProcess_WithSameSourcePath.WindowStyle = ProcessWindowStyle.Hidden;
                    _NewProcess_WithSameSourcePath.UseShellExecute = true;

                    int pid = Process.Start(_NewProcess_WithSameSourcePath).Id;
                    long vms64_2 = Process.GetProcessById(pid).PrivateMemorySize64 / 1024;
                    long vms64_2p = Process.GetProcessById(pid).PagedMemorySize64 / 1024;


                    byte[] targetprocessbytes_original = null;

                    Thread.Sleep(1200);

                    targetprocessbytes_original = Scan_Process_Memory(Process.GetProcessById(pid));


                    NtSuspendProcess(Process.GetProcessById(pid).Handle);


                    result += "Same Source Process Bytes:\n" + HexDump2(targetprocessbytes_original);

                    result += "Target Process Memory (bytes Size):" + targetprocessbytes.Length / 1024
                        + ",  Same Source Process Memory (bytes Size):" + targetprocessbytes_original.Length / 1024;

                    result += "\nTarget Process PrivateMemorySize64:" + vms64
                       + ",  Same Source Process PrivateMemorySize64:" + vms64_2;
                    result += "\nTarget Process PagedMemorySize64:" + vms64p
                      + ",  Same Source Process PagedMemorySize64:" + vms64_2p;

                    Process.GetProcessById(pid).Kill();

                }
                catch (Exception)
                {
                    return result;
                }

                return result;
            }

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool ReadProcessMemory(IntPtr hProcess, UIntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, IntPtr lpNumberOfBytesRead);

            [DllImport("ntdll.dll", SetLastError = true)]
            public static extern NtStatus NtReadVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, UInt32 NumberOfBytesToRead, ref UInt32 NumberOfBytesRead);

            [DllImport("kernel32.dll", SetLastError = true)]
            static extern bool CloseHandle(UIntPtr hObject);

            [DllImport("Kernel32.dll")]
            public static extern uint QueryFullProcessImageName(IntPtr hProcess, uint flags, StringBuilder str, out uint size);

            [DllImport("kernel32.dll")]
            [return: MarshalAs(UnmanagedType.Bool)]
            private static extern bool SetProcessWorkingSetSize(IntPtr process, UIntPtr minimumWorkingSetSize, UIntPtr maximumWorkingSetSize);

            [DllImport("kernel32.dll", SetLastError = true)]
            static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, IntPtr lpNumberOfBytesRead);

            [DllImport("kernel32.dll")]
            static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, int dwLength);

            [DllImport("ntdll.dll", PreserveSig = false)]
            public static extern void NtSuspendProcess(IntPtr processHandle);

            [DllImport("ntdll.dll")]
            private static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, ref ParentProcessUtilities processInformation, int processInformationLength, out int returnLength);


            private const int PAGE_READWRITE = 0x04;
            private const int PAGE_WRITECOPY = 0x08;
            private const int PAGE_EXECUTE_READWRITE = 0x40;
            private const int PAGE_EXECUTE_WRITECOPY = 0x80;
            private const int PAGE_GUARD = 0x100;
            private const int WRITABLE = PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY | PAGE_GUARD;
            private const int MEM_COMMIT = 0x1000;
            public static byte[] buff;

            [StructLayout(LayoutKind.Sequential)]
            public struct MEMORY_BASIC_INFORMATION
            {
                public IntPtr BaseAddress;
                public IntPtr AllocationBase;
                public uint AllocationProtect;
                public IntPtr RegionSize;
                public uint State;
                public uint Protect;
                public uint Type;
            }
            [StructLayout(LayoutKind.Sequential)]
            public struct ParentProcessUtilities
            {
                internal IntPtr Reserved1;
                internal IntPtr PebBaseAddress;
                internal IntPtr Reserved2_0;
                internal IntPtr Reserved2_1;
                internal IntPtr UniqueProcessId;
                internal IntPtr InheritedFromUniqueProcessId;
            }

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
