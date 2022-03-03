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
        public static bool is_system4_excluded = true;
        public Int64 i6 = 0;
        public static System.Timers.Timer t = new System.Timers.Timer(10000);
        public static System.Timers.Timer t2 = new System.Timers.Timer(5000);
        public static System.Timers.Timer t3 = new System.Timers.Timer(5000);
        public static System.Timers.Timer t4 = new System.Timers.Timer(15000);
        public static System.Timers.Timer t4_1 = new System.Timers.Timer(1500);
        public static System.Timers.Timer t5 = new System.Timers.Timer(10000);

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


        public delegate void __MyDelegate_LogFileReader_Method();
        public delegate void __MyDelegate_showdatagrid();
        public delegate void __LogReader();
        public delegate void __Additem(object itemsOfListview1_2_5_6);
        public delegate void __AddTextTorichtexhbox1(object str);
        public delegate void __core2(object str);
        public delegate void __Updatelistview1();
        public delegate void __Obj_Updater_to_WinForm();
      

        public static List<_All_Injection_Details_info_Filter_withoutSystem4> _List_All_Injection_Details_info_Filter_withoutSystem4 = new List<_All_Injection_Details_info_Filter_withoutSystem4>();
        public struct _All_Injection_Details_info_Filter_withoutSystem4
        {
       
            public string _time_evt { set; get; }
            public string _ThreadStartAddress { set; get; }
            public Int32 _RemoteThreadID { set; get; }
            public Int32 _TargetPID { set; get; }
            public string _TargetPID_Path { set; get; }
            public Int32 _InjectorPID { set; get; }
            public string _InjectorPID_Path { set; get; }
            
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
            public string TCPDetails;
            public string Description;
            public int PID;
            public int Injector;
            public string Injector_Path;
            public string ProcessName;
            public string ProcessName_Path;
            public bool IsLive;
            public bool IsShow { set; get; }
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
        }

        public static List<_TableofProcess_Scanned_01> Scanned_PIds = new List<_TableofProcess_Scanned_01>();
        public static string strOutput = "";
        public static System.Diagnostics.Process outputs = new System.Diagnostics.Process();
        public static bool Init_to_runPEScanner_01 = false;

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
        public static string subitemX = "";
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

        public static List<_TableofProcess_ETW_Event_Counts> _ETW_Events_Counts = new List<_TableofProcess_ETW_Event_Counts>();
        public static _TableofProcess_ETW_Event_Counts Temp_Table_structure;
        public static string evtstring2, evtstring3 = "";
        public static Int32 ListiveItemCount = 1000;
        public static Int32 counter_for_tcp_packets_filter = 0;
        public static bool IsSearchFormActived = false;
        public static bool show_tcp_packets_filter = false;
        public static bool _StopLoopingScan_Exec_01 = false;
        public static bool _StopLoopingScan_Exec_02 = false;
        public static bool ScannerMixedMode_Pesieve = false;
        public static bool ScannerEvery10minMode_Pesieve = false;
        public static bool ScannerMixedMode_Hollowh = false;
        public static bool ScannerEvery10minMode_Hollowh = false;
        public static string eventstring_tmp3 = "";
        public static bool NetworkConection_found = false;
        public static Int64 NetworkConection_TCP_counts = 0;
        public static bool IsTargetProcessTerminatedbyETWPM2monitor = false;
        public static string _windir = Environment.GetEnvironmentVariable("windir").ToLower();
        public static NotifyIcon ico = new NotifyIcon();
        public static bool _isNotifyEnabled = true;

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

        /// <summary>
        /// save this obj as event which was detected as Shell or TCP Meterpreter session to Windows EventLog "ETWPM2Monitor2"
        /// </summary>
        /// <param name="Obj"></param>
        public static void _Save_New_DetectionLogs_TCP_Shell_Events_to_WinEventLog(object Obj)
        {
            try
            {

                ListViewItem _items_Objects = (ListViewItem)Obj;

                ETW2MON = new EventLog("ETWPM2Monitor2", ".", "ETWPM2Monitor2.1");

                StringBuilder st = new StringBuilder();

                st.AppendLine("[#] Time: " + _items_Objects.SubItems[1].Text + ", Process: " + _items_Objects.SubItems[2].Text.Replace('\r', ' ').Replace('\n', ' ')
                    + ", Status: " + _items_Objects.SubItems[3].Text + "\nETW Event Type: " + _items_Objects.SubItems[4].Text +
                    " , Actions: " + _items_Objects.SubItems[5].Text + "\n\nEvent Message: " + "\n" + _items_Objects.Name);

                if (_items_Objects.SubItems[3].Text.Contains("Found Shell"))
                {
                    string simpledescription = "[#] Time: " + _items_Objects.SubItems[1].Text + "\n" + _items_Objects.SubItems[3].Text + " via Process: "
                        + _items_Objects.SubItems[2].Text.Replace('\r', ' ').Replace('\n', ' ') + " Detected by ETWPM2Monitor2 (Detection High level)!\n"
                     + "------------------------------------------------------------\n";
                    ETW2MON.WriteEntry(simpledescription + st.ToString(), EventLogEntryType.Warning, 4);
                }

                if (_items_Objects.SubItems[3].Text.Contains("Suspicious Traffic [Meterpreter!]"))
                {
                    string simpledescription = "[#] Time: " + _items_Objects.SubItems[1].Text + "\n" + _items_Objects.SubItems[3].Text + " via Process: "
                        + _items_Objects.SubItems[2].Text.Replace('\r', ' ').Replace('\n', ' ') + " Detected by ETWPM2Monitor2 (Detection Medium level)!\n"
                     + "------------------------------------------------------------\n";
                    ETW2MON.WriteEntry(simpledescription + st.ToString(), EventLogEntryType.Information, 3);
                }
            }
            catch (Exception)
            {


            }
        }

        /// <summary>
        ///  save all Alarms like "Terminated,Suspended,Scannedfound,Detected" by Memory scanners etc to windows eventlog "ETWPM2Monitor2". Event ID1 (Medium Level) , Event ID2 (High Level)
        /// </summary>
        /// <param name="AlarmObjects"></param>
        public static void _SaveNewETW_Alarms_to_WinEventLog(object AlarmObjects)
        {
            try
            {

                ETW2MON = new EventLog("ETWPM2Monitor2", ".", "ETWPM2Monitor2.1");
                ListViewItem __AlarmObject = (ListViewItem)AlarmObjects;

                StringBuilder st = new StringBuilder();

                ListViewItem xitem = __AlarmObject;

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

                st.AppendLine(" ");


                if (__AlarmObject.SubItems[5].Text.Contains("Terminated") ||
                    __AlarmObject.SubItems[5].Text.Contains("Suspended") ||
                    __AlarmObject.SubItems[5].Text.Contains("Scanned & Found") ||
                     __AlarmObject.SubItems[7].Text.Contains(">>Detected") ||
                    Convert.ToInt32(string.Join("", ("0" + __AlarmObject.SubItems[6].Text).Where(char.IsDigit)).ToString()) > 0)
                {
                    string simpledescription = "[#] Time: " + xitem.SubItems[1].Text + "\nProcess: " + xitem.SubItems[2].Text + " Detected by ETWPM2Monitor2 (Detection High level)!\n"
                        + "------------------------------------------------------------\n";
                    ETW2MON.WriteEntry(simpledescription + st.ToString(), EventLogEntryType.Warning, 2);
                }
                else
                {
                    string simpledescription = "[#] Time: " + xitem.SubItems[1].Text + "\nProcess: " + xitem.SubItems[2].Text + " Detected by ETWPM2Monitor2 (Detection Medium level)!\n"
                      + "------------------------------------------------------------\n";
                    ETW2MON.WriteEntry(simpledescription + st.ToString(), EventLogEntryType.Information, 1);
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
                                MyLviewItemsX1.BackColor = Color.Gray;
                                MyLviewItemsX1.ForeColor = Color.White;

                            }

                            MyLviewItemsX1.SubItems[5].Text += "\n\n#This Description Added by ETWPM2Monitor2 tool#\n##Warning Description: Packet with [size:160] maybe was for Meterpreter Session which will send every 1 min between Client/Server##\n" +
                            "##Warning Description: Packet with [size:192] is for meterpreter session which will send before every command excution from/to server##\n" +
                            "##Warning Description: DestinationPort [dport:4444] is Default port for Meterpreter session##";

                            System_Detection_Log_events2.Invoke((object)MyLviewItemsX1, null);

                        } else if (MyLviewItemsX1.SubItems[5].Text.Split('\n')[6].Contains("[dport:4444]"))
                        {
                            MyLviewItemsX1.BackColor = Color.LightSlateGray;
                            MyLviewItemsX1.ForeColor = Color.White;

                            MyLviewItemsX1.SubItems[5].Text += "\n\n#This Description Added by ETWPM2Monitor2 tool#\n##Warning Description: Packet with [size:160] maybe was for Meterpreter Session which will send every 1 min between Client/Server##\n" +
                               "##Warning Description: Packet with [size:192] is for meterpreter session which will send before every command excution from/to server##\n" +
                               "##Warning Description: DestinationPort [dport:4444] is Default port for Meterpreter session##";
                            System_Detection_Log_events2.Invoke((object)MyLviewItemsX1, null);
                        }

                        listView1.Items.Add(MyLviewItemsX1);
                    }

                    /// EventID 1 = Create New Process
                    if (MyLviewItemsX1.SubItems[2].Text == "1")
                    {
                        string commandline = MyLviewItemsX1.SubItems[5].Text.Split('\n')[4].ToLower();
                        string parentid = MyLviewItemsX1.SubItems[5].Text.Split('\n')[6].ToLower();
                        if (commandline.Contains("[commandline: "+ _windir +"\\system32\\cmd.exe") || commandline.Contains("[commandline: cmd"))
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

                        listView1.Items.Add(MyLviewItemsX1);

                    }
                    /// EventID 2 = Injection
                    if (MyLviewItemsX1.SubItems[2].Text == "2")
                    {
                        listView1.Items.Add(MyLviewItemsX1);
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
            try
            {
                Thread.Sleep(1);
                bool found = false;
                if (MyLviewItemsX2 != null)
                {

                   
                    if (MyLviewItemsX2.SubItems[9].Text == "")
                    {
                        if (MyLviewItemsX2.SubItems[5].Text.Contains("Terminated") || MyLviewItemsX2.SubItems[5].Text.Contains("Suspended"))
                        {
                            if (MyLviewItemsX2.Name != tmpitemListview2)
                            {
                                listView2.Items.Add(MyLviewItemsX2);
                                BeginInvoke(new __core2(_SaveNewETW_Alarms_to_WinEventLog), MyLviewItemsX2);

                                //_SaveNewETW_Alarms_to_WinEventLog(MyLviewItemsX2);
                                Thread.Sleep(10);
                                tabPage4.Text = "Alarms by ETW " + "(" + listView2.Items.Count.ToString() + ")";
                                toolStripStatusLabel6.Text = "| Alarms by ETW " + "(" + listView2.Items.Count.ToString() + ")";
                            }

                            if (MyLviewItemsX2.ImageIndex == 1) { Chart_Orange++; }
                            else if (MyLviewItemsX2.ImageIndex == 2) { Chart_Redflag++; }

                            if (MyLviewItemsX2.SubItems[5].Text.Contains("Terminated")) Chart_Terminate++;

                            if (MyLviewItemsX2.SubItems[5].Text.Contains("Suspended")) Chart_suspend++;

                            tmpitemListview2 = MyLviewItemsX2.Name;
                        }

                    }
                    else
                    {
                        if (MyLviewItemsX2.Name != tmpitemListview2)
                        {
                            listView2.Items.Add(MyLviewItemsX2);
                            BeginInvoke(new __core2(_SaveNewETW_Alarms_to_WinEventLog), MyLviewItemsX2);

                            //_SaveNewETW_Alarms_to_WinEventLog(MyLviewItemsX2);
                            Thread.Sleep(10);
                            tabPage4.Text = "Alarms by ETW " + "(" + listView2.Items.Count.ToString() + ")";
                            toolStripStatusLabel6.Text = "| Alarms by ETW " + "(" + listView2.Items.Count.ToString() + ")";
                        }
                        if (MyLviewItemsX2.ImageIndex == 1) { Chart_Orange++; }
                        else if (MyLviewItemsX2.ImageIndex == 2) { Chart_Redflag++; }

                        if (MyLviewItemsX2.SubItems[5].Text.Contains("Terminated")) Chart_Terminate++;

                        if (MyLviewItemsX2.SubItems[5].Text.Contains("Suspended")) Chart_suspend++;

                        tmpitemListview2 = MyLviewItemsX2.Name;
                    }

                    if (MyLviewItemsX2.SubItems[9].Text != "")
                    {
                        InjectionMemoryInfoDetails_torichtectbox(MyLviewItemsX2.SubItems[9].Text);
                    }


                    Thread.Sleep(5);

                    List_ofProcess_inListview2.Add(MyLviewItemsX2.Name.Split(':')[0] + ":" + MyLviewItemsX2.Name.Split(':')[1].Split('>')[0]);

                    evtstring2 = MyLviewItemsX2.Name;

                    /// time to search in list of injected thread for showing Hex one by one for all injector to target pid....
                    /// 
                    List<_All_Injection_Details_info_Filter_withoutSystem4> _TidDetails =
            _List_All_Injection_Details_info_Filter_withoutSystem4.FindAll(_y =>
            _y._TargetPID == Convert.ToInt32(MyLviewItemsX2.Name.Split(':')[1].Split('>')[0]));

                    foreach (_All_Injection_Details_info_Filter_withoutSystem4 _itemX in _TidDetails)
                    {
                        _DumpMemoryInfo_Injected_Bytes(_itemX._ThreadStartAddress, _itemX._RemoteThreadID, _itemX._TargetPID, _itemX._InjectorPID.ToString());

                    }

                 

                }



            }
            catch (Exception ee)
            {


            }

        }

        /// <summary>
        /// add items to SystemDetection Logs like [meterpreter session,foundshell and all alarms by etw] 
        /// </summary>
        /// <param name="obj"></param>
        public void _Additems_toListview3(object obj)
        {
            ListViewItem MyLviewItemsX6 = (ListViewItem)obj;
            try
            {

                Thread.Sleep(10);
                if (MyLviewItemsX6 != null)
                {
                    if (MyLviewItemsX6.Name != evtstring3)
                    {

                        listView3.BeginUpdate();
                        listView3.Items.Add(MyLviewItemsX6);
                        listView3.Update();
                        listView3.EndUpdate();
                        evtstring3 = MyLviewItemsX6.Name;
                        Thread.Sleep(50);

                        if (_isNotifyEnabled)
                        {
                            if (MyLviewItemsX6.SubItems[3].Text.Contains("Scanned & Found")
                                || MyLviewItemsX6.SubItems[3].Text.Contains("Suspended")
                                || MyLviewItemsX6.SubItems[3].Text.Contains("Terminated"))
                                _Show_Notify_Ico_Popup(MyLviewItemsX6);
                        }
                    }
                }
                tabPage3.Text = "System/Detection Logs " + "(" + listView3.Items.Count.ToString() + ")";
                toolStripStatusLabel5.Text = "| System/Detection Logs " + "(" + listView3.Items.Count.ToString() + ")";

            }
            catch (Exception ee)
            {

            }

        }

        public void Update_Richtexbox8_SystemDetection_ETW_AllDetails_info()
        {
            try
            {
                richTextBox8.Text = listView3.SelectedItems[0].Name;
            }
            catch (Exception)
            {


            }

        }
        
        /// <summary>
        /// dump all details info about Injected ThreadId , StartAddress , Hex bytes and more also add them to richtextbox1 Realtime text Tab
        /// </summary>       
        public void _DumpMemoryInfo_Injected_Bytes(string _i32StartAddress , Int32 _InjectedTID , Int32 _TPID , string _InjectorPID)
        {
            string d = _i32StartAddress.Substring(2);
            ulong i32StartAddress = Convert.ToUInt64(_i32StartAddress.Substring(3), 16);

            Int64 TID = Convert.ToInt64(_InjectedTID);
            Int32 prc = _TPID;
            buf = new byte[208];
            buf = new byte[208];
            try
            {
                IntPtr prch = System.Diagnostics.Process.GetProcessById(prc).Handle;
                string pname = System.Diagnostics.Process.GetProcessById(prc).ProcessName;
                string XStartAddress = _i32StartAddress;
                string _injector = _InjectorPID;
                bool MemoryBytes = Memoryinfo.ReadProcessMemory(prch, (UIntPtr)i32StartAddress, buf, buf.Length, IntPtr.Zero);
                string _buf = Memoryinfo.HexDump(buf);
                string _bytes = BitConverter.ToString(buf).ToString();
               
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
            catch (Exception)
            {
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
            if(input >= 1)
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
        public static string Delta_Time(DateTime currenttime_for_packet , DateTime lasttime_for_packet)
        {
            DateTime date1 = lasttime_for_packet;
            DateTime date2 = currenttime_for_packet;
            TimeSpan _ts = date2 - date1;
            
           
            return "D:" + Setinputs(_ts.TotalDays) + " or " + "H:" + Setinputs(_ts.TotalHours) + " or " + "M:" + _ts.TotalMinutes.ToString();
        }

        public void StartQueries_Mon(string queries)
        {
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
                string _Query = queries.ToString();
                EvtWatcher.Dispose();
                ETWPM2Query = new EventLogQuery("ETWPM2", PathType.LogName, _Query);

                EvtWatcher = new EventLogWatcher(ETWPM2Query);
                EvtWatcher.EventRecordWritten += Watcher_EventRecordWritten;
                EvtWatcher.Enabled = true;
                toolStripStatusLabel1.Text = "Monitor Status: on";
            }
            catch (Exception)
            {


            }
        }

        /// <summary>
        /// core code for realtime monitoring Windows eventlog "ETWPM2".
        /// </summary>
        public void _Core()
        {
            try
            {
                string Query = "*";
                ETWPM2Query = new EventLogQuery("ETWPM2", PathType.LogName);

                EvtWatcher = new EventLogWatcher(ETWPM2Query);
                EvtWatcher.EventRecordWritten += Watcher_EventRecordWritten;

                EvtWatcher.Enabled = true;
                toolStripStatusLabel1.Text = "Monitor Status: on";
            }
            catch (Exception)
            {

                
            }
           
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            try
            {
                /// very important  
                Form.CheckForIllegalCrossThreadCalls = false;


                ThreadStart Core = new ThreadStart(delegate { BeginInvoke(new __Obj_Updater_to_WinForm(_Core)); });
                Thread _T1_Core1 = new Thread(Core);
                _T1_Core1.Priority = ThreadPriority.Highest;
                _T1_Core1.Start();
                try
                {
                    /// added in v2.1 => All Alarms will save to Windows EventLog "ETWPM2Monitor2" (run as admin)
                    if (!EventLog.Exists("ETWPM2Monitor2"))
                    {
                        EventSourceCreationData ESCD = new EventSourceCreationData("ETWPM2Monitor2.1", "ETWPM2Monitor2");
                        System.Diagnostics.EventLog.CreateEventSource(ESCD);

                    }
                    ETW2MON = new EventLog("ETWPM2Monitor2", ".", "ETWPM2Monitor2.1");
                    ETW2MON.WriteEntry("ETWPM2Monitor2 v2.1 Started", EventLogEntryType.Information, 255);
                }
                catch (Exception)
                {


                }

                listView1.SmallImageList = imageList1;

                listView4.SmallImageList = imageList1;

                listView2.HeaderStyle = ColumnHeaderStyle.Nonclickable;
                listView2.BorderStyle = BorderStyle.FixedSingle;
                listView1.HeaderStyle = ColumnHeaderStyle.Nonclickable;
                listView1.BorderStyle = BorderStyle.FixedSingle;
                listView3.HeaderStyle = ColumnHeaderStyle.Nonclickable;
                listView3.BorderStyle = BorderStyle.FixedSingle;


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
                t4.Elapsed += T4_Elapsed;
                t4.Enabled = true;
                t4.Start();
                t4_1.Elapsed += T4_1_Elapsed;
                t4_1.Enabled = true;
                t4_1.Start();

                t5.Elapsed += T5_Elapsed;
                t5.Enabled = true;
                t5.Start();

                //t3.Elapsed += T3_Elapsed;
                //t3.Enabled = true;
                //t3.Start();


                listView1.Columns.Add(" ", 20, HorizontalAlignment.Left);
                listView1.Columns.Add("Time", 130, HorizontalAlignment.Left);
                listView1.Columns.Add("EventID", 55, HorizontalAlignment.Left);
                listView1.Columns.Add("Process", 170, HorizontalAlignment.Left);
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

                listView2.Columns.Add(" ", 20, HorizontalAlignment.Left);
                listView2.Columns.Add("LocalTime", 130, HorizontalAlignment.Left);
                listView2.Columns.Add("Process", 140, HorizontalAlignment.Left);
                listView2.Columns.Add("Injection-Type", 100, HorizontalAlignment.Left);
                listView2.Columns.Add("Tcp Sends", 120, HorizontalAlignment.Left);
                listView2.Columns.Add("Status", 100, HorizontalAlignment.Left);
                listView2.Columns.Add("PE-Sieve Pe:Shell:Replaced", 250, HorizontalAlignment.Left);
                listView2.Columns.Add("HollowsHunter Pe:", 250, HorizontalAlignment.Left);
                listView2.Columns.Add("Description", 250, HorizontalAlignment.Left);
                listView2.Columns.Add("EventMessage", 1000, HorizontalAlignment.Left);
 

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
                listView3.Columns.Add("Time", 130, HorizontalAlignment.Left);
                listView3.Columns.Add("Process", 180, HorizontalAlignment.Left);
                listView3.Columns.Add("Status", 180, HorizontalAlignment.Left);
                listView3.Columns.Add("Detection by ETW Events Inj:New:Tcp", 200, HorizontalAlignment.Left);
                listView3.Columns.Add("Actions Scanned:Suspended:Terminated", 220, HorizontalAlignment.Left);
                listView3.Columns.Add("Memory Scanner", 200, HorizontalAlignment.Left);


                listView4.SmallImageList = imageList1;
                /// Set the view to show details.
                listView4.View = View.Details;
                /// Allow the user to edit item text.
                listView4.LabelEdit = false;
                /// Allow the user to rearrange columns.
                listView4.AllowColumnReorder = true;
                /// Display check boxes.
                listView4.CheckBoxes = false;
                /// Select the item and subitems when selection is made.
                listView4.FullRowSelect = true;
                /// Display grid lines.
                listView4.GridLines = false;
                listView4.Sorting = SortOrder.Ascending;
                listView4.Columns.Add(" ", 20, HorizontalAlignment.Left);
                listView4.Columns.Add("Time", 124, HorizontalAlignment.Left);
                listView4.Columns.Add("Process", 180, HorizontalAlignment.Left);
                listView4.Columns.Add("Status", 64, HorizontalAlignment.Left);
                listView4.Columns.Add("Source IP:Port", 120, HorizontalAlignment.Left);
                listView4.Columns.Add("Destination IP:Port", 120, HorizontalAlignment.Left);
                listView4.Columns.Add("Delta Time (Days or Hours or Minutes)", 187, HorizontalAlignment.Left);
                listView4.Columns.Add("Event Count", 77, HorizontalAlignment.Left);
                listView4.Columns.Add("Event TTL (D:H:Minutes)", 135, HorizontalAlignment.Left);
                listView4.Columns.Add("Event First Time", 130, HorizontalAlignment.Left);

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

                removeRealtimeRecordsAfter1000RecordsToolStripMenuItem.Checked = true;

                BeginInvoke(new __Obj_Updater_to_WinForm(_RunRemoveItemsLisview1));
               
            }
            catch (EventLogReadingException err)
            {

            }
        }

        /// <summary>
        /// time for refresh listview4 [network connections Tab] items and verfiy tcp connection for each items [realtime] to change their imageindex (refresh every 10sec) 
        /// </summary>        
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
                            //listView4.Refresh();
                        }
                    }
                    listView4.Refresh();
                });
            }
            catch (Exception)
            {


            }
        }

        /// <summary>
        /// timer to refresh listview4 [network connection Tab] and change colors to white (delay 25millisec) 
        /// </summary>        
        private void T4_1_Elapsed(object sender, System.Timers.ElapsedEventArgs e)
        {
            try
            {
                System.Threading.Thread.Sleep(25);
                /// for sure check all index ;)
                for (int ii = 0; ii < listView4.Items.Count; ii++)
                {

                    listView4.Items[ii].BackColor = Color.White;

                }
                listView4.Refresh();

            }
            catch (Exception)
            {


            }
            t4_1.Enabled = false;
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
            BeginInvoke(new __Additem(Refresh_NetworkConection_in_Network_Tab), sender);
        }
  
        public async Task _ChangedProperty_Color_changed_delay(object itemid)
        {
            try
            {

                await new TaskFactory().StartNew(() =>
                {
                    listView4.Items[(int)itemid].BackColor = Color.Red;
                    listView4.Items[(int)itemid].SubItems[0].Text = "*";
                    listView4.Refresh();
                    ChangeColorstoDefault.Invoke((object)itemid, null);
                    System.Threading.Thread.Sleep(5);
                    listView4.BackColor = Color.White;
                    listView4.Refresh();
                    
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

                ListViewItem NetworkTCP = (ListViewItem)obj;
                ListViewItem __obj = (ListViewItem)obj;
                string sip = __obj.SubItems[5].Text.Split('\n')[6].Split(']')[2].Split(':')[1];
                string sip_port = __obj.SubItems[5].Text.Split('\n')[6].Split(']')[4].Split(':')[1];
                string dip = __obj.SubItems[5].Text.Split('\n')[6].Split(']')[1].Split(':')[1];
                string dip_port = __obj.SubItems[5].Text.Split('\n')[6].Split(']')[3].Split(':')[1];
                NetworkTCP.Name = __obj.SubItems[3].Text + sip + sip_port + dip + dip_port;
                iList4 = new ListViewItem();

                if (listView4.Items.Count > 0)
                {
                    for (int i = 0; i < listView4.Items.Count; i++)
                    {
                        if (listView4.Items[i].Name != __obj.SubItems[3].Text + sip + dip + dip_port)
                        {
                            NetworkConection_found = false;

                        }
                        else if (listView4.Items[i].Name == __obj.SubItems[3].Text + sip + dip + dip_port)
                        {
                            listView4.Items[i].SubItems[6].Text = Delta_Time(Convert.ToDateTime(__obj.SubItems[1].Text), Convert.ToDateTime(listView4.Items[i].SubItems[1].Text));
                            listView4.Items[i].SubItems[1].Text = NetworkTCP.SubItems[1].Text;
                            listView4.Items[i].SubItems[4].Text = sip + ":" + sip_port;
                            NetworkConection_TCP_counts = Convert.ToInt64(listView4.Items[i].SubItems[7].Text);
                            NetworkConection_TCP_counts++;
                            listView4.Items[i].SubItems[7].Text = NetworkConection_TCP_counts.ToString();
                            TimeSpan _ttl = Convert.ToDateTime(NetworkTCP.SubItems[1].Text) - Convert.ToDateTime(listView4.Items[i].SubItems[9].Text);
                            listView4.Items[i].SubItems[8].Text = "D:" +_ttl.Days.ToString() + " , H:" + _ttl.Hours.ToString() + " , M:" + _ttl.Minutes.ToString();
                            listView4.Refresh();                            
                            BeginInvoke(new __Additem(_Run_ChangeColor_for_listview4), i);
                            NetworkConection_found = true;
                            tabPage9.Text = "Network Connections (" + listView4.Items.Count.ToString() + ")";
                            toolStripStatusLabel7.Text= "| Network Connections (" + listView4.Items.Count.ToString() + ")";
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
                        iList4.Name = __obj.SubItems[3].Text + sip  + dip + dip_port;
                        int _i = listView4.Items.Add(iList4).Index;                        
                        BeginInvoke(new __Additem(_Run_ChangeColor_for_listview4), _i);
                        tabPage9.Text = "Network Connections (" + listView4.Items.Count.ToString() + ")";
                        toolStripStatusLabel7.Text = "| Network Connections (" + listView4.Items.Count.ToString() + ")";

                    }
                }
                else if (listView4.Items.Count <= 0)
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
                    iList4.Name = __obj.SubItems[3].Text + sip  + dip + dip_port;
                    int _i = listView4.Items.Add(iList4).Index;                    
                    BeginInvoke(new __Additem(_Run_ChangeColor_for_listview4), _i);
                    tabPage9.Text = "Network Connections (" + listView4.Items.Count.ToString() + ")";
                    toolStripStatusLabel7.Text = "| Network Connections (" + listView4.Items.Count.ToString() + ")";


                }
            }
            catch (Exception err)
            {
 
            }
        }

        /// <summary>
        /// add detected events to System_Detection_Logs Tab , for TCP Meterpreter events and Found Shell events (only)
        /// </summary>        
        private void Form1_System_Detection_Log_events2(object sender, EventArgs e)
        {
            try
            {

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
                            bool found = false;
                            for (int i = 0; i < listView3.Items.Count; i++)
                            {
                                if (listView3.Items[i].SubItems[2].Text + listView3.Items[i].SubItems[3].Text == tmp2.SubItems[3].Text + "[!] Suspicious Traffic [Meterpreter!]")
                                {
                                    found = true;
                                }
                            }
                            if (!found)
                            {
                                BeginInvoke(new __Additem(_Additems_toListview3), iList3);
                                eventstring_tmp3 = tmp2.Name;
                                BeginInvoke(new __core2(_Save_New_DetectionLogs_TCP_Shell_Events_to_WinEventLog), iList3);
                            }
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
                            bool found = false;
                            for (int i = 0; i < listView3.Items.Count; i++)
                            {
                                if (listView3.Items[i].SubItems[2].Text + listView3.Items[i].SubItems[3].Text == tmp2.SubItems[3].Text + "[!] Suspicious Traffic [Meterpreter!]")
                                {
                                    found = true;
                                }
                            }
                            if (!found)
                            {
                                BeginInvoke(new __Additem(_Additems_toListview3), iList3);
                                eventstring_tmp3 = tmp2.Name;
                                BeginInvoke(new __core2(_Save_New_DetectionLogs_TCP_Shell_Events_to_WinEventLog), iList3);

                            }
                        }
                    }
                }

                if (tmp2.SubItems[2].Text == "1")
                {
                    string commandline = tmp2.SubItems[5].Text.Split('\n')[4].ToLower();
                    string parentid = tmp2.SubItems[5].Text.Split('\n')[5].ToLower();
                    string Shell_Pid = tmp2.SubItems[5].Text.Split('\n')[2].Substring(6).Split(' ')[0];

                    if (commandline.Contains("[commandline: " + _windir + "\\system32\\cmd.exe") || commandline.Contains("[commandline: cmd"))
                    {

                        if (parentid != "[parentid path: " + _windir + "\\explorer.exe]")
                        {
                            iList3 = new ListViewItem();
                            iList3.Name = tmp2.SubItems[5].Text;
                            iList3.SubItems.Add(tmp2.SubItems[1].Text);
                            iList3.SubItems.Add(tmp2.SubItems[3].Text + ":" + Shell_Pid + " (with " + parentid + ")");

                            iList3.SubItems.Add("[!] Found Shell");
                            iList3.SubItems.Add("ETW [New] event");
                            iList3.SubItems.Add("Event Detected!");


                            iList3.SubItems.Add("--");
                            iList3.ImageIndex = 2;
                            if (tmp2.Name != eventstring_tmp3)
                            {
                                bool found = false;
                                for (int i = 0; i < listView3.Items.Count; i++)
                                {
                                    if ((listView3.Items[i].SubItems[2].Text + listView3.Items[i].SubItems[3].Text) == (tmp2.SubItems[3].Text + "[!] Found Shell"))
                                    {
                                        found = true;
                                    }
                                }
                                if (!found)
                                {
                                    BeginInvoke(new __Additem(_Additems_toListview3), iList3);
                                    eventstring_tmp3 = tmp2.Name;
                                    BeginInvoke(new __core2(_Save_New_DetectionLogs_TCP_Shell_Events_to_WinEventLog), iList3);

                                }
                            }
                        }
                    }
                    else
                    {

                    }

                    
                }
            }
            catch (Exception)
            {

                 
            }
        }

        /// <summary>
        /// add detected events to System_Detection_Logs Tab , for Injections events (only)
        /// </summary>       
        private void Form1_System_Detection_Log_events(object sender, EventArgs e)
        {
            try
            {

                ListViewItem tmp = (ListViewItem)sender;

                if (tmp.SubItems[3].Text.ToString() == "Injection" || tmp.SubItems[3].Text.ToString() == "Process-Hollowing")
                {
                    Thread.Sleep(100);
                    ///  detecting etw event
                    iList3 = new ListViewItem();
                    iList3.Name = tmp.Name;
                    iList3.SubItems.Add(tmp.SubItems[1].Text);
                    iList3.SubItems.Add(tmp.SubItems[2].Text);
                    if (tmp.SubItems[5].Text == "--")
                    {
                        if (Convert.ToInt32(string.Join("", ("0" + tmp.SubItems[6].Text).ToCharArray().Where(char.IsDigit)).ToString()) > 0 
                            || tmp.SubItems[7].Text.Contains(">>Detected"))
                        {
                            iList3.SubItems.Add("[!] Found Suspicious");
                            iList3.SubItems.Add("ETW [Inj] event");
                            iList3.SubItems.Add("Scanned & Found!");
                        }
                        else
                        {
                            iList3.SubItems.Add("[!] Found Suspicious");
                            iList3.SubItems.Add("ETW [Inj] event");
                            iList3.SubItems.Add("Scanned");
                        }
                           
                    }
                    else
                    {
                        iList3.SubItems.Add("[!] " + tmp.SubItems[5].Text);
                        iList3.SubItems.Add("ETW [Inj] event");
                        iList3.SubItems.Add(tmp.SubItems[5].Text);
                    }

                    iList3.SubItems.Add("PESieve & HollowsHunter.exe");
                    iList3.ImageIndex = tmp.ImageIndex;
                    if (tmp.Name != eventstring_tmp3 )
                    {
                        bool found = false;
                        for (int i = 0; i < listView3.Items.Count; i++)
                        {
                            if (listView3.Items[i].SubItems[2].Text + listView3.Items[i].SubItems[4].Text == tmp.SubItems[2].Text + "ETW [Inj] event")
                            {
                                found = true;
                            }
                        }
                        if (!found)
                        {
                            BeginInvoke(new __Additem(_Additems_toListview3), iList3);
                            eventstring_tmp3 = tmp.Name;
                        }

                        if (tmp.SubItems[5].Text=="Terminated" || tmp.SubItems[5].Text == "Suspended")
                        {
                            BeginInvoke(new __Additem(_Additems_toListview3), iList3);
                            eventstring_tmp3 = tmp.Name;
                        }
 
                    }
                    
                    Thread.Sleep(100);
                }
                

            }
            catch (Exception)
            {


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

            await new TaskFactory().StartNew(() =>
            {

                while (true)
                {
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

        private void T4_Elapsed(object sender, System.Timers.ElapsedEventArgs e)
        {
            
        }
       
        /// <summary>
        /// C# event for add all ETW events from windows evet log real_time to listview1
        /// </summary>       
        private void Form1_NewEventFrom_EventLogsCome(object sender, EventArgs e)
        {
            ListViewItem MyLviewItemsX = (ListViewItem)sender;
            try
            {
                /// Filter added for system:4 injection 
                if (is_system4_excluded)
                {
                    if (MyLviewItemsX.SubItems[3].Text.ToString().ToUpper() != "SYSTEM:4")
                    {
                        BeginInvoke(new __Additem(_Additems_toListview1), MyLviewItemsX);

                    }
                }
                else
                {
                    BeginInvoke(new __Additem(_Additems_toListview1), MyLviewItemsX);

                }
            }
            catch (Exception ee)
            {
 
            }
        }

        /// <summary>
        /// C# event for add RemoteThreadInjection Detection to the list of process [Process_Table table], [_ETW_Events_Counts table] , Event ID 2
        /// </summary>       
        private void Form1_RemoteThreadInjectionDetection_ProcessLists(object sender, EventArgs e)
        {
            try
            {
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

                string InjectorPID = EventMessage.Substring(EventMessage.IndexOf("[Injected by ") - 7).Split(':')[1].Split('[')[0];
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
                    IsShow = false

                });

                if (_ETW_Events_Counts.Exists(_xPID => _xPID.PID == Convert.ToInt32(PName_PID.Split(':')[1])))
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
                else
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
            catch (Exception ohwoOwwtfk)
            {

            }
        }

        /// <summary>
        /// C# event for add New Process events to the list of process [NewProcess_Table table], Event ID 1
        /// </summary>        
        private void Form1_NewProcessAddedtolist_NewProcessEvt(object sender, EventArgs e)
        {
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
            catch (Exception)
            {

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

                string PName_PID = sender.ToString().Split('@')[0];
                string tcpdetails = sender.ToString().Split('@')[1];

                subitemX = "Injection";
                bool foundinlist = false;
                string lastshow = "";
                Int32 PID = Convert.ToInt32(PName_PID.Split(':')[1]);

                string ProcessName = PName_PID.Split(':')[0];
                string _des_address_port = tcpdetails.Substring(tcpdetails.IndexOf("daddr:") + 6).Split(']')[0] + ":" + tcpdetails.Substring(tcpdetails.IndexOf("dport:") + 6).Split(']')[0];


                string Procesname_path = ProcessName;
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

                    _StopLoopingScan_Exec_01 = false;
                    _StopLoopingScan_Exec_02 = false;

                    foreach (_TableofProcess item in _Table)
                    {
                        if (item.ProcessName + ":" + item.PID + item.ProcessName_Path + item.Injector_Path + item.Injector.ToString() != tmplasttcpevent)
                        {
                            _finalresult_Scanned_02[2] = "--";
                            iList2 = new ListViewItem();


                            if (!_StopLoopingScan_Exec_01)
                            {
                                /// pe-sieve64.exe scanner
                                _finalresult_Scanned_01 = executeutilities_01(item.PID.ToString(), item.ProcessName_Path, item.Injector_Path + ":" + item.Injector.ToString());
                            }

                            Thread.Sleep(100);

                            if (!_StopLoopingScan_Exec_02)
                            {
                                /// hollowshunter.exe scanner
                                _finalresult_Scanned_02 = executeutilities_02(item.PID.ToString(), item.ProcessName_Path, item.Injector_Path + ":" + item.Injector.ToString());
                            }

                            iList2.Name = item.ProcessName + ":" + item.PID + ">\n" + _finalresult_Scanned_01[1] + _finalresult_Scanned_02[1]
                                + "\n-------------------\nScanner Result/Status: " + _finalresult_Scanned_02[2];
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
                                catch (Exception)
                                {


                                }


                                if (_finalresult_Scanned_01[0].Contains("Replaced:0"))
                                {
                                    // "[Implanted:0\r][][Replaced:0\r]"
                                    iList2.ImageIndex = 1;
                                    if (!_finalresult_Scanned_01[0].Contains("PE:0") && !_finalresult_Scanned_01[0].Contains("shc:0"))
                                    {
                                        // iList2.ImageIndex = 2;


                                    }
                                    else if (!_finalresult_Scanned_01[0].Contains("PE:0") || !_finalresult_Scanned_01[0].Contains("shc:0"))
                                    {
                                        // iList2.ImageIndex = 1;
                                    }
                                }
                                if (!(_finalresult_Scanned_01[0].Contains("Replaced:0")))
                                {
                                    if (_finalresult_Scanned_01[0] != "[error not found pe-sieve64.exe[not scanned:0]")
                                    {
                                        // iList2.ImageIndex = 2;
                                    }
                                    else if (_finalresult_Scanned_01[0] == "[error not found pe-sieve64.exe[not scanned:0]")
                                    {
                                        subitemX = "Injection";
                                        // iList2.ImageIndex = 1;
                                    }
                                }
                            }



                            if (isHollowHunteronoff)
                            {

                                if (_finalresult_Scanned_02[0].Contains(">>Detected:"))
                                {
                                    _StopLoopingScan_Exec_02 = true;
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

                            /// ico detection base on memory scanners result
                            if (ResultNumbers_of__finalresult_Scanned_01 > 0)
                            {
                                iList2.ImageIndex = 2;
                            }
                            else
                            {
                                iList2.ImageIndex = 1;
                                if (_finalresult_Scanned_02[0].Contains(">>Detected:"))
                                {

                                    iList2.ImageIndex = 2;

                                }
                            }

                            IsTargetProcessTerminatedbyETWPM2monitor = false;

                            if (Convert.ToInt32(string.Join("", ("0" + _finalresult_Scanned_01[0]).ToCharArray().Where(char.IsDigit))) > 0)
                            {
                                if (_finalresult_Scanned_02[2] != "Terminated" && _finalresult_Scanned_02[2] != "Suspended")
                                {
                                    _finalresult_Scanned_02[2] = "Scanned & Found!";
                                }
                                if (Pe_sieveLevel == 2)
                                {
                                    try
                                    {
                                        Process.GetProcessById(PID).Kill();
                                        _finalresult_Scanned_02[2] = "Terminated";
                                        IsTargetProcessTerminatedbyETWPM2monitor = true;
                                         
                                    }
                                    catch (Exception)
                                    {


                                    }

                                }

                            }

                            /// injection type
                            iList2.SubItems.Add(subitemX);
                            /// tcp send info
                            iList2.SubItems.Add(_des_address_port);
                            /// status for suspend/terminate by hollowshunter
                            iList2.SubItems.Add(_finalresult_Scanned_02[2]);
                            /// detection info by pe-sieve64
                            iList2.SubItems.Add(_finalresult_Scanned_01[0]);
                            /// detection info by hollowshunter
                            iList2.SubItems.Add(_finalresult_Scanned_02[0]);                         

                            /// injection description && / || [bug]
                            _TableofProcess_NewProcess_evt FindingInjectorInfo = NewProcess_Table.Find(x => x.PID == item.Injector || x.ProcessName_Path == item.Injector_Path);

                            iList2.SubItems.Add(item.ProcessName_Path + " Injected by => " + item.Injector_Path + " (PID:" + item.Injector.ToString() + ") \nInjector Details:\nInjector-ProcessName: "
                                + FindingInjectorInfo.ProcessName + "\nInjector-Path: " + FindingInjectorInfo.ProcessName_Path +
                                "\nInjector-CommandLine: " + FindingInjectorInfo.CommandLine);

                            /// ETW Event message for injection which is decription value 
                            _TableofProcess RelatedEvt_Description = Process_Table.Find(x => x.PID == PID && x.ProcessName == ProcessName
                            && x.Description.Contains(":" + item.Injector.ToString() + "[Injected by "));
                            iList2.SubItems.Add(RelatedEvt_Description.Description);


                            /// if mixed mode disabled for memoryscanner02, need this to show new event in system/detection logs Tab & alarms by ETW Tab
                            /// bug was here
                            if ((!ScannerMixedMode_Hollowh) && (IsTargetProcessTerminatedbyETWPM2monitor))
                            {
                               
                                // BeginInvoke(new __Additem(_Additems_toListview2), iList2);

                                System_Detection_Log_events.Invoke((object)iList2, null);                                
                            }

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
                                if (Init_to_runPEScanner_01 || Init_to_runPEScanner_02)
                                {
                                    BeginInvoke(new __Additem(_Additems_toListview2), iList2);

                                    System_Detection_Log_events.Invoke((object)iList2, null);

                                }
                                bool found_obj = false;
                                foreach (string Objitem in showitemsHash)
                                {
                                    if (Objitem == item.ProcessName + ":" + item.PID.ToString() + _des_address_port + _finalresult_Scanned_01[0] +
                               item.ProcessName_Path + " Injected by => " + item.Injector_Path + " (PID:" + item.Injector.ToString() + ") " + HollowHunterLevel.ToString())
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

                                /// bug here 5 feb
                                // tabPage4.Text = "Alarms by ETW " + "(" + listView2.Items.Count.ToString() + ")";

                                Thread.Sleep(10);
                            }

                            tmplasttcpevent = item.ProcessName + ":" + item.PID + item.ProcessName_Path + item.Injector_Path + item.Injector.ToString();

                            lastshow = item.ProcessName + ":" + item.PID.ToString() + _des_address_port + _finalresult_Scanned_01[0] +
                                item.ProcessName_Path + " Injected by => " + item.Injector_Path + " (PID:" + item.Injector.ToString() + ") ";

                        }
                    }
                }
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

        /// <summary>
        /// C# Method to scan target process moemory  (memory scanner 01)
        /// result will be result1 = "[" + temp1 + "][" + temp2 + "][" + temp3 + "]" + "[" + temp4 + "]";
        /// result is finalresult_Scanned_01[0] = result2;
        /// memory scanner output is finalresult_Scanned_01[1] = strOutput;
        /// </summary>        
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

        /// <summary>
        /// C# Method to scan target process moemory  (memory scanner 02)
        /// results are finalresult_Scanned_02[0] , finalresult_Scanned_02[1] = "", finalresult_Scanned_02[2] = "Scanned & Found!";
        /// </summary>  
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

                if (ScannerEvery10minMode_Hollowh)
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

                if (ScannerMixedMode_Hollowh)
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
                        try
                        {


                            if (!Process.GetProcessById(Convert.ToInt32(pid)).HasExited)
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
                                            finalresult_Scanned_02[2] = "Terminated";
                                        }
                                        else if (HollowHunterLevel == 1)
                                        {
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
                                finalresult_Scanned_02[0] = "[error not found Target Process[not scanned:0]";
                                finalresult_Scanned_02[1] = "[error not found Target Process[not scanned:0]";
                                finalresult_Scanned_02[2] = "error";
                            }
                        }
                        catch (Exception err)
                        {

                            finalresult_Scanned_02[0] = "[error not found Target Process[not scanned:0]";
                            finalresult_Scanned_02[1] = "[error not found Target Process[not scanned:0]";
                            finalresult_Scanned_02[2] = "error";
                        }
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

            BeginInvoke(new __Updatelistview1(UpdateRefreshListview1));

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
                        _TargetPID_Path = temp_str[15].Split('>')[1]
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
                        iList.SubItems.Add(e.EventRecord.FormatDescription().Substring(e.EventRecord.FormatDescription().IndexOf("ProcessName = ") + 14).Split('[')[0]);
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
                        iList.SubItems.Add(e.EventRecord.FormatDescription().Substring(e.EventRecord.FormatDescription().IndexOf(":")).Split(' ')[1]);
                        iList.SubItems.Add("[INJ]");
                        iList.SubItems.Add(e.EventRecord.FormatDescription());
                        iList.ImageIndex = 1;

                        LviewItemsX = iList;
                        Thread.Sleep(25);
                        chart_Inj++;

                        RemoteThreadInjectionDetection_ProcessLists.Invoke((object)(e.EventRecord.FormatDescription().Substring(e.EventRecord.FormatDescription().IndexOf(":")).Split(' ')[1]
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
                        NewTCP_Connection_Detected.Invoke((object)LviewItemsX,null);

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
                EvtWatcher.Enabled = false;
                EvtWatcher.Dispose();
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
                    bool MemoryBytes = Memoryinfo.ReadProcessMemory(prch, (UIntPtr)i32StartAddress, buf, buf.Length, IntPtr.Zero);

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

                    bool MemoryBytes = Memoryinfo.ReadProcessMemory(prch, (UIntPtr)i32StartAddress, buf, buf.Length, IntPtr.Zero);

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
                                                       + "MemoryScanner HollowsHunter Result: " + __result02 + "\n\n"
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
                                                       + "MemoryScanner HollowsHunter Result: " + __result02 + "\n\n"
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
                                                       + "MemoryScanner HollowsHunter Result: " + __result02 + "\n\n"
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

        private void AboutToolStripMenuItem1_Click(object sender, EventArgs e)
        {
            MessageBox.Show(null, "ETWPM2Monitor2 v2.1 [test version 2.1.18.84]\nCode Published by Damon Mohammadbagher , Jul 2021", "About ETWPM2Monitor2 v2.1", MessageBoxButtons.OK, MessageBoxIcon.Information);

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
      
        private void MixedModeToolStripMenuItem_Click(object sender, EventArgs e)
        {
            ScannerMixedMode_Pesieve = true;
            ScannerEvery10minMode_Pesieve = false;
            mixedModeToolStripMenuItem.Checked = true;
            scanningTargetProcessEvery10mininBackgroundToolStripMenuItem.Checked = false;
            disableAllModesToolStripMenuItem.Checked = false;
        }

        private void ScanningTargetProcessEvery10mininBackgroundToolStripMenuItem_Click(object sender, EventArgs e)
        {
            mixedModeToolStripMenuItem.Checked = false;
            scanningTargetProcessEvery10mininBackgroundToolStripMenuItem.Checked = true;
            disableAllModesToolStripMenuItem.Checked = false;
            ScannerEvery10minMode_Pesieve = true;
            ScannerMixedMode_Pesieve = false;

        }

        private void DisableAllModesToolStripMenuItem_Click(object sender, EventArgs e)
        {
            ScannerMixedMode_Pesieve = false;
            ScannerEvery10minMode_Pesieve = false;
            disableAllModesToolStripMenuItem.Checked = true;
            
            scanningTargetProcessEvery10mininBackgroundToolStripMenuItem.Checked = false;
            mixedModeToolStripMenuItem.Checked = false;

        }

        private void ScanningTargetProcessEvery10mininBackgroundToolStripMenuItem1_Click(object sender, EventArgs e)
        {
            ScannerMixedMode_Hollowh = false;
            ScannerEvery10minMode_Hollowh = true;
            scanningTargetProcessEvery10mininBackgroundToolStripMenuItem1.Checked = true;
            mixedModeToolStripMenuItem1.Checked = false;
            disableBothToolStripMenuItem.Checked = false;

        }

        private void MixedModeToolStripMenuItem1_Click(object sender, EventArgs e)
        {
            ScannerMixedMode_Hollowh = true;
            ScannerEvery10minMode_Hollowh = false;
            mixedModeToolStripMenuItem1.Checked = true;
            scanningTargetProcessEvery10mininBackgroundToolStripMenuItem1.Checked = false;
            disableBothToolStripMenuItem.Checked = false;
        }

        private void DisableBothToolStripMenuItem_Click(object sender, EventArgs e)
        {
            ScannerMixedMode_Hollowh = false;
            ScannerEvery10minMode_Hollowh = false;
            disableBothToolStripMenuItem.Checked = true;

            mixedModeToolStripMenuItem1.Checked = false;
            scanningTargetProcessEvery10mininBackgroundToolStripMenuItem1.Checked = false;
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

        private void ListView3_SelectedIndexChanged(object sender, EventArgs e)
        {
            try
            {
                BeginInvoke(new __Obj_Updater_to_WinForm(Update_Richtexbox8_SystemDetection_ETW_AllDetails_info));

            }
            catch (Exception)
            {


            }
        }

        private void ScanOnlyModeDefaultToolStripMenuItem_Click(object sender, EventArgs e)
        {
            Pe_sieveLevel = 0;
            scanKillSuspiciousRunAsAdminToolStripMenuItem.Checked = false;
            scanOnlyModeDefaultToolStripMenuItem.Checked = true;
        }

        private void ScanKillSuspiciousRunAsAdminToolStripMenuItem_Click(object sender, EventArgs e)
        {
            Pe_sieveLevel = 2;
            scanKillSuspiciousRunAsAdminToolStripMenuItem.Checked = true;
            scanOnlyModeDefaultToolStripMenuItem.Checked = false;
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

        private void DontDumpPEOfilterToolStripMenuItem_Click(object sender, EventArgs e)
        {
            toolStripStatusLabel4.Text = "| hollowshunter is on";

            dumpAllProcessToolStripMenuItem.Text = "Default dump all Process [off]";
            dontDumpPEOfilterToolStripMenuItem.Text = "don't dump the modified PEs, but save the report [on]";
            dontDumpAnyFilesToolStripMenuItem.Text = "don't dump any files [off]";
            hollowshunter_DumpSwitches = 1;
        }

        private void DontDumpAnyFilesToolStripMenuItem_Click(object sender, EventArgs e)
        {
            toolStripStatusLabel4.Text = "| hollowshunter is on";

            dumpAllProcessToolStripMenuItem.Text = "Default dump all Process [off]";
            dontDumpAnyFilesToolStripMenuItem.Text = "don't dump any files [on]";
            dontDumpPEOfilterToolStripMenuItem.Text = "don't dump the modified PEs, but save the report [off]";
            hollowshunter_DumpSwitches = 2;
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

        private void DumpAllProcessToolStripMenuItem_Click(object sender, EventArgs e)
        {
            toolStripStatusLabel4.Text = "| hollowshunter is on";

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
            isPEScanonoff = false;
            if (isHollowHunteronoff == false && isPEScanonoff == false)
                MessageBox.Show("\"Alarms by ETW\" TAB is disable now, because all memory-scanners are OFF\n" + "you need to set \"ON\" at least one of them");

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
                     foreach (_InjectedThreadDetails_bytes item in _InjectedTIDList.FindAll(y => y._TargetPID == Convert.ToInt32(PID) && y._InjectorPID == temp_get_InjectorPID_from_eventmessage))
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
                                 counter++;
                                 richTextBox3.Text += "[" + counter.ToString() + "] " + "Remote Thread Injection Detected!" + "\n";
                                 richTextBox3.Text += "[" + counter.ToString() + "] " + "Injection by InjectorPID:" + item._InjectorPID.ToString() + "===>==TID:" +
                                item._RemoteThreadID.ToString() + "==>==Injected into====>" + PIDName + ":" + PID

                                + "\nInjector More Details:"
                                + "\nInjector CommandLine:" + NewProcess_Table.Find(_w => (_w.PID == item._InjectorPID && _w.CommandLine.Contains(temp_get_InjectorPN_from_description))).CommandLine.Substring(13)
                                + "\nInjector Path:" + NewProcess_Table.Find(_w => _w.PID == item._InjectorPID).ProcessName_Path
                                + "\nInjector PPID:" + NewProcess_Table.Find(_w => _w.PID == item._InjectorPID).PPID_Path
                                + "\nTarget Process More Details:"
                                + "\nTarget Process Path:" + NewProcess_Table.Find(_w => _w.ProcessName.Substring(1) == item._TargetPIDName && _w.PID == item._TargetPID).ProcessName_Path
                                + "\n"
                                + "Injected Bytes:  (TID: " + item._RemoteThreadID.ToString() + ") " + " (StartAddress: " + item._ThreadStartAddress.ToString() + ")\n" + item.Injected_Memory_Bytes_Hex + "\n";
                                 last_tid = item._RemoteThreadID.ToString();
                             }


                         }
                         catch (Exception)
                         {

                         }
                     }

                     temptids.Clear();
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
                int PID = Convert.ToInt32(_PID);
                
                richTextBox7.Text = "";
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

                            richTextBox7.Text += item + "\n";

                            //if (item.Contains("is_shellcode"))
                            //{
                            try
                            {

                                if (module + ".dll" == filename)
                                {
                                    buf = new byte[200];
                                    buf = File.ReadAllBytes(@".\process_" + PID + @"\" + module + ".dll");
                                    dump = Memoryinfo.HexDump2(buf) + "\n--------------------------------------------------------------------------------------------------------------------------\n";
                                    if (dump != null)
                                    {
                                        richTextBox7.Text += dump;
                                    }
                                }
                                else if (module + ".shc" == filename)
                                {
                                    buf = new byte[200];
                                    buf = File.ReadAllBytes(@".\process_" + PID + @"\" + module + ".shc");
                                    dump = Memoryinfo.HexDump2(buf) + "\n--------------------------------------------------------------------------------------------------------------------------\n";
                                    if (dump != null)
                                    {
                                        richTextBox7.Text += dump;
                                    }
                                }
                                else if (item.Contains("dump_file"))
                                {
                                    buf = new byte[200];
                                    buf = File.ReadAllBytes(@".\process_" + PID + @"\" + filename);
                                    dump = Memoryinfo.HexDump2(buf) + "\n";
                                    if (dump != null)
                                    {
                                        richTextBox7.Text += dump;
                                    }

                                }
                                else if (item.Contains("\"is_shellcode\" :"))
                                {
                                    richTextBox7.Text += "\n--------------------------------------------------------------------------------------------------------------------------\n";
                                }
                            }
                            catch (Exception)
                            {


                            }
                            // }

                        }

                    }
                }
                else
                {
                    richTextBox7.Text = "";
                }
                 

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
            hollowHunterexeOnToolStripMenuItem.Text = "HollowsHunter.exe on";
            scanOnlyModeToolStripMenuItem.Text = "Scan only mode (Default)";
            scanSuspendToolStripMenuItem.Text = "Scan + Suspend Suspicious (Run as Admin)";
            scanKillSuspiciousToolStripMenuItem.Text = "Scan + Kill Suspicious (Run as Admin)";
            if (isHollowHunteronoff == false && isPEScanonoff == false)
                MessageBox.Show("\"Alarms by ETW\" TAB is disable now, because all memory-scanners are OFF\n" + "you need to set \"ON\" at least one of them");

        }

        private void ScanOnlyModeToolStripMenuItem_Click(object sender, EventArgs e)
        {
            toolStripStatusLabel4.Text = "| hollowshunter is on";
            isHollowHunteronoff = true;
            HollowHunterLevel = 0;
            hollowHunterexeOnToolStripMenuItem.Text = "HollowsHunter.exe [on]";
            scanOnlyModeToolStripMenuItem.Text = "Scan only mode (Default) [on]";
            scanOnlyModeToolStripMenuItem.Checked = true;
            scanSuspendToolStripMenuItem.Checked = false;
            scanKillSuspiciousToolStripMenuItem.Checked = false;
            scanSuspendToolStripMenuItem.Text = "Scan + Suspend Suspicious (Run as Admin)";
            scanKillSuspiciousToolStripMenuItem.Text = "Scan + Kill Suspicious (Run as Admin)";
            hollowHunterexeoffToolStripMenuItem.Text = "HollowsHunter.exe off";

        }

        private void ScanSuspendToolStripMenuItem_Click(object sender, EventArgs e)
        {
            toolStripStatusLabel4.Text = "| hollowshunter is on";

            isHollowHunteronoff = true;
            HollowHunterLevel = 1;
            hollowHunterexeOnToolStripMenuItem.Text = "HollowsHunter.exe [on]";
            scanSuspendToolStripMenuItem.Text = "Scan + Suspend Suspicious (Run as Admin) [on]";
            scanOnlyModeToolStripMenuItem.Checked = false;
            scanSuspendToolStripMenuItem.Checked = true;
            scanKillSuspiciousToolStripMenuItem.Checked = false;
            scanOnlyModeToolStripMenuItem.Text = "Scan only mode (Default)";
            scanKillSuspiciousToolStripMenuItem.Text = "Scan + Kill Suspicious (Run as Admin)";
            hollowHunterexeoffToolStripMenuItem.Text = "HollowsHunter.exe off";


        }

        private void ScanKillSuspiciousToolStripMenuItem_Click(object sender, EventArgs e)
        {
            toolStripStatusLabel4.Text = "| hollowshunter is on";

            isHollowHunteronoff = true;
            HollowHunterLevel = 2;
            hollowHunterexeOnToolStripMenuItem.Text = "HollowsHunter.exe [on]";
            scanOnlyModeToolStripMenuItem.Text = "Scan only mode (Default)";
            scanKillSuspiciousToolStripMenuItem.Text = "Scan + Kill Suspicious (Run as Admin) [on]";
            scanOnlyModeToolStripMenuItem.Checked = false;
            scanSuspendToolStripMenuItem.Checked = false;
            scanKillSuspiciousToolStripMenuItem.Checked = true;
            scanSuspendToolStripMenuItem.Text = "Scan + Suspend Suspicious (Run as Admin)";
            hollowHunterexeoffToolStripMenuItem.Text = "HollowsHunter.exe off";


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
                richTextBox1.Text += str.ToString();
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
                    bool MemoryBytes = Memoryinfo.ReadProcessMemory(prch, (UIntPtr)i32StartAddress, buf, buf.Length, IntPtr.Zero);
                    string _buf = Memoryinfo.HexDump(buf);
                    string _bytes = BitConverter.ToString(buf).ToString();
                    /// added
                    ThreadStart __T5_info_for_additems_to_Richtextbox1 = new ThreadStart(delegate
                    {
                        BeginInvoke(new __Additem(_Additems_str_toRichtextbox1),
                        EventMessage + "\n\nEventID: " + "2" + "\nEventRecord_ID: " + EventMessageRecordId + "\n\n[Remote-Thread-Injection Memory Information]\n\tTID: " + TID.ToString() + "\n\tTID StartAddress: " +
                         XStartAddress.ToString() + "\n\tTID Win32StartAddress: " + i32StartAddress.ToString() + "\n\tTarget_Process PID: " + prc.ToString() +
                         "\n\nInjected Memory Bytes: " + _bytes  + "\n\n" + _buf + "\n_____________________\n");
                    });

                    Thread _T5_for_additems_to_Richtextbox1 = new Thread(__T5_info_for_additems_to_Richtextbox1);
                    _T5_for_additems_to_Richtextbox1.Start();

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
            public static extern NtStatus NtReadVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, UInt32 NumberOfBytesToRead, ref UInt32 NumberOfBytesRead);

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
