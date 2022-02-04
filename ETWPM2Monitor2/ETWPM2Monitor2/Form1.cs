using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Drawing;
using System.IO;
using System.Linq;
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
        public static uint NTReadTmpRef = 0;
        public EventLog ETW2MON;
        public static EventLogQuery ETWPM2Query;
        public ListViewItem iList = new ListViewItem();
        public ListViewItem iList2 = new ListViewItem();
        public ListViewItem iList3 = new ListViewItem();
        public static EventLogWatcher EvtWatcher = null;
        public string tempMessage, tempMessage2, EventMessage = "";
        public static byte[] buf = new byte[90];
        public static BackgroundWorker bgw = new BackgroundWorker();
        public static ListViewItem LviewItemsX = null;
        public static string evtstring, tmplasttcpevent = "";
        public static bool isPEScanonoff = true;
        public static bool isHollowHunteronoff = false;

        public delegate void __MyDelegate_LogFileReader_Method();
        public delegate void __MyDelegate_showdatagrid();
        public delegate void __LogReader();
        public delegate void __Additem(object itemsOfListview1_2_5_6);
        public delegate void __AddTextTorichtexhbox1(object str);
        public delegate void __core2(object str);
        public delegate void __Updatelistview1();
        public delegate void __Obj_Updater_to_WinForm();


        public struct _InjectedThreadDetails_bytes
        {

            public string _ThreadStartAddress { set; get; }
            public Int32 _RemoteThreadID { set; get; }
            public Int32 _TargetPID { set; get; }
            public Int32 _InjectorPID { set; get; }
            public string Injected_Memory_Bytes { set; get; }
            public string Injected_Memory_Bytes_Hex { set; get; }

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
        public static int HollowHunterLevel = 0;
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

        public struct _TableofProcess_ETW_Event_Counts
        {
            //private Int64 Virtualmemalloc_count;
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

        public static int _percent(int count, int total)
        {
            return (count * 100) / total;
        }

        public void _Additems_toListview1(object obj)
        {

            try
            {

                ListViewItem MyLviewItemsX1 = (ListViewItem)obj;
                Thread.Sleep(1);
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

                            if (MyLviewItemsX1.SubItems[5].Text.Split('\n')[6].Contains("[dport:4444]"))
                            {
                                MyLviewItemsX1.BackColor = Color.Gray;
                            }

                            MyLviewItemsX1.SubItems[5].Text += "\n\n#This Description Added by ETWPM2Monitor2 tool#\n##Warning Description: Packet with [size:160] maybe was for Meterpreter Session which will send every 1 min between Client/Server##\n" +
                            "##Warning Description: Packet with [size:192] is for meterpreter session which will send before every command excution from server##\n" +
                            "##Warning Description: DestinationPort [dport:4444] is Default port for Meterpreter session##";
                        }



                        listView1.Items.Add(MyLviewItemsX1);
                    }

                    /// EventID 1 = Create New Process
                    if (MyLviewItemsX1.SubItems[2].Text == "1")
                    {
                        string commandline = MyLviewItemsX1.SubItems[5].Text.Split('\n')[4].ToLower();
                        string parentid = MyLviewItemsX1.SubItems[5].Text.Split('\n')[6].ToLower();
                        if (commandline.Contains("[commandline: c:\\windows\\system32\\cmd.exe") || commandline.Contains("[commandline: cmd"))

                        {
                            if (parentid != "[parentid path: c:\\windows\\explorer.exe]")
                            {
                                MyLviewItemsX1.BackColor = Color.Red;
                                MyLviewItemsX1.ForeColor = Color.Black;
                                MyLviewItemsX1.ImageIndex = 2;
                                MyLviewItemsX1.SubItems[5].Text += "\n\n#This Description Added by ETWPM2Monitor2 tool#\n##Warning Description: [ParentID Path] & [PPID] for this New Process is not Normal! (maybe Shell Activated?)##\n";
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
        public static List<string> List_ofProcess_inListview2 = new List<string>();
        public void _Additems_toListview2(object obj)
        {
            ListViewItem MyLviewItemsX2 = (ListViewItem)obj;
            try
            {
                Thread.Sleep(1);
                bool found = false;
                if (MyLviewItemsX2 != null)
                {

                    if (MyLviewItemsX2.Name != evtstring2)
                    {
                        foreach (string item in List_ofProcess_inListview2)
                        {
                            if (item == MyLviewItemsX2.Name.Split(':')[0] + ":" + MyLviewItemsX2.Name.Split(':')[1].Split('>')[0])
                            {
                                found = true;
                            }
                        }
                        if (!found)
                        {
                            listView2.Items.Add(MyLviewItemsX2);
                            InjectionMemoryInfoDetails_torichtectbox(MyLviewItemsX2.SubItems[9].Text);
                            Thread.Sleep(5);
                            List_ofProcess_inListview2.Add(MyLviewItemsX2.Name.Split(':')[0] + ":" + MyLviewItemsX2.Name.Split(':')[1].Split('>')[0]);
                            evtstring2 = MyLviewItemsX2.Name;
                        }
                    }

                }
                tabPage4.Text = "Alarms by ETW " + "(" + listView2.Items.Count.ToString() + ")";


            }
            catch (Exception ee)
            {


            }


        }

        public Form1()
        {
            InitializeComponent();
        }

        public void StartQueries_Mon(string queries)
        {
            ThreadStart Core2 = new ThreadStart(delegate { BeginInvoke(new __core2(_Core2), queries); });
            Thread _T1_Core2 = new Thread(Core2);
            _T1_Core2.Priority = ThreadPriority.Highest;
            _T1_Core2.Start();

        }

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

        public void _Core()
        {
            string Query = "*";
            ETWPM2Query = new EventLogQuery("ETWPM2", PathType.LogName);

            EvtWatcher = new EventLogWatcher(ETWPM2Query);
            EvtWatcher.EventRecordWritten += Watcher_EventRecordWritten;

            EvtWatcher.Enabled = true;
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            try
            {
                ThreadStart Core = new ThreadStart(delegate { BeginInvoke(new __Obj_Updater_to_WinForm(_Core)); });
                Thread _T1_Core1 = new Thread(Core);
                _T1_Core1.Priority = ThreadPriority.Highest;
                _T1_Core1.Start();
                //string Query = "*";
                //ETWPM2Query = new EventLogQuery("ETWPM2", PathType.LogName);

                //EvtWatcher = new EventLogWatcher(ETWPM2Query);
                //EvtWatcher.EventRecordWritten += Watcher_EventRecordWritten;
                //EvtWatcher.Enabled = true;

                listView1.SmallImageList = imageList1;


                listView2.HeaderStyle = ColumnHeaderStyle.Nonclickable;
                listView2.BorderStyle = BorderStyle.FixedSingle;
                listView1.HeaderStyle = ColumnHeaderStyle.Nonclickable;
                listView1.BorderStyle = BorderStyle.FixedSingle;


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
                //t3.Elapsed += T3_Elapsed;
                //t3.Enabled = true;
                //t3.Start();
                t4.Elapsed += T4_Elapsed;
                t4.Enabled = true;
                t4.Start();
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

                /// event for add Process to Alarm-Tab by ETW & scanning Target Process by Memory Scanners
                /// event is ready ...
                NewProcessAddedtolist += Form1_NewProcessAddedtolist1;

                /// event for add Process to list of New Process
                NewProcessAddedtolist_NewProcessEvt += Form1_NewProcessAddedtolist_NewProcessEvt;

                /// event for add target Process to list of Injected Process which had RemoteThreadInjection
                RemoteThreadInjectionDetection_ProcessLists += Form1_RemoteThreadInjectionDetection_ProcessLists;

                /// event for refresing listviw real-time events
                NewEventFrom_EventLogsCome += Form1_NewEventFrom_EventLogsCome;

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
                listView3.Columns.Add("LastEvent-Time", 100, HorizontalAlignment.Left);
                listView3.Columns.Add("Process", 100, HorizontalAlignment.Left);
                listView3.Columns.Add("ThreadInjection-Count", 50, HorizontalAlignment.Left);
                listView3.Columns.Add("TCPSend-Count", 50, HorizontalAlignment.Left);
                listView3.Columns.Add("LastTCP-Details", 250, HorizontalAlignment.Left);



            }
            catch (EventLogReadingException err)
            {

            }
        }

        public void Update_ETW_Counts_info()
        {
            /// disabled ;)
            //try
            //{

            //    time4t++;
            //    if (listView3.Items.Count != _ETW_Events_Counts.Count || time4t >= 2)
            //    {
            //        time4t = 0;
            //        listView3.Items.Clear();
            //        listView3.Sorting = SortOrder.Ascending;
            //        if (checkBox1.Checked)
            //        {
            //            foreach (_TableofProcess_ETW_Event_Counts item in _ETW_Events_Counts.ToArray().OrderBy(x => x._RemoteThreadInjection_count))
            //            {
            //                //listView3.BeginUpdate();
            //                iList3 = new ListViewItem();
            //                iList3.Name = item.PID + ":" + item.CommandLine;
            //                iList3.SubItems.Add(item.lastEventtime);
            //                if (item.ProcNameANDPath.Contains("Process Exited (PID"))
            //                {
            //                    string tmpPrc = Process_Table.Find(j => j.PID == item.PID).ProcessName;
            //                    iList3.SubItems.Add(tmpPrc + ":" + item.PID.ToString());
            //                }
            //                else if (!item.ProcNameANDPath.Contains("Process Exited (PID"))
            //                {
            //                    iList3.SubItems.Add(item.ProcNameANDPath + ":" + item.PID.ToString());
            //                }
            //                iList3.SubItems.Add(item._RemoteThreadInjection_count.ToString());
            //                iList3.SubItems.Add(item._TCPSend_count.ToString());
            //                iList3.SubItems.Add(item._LastTCP_Details);
            //                listView3.Items.Add(iList3);
            //                listView3.Update();

            //            }
            //        }
            //        else
            //        if (checkBox2.Checked)
            //        {
            //            foreach (_TableofProcess_ETW_Event_Counts item in _ETW_Events_Counts.ToArray().OrderBy(x => x._TCPSend_count))
            //            {

            //                iList3 = new ListViewItem();
            //                iList3.Name = item.PID + ":" + item.CommandLine;
            //                iList3.SubItems.Add(item.lastEventtime);
            //                if (item.ProcNameANDPath.Contains("Process Exited (PID"))
            //                {
            //                    string tmpPrc = Process_Table.Find(j => j.PID == item.PID).ProcessName;
            //                    iList3.SubItems.Add(tmpPrc + ":" + item.PID.ToString());
            //                }
            //                else if (!item.ProcNameANDPath.Contains("Process Exited (PID"))
            //                {
            //                    iList3.SubItems.Add(item.ProcNameANDPath + ":" + item.PID.ToString());
            //                }
            //                iList3.SubItems.Add(item._RemoteThreadInjection_count.ToString());
            //                iList3.SubItems.Add(item._TCPSend_count.ToString());
            //                iList3.SubItems.Add(item._LastTCP_Details);
            //                listView3.Items.Add(iList3);
            //                listView3.Update();

            //            }
            //        }
            //        else
            //        if (checkBox3.Checked)
            //        {
            //            foreach (_TableofProcess_ETW_Event_Counts item in _ETW_Events_Counts.ToArray().OrderBy(x => x.lastEventtime))
            //            {

            //                iList3 = new ListViewItem();
            //                iList3.Name = item.PID + ":" + item.CommandLine;
            //                iList3.SubItems.Add(item.lastEventtime);
            //                if (item.ProcNameANDPath.Contains("Process Exited (PID:"))
            //                {
            //                    string tmpPrc = Process_Table.Find(j => j.PID == item.PID).ProcessName;
            //                    iList3.SubItems.Add(tmpPrc + ":" + item.PID.ToString());
            //                }
            //                else if (!item.ProcNameANDPath.Contains("Process Exited (PID"))
            //                {
            //                    iList3.SubItems.Add(item.ProcNameANDPath + ":" + item.PID.ToString());
            //                }
            //                iList3.SubItems.Add(item._RemoteThreadInjection_count.ToString());
            //                iList3.SubItems.Add(item._TCPSend_count.ToString());
            //                iList3.SubItems.Add(item._LastTCP_Details);
            //                listView3.Items.Add(iList3);
            //                listView3.Update();

            //            }
            //        }
            //        else
            //        {

            //            foreach (_TableofProcess_ETW_Event_Counts item in _ETW_Events_Counts.ToArray().OrderBy(x => x.ProcNameANDPath))
            //            {

            //                iList3 = new ListViewItem();
            //                iList3.Name = item.PID + ":" + item.CommandLine;
            //                iList3.SubItems.Add(item.lastEventtime);
            //                if (item.ProcNameANDPath.Contains("Process Exited (PID"))
            //                {
            //                    string tmpPrc = Process_Table.Find(j => j.PID == item.PID).ProcessName;
            //                    iList3.SubItems.Add(tmpPrc + ":" + item.PID.ToString());
            //                }
            //                else if (!item.ProcNameANDPath.Contains("Process Exited (PID"))
            //                {
            //                    iList3.SubItems.Add(item.ProcNameANDPath + ":" + item.PID.ToString());
            //                }
            //                iList3.SubItems.Add(item._RemoteThreadInjection_count.ToString());
            //                iList3.SubItems.Add(item._TCPSend_count.ToString());
            //                iList3.SubItems.Add(item._LastTCP_Details);
            //                listView3.Items.Add(iList3);
            //                listView3.Update();

            //            }

            //        }
            //    }
            //}
            //catch (Exception)
            //{


            //}
        }

        private void T4_Elapsed(object sender, System.Timers.ElapsedEventArgs e)
        {
            // BeginInvoke(new __Obj_Updater_to_WinForm(Update_ETW_Counts_info));

        }

        private void T3_Elapsed(object sender, System.Timers.ElapsedEventArgs e)
        {
            // GC.Collect();

        }

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
                //  MessageBox.Show(ee.Message);

            }
        }

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

        private void Form1_NewProcessAddedtolist1(object sender, EventArgs e)
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

                foreach (_TableofProcess item in _Table)
                {
                    if (item.ProcessName + ":" + item.PID + item.ProcessName_Path + item.Injector_Path + item.Injector.ToString() != tmplasttcpevent)
                    {
                        _finalresult_Scanned_02[2] = "-+";
                        iList2 = new ListViewItem();

                        Parallel.Invoke(
                           () =>
                        {
                            _finalresult_Scanned_01 = executeutilities_01(item.PID.ToString(), item.ProcessName_Path, item.Injector_Path + ":" + item.Injector.ToString());

                        }, () =>
                        {
                            /// thread wait(1000/2000) only for terminate action needed in this code 
                            /// because before adding to list target process will terminate without adding to list of detection/logs 
                            if (HollowHunterLevel == 2)
                            {
                                Thread.Sleep(2000);
                            }

                            _finalresult_Scanned_02 = executeutilities_02(item.PID.ToString(), item.ProcessName_Path, item.Injector_Path + ":" + item.Injector.ToString());

                        });

                        ///// pe-sieve64.exe scanner
                        //_finalresult_Scanned_01 = executeutilities_01(item.PID.ToString(), item.ProcessName_Path, item.Injector_Path + ":" + item.Injector.ToString());

                        //Thread.Sleep(100);
                        //_finalresult_Scanned_02[2] = "-+";

                        ///// hollowshunter.exe scanner
                        //_finalresult_Scanned_02 = executeutilities_02(item.PID.ToString(), item.ProcessName_Path, item.Injector_Path + ":" + item.Injector.ToString());

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

                                ThreadStart __T2_info_for_additems_to_Listview2 = new ThreadStart(delegate { BeginInvoke(new __Additem(_Additems_toListview2), iList2); });
                                Thread _T2_for_additems_to_Listview2 = new Thread(__T2_info_for_additems_to_Listview2);
                                _T2_for_additems_to_Listview2.Start();

                                // listView2.Items.Add(iList2);

                                if (iList2.ImageIndex == 1) { Chart_Orange++; }
                                else if (iList2.ImageIndex == 2) { Chart_Redflag++; }
                            }

                            showitemsHash.Add(item.ProcessName + ":" + item.PID.ToString() + _des_address_port + _finalresult_Scanned_01[0] +
                           item.ProcessName_Path + " Injected by => " + item.Injector_Path + " (PID:" + item.Injector.ToString() + ") ");
                            Thread.Sleep(10);

                            //BeginInvoke(new __core2(update_tabpage4), "Alarms by ETW " + "(" + listView2.Items.Count.ToString() + ")");

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

        public void update_tabpage4(object str)
        {
            // tabPage4.Text = "Alarms by ETW " + "(" + listView2.Items.Count.ToString() + ")";
            // tabPage4.Text = str.ToString();
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
                    else if (resultPEScanned.Count == 1)
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
                    else if (resultPEScanned.Count >= 2)
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

                                    if (pe_sieve_DumpSwitches == 0) { outputs.StartInfo.Arguments = "/shellc /iat 2 /pid " + pid; }
                                    else if (pe_sieve_DumpSwitches == 1) { outputs.StartInfo.Arguments = "/ofilter 1 /shellc /iat 2 /pid " + pid; }
                                    else if (pe_sieve_DumpSwitches == 2) { outputs.StartInfo.Arguments = "/ofilter 2 /shellc /iat 2 /pid " + pid; }

                                    //else if (pe_sieve_DumpSwitches == 1) { outputs.StartInfo.Arguments = "/ofilter 1 /data 3 /shellc /iat 2 /pid " + pid; }
                                    //else if (pe_sieve_DumpSwitches == 2) { outputs.StartInfo.Arguments = "/ofilter 2 /data 3 /shellc /iat 2 /pid " + pid; }

                                    outputs.StartInfo.CreateNoWindow = true;
                                    outputs.StartInfo.UseShellExecute = false;
                                    outputs.StartInfo.RedirectStandardOutput = true;
                                    outputs.StartInfo.RedirectStandardInput = true;
                                    outputs.StartInfo.RedirectStandardError = true;

                                    outputs.Start();

                                    strOutput = outputs.StandardOutput.ReadToEnd();
                                    string temp1, temp2, temp3 = "";
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

                                    result1 = "[" + temp1 + "][" + temp2 + "][" + temp3 + "]";

                                    //result1 = "[" + strOutput.Substring(strOutput.IndexOf("Implanted PE:")).Split('\n')[0] + "][" +
                                    //    strOutput.Substring(strOutput.IndexOf("Implanted shc:")).Split('\n')[0]
                                    //      + "][" + strOutput.Substring(strOutput.IndexOf("Replaced:")).Split('\n')[0] + "]";


                                    string result2 = "";
                                    foreach (char item in result1)
                                    {
                                        if (item != ' ')
                                            result2 += item;
                                    }

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

                        Scanned_PIds.Add(new _TableofProcess_Scanned_01
                        {
                            time_Hour = DateTime.Now.Hour,
                            time_min = DateTime.Now.Minute,
                            PID = Convert.ToInt32(pid),
                            ProcNameANDPath = InProcessName_Path,
                            injectorPathPID = _injectorPathPid
                        });

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
                        try
                        {


                            if (!Process.GetProcessById(Convert.ToInt32(pid)).HasExited)
                            {
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

                                finalresult_Scanned_02[0] = result2;
                                finalresult_Scanned_02[1] = strOutput2;
                            }
                            else
                            {
                                finalresult_Scanned_02[0] = "[error not found Targer Process[not scanned:0]";
                                finalresult_Scanned_02[1] = "[error not found Targer Process[not scanned:0]";
                                finalresult_Scanned_02[2] = "error";
                            }
                        }
                        catch (Exception err)
                        {

                            finalresult_Scanned_02[0] = "[error not found Targer Process[not scanned:0]";
                            finalresult_Scanned_02[1] = "[error not found Targer Process[not scanned:0]";
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

        public void Watcher_EventRecordWritten(object sender, EventRecordWrittenEventArgs e)
        {


            try
            {

                if (e.EventRecord.FormatDescription() != tempMessage2)
                {


                    //ThreadStart __T5_info_for_additems_to_Richtextbox1 = new ThreadStart(delegate
                    //{
                    //BeginInvoke(new __Additem(_Additems_str_toRichtextbox1),
                    // "[Time = " + e.EventRecord.TimeCreated + "] \n[EventID = " + e.EventRecord.Id.ToString() + "] \n[Message : " + e.EventRecord.FormatDescription() + "]\n_____________________\n");
                    //});
                    //Thread _T5_for_additems_to_Richtextbox1 = new Thread(__T5_info_for_additems_to_Richtextbox1);
                    //_T5_for_additems_to_Richtextbox1.Start();


                    BeginInvoke(new __Additem(_Additems_str_toRichtextbox1),
                               "[Time = " + e.EventRecord.TimeCreated + "] \n[EventID = " + e.EventRecord.Id.ToString() + "] \nMessage : " + e.EventRecord.FormatDescription() + "\n_____________________\n");

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
                    }
                }

                Chart_Counts++;

            }
            catch (Exception _e)
            {
                // MessageBox.Show("ops:core 1 "  + _e.Message);
            }



        }

        private void Form1_FormClosed(object sender, FormClosedEventArgs e)
        {
            EvtWatcher.Enabled = false;
            EvtWatcher.Dispose();
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

            toolStripStatusLabel2.Text = "| Filters: Select All EventIDs 1,2,3 [NewProcess , RemoteThreadInjection Detection , TCPIP Send]";

        }

        public void EventID12ToolStripMenuItem_Click(object sender, EventArgs e)
        {
            string _Query = "<QueryList><Query Id=\"0\" Path=\"ETWPM2\"><Select Path=\"ETWPM2\">*[System[(EventID=1 or EventID=2)]]</Select></Query></QueryList>";

            StartQueries_Mon(_Query);
            toolStripStatusLabel2.ForeColor = Color.Red;
            toolStripStatusLabel2.Text = "| Filters: Select All EventIDs 1,2 [NewProcess , RemoteThreadInjection Detection] | " + AlarmsDisabled;

            MessageBox.Show(AlarmsDisabled);
        }

        public void EventID13ToolStripMenuItem_Click(object sender, EventArgs e)
        {
            string _Query = "<QueryList><Query Id=\"0\" Path=\"ETWPM2\"><Select Path=\"ETWPM2\">*[System[(EventID=1 or EventID=3)]]</Select></Query></QueryList>";

            StartQueries_Mon(_Query);
            toolStripStatusLabel2.ForeColor = Color.Red;

            toolStripStatusLabel2.Text = "| Filters: Select All EventIDs 1,3 [NewProcess , TCPIP Send] | " + AlarmsDisabled;

            MessageBox.Show(AlarmsDisabled);
        }

        public void EventID23InjectionTCPIPToolStripMenuItem_Click(object sender, EventArgs e)
        {
            string _Query = "<QueryList><Query Id=\"0\" Path=\"ETWPM2\"><Select Path=\"ETWPM2\">*[System[(EventID=2 or EventID=3)]]</Select></Query></QueryList>";

            StartQueries_Mon(_Query);
            toolStripStatusLabel2.ForeColor = Color.Red;

            toolStripStatusLabel2.Text = "| Filters: Select All EventIDs 2,3 [RemoteThreadInjection Detection , TCPIP Send]";

        }

        private void EventID1ToolStripMenuItem_Click(object sender, EventArgs e)
        {
            string _Query = "<QueryList><Query Id=\"0\" Path=\"ETWPM2\"><Select Path=\"ETWPM2\">*[System[(EventID=1)]]</Select></Query></QueryList>";

            StartQueries_Mon(_Query);
            toolStripStatusLabel2.ForeColor = Color.Red;

            toolStripStatusLabel2.Text = "| Filters: Select All EventID 1 [NewProcess] | " + AlarmsDisabled;

            MessageBox.Show(AlarmsDisabled);

        }

        private void EventID2ToolStripMenuItem_Click(object sender, EventArgs e)
        {
            string _Query = "<QueryList><Query Id=\"0\" Path=\"ETWPM2\"><Select Path=\"ETWPM2\">*[System[(EventID=2)]]</Select></Query></QueryList>";

            StartQueries_Mon(_Query);
            toolStripStatusLabel2.ForeColor = Color.Red;

            toolStripStatusLabel2.Text = "| Filters: Select All EventID 2 [RemoteThreadInjection Detection] | " + AlarmsDisabled;

            MessageBox.Show(AlarmsDisabled);

        }

        private void EventID3ToolStripMenuItem_Click(object sender, EventArgs e)
        {
            string _Query = "<QueryList><Query Id=\"0\" Path=\"ETWPM2\"><Select Path=\"ETWPM2\">*[System[(EventID=3)]]</Select></Query></QueryList>";

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
            MessageBox.Show(null, "ETWPM2Monitor v2 [test version 2.1.0.87]\nCode Published by Damon Mohammadbagher , Jul 2021", "About ETWPM2Monitor v2", MessageBoxButtons.OK, MessageBoxIcon.Information);

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

        private void Button1_Click(object sender, EventArgs e)
        {

        }

        private void CheckBox1_CheckedChanged(object sender, EventArgs e)
        {
            checkBox2.Checked = false;
            checkBox3.Checked = false;

        }

        private void CheckBox2_CheckedChanged(object sender, EventArgs e)
        {
            checkBox1.Checked = false;
            checkBox3.Checked = false;
        }

        private void CheckBox3_CheckedChanged(object sender, EventArgs e)
        {
            checkBox2.Checked = false;
            checkBox1.Checked = false;
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
            BeginInvoke(new __Obj_Updater_to_WinForm(Changedindexof_listview_2));
        }

        public void Changedindexof_listview_2()
        {
            try
            {
                richTextBox2.Text = listView2.SelectedItems[0].Name;
                richTextBox4.Text = listView2.SelectedItems[0].SubItems[9].Text;
                richTextBox5.Text = listView2.SelectedItems[0].SubItems[8].Text;
                string PIDName = listView2.SelectedItems[0].Name.Split('>')[0].Split(':')[0];
                string PID = listView2.SelectedItems[0].Name.Split('>')[0].Split(':')[1];
                string dumpinfotext = richTextBox1.Text;
                StringBuilder lines = new StringBuilder(dumpinfotext);
                richTextBox3.Text = "";
                richTextBox3.Text += "TargetProcess [" + PIDName + ":" + PID + "] Injection History with Debug info:\n";
                richTextBox3.Text += "\n-------------------------------------------------------\n";
                int counter = 0;
                 
                richTextBox3.Text += "Alarm Description & Injector Details:\n";
                /// injection description
                richTextBox3.Text += listView2.SelectedItems[0].SubItems[8].Text + "\n";
                richTextBox3.Text += "\n-------------------------------------------------------\n";
                foreach (string item in lines.ToString().Split('\n'))
                {
                    if (item.Contains("Target_Process: " + PIDName + ":" + PID))
                    {
                        if (!item.Contains("TaskName(TcpIp)"))
                        {
                            richTextBox3.Text += "[" + counter.ToString() + "] " + item + "\n";
                            counter++;
                        }
                    }
                    if ((item.Contains("Debug info:") && item.Contains("PID: (" + PID + ")(" + PIDName + ")")) && (!item.Contains("TaskName(TcpIp)")))
                    {

                        if (!item.Contains("TaskName(TcpIp)"))
                        {
                            richTextBox3.Text += "[" + counter.ToString() + "] " + item + "\n";
                            richTextBox3.Text += "[" + counter.ToString() + "] " + "Injection by " + item.Substring(item.IndexOf("Injected by ")).Split(']')[0].Split(' ')[2] + "===>==TID:" +
                           item.Substring(item.IndexOf("::") - 5, 5) + "==>==Injected into====>" + PIDName + ":" + PID + "\n\n";

                            try
                            {
                                //"Debug info: [2/4/2022 5:58:26 PM] PID: (6592)(notepad) 10336::0x7ff7878c3db0:12408:3652[Injected by dotnet.exe:3652]"

                                var _injector = 0;
                                var __tid = Convert.ToInt32(item.Substring(item.IndexOf("::") - 5, 5));
                                string _System = item.Substring(item.IndexOf("::")).Split(':')[2];

                                try
                                {
                                    _injector = Convert.ToInt32(item.Split('[')[1].Split(':')[7]);
                                }
                                catch (Exception)
                                {

                                    _injector = Convert.ToInt32(item.Substring(item.IndexOf("Injected by ")).Split(']')[0].Split(' ')[2].Split(':')[1]);
                                }

                                richTextBox3.Text += "ETW Event & Injection Details:\n";

                                try
                                {
                                    _InjectedThreadDetails_bytes details = _InjectedTIDList.Find(_x => _x._RemoteThreadID == __tid && _x._TargetPID == Convert.ToInt32(PID) && _x._InjectorPID == _injector);

                                    richTextBox3.Text += "\nInjectorPID: " + details._InjectorPID.ToString() +
                                        "\nTargetPID: " + details._TargetPID.ToString() + "\nInjectedTID: " + details._RemoteThreadID.ToString() +
                                        "\nStartAddress: " + details._ThreadStartAddress + "\n\nInjectedBytes[HEX]:\n" + details.Injected_Memory_Bytes_Hex + "\n";
                                }
                                catch (Exception)
                                {


                                }

                            }
                            catch (Exception)
                            {


                            }
                        }
                    }

                }
                richTextBox3.Text += "\n-------------------------------------------------------\n\n";


            }
            catch (Exception)
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

            richTextBox1.BackColor = Control.DefaultBackColor;
            toolStripSeparator1.BackColor = Control.DefaultBackColor;
            statusStrip1.BackColor = Control.DefaultBackColor;
            menuStrip3.BackColor = Control.DefaultBackColor;
            toolStripSeparator1.BackColor = Color.Black;
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
                        _InjectorPID = Convert.ToInt32(_injector)

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
                st.AppendLine(xitem.SubItems[6].Text);
                st.AppendLine(xitem.SubItems[7].Text);
                st.AppendLine("Description:");
                st.AppendLine(xitem.SubItems[8].Text);
                st.AppendLine("ETW Event Message:");
                st.AppendLine(xitem.SubItems[9].Text);              
                st.AppendLine(" ");
                st.AppendLine("Debug Info & Details:");
                string PIDName = xitem.SubItems[2].Text.Split(':')[0];
                string PID = xitem.SubItems[2].Text.Split(':')[1];
                int counter = 0;
                int showtime = 1;
                bool showshowtime = false;
                foreach (string item in lines.ToString().Split('\n'))
                {
                    if (item.Contains("Target_Process: " + PIDName + ":" + PID))
                    {
                        if (!item.Contains("TaskName(TcpIp)"))
                        {
                            st.AppendLine("[" + counter.ToString() + "] " + item + "\n");
                            counter++;
                        }
                    }
                    if ((item.Contains("Debug info:") && item.Contains("PID: (" + PID + ")(" + PIDName + ")")) && (!item.Contains("TaskName(TcpIp)")))
                    {

                        if (!item.Contains("TaskName(TcpIp)"))
                        {
                            st.AppendLine("[" + counter.ToString() + "] " + item + "\n");
                            st.AppendLine("[" + counter.ToString() + "] " + "Injection by " + item.Substring(item.IndexOf("Injected by ")).Split(']')[0].Split(' ')[2] + "===>==TID:" +
                           item.Substring(item.IndexOf("::") - 5, 5) + "==>==Injected into====>" + PIDName + ":" + PID + "\n\n");
                            //counter++;
                            showshowtime = true;
                            st.AppendLine("ETW Event & Injection Details:\n");
                        }
                    }
                    if (showshowtime)
                    {
                        if (showtime <= 27)
                        {
                            st.AppendLine(item + "\n");
                            showtime++;
                        }
                        if (showtime == 29 || item.Contains("ReadProcessMemory [ERROR]"))
                        {
                            showshowtime = false;
                            showtime = 1;
                        }
                    }
                }
                st.AppendLine(" ");
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
