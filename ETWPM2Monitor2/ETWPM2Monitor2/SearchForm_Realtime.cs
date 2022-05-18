using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace ETWPM2Monitor2
{
    public partial class SearchForm_Realtime : Form
    {
        public SearchForm_Realtime()
        {
            InitializeComponent();
        }

        public static DataTable ProcessTable1 = new DataTable("ETW_logs");
        public static DataColumn Processcolumn1;
        public static DataRow Processrow1;
        public Form newform = new Form();
        public static EventLog ETW2MON;
        public static EventLogQuery ETWPM2Query;
        public static Thread _Thread_02, _Thread_01;

        public delegate void __SearchRun();
        public delegate void __Obj_Updater_to_WinForm();

        public static bool formclosing, stopsearch, isrunningSearch = false;

        public static CancellationTokenSource _dowork;
        public static ListViewItem MyLviewItemsX = new ListViewItem();
        public static Form1 _Form1 = new Form1();
        public static bool ALT_F4 = false;
        public static bool _StopFilter = false;
        string Help = "";
        
        

        public static void GetRowsTODataTable(DateTime _Time, string _EventID, Int32 _PID, string _Process, string _EventMessage )
        {

            try
            {
                Processrow1 = ProcessTable1.NewRow();
                Processrow1["Time"] = _Time;
                Processrow1["EventID"] = _EventID;
                Processrow1["Process"] = _Process;
                Processrow1["PID"] = _PID;
                Processrow1["EventMessage"] = _EventMessage;
                ProcessTable1.Rows.Add(Processrow1);
            }
            catch (Exception err)
            {


            }


        }
             
        public static void TCPIP_settable2()
        {
            try
            {
                ProcessTable1.Columns.Clear();
                ProcessTable1.Rows.Clear();

                Processcolumn1 = new DataColumn();
                Processcolumn1.DataType = System.Type.GetType("System.DateTime");
                Processcolumn1.ColumnName = "Time";
                ProcessTable1.Columns.Add(Processcolumn1);
                 
                Processcolumn1 = new DataColumn();
                Processcolumn1.DataType = Type.GetType("System.String");
                Processcolumn1.ColumnName = "EventID";
                ProcessTable1.Columns.Add(Processcolumn1);

                Processcolumn1 = new DataColumn();
                Processcolumn1.DataType = System.Type.GetType("System.String");
                Processcolumn1.ColumnName = "Process";
                ProcessTable1.Columns.Add(Processcolumn1);

                Processcolumn1 = new DataColumn();
                Processcolumn1.DataType = System.Type.GetType("System.Int32");
                Processcolumn1.ColumnName = "PID";
                ProcessTable1.Columns.Add(Processcolumn1);

                Processcolumn1 = new DataColumn();
                Processcolumn1.DataType = System.Type.GetType("System.String");
                Processcolumn1.ColumnName = "EventMessage";
                ProcessTable1.Columns.Add(Processcolumn1);

            }
            catch (Exception err)
            {
               
            }
        }

        private void Button1_Click(object sender, EventArgs e)
        {
            DataTable dt = new DataTable();
            ThreadStart __SearchItems_Addtolistview1 = new ThreadStart(delegate
            {
                BeginInvoke(new __SearchRun(_RunSearch));
            });
            _Thread_01 = new Thread(__SearchItems_Addtolistview1);
            _Thread_01.Priority = ThreadPriority.Highest;
            _Thread_01.Start();
            DataView __Resourcetosearch = new DataView();
            button1.Enabled = false;
            button2.Enabled = false;
            button4.Enabled = false;
            button5.Enabled = false;
        }

        public async void _RunSearch()
        {
            await _Search_Core();
        }
       
        public async Task _Search_Core()
        {
            try
            {

                TCPIP_settable2();
                listView1.Items.Clear();
                stopsearch = false;
                formclosing = false;
                richTextBox1.Text = "";

                await Task.Run(() =>
                {
                    try
                    {
 
                        EventLog dump_filters = new EventLog("ETWPM2", ".");
                        _dowork = new CancellationTokenSource();

                        if (_dowork.IsCancellationRequested)
                        {
                            _Thread_01.Abort();
                           
                        }

                        MyLviewItemsX = new ListViewItem();

                        if (comboBox1.SelectedIndex == 0)
                        {
                            /// searching in Event ID 1 or New Process Events
                            listView1.Enabled = false;
                            textBox1.Enabled = false;
                            string __FirstCondition = "";
                            if (checkBox1.Checked) { __FirstCondition = "processname = "; }
                            if (checkBox2.Checked) { __FirstCondition = "commandline: "; }
                            if (checkBox3.Checked) { __FirstCondition = "parentid: "; }
                            if (checkBox4.Checked) { __FirstCondition = "parentid path: "; }
                            if (checkBox5.Checked) { __FirstCondition = ""; }

                            List<EventLogEntry> evtx = dump_filters.Entries.Cast<EventLogEntry>()
                            .ToList().FindAll(x => x.InstanceId == 1 && x.Message.ToLower().Contains(__FirstCondition + textBox1.Text.ToLower()));

                          
                            foreach (EventLogEntry item in evtx)                                                       
                            {
                               
                                if (_dowork.IsCancellationRequested)
                                {
                                   
                                    break;

                                }

                                Thread.Sleep(1);

                                if (stopsearch) break;
                                isrunningSearch = true;
                                MyLviewItemsX = new ListViewItem();

                                try
                                {

                                    GetRowsTODataTable(
                                          item.TimeGenerated
                                        , item.InstanceId.ToString()
                                        , Convert.ToInt32(item.Message.Split('\n')[2].Split(' ')[2])
                                        , item.Message.Split('\n')[3].Split('=')[1]
                                        , item.Message);
                                    MyLviewItemsX.SubItems.Add(item.TimeGenerated.ToString());
                                    MyLviewItemsX.SubItems.Add(item.Message.Split('\n')[3].Split('=')[1] + ":" + item.Message.Split('\n')[2].Split(' ')[2]);
                                    MyLviewItemsX.SubItems.Add(item.InstanceId.ToString());
                                    MyLviewItemsX.SubItems.Add(item.Message);
                                    MyLviewItemsX.Name = item.Message;
                                    listView1.Items.Add(MyLviewItemsX);

                                }
                                catch (Exception)
                                {
                                    button1.Enabled = true;
                                    button2.Enabled = true;
                                    button4.Enabled = true;
                                    button5.Enabled = true;
                                    listView1.Enabled = true;
                                    break;
                                }
                               
                                if (stopsearch) break;

                            }

                            isrunningSearch = false;
                            button1.Enabled = true;
                            button2.Enabled = true;
                            button4.Enabled = true;
                            button5.Enabled = true;
                            listView1.Enabled = true;
                            textBox1.Enabled = true;

                        }
                        else if (comboBox1.SelectedIndex == 1)
                        {

                            /// searching in Event ID 2 or Remote Thread Injected Events
                            listView1.SmallImageList = _Form1.imageList1;
                           
                            listView1.Enabled = false;
                            textBox1.Enabled = false;

                            string __FirstCondition1 = "";
                            if (checkBox_ID2_TargetProcessName.Checked) { __FirstCondition1 = "targetprocessname > "; }
                            if (checkBox_ID2_Eventmessage.Checked) { __FirstCondition1 = ""; }
                            if (checkBox_ID2_InjectedTID.Checked) { __FirstCondition1 = "injectedtid > "; }
                            if (checkBox_ID2_InjectorPID.Checked) { __FirstCondition1 = "injectorpid > "; }
                            if (checkBox_ID2_StartAdd.Checked) { __FirstCondition1 = "startaddress > "; }
                            if (checkBox_ID2_Target_ProcessPath.Checked) { __FirstCondition1 = "target_processpath: "; }
                            if (checkBox_ID2_TPID.Checked) { __FirstCondition1 = "tpid > "; }

                            List<EventLogEntry> evtx = dump_filters.Entries.Cast<EventLogEntry>()
                           .ToList().FindAll(x => x.InstanceId == 1 && x.Message.ToLower().Contains(__FirstCondition1 + textBox1.Text.ToLower()));

                           
                            foreach (EventLogEntry item in evtx)
                            {
                                
                                if (_dowork.IsCancellationRequested)
                                {
                                    
                                    break;
                                }

                                Thread.Sleep(1);

                                if (stopsearch) break;
                                isrunningSearch = true;
                                MyLviewItemsX = new ListViewItem();

                                try
                                {

                                    GetRowsTODataTable(
                                          item.TimeGenerated
                                        , item.InstanceId.ToString()
                                        , Convert.ToInt32(item.Message.Split('\n')[8].Split('>')[1].Substring(1))
                                        , item.Message.Split('\n')[15].Split('>')[1].Substring(1)
                                        , item.Message);
                                    MyLviewItemsX.SubItems.Add(item.TimeGenerated.ToString());
                                    MyLviewItemsX.SubItems.Add(item.Message.Split('\n')[15].Split('>')[1].Substring(1)
                                        + ":" + item.Message.Split('\n')[8].Split('>')[1].Substring(1));
                                    MyLviewItemsX.SubItems.Add(item.InstanceId.ToString());
                                    MyLviewItemsX.SubItems.Add(item.Message);
                                    MyLviewItemsX.Name = item.Message;

                                    if (!item.Message.Split('\n')[5].Contains("[Injected by System]")
                                        && !item.Message.Split('\n')[5].Contains("[Injected by explorer]"))
                                    {
                                        MyLviewItemsX.ImageIndex = 9;
                                    }
                                    else
                                    {
                                        MyLviewItemsX.ImageIndex = 8;
                                    }

                                    listView1.Items.Add(MyLviewItemsX);

                                }
                                catch (Exception)
                                {
                                    button1.Enabled = true;
                                    button2.Enabled = true;
                                    button4.Enabled = true;
                                    button5.Enabled = true;
                                    listView1.Enabled = true;
                                    break;
                                }
                                 
                                if (stopsearch) break;

                            }

                            isrunningSearch = false;
                            button1.Enabled = true;
                            button2.Enabled = true;
                            button4.Enabled = true;
                            button5.Enabled = true;
                            listView1.Enabled = true;
                            textBox1.Enabled = true;

                        }
                        else if (comboBox1.SelectedIndex == 2)
                        {
                            /// searching in Event ID 3 or TCP Connect/send Events
                            listView1.SmallImageList = _Form1.imageList1;
                            ///This Description Added by ETWPM2Monitor2 tool
                            listView1.Enabled = false;
                            textBox1.Enabled = false;
 
                            string __FirstCondition3 = "";

                            if (checkBox_ID3_EventMessage.Checked) { __FirstCondition3 = ""; }
                            if (checkBox_ID3_PIDPath.Checked) { __FirstCondition3 = "pidpath = "; }
                            if (checkBox_ID3_Target_Process.Checked) { __FirstCondition3 = "target_process: "; }



                            List<EventLogEntry> evtx = dump_filters.Entries.Cast<EventLogEntry>()
                          .ToList().FindAll(x => x.InstanceId == 1 && x.Message.ToLower().Contains(__FirstCondition3 + textBox1.Text.ToLower()));

                            foreach (EventLogEntry item in evtx)
                            {

                                if (_dowork.IsCancellationRequested)
                                {
                                   
                                    break;
                                }
                                Thread.Sleep(1);
                                if (stopsearch) break;
                                isrunningSearch = true;
                                MyLviewItemsX = new ListViewItem();

                                try
                                {

                                    GetRowsTODataTable(
                                          item.TimeGenerated
                                        , item.InstanceId.ToString()
                                        , Convert.ToInt32(item.Message.Split('\n')[2].Split(':')[2].Split(' ')[0])
                                        , item.Message.Split('\n')[2].Split(':')[1].Substring(1)
                                        , item.Message);
                                    MyLviewItemsX.SubItems.Add(item.TimeGenerated.ToString());
                                    MyLviewItemsX.SubItems.Add(item.Message.Split('\n')[2].Split(':')[1].Substring(1)
                                        + ":" + item.Message.Split('\n')[2].Split(':')[2].Split(' ')[0]);
                                    MyLviewItemsX.SubItems.Add(item.InstanceId.ToString());

                                    if ((item.Message.Split('\n')[6].Contains("[dport:4444]")) || (item.Message.Split('\n')[6].Contains("[size:160]")) || (item.Message.Split('\n')[6].Contains("[size:192]")))
                                    {
                                        MyLviewItemsX.ImageIndex = 12;
                                        MyLviewItemsX.SubItems.Add(item.Message + "\n\n#This Description Added by ETWPM2Monitor2 tool#\n##Warning Description: Packet with [size:160] maybe was for Meterpreter Session which will send every 1 min between Client/Server##\n" +
                                        "##Warning Description: Packet with [size:192] is for meterpreter session which will send before every command excution from/to server##\n" +
                                        "##Warning Description: DestinationPort [dport:4444] is Default port for Meterpreter session##");
                                    }
                                    else
                                    {
                                        MyLviewItemsX.SubItems.Add(item.Message);
                                    }

                                    MyLviewItemsX.Name = item.Message;
                                    listView1.Items.Add(MyLviewItemsX);

                                }
                                catch (Exception)
                                {
                                    button1.Enabled = true;
                                    button2.Enabled = true;
                                    button4.Enabled = true;
                                    button5.Enabled = true;
                                    listView1.Enabled = true;
                                    break;
                                }

                                
                                if (stopsearch) break;

                            }

                            isrunningSearch = false;
                            button1.Enabled = true;
                            button2.Enabled = true;
                            button4.Enabled = true;
                            button5.Enabled = true;
                            listView1.Enabled = true;
                            textBox1.Enabled = true;
                        }

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

        private void SearchForm_Realtime_Load(object sender, EventArgs e)
        {
            comboBox1.SelectedIndex = 0;

            _Thread_01 = null;
            _Thread_02 = null;
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

            listView1.Columns.Add(" ", 20, HorizontalAlignment.Left);
            listView1.Columns.Add("Time", 130, HorizontalAlignment.Left);
            listView1.Columns.Add("Process", 120, HorizontalAlignment.Left);
            listView1.Columns.Add("EventID", 60, HorizontalAlignment.Left);
            listView1.Columns.Add("EventMessage", 400, HorizontalAlignment.Left);

            Help = "################Event ID 1 NewProcess Created#####################################" + "\n" +
"[ETW] " + "\n" +
"[MEM] NewProcess Started " + "\n" +
"PID = 8932  PIDPath = C:\\Program Files\\Windows Defender\\MpCmdRun.exe" + "\n" +
"ProcessName = MpCmdRun" + "\n" +
"[CommandLine: \"C:\\Program Files\\Windows Defender\\MpCmdRun.exe\" Scan -ScheduleJob -ScanTrigger 55]" + "\n" +
"[ParentID: 1320]" + "\n" +
"[ParentID Path: C:\\Windows\\System32\\svchost.exe]" + "\n" +
"EventTime = 5/13/2022 12:10:06 AM" + "\n" +
"----------------------------------------------------------------------------------" + "\n" +
"Filter Examples:" + "\n" +
"step one : you should search items by string." + "\n" +
"note (step one): if you want to use filter on all NewProcess records you should use \"[MEM] NewProcess Started\" string in search items and Select EventMessage Checkbox and click search to find/load all records then you can use Filters for all records." + "\n" +
"step two : use filters on search results..." + "\n" +
"" + "\n" +
"1.filter NewProcess via Args in CommandLine in Eventmessage \"Column\"" + "\n" +
"eventmessage like '*ScheduleJob*'" + "\n" +
"eventmessage like '*,*'" + "\n" +
"eventmessage like '*fc,48,83,e4,f0*'" + "\n" +
"eventmessage like '*--type=renderer*'" + "\n" +
"eventmessage like '*192.168.56.1*'" + "\n" +
"" + "\n" +
"2.filter NewProcess via ParentID in Eventmessage \"Column\"" + "\n" +
"eventmessage like '*ParentID: 1320*'" + "\n" +
"" + "\n" +
"3.filter NewProcess via ParentID Path in Eventmessage \"Column\"" + "\n" +
"eventmessage like '*ParentID Path: C:\\Windows\\System32\\cmd.exe*'" + "\n" +
"eventmessage like '*ParentID Path: c:\\windows\\system32\\cmd.exe*' or PID > 1000" + "\n" +
"eventmessage like '*ParentID Path: c:\\windows\\system32\\cmd.exe*' and PID >= 1000" + "\n" +
"eventmessage like '*ParentID Path: c:\\windows\\system32\\cmd.exe*' or eventmessage like '*ParentID Path: c:\\windows\\explorer.exe*'" + "\n" +
"eventmessage like '*ParentID Path: c:\\windows\\system32\\cmd.exe*' or eventmessage not like '*ParentID Path: c:\\windows\\explorer.exe*'" + "\n" +
"eventmessage like '*ParentID Path: c:\\windows\\system32\\cmd.exe*' and eventmessage not like '*ProcessName = MpCmdRun*'" + "\n" +
"" + "\n" +
"4.filter NewProcess via EventTime in Eventmessage \"Column\"" + "\n" +
"eventmessage like '*EventTime = 5/13/*'" + "\n" +
"" + "\n" +
"5.filter NewProcess via numbers in PID \"Column\"" + "\n" +
"PID = 8932" + "\n" +
"PID <= 8932" + "\n" +
"" + "\n" +
"6.filter NewProcess via Process \"Column\"" + "\n" +
"Process like '*svchost*'" + "\n" +
"" + "\n" +
"7.filter NewProcess via Time \"Column\"" + "\n" +
"time = '5/12/2022 11:56:46 PM'" + "\n" +
"time = '5/14/2022 3:05:23 PM' or Process like '*dotnet*'" + "\n" +
"time = '5/14/2022 3:05:23 PM' and Process not like '*dotnet*'" + "\n" +
"time > '5/12/2022 11:56:46 PM' or Process like '*conh*'" + "\n" +
"time < '5/12/2022 11:56:46 PM' and Process like '*conhost*'" + "\n" +
"" + "\n" +
"################Event ID 1 NewProcess Created#####################################" + "\n" +
"" + "\n" +
"################Event ID 2 Injected ThreadStart Detected##########################" + "\n" +
"[ETW] " + "\n" +
"[MEM] Injected ThreadStart Detected," + "\n" +
"Target_Process: svchost:1616   TID(10916) Injected by Process Exited (PID:4)" + "\n" +
"Target_ProcessPath: C:\\Windows\\System32\\svchost.exe" + "\n" +
"" + "\n" +
"Debug info: [5/12/2022 11:55:44 PM] PID: (1616)(svchost) 10916::0x7ff87e6a2ad0:36:4[Injected by System]" + "\n" +
"---------------------------------------------" + "\n" +
"Debug Integers : TargetProcessPID,InjectedTID:StartAddress:ParentThreadID:InjectorPID" + "\n" +
"TPID > 1616" + "\n" +
"InjectedTID > 10916" + "\n" +
"StartAddress > 0x7ff87e6a2ad0" + "\n" +
"PTID > 36" + "\n" +
"InjectorPID > 4" + "\n" +
"---------------------------------------------" + "\n" +
"Debug Process_Names : TargetProcessName,InjectorProcessName" + "\n" +
"TargetProcessName > svchost" + "\n" +
"InjectorProcessName > Process Exited (PID:4)" + "\n" +
"EventTime > 5/12/2022 11:55:44 PM" + "\n" +
"----------------------------------------------------------------------------------" + "\n" +
"Filter Examples:" + "\n" +
"step one : you should search items by string." + "\n" +
"note (step one): if you want to use filter on all Injected Thread records you should use \"[MEM] Injected ThreadStart Detected\" string in search items and Select EventMessage Checkbox and click search to find/load all records then you can use Filters for all records." + "\n" +
"step two : use filters on search results..." + "\n" +
"" + "\n" +
"1.filter Injected Threads Records via Useful string (Not injected by explorer or system:4) in Eventmessage \"Column\", this" + "\n" +
"will help you to find injectors which is not system (pid:4) or explorer etc." + "\n" +
"eventmessage not like '* Injected by C:\\Windows\\explorer.exe*' and eventmessage not like '* Injected by Process Exited (PID:4)*'" + "\n" +
"" + "\n" +
"2.filter Injected Threads Records via TargetProcess Name in Eventmessage \"Column\"" + "\n" +
"eventmessage like '*Target_Process: svchost:3426*'" + "\n" +
"eventmessage like '*Target_Process: svchost:*'" + "\n" +
"eventmessage like '*Target_Process: mspaint*'" + "\n" +
"eventmessage like '*Target_Process: svc*' or eventmessage like '*Target_Process: ms*'" + "\n" +
"eventmessage like '*Target_Process: svc*' or eventmessage not like '*Target_Process: ms*'" + "\n" +
"" + "\n" +
"3.filter Injected Threads Records via InjectorPID in Eventmessage \"Column\"" + "\n" +
"eventmessage like '*InjectorPID > 10936*'" + "\n" +
"eventmessage like '*InjectorPID > 10936*' or eventmessage not like '*InjectorPID > 4*'" + "\n" +
"" + "\n" +
"4.filter Injected Threads Records via StartAddress in Eventmessage \"Column\"" + "\n" +
"eventmessage like '*StartAddress > 0x7ff87e6*'" + "\n" +
"################Event ID 2 Injected ThreadStart Detected##########################" + "\n" +
"" + "\n" +
"################Event ID 3 TcpIpSend/Connect Detected#############################" + "\n" +
"[ETW] " + "\n" +
"[TCPIP] TcpIpSend Detected" + "\n" +
"Target_Process: msedge:9676  TID(-1) TaskName(TcpIp) " + "\n" +
"PIDPath = C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" + "\n" +
"EventTime = 5/14/2022 3:05:23 PM" + "\n" +
"" + "\n" +
"[size:0][daddr:127.0.0.1][saddr:127.0.0.1][dport:80][sport:50145][mss:-41][sackopt:1][tsopt:0][wsopt:1][rcvwin:2619800][rcvwinscale:8][sndwinscale:8][seqnum:0][connid:0]" + "\n" +
"----------------------------------------------------------------------------------" + "\n" +
"[ETW] " + "\n" +
"[TCPIP] TcpIpSend Detected" + "\n" +
"Target_Process: mspaint:8400  TID(-1) TaskName(TcpIp) " + "\n" +
"PIDPath = C:\\Windows\\System32\\mspaint.exe" + "\n" +
"EventTime = 5/12/2022 11:54:25 PM" + "\n" +
"" + "\n" +
"[size:0][daddr:192.168.56.101][saddr:192.168.56.1][dport:443][sport:50755][mss:1460][sackopt:1][tsopt:0][wsopt:1][rcvwin:262144][rcvwinscale:8][sndwinscale:7][seqnum:0][connid:18446744069414584320]" + "\n" +
"" + "\n" +
"Filter Examples:" + "\n" +
"step one : you should search items by string." + "\n" +
"note (step one): if you want to use filter on all TcpIpSend/Connect Detected records you should use \"[TCPIP] TcpIpSend Detected\" string in search items and Select EventMessage Checkbox and click search to find/load all records then you can use Filters for all records." + "\n" +
"step two : use filters on search results..." + "\n" +
"" + "\n" +
"1.filter TCP Connect events via pidpath in Eventmessage  \"Column\" , useful to detect network connections which made by attackers (sometimes)" + "\n" +
"EVENTMESSAGE NOT LIKE '*PIDPath = C:\\WINDOWS\\*'" + "\n" +
"EVENTMESSAGE NOT LIKE '*\\WINDOWS\\*'" + "\n" +
"" + "\n" +
"2.filter TCP Connect events via size in Eventmessage \"Column\"" + "\n" +
"eventmessage like '*size:160*'" + "\n" +
"" + "\n" +
"3.filter TCP Connect events via Destination IP in Eventmessage \"Column\"" + "\n" +
"eventmessage like '*daddr:192.168.56.101*'" + "\n" +
"" + "\n" +
"4.filter TCP Connect events via process name in Process \"Column\"" + "\n" +
"Process like '*mspaint*'" + "\n" +
"" + "\n" +
"5.filter TCP Connect events via numbers in Time \"Column\"" + "\n" +
"time = '5/12/2022 11:56:46 PM'" + "\n" +
"time = '5/14/2022 3:05:23 PM' or Process like '*dotnet*'" + "\n" +
"time = '5/14/2022 3:05:23 PM' and Process not like '*dotnet*'" + "\n" +
"time > '5/12/2022 11:56:46 PM' or Process like '*mspaint*'" + "\n" +
"time < '5/12/2022 11:56:46 PM' and Process like '*notepad*'" + "\n" +
"################Event ID 3 TcpIpSend/Connect Detected#############################" + "\n";


         
        }

        public async void _Runfilterasync()
        {
            await _RunFilters();
        }

        public async Task _RunFilters()
        {
            try
            {
                _StopFilter = false;
                button4.Enabled = false;
                listView1.Items.Clear();
                listView1.Enabled = false;
                richTextBox2.Text = "";
                textBox2.Enabled = false;
                 

                await Task.Run(() =>
                {
                    DataRow[] DT = ProcessTable1.Select(textBox2.Text);
                    
                    foreach (DataRow item in DT)
                    {
                        if (_StopFilter)
                        {
                            textBox2.Enabled = true;
                            listView1.Enabled = true;
                            button4.Enabled = true;
                            button1.Enabled = true;
                            button3.Enabled = true;
                            button2.Enabled = true;
                            _Thread_02.Abort();
                            break;
                        }
                        MyLviewItemsX = new ListViewItem();

                        MyLviewItemsX.SubItems.Add(item[0].ToString());
                        MyLviewItemsX.SubItems.Add(item[2].ToString() + ":" + item[3].ToString());
                        MyLviewItemsX.SubItems.Add(item[1].ToString());
                        MyLviewItemsX.SubItems.Add(item[4].ToString());
                        MyLviewItemsX.Name = item[4].ToString();
                        listView1.Items.Add(MyLviewItemsX);
                    }
                });
                textBox2.Enabled = true;
                listView1.Enabled = true;              
                button4.Enabled = true;
                button1.Enabled = true;
                button3.Enabled = true;
                button2.Enabled = true;
            }
            catch (Exception error)
            {
                richTextBox2.Text = error.Message;
                textBox2.Enabled = true;
                listView1.Enabled = true;
                button4.Enabled = true;
                button1.Enabled = true;
                button3.Enabled = true;
                button2.Enabled = true;
            }
        }

        private void Button2_Click(object sender, EventArgs e)
        {
            try
            {
                ThreadStart __SearchItems_Addtolistview1_filter = new ThreadStart(delegate
                {
                    BeginInvoke(new __Obj_Updater_to_WinForm(_Runfilterasync));
                });
                _Thread_02 = new Thread(__SearchItems_Addtolistview1_filter);
                _Thread_02.Priority = ThreadPriority.Highest;
                _Thread_02.Start();
                button1.Enabled = false;
                button3.Enabled = false;
                button2.Enabled = false;
            }
            catch (Exception error)
            {
              
               
            }
        }

        public void ShowDetailsRichTextbox1()
        {
            try
            {
                richTextBox1.Text = listView1.SelectedItems[0].SubItems[4].Text.ToString();
            }
            catch (Exception)
            {
            
            }
        }

        private void ListView1_SelectedIndexChanged(object sender, EventArgs e)
        {
            try
            {
                BeginInvoke(new __Obj_Updater_to_WinForm(ShowDetailsRichTextbox1));

            }
            catch (Exception)
            {

            }

        }

        private void TextBox1_TextChanged(object sender, EventArgs e)
        {

        }

        private void ComboBox1_SelectedIndexChanged(object sender, EventArgs e)
        {
            if(comboBox1.SelectedIndex == 0)
            {
                checkBox1.Enabled = true;
                checkBox2.Enabled = true;
                checkBox3.Enabled = true;
                checkBox4.Enabled = true;
                checkBox5.Enabled = true;
                checkBox_ID2_Eventmessage.Enabled = false;
                checkBox_ID2_InjectedTID.Enabled = false;
                checkBox_ID2_InjectorPID.Enabled = false;
                checkBox_ID2_StartAdd.Enabled = false;
                checkBox_ID2_TargetProcessName.Enabled = false;
                checkBox_ID2_Target_ProcessPath.Enabled = false;
                checkBox_ID2_TPID.Enabled = false;

                checkBox_ID3_EventMessage.Enabled = false;
                checkBox_ID3_PIDPath.Enabled = false;
                checkBox_ID3_Target_Process.Enabled = false;
            }
            if (comboBox1.SelectedIndex == 1)
            {
                checkBox1.Enabled = false;
                checkBox2.Enabled = false;
                checkBox3.Enabled = false;
                checkBox4.Enabled = false;
                checkBox5.Enabled = false;
                checkBox_ID2_Eventmessage.Enabled = true;
                checkBox_ID2_InjectedTID.Enabled = true;
                checkBox_ID2_InjectorPID.Enabled = true;
                checkBox_ID2_StartAdd.Enabled = true;
                checkBox_ID2_TargetProcessName.Enabled = true;
                checkBox_ID2_Target_ProcessPath.Enabled = true;
                checkBox_ID2_TPID.Enabled = true;
                checkBox_ID3_EventMessage.Enabled = false;
                checkBox_ID3_PIDPath.Enabled = false;
                checkBox_ID3_Target_Process.Enabled = false;
            }
            if (comboBox1.SelectedIndex == 2)
            {
                checkBox1.Enabled = false;
                checkBox2.Enabled = false;
                checkBox3.Enabled = false;
                checkBox4.Enabled = false;
                checkBox5.Enabled = false;
                checkBox_ID2_Eventmessage.Enabled = false;
                checkBox_ID2_InjectedTID.Enabled = false;
                checkBox_ID2_InjectorPID.Enabled = false;
                checkBox_ID2_StartAdd.Enabled = false;
                checkBox_ID2_TargetProcessName.Enabled = false;
                checkBox_ID2_Target_ProcessPath.Enabled = false;
                checkBox_ID2_TPID.Enabled = false;
                checkBox_ID3_EventMessage.Enabled = true ;
                checkBox_ID3_PIDPath.Enabled = true;
                checkBox_ID3_Target_Process.Enabled = true;
            }
        }

        private void Button4_Click(object sender, EventArgs e)
        {
            stopsearch = true;
            ALT_F4 = true;
            try
            {
                GC.Collect();
                newform.Close();
            }
            catch (Exception)
            {

                
            }
           
            Thread.Sleep(1000);
            this.Close();
           
        }

        private void CheckBox5_CheckedChanged(object sender, EventArgs e)
        {
          
             if (checkBox5.Checked) {  checkBox2.Checked = false; checkBox3.Checked = false; checkBox4.Checked = false; checkBox1.Checked = false; }
        }

        private void CheckBox1_CheckedChanged(object sender, EventArgs e)
        {
            if (checkBox1.Checked) { checkBox2.Checked = false; checkBox3.Checked = false; checkBox4.Checked = false; checkBox5.Checked = false; }
            
        }

        private void CheckBox2_CheckedChanged(object sender, EventArgs e)
        {
            
             if (checkBox2.Checked) { checkBox1.Checked = false; checkBox3.Checked = false; checkBox4.Checked = false; checkBox5.Checked = false; }
          
        }

        private void CheckBox4_CheckedChanged(object sender, EventArgs e)
        {
           
             if (checkBox4.Checked) { checkBox2.Checked = false; checkBox3.Checked = false; checkBox1.Checked = false; checkBox5.Checked = false; }
           
        }

        private void CheckBox_ID2_Eventmessage_CheckedChanged(object sender, EventArgs e)
        {
            if (checkBox_ID2_Eventmessage.Checked)
            {
                checkBox_ID2_InjectedTID.Checked = false;
                checkBox_ID2_InjectorPID.Checked = false;
                checkBox_ID2_StartAdd.Checked = false;
                checkBox_ID2_TargetProcessName.Checked = false;
                checkBox_ID2_Target_ProcessPath.Checked = false;
                checkBox_ID2_TPID.Checked = false;
            }
        }

        private void CheckBox_ID2_TargetProcessName_CheckedChanged(object sender, EventArgs e)
        {
            if (checkBox_ID2_TargetProcessName.Checked)
            {
                checkBox_ID2_InjectedTID.Checked = false;
                checkBox_ID2_InjectorPID.Checked = false;
                checkBox_ID2_StartAdd.Checked = false;
                checkBox_ID2_Target_ProcessPath.Checked = false;
                checkBox_ID2_Eventmessage.Checked = false;
                checkBox_ID2_TPID.Checked = false;
            }
        }

        private void CheckBox_ID2_TPID_CheckedChanged(object sender, EventArgs e)
        {
            if (checkBox_ID2_TPID.Checked)
            {
                checkBox_ID2_InjectedTID.Checked = false;
                checkBox_ID2_InjectorPID.Checked = false;
                checkBox_ID2_StartAdd.Checked = false;
                checkBox_ID2_Target_ProcessPath.Checked = false;
                checkBox_ID2_Eventmessage.Checked = false;
                checkBox_ID2_TargetProcessName.Checked = false;
            }
        }

        private void CheckBox_ID2_InjectedTID_CheckedChanged(object sender, EventArgs e)
        {
            if (checkBox_ID2_InjectedTID.Checked)
            {
                checkBox_ID2_TPID.Checked = false;
                checkBox_ID2_InjectorPID.Checked = false;
                checkBox_ID2_StartAdd.Checked = false;
                checkBox_ID2_Target_ProcessPath.Checked = false;
                checkBox_ID2_Eventmessage.Checked = false;
                checkBox_ID2_TargetProcessName.Checked = false;
            }
        }

        private void CheckBox_ID2_StartAdd_CheckedChanged(object sender, EventArgs e)
        {
            if (checkBox_ID2_StartAdd.Checked)
            {
                checkBox_ID2_InjectedTID.Checked = false;
                checkBox_ID2_InjectorPID.Checked = false;
                checkBox_ID2_TPID.Checked = false;
                checkBox_ID2_Target_ProcessPath.Checked = false;
                checkBox_ID2_Eventmessage.Checked = false;
                checkBox_ID2_TargetProcessName.Checked = false;
            }
        }

        private void CheckBox_ID2_InjectorPID_CheckedChanged(object sender, EventArgs e)
        {
            if (checkBox_ID2_InjectorPID.Checked)
            {
                checkBox_ID2_InjectedTID.Checked = false;
                checkBox_ID2_TPID.Checked = false;
                checkBox_ID2_StartAdd.Checked = false;
                checkBox_ID2_Target_ProcessPath.Checked = false;
                checkBox_ID2_Eventmessage.Checked = false;
                checkBox_ID2_TargetProcessName.Checked = false;
            }
        }

        private void CheckBox_ID2_Target_ProcessPath_CheckedChanged(object sender, EventArgs e)
        {
            if (checkBox_ID2_Target_ProcessPath.Checked)
            {
                checkBox_ID2_InjectedTID.Checked = false;
                checkBox_ID2_TPID.Checked = false;
                checkBox_ID2_StartAdd.Checked = false;
                checkBox_ID2_InjectorPID.Checked = false;
                checkBox_ID2_Eventmessage.Checked = false;
                checkBox_ID2_TargetProcessName.Checked = false;
            }
        }

        private void CheckBox_ID3_EventMessage_CheckedChanged(object sender, EventArgs e)
        {
            if (checkBox_ID3_EventMessage.Checked)
            {
                checkBox_ID3_PIDPath.Checked = false;
                checkBox_ID3_Target_Process.Checked = false;
            }
        }

        private void CheckBox_ID3_Target_Process_CheckedChanged(object sender, EventArgs e)
        {
            if (checkBox_ID3_Target_Process.Checked)
            {
                checkBox_ID3_PIDPath.Checked = false;
                checkBox_ID3_EventMessage.Checked = false;
            }
        }

        private void CheckBox_ID3_PIDPath_CheckedChanged(object sender, EventArgs e)
        {
            if (checkBox_ID3_PIDPath.Checked)
            {
                checkBox_ID3_EventMessage.Checked = false;
                checkBox_ID3_Target_Process.Checked = false;
            }
        }

        private void SearchForm_Realtime_FormClosing(object sender, FormClosingEventArgs e)
        {
            if (!ALT_F4)
            {
                e.Cancel = true;
                base.OnClosing(e);
            }
            else
            {
                Form1.IsSearchFormActived = false;
            }
        }

        private void Button5_Click(object sender, EventArgs e)
        {
            _StopFilter = true;
            button1.Enabled = true;
            button3.Enabled = true;

            if (_Thread_02 != null)
            {
                if (_Thread_02.IsAlive)
                    _Thread_02.Abort();                 
            }

        }

        private void Button6_Click(object sender, EventArgs e)
        {
            try
            {
                newform.Close();
            }
            catch (Exception)
            {


            }

            newform = new Form();
            newform.Size = new Size(900, 450);
            newform.Text = "Simple Help for Filters...";
            
            newform.Show();
            RichTextBox rtbx = new RichTextBox();

            rtbx.Font = new System.Drawing.Font("Microsoft Sans Serif", 11F, System.Drawing.FontStyle.Bold,
                System.Drawing.GraphicsUnit.Point, ((byte)(0)));

            newform.Controls.Add(rtbx);
            rtbx.BackColor = Color.LightCyan;
            rtbx.Dock = DockStyle.Fill;
            rtbx.ReadOnly = true;
            rtbx.Text = Help;


        }

        private void ComboBox1_KeyPress(object sender, KeyPressEventArgs e)
        {
             e.KeyChar = (char)Keys.None;
        }

        private void CheckBox3_CheckedChanged(object sender, EventArgs e)
        {


             if (checkBox3.Checked) { checkBox2.Checked = false; checkBox1.Checked = false; checkBox4.Checked = false; checkBox5.Checked = false; }
        }
      
        private void Button3_Click(object sender, EventArgs e)
        {
            try
            {
                if (_Thread_01 != null)
                {
                    _dowork.Cancel();

                    if (_Thread_01.IsAlive)
                        _Thread_01.Abort();

                     
                }

                stopsearch = true;
                button1.Enabled = true;
                button3.Enabled = true;
                button4.Enabled = true;
                button2.Enabled = true;
                button5.Enabled = true;
               
            }
            catch (Exception)
            {
                if (_Thread_01 != null)
                {
                    _dowork.Cancel();

                    if (_Thread_01.IsAlive)
                        _Thread_01.Abort();

                  
                }

                stopsearch = true;
                button1.Enabled = true;
                button3.Enabled = true;
                button4.Enabled = true;
                button2.Enabled = true;
                button5.Enabled = true;
               
            }
           
        }
    }
}
