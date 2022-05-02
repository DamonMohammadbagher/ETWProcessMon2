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

        public static EventLog ETW2MON;
        public static EventLogQuery ETWPM2Query;

        public delegate void __SearchRun();
        public delegate void __Obj_Updater_to_WinForm();

        public static bool formclosing, stopsearch, isrunningSearch = false;

        public static CancellationTokenSource _dowork;
        public static ListViewItem MyLviewItemsX = new ListViewItem();
        public static Form1 _Form1 = new Form1();
        public static bool ALT_F4 = false;
        public static bool _StopFilter = false;

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
            Thread _Thread_01 = new Thread(__SearchItems_Addtolistview1);
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

                            foreach (EventLogEntry item in dump_filters.Entries.Cast<EventLogEntry>()
                            .Where(x => x.InstanceId == 1 && x.Message.ToLower().Contains(__FirstCondition + textBox1.Text.ToLower())))
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

                            foreach (EventLogEntry item in dump_filters.Entries.Cast<EventLogEntry>()
                            .Where(x => x.InstanceId == 2 && x.Message.ToLower().Contains(__FirstCondition1 + textBox1.Text.ToLower())))
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
                            
                            foreach (EventLogEntry item in dump_filters.Entries.Cast<EventLogEntry>()
                            .Where(x => x.InstanceId == 3 && x.Message.ToLower().Contains(__FirstCondition3 + textBox1.Text.ToLower())))
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

                                //if (formclosing) break;
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
                Thread _Thread_02 = new Thread(__SearchItems_Addtolistview1_filter);
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
        }

        private void CheckBox3_CheckedChanged(object sender, EventArgs e)
        {


             if (checkBox3.Checked) { checkBox2.Checked = false; checkBox1.Checked = false; checkBox4.Checked = false; checkBox5.Checked = false; }
        }
      
        private void Button3_Click(object sender, EventArgs e)
        {
            try
            {
                _dowork.Cancel();
                stopsearch = true;
                button1.Enabled = true;
                button3.Enabled = true;
                button4.Enabled = true;
                button2.Enabled = true;
                button5.Enabled = true;
            }
            catch (Exception)
            {

                //_dowork.Cancel();
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
