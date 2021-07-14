using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace ETWPM2Monitor
{
    public partial class Form1 : Form
    {
        /// <summary>
        /// ETWPM2Monitor v1.1 [test version] Code Published by Damon Mohammadbagher , Jul 2021 
        /// Console App for Realtime monitor ETW Events "ETWPM2" which made by ETWProcessMon2
        /// this app will monitor events in windows event log [logname = ETWPM2].
        /// NewProcess events + RemoteThreadInjection events + TCPIP Send events will monitor by ETWProcessMon2 with logname ETWPM2 which by this tool "ETWPM2Monitor" you can watch them "realtime"
        /// also RemoteThreadInjection events + VirtualMemAlloc events will save by ETWProcessMon2 into text logfile "ETWProcessMonlog.txt" at the same time.
        /// </summary>

        public Int64 i6 = 0;
        public static System.Timers.Timer t = new System.Timers.Timer(1500);
        public delegate void DelegateIteamAdd(ListViewItem i);
        public EventLog ETW2MON;
        public static EventLogQuery ETWPM2Query;
        public ListViewItem iList = new ListViewItem();
        public static EventLogWatcher EvtWatcher = null;
        public string tempMessage, tempMessage2 = "";

        public Form1()
        {
            InitializeComponent();

        }
        public void StartQueries_Mon(string queries)
        {
            string _Query = queries;
            EvtWatcher.Dispose();
            ETWPM2Query = new EventLogQuery("ETWPM2", PathType.LogName, _Query);

            EvtWatcher = new EventLogWatcher(ETWPM2Query);
            EvtWatcher.EventRecordWritten += Watcher_EventRecordWritten;
            EvtWatcher.Enabled = true;
            toolStripStatusLabel1.Text = "Monitor Status: on";
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            try
            {
                string Query = "*";
                ETWPM2Query = new EventLogQuery("ETWPM2", PathType.LogName, Query);

                EvtWatcher = new EventLogWatcher(ETWPM2Query);
                EvtWatcher.EventRecordWritten += Watcher_EventRecordWritten;

                listView1.SmallImageList = imageList1;
                EvtWatcher.Enabled = true;
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
                /// Sort the items in the list in ascending order.

                t.Elapsed += T_Elapsed;
                t.Enabled = true;

                listView1.Columns.Add(" ", 20, HorizontalAlignment.Left);
                listView1.Columns.Add("Time", 130, HorizontalAlignment.Left);
                listView1.Columns.Add("EventID", 55, HorizontalAlignment.Left);
                listView1.Columns.Add("EventMessage", 1000, HorizontalAlignment.Left);
            }
            catch (EventLogReadingException err)
            {

            }
        }

        private async void T_Elapsed(object sender, System.Timers.ElapsedEventArgs e)
        {
            await Task.Factory.StartNew(() =>
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
            });
        }

        public async void IlistItemAdd(ListViewItem i)
        {

            await Task.Factory.StartNew(() =>
              {
                  listView1.BeginUpdate();
                  listView1.Items.Add(i);
                  listView1.EndUpdate();
                  listView1.Update();
                  Thread.Sleep(1000);
              });
        }

        public void Watcher_EventRecordWritten(object sender, EventRecordWrittenEventArgs e)
        {
            GC.Collect();

            if (e.EventRecord.FormatDescription() != tempMessage2)
                richTextBox1.Text += "[Time = " + e.EventRecord.TimeCreated + "] \n[EventID = " + e.EventRecord.Id.ToString() + "] \n[Message : " + e.EventRecord.FormatDescription() + "]\n_____________________\n";

            tempMessage2 = e.EventRecord.FormatDescription();

            if (e.EventRecord.Id == 1)
            {
                if (e.EventRecord.FormatDescription() != string.Empty)
                {
                    iList = new ListViewItem();
                    iList.Name = e.EventRecord.Id.ToString();
                    iList.SubItems.Add(e.EventRecord.TimeCreated.ToString());
                    iList.SubItems.Add(e.EventRecord.Id.ToString());
                    iList.SubItems.Add(e.EventRecord.FormatDescription());
                    iList.ImageIndex = 0;
                    listView1.BeginUpdate();
                    //listView1.Items.Add(iList);
                    DelegateIteamAdd __DelegateMethod = new DelegateIteamAdd(IlistItemAdd);
                    BeginInvoke(__DelegateMethod, iList);
                    listView1.EndUpdate();
                    Thread.Sleep(500);
                   
                }
            }
            if (e.EventRecord.Id == 2)
            {
                if (e.EventRecord.FormatDescription() != string.Empty)
                {

                    iList = new ListViewItem();
                    iList.Name = e.EventRecord.Id.ToString();
                    iList.SubItems.Add(e.EventRecord.TimeCreated.ToString());
                    iList.SubItems.Add(e.EventRecord.Id.ToString());
                    iList.SubItems.Add(e.EventRecord.FormatDescription());
                    iList.ImageIndex = 1;
                    listView1.BeginUpdate();
                    //listView1.Items.Add(iList);
                    DelegateIteamAdd __DelegateMethod = new DelegateIteamAdd(IlistItemAdd);
                    BeginInvoke(__DelegateMethod, iList);
                    listView1.EndUpdate();
                    Thread.Sleep(500);
                   


                }
            }
            if ((e.EventRecord.Id == 3) && (e.EventRecord.FormatDescription() != tempMessage))
            {
                if (e.EventRecord.FormatDescription() != string.Empty)
                {
                    iList = new ListViewItem();
                    tempMessage = e.EventRecord.FormatDescription();
                    iList.Name = e.EventRecord.Id.ToString();
                    iList.SubItems.Add(e.EventRecord.TimeCreated.ToString());
                    iList.SubItems.Add(e.EventRecord.Id.ToString());
                    iList.SubItems.Add(e.EventRecord.FormatDescription());
                    iList.ImageIndex = 0;
                    listView1.BeginUpdate();

                    //listView1.Items.Add(iList);
                    DelegateIteamAdd __DelegateMethod = new DelegateIteamAdd(IlistItemAdd);
                    BeginInvoke(__DelegateMethod, iList);
                    listView1.EndUpdate();

                }
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
        }

        private void StoptMonitorToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (EvtWatcher.Enabled)
            {
                EvtWatcher.Enabled = false;
                EvtWatcher.Dispose();
                toolStripStatusLabel1.Text = "Monitor Status: off";
            }
        }

        private void SaveToolStripMenuItem_Click(object sender, EventArgs e)
        {
            try
            {

                Task.Factory.StartNew(() =>
                {
                    using (StreamWriter _file = new StreamWriter("ETWPM2_RealtimeEvents_" + DateTime.Now.Hour.ToString() + "-" + DateTime.Now.Minute.ToString() + "-" + DateTime.Now.Second.ToString() + ".txt", false))
                    {
                        _file.WriteLine(richTextBox1.Text);
                    };
                });
            }
            catch (Exception)
            {
 
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
            toolStripStatusLabel2.Text = "| Filters: Select All EventIDs 1,2 [NewProcess , RemoteThreadInjection Detection]";

        }

        public void EventID13ToolStripMenuItem_Click(object sender, EventArgs e)
        {
            string _Query = "<QueryList><Query Id=\"0\" Path=\"ETWPM2\"><Select Path=\"ETWPM2\">*[System[(EventID=1 or EventID=3)]]</Select></Query></QueryList>";

            StartQueries_Mon(_Query);
            toolStripStatusLabel2.ForeColor = Color.Red;

            toolStripStatusLabel2.Text = "| Filters: Select All EventIDs 1,3 [NewProcess , TCPIP Send]";

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

            toolStripStatusLabel2.Text = "| Filters: Select All EventID 1 [NewProcess]";
        }

        private void EventID2ToolStripMenuItem_Click(object sender, EventArgs e)
        {
            string _Query = "<QueryList><Query Id=\"0\" Path=\"ETWPM2\"><Select Path=\"ETWPM2\">*[System[(EventID=2)]]</Select></Query></QueryList>";

            StartQueries_Mon(_Query);
            toolStripStatusLabel2.ForeColor = Color.Red;

            toolStripStatusLabel2.Text = "| Filters: Select All EventID 2 [RemoteThreadInjection Detection]";
        }

        private void EventID3ToolStripMenuItem_Click(object sender, EventArgs e)
        {
            string _Query = "<QueryList><Query Id=\"0\" Path=\"ETWPM2\"><Select Path=\"ETWPM2\">*[System[(EventID=3)]]</Select></Query></QueryList>";

            StartQueries_Mon(_Query);
            toolStripStatusLabel2.ForeColor = Color.Red;

            toolStripStatusLabel2.Text = "| Filters: Select All EventID 3 [TCPIP Send]";
        }

        private void ListView1_SelectedIndexChanged(object sender, EventArgs e)
        {
          
        }

        private void RichTextBox1_TextChanged(object sender, EventArgs e)
        {
            try
            {
                Task.Factory.StartNew(() =>
                {
                    if (t.Enabled)
                    {
                        try
                        {
                            richTextBox1.SelectionStart = richTextBox1.Text.Length;
                            richTextBox1.ScrollToCaret();
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

        private void OnToolStripMenuItem_Click(object sender, EventArgs e)
        {
            t.Enabled = true;
            onToolStripMenuItem.Text = "[on]";
            offToolStripMenuItem.Text = "off";
        }

        private void OffToolStripMenuItem_Click(object sender, EventArgs e)
        {
            t.Enabled = false;
            onToolStripMenuItem.Text = "on";
            offToolStripMenuItem.Text = "[off]";
        }

        private void ClearAllToolStripMenuItem_Click(object sender, EventArgs e)
        {
            listView1.Items.Clear();
            Thread.Sleep(50);
            richTextBox1.Clear();
        }
    }
}
