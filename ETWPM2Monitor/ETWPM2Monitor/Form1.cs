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

namespace ETWPM2Monitor
{
    public partial class Form1 : Form
    {
        /// <summary>
        /// ETWPM2Monitor v1.2 [test version] Code Published by Damon Mohammadbagher , 20 Jul 2021 
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
        public string tempMessage, tempMessage2, EventMessage = "";
        public static byte[] buf = new byte[90];

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
                
                t.Elapsed += T_Elapsed;
                t.Enabled = true;

                listView1.Columns.Add(" ", 20, HorizontalAlignment.Left);
                listView1.Columns.Add("Time", 130, HorizontalAlignment.Left);
                listView1.Columns.Add("EventID", 55, HorizontalAlignment.Left);
                listView1.Columns.Add("Process", 100, HorizontalAlignment.Left);
                listView1.Columns.Add("Evt-Type", 55, HorizontalAlignment.Left);
                listView1.Columns.Add("EventMessage", 1500, HorizontalAlignment.Left);
            }
            catch (EventLogReadingException err)
            {

            }
        }

        private async void T_Elapsed(object sender, System.Timers.ElapsedEventArgs e)
        {
            //await Task.Factory.StartNew(() =>
            //{
            //  });

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

        //public async void IlistItemAdd(ListViewItem i)
        //{

        //   await  Task.Factory.StartNew(() =>
        //      {
        //          listView1.BeginUpdate();
        //          listView1.Items.Add(i);
        //          listView1.EndUpdate();
        //          listView1.Update();
        //          Thread.Sleep(1000);
        //      });
        //}

        public void Watcher_EventRecordWritten(object sender, EventRecordWrittenEventArgs e)
        {
           
            GC.Collect();
            try
            {

                if (e.EventRecord.FormatDescription() != tempMessage2)
                {

                    if (e.EventRecord.Id == 2)
                    {
                        InjectionMemoryInfoDetails_torichtectbox(e.EventRecord.FormatDescription(), e.EventRecord.RecordId.ToString());
                    }
                    else
                    {
                        richTextBox1.Text += "[Time = " + e.EventRecord.TimeCreated + "] \n[EventID = " + e.EventRecord.Id.ToString() + "] \n[Message : " + e.EventRecord.FormatDescription() + "]\n_____________________\n";
                    }
                    // richTextBox1.AppendText("[Time = " + e.EventRecord.TimeCreated + "] \n[EventID = " + e.EventRecord.Id.ToString() + "] \n[Message : " + e.EventRecord.FormatDescription() + "]\n_____________________\n");
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
                        Task.Factory.StartNew(() =>
                        {
                            listView1.BeginUpdate();
                            listView1.Items.Add(iList);
                            listView1.EndUpdate();
                            listView1.Update();
                            Thread.Sleep(500);
                        });
                        // DelegateIteamAdd __DelegateMethod = new DelegateIteamAdd(IlistItemAdd);

                        // BeginInvoke(__DelegateMethod, iList);
                        Thread.Sleep(500);

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
                        Task.Factory.StartNew(() =>
                        {
                            listView1.BeginUpdate();
                            listView1.Items.Add(iList);
                            listView1.EndUpdate();
                            listView1.Update();
                            Thread.Sleep(500);
                        });
                       // DelegateIteamAdd __DelegateMethod = new DelegateIteamAdd(IlistItemAdd);
                      //  BeginInvoke(__DelegateMethod, iList);
                        Thread.Sleep(500);

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
                        Task.Factory.StartNew(() =>
                        {
                            listView1.BeginUpdate();
                            listView1.Items.Add(iList);
                            listView1.EndUpdate();
                            listView1.Update();
                            Thread.Sleep(500);
                        });
                        // DelegateIteamAdd __DelegateMethod = new DelegateIteamAdd(IlistItemAdd);
                        // BeginInvoke(__DelegateMethod, iList);
                        Thread.Sleep(500);
                    }
                }
            }
            catch (Exception _e)
            {
                MessageBox.Show(_e.Message);
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
            richTextBox1.Clear();
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

                MessageBox.Show("Please first Select one row/event in listview\n"+ error.Message);
            }
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

        private void AboutToolStripMenuItem_Click(object sender, EventArgs e)
        {
            MessageBox.Show(null,"ETWPM2Monitor v1.2 [test version 1.2.10.18]\nCode Published by Damon Mohammadbagher , Jul 2021", "About ETWPM2Monitor",MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        public void InjectionMemoryInfoDetails_torichtectbox(string etwEvtMessage, string _EventMessageRecordId)
        {

            try
            {
                string EventMessage = etwEvtMessage;
                string EventMessageRecordId = _EventMessageRecordId;
                ulong i32StartAddress = Convert.ToUInt64(EventMessage.Substring(EventMessage.IndexOf("::") + 2).Split(':')[0].Substring(2), 16);
                Int64 TID = Convert.ToInt64(EventMessage.Substring(EventMessage.IndexOf("::") - 8).Split(')', ':')[1]);
                Int32 prc = Convert.ToInt32(EventMessage.Substring(EventMessage.IndexOf("PID: (") + 6).Split(')')[0]);
                buf = new byte[208];
                IntPtr prch = System.Diagnostics.Process.GetProcessById(prc).Handle;
                string XStartAddress = EventMessage.Substring(EventMessage.IndexOf("::") + 2).Split(':')[0];
                bool MemoryBytes = Memoryinfo.ReadProcessMemory(prch,(UIntPtr)i32StartAddress, buf, buf.Length, IntPtr.Zero);
                richTextBox1.Text += EventMessage + "\n\nEventID: " + "2" + "\nEventRecord_ID: " + EventMessageRecordId  +"\n\n[Remote-Thread-Injection Memory Information]\n\tTID: " + TID.ToString() + "\n\tTID StartAddress: " +
                XStartAddress.ToString() + "\n\tTID Win32StartAddress: " + i32StartAddress.ToString() + "\n\tTarget_Process PID: " + prc.ToString() +
                "\n\nInjected Memory Bytes: " + BitConverter.ToString(buf).ToString() +"\n\n"+ Memoryinfo.HexDump(buf) + "\n_____________________\n";


            }
            catch (Exception ohwoOwwtfk)
            {
                richTextBox1.Text += etwEvtMessage + "\n\nEventID: " + "2" + "\n";

                richTextBox1.Text += "EventID: 2, Read Target_Process Memory via API::ReadProcessMemory [ERROR] => " + ohwoOwwtfk.Message + "\n[Remote-Thread-Injection Memory Information]\n_____________________________error______________________________\n";
            }
        }

        public static class Memoryinfo
        {
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

            [DllImport("kernel32.dll", SetLastError = true)]
            static extern bool CloseHandle(UIntPtr hObject);

            //public enum ThreadAccess : int
            //{
            //    Terminate = 0x0001,
            //    SuspendResume = 0x0002,
            //    GetContext = 0x0008,
            //    SetContext = 0x0010,
            //    SetInformation = 0x0020,
            //    QueryInformation = 0x0040,
            //    SetThreadToken = 0x0080,
            //    Impersonate = 0x0100,
            //    DirectImpersonation = 0x0200
            //}
            //public enum ThreadInfoClass : int
            //{
            //    ThreadQuerySetWin32StartAddress = 9
            //}

            /// ==============================================
            /// some cross threads error was for here ;) , fixed
            /// startAddress value now Directly comes from ETW events without using Native APIs (XStartAddress, i32StartAddress)
            /// ==============================================

            //[DllImport("kernel32.dll", SetLastError = true)]
            //static extern UIntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, ulong dwThreadId);

            //[return: MarshalAs(UnmanagedType.Bool)]
            //[DllImport("kernel32.dll")]
            //private static extern bool SetProcessWorkingSetSize(IntPtr process, UIntPtr minimumWorkingSetSize, UIntPtr maximumWorkingSetSize);
            //[DllImport("ntdll.dll", SetLastError = true)]
            //public static extern int NtQueryInformationThread(UIntPtr threadHandle, ThreadInfoClass threadInformationClass, IntPtr threadInformation, int threadInformationLength, IntPtr returnLengthPtr);

            //public static string _Return_Threads_StartAddress(ulong tid)
            //{
            //    return (string.Format("{0:X16}", (ulong)GetThreadStartAddress(tid)));
            //}

            //public static IntPtr GetThreadStartAddress(ulong threadId)
            //{
            //    //var hThread = OpenThread(ThreadAccess.QueryInformation, false, threadId);
            //    //var buf = Marshal.AllocHGlobal(IntPtr.Size);
            //    UIntPtr hThread = UIntPtr.Zero;
            //    IntPtr buf = IntPtr.Zero;
            //    try
            //    {

            //            hThread = OpenThread(ThreadAccess.QueryInformation, false, threadId);
            //            buf = Marshal.AllocHGlobal(IntPtr.Size);
            //            var result = NtQueryInformationThread(hThread, ThreadInfoClass.ThreadQuerySetWin32StartAddress, buf, IntPtr.Size, IntPtr.Zero);
            //            return Marshal.ReadIntPtr(buf);

            //    }
            //    finally
            //    {
            //        CloseHandle(hThread);
            //        Marshal.FreeHGlobal(buf);
            //        GC.Collect(GC.MaxGeneration);
            //        GC.WaitForPendingFinalizers();
            //        SetProcessWorkingSetSize(Process.GetCurrentProcess().Handle, (UIntPtr)0xFFFFFFFF, (UIntPtr)0xFFFFFFFF);
            //    }
            //}
        }
    }
}
