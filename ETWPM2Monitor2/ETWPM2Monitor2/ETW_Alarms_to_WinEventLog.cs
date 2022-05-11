using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace ETWPM2Monitor2
{
    public partial class ETW_Alarms_to_WinEventLog 
    {
        public static string lastETW_Alarms_Detection = "";
        public static string lastETW_Alarms_Detection2 = "";
        public static EventLog ETW2MON;
        public static Form1 MainForm1 = new Form1();
        public async void AsyncRun___Save_New_DetectionLogs_TCP_Shell_Events_to_WinEventLog(object obj)
        {
            await _Save_New_DetectionLogs_TCP_Shell_Events_to_WinEventLog(obj);
        }
        /// <summary>
        /// save this obj as event which was detected as Shell or TCP Meterpreter session to Windows EventLog "ETWPM2Monitor2"
        /// </summary>
        /// <param name="Obj"></param>
        public async Task _Save_New_DetectionLogs_TCP_Shell_Events_to_WinEventLog(object Obj)
        {
            await Task.Run(() =>
            {
                try
                {
                   //if (Form1.IsSystemDeveloperLogs_on) Form.ActiveForm.BeginInvoke(new Form1.__core2(MainForm1.AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [_Save_New_DetectionLogs_TCP_Shell_Events_to_WinEventLog] Method Call: Started");
                    //if(IsSystemDeveloperLogIson) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [_Save_New_DetectionLogs_TCP_Shell_Events_to_WinEventLog] Method Call: error1 => " + ee.Message);

                    ListViewItem _items_Objects = (ListViewItem)Obj;


                    ETW2MON = new EventLog("ETWPM2Monitor2", ".", "ETWPM2Monitor2.1");

                    StringBuilder st = new StringBuilder();

                    st.AppendLine("[#] Time: " + _items_Objects.SubItems[1].Text + ", Process: " + _items_Objects.SubItems[2].Text.Replace('\r', ' ').Replace('\n', ' ')
                        + ", Status: " + _items_Objects.SubItems[3].Text + "\nETW Event Type: " + _items_Objects.SubItems[4].Text +
                        " , Actions: " + _items_Objects.SubItems[5].Text + "\n\nEvent Message: " + "\n" + _items_Objects.Name);

                    if (_items_Objects.SubItems[3].Text.Contains("Found Shell"))
                    {
                        Task.Delay(50);

                        string simpledescription = "[#] Time: " + _items_Objects.SubItems[1].Text + "\n" + _items_Objects.SubItems[3].Text + " via Process: "
                            + _items_Objects.SubItems[2].Text.Replace('\r', ' ').Replace('\n', ' ') + " Detected by ETWPM2Monitor2 (Detection High level)!\n"
                         + "------------------------------------------------------------\n";

                        if (lastETW_Alarms_Detection2 != simpledescription + st.ToString())
                        {
                            ETW2MON.WriteEntry(simpledescription + st.ToString(), EventLogEntryType.Warning, 4);
                        }

                        lastETW_Alarms_Detection2 = simpledescription + st.ToString();


                        Task.Delay(50);

                    }

                    if (_items_Objects.SubItems[3].Text.Contains("Suspicious Traffic [Meterpreter!]"))
                    {
                        Task.Delay(50);

                        string simpledescription = "[#] Time: " + _items_Objects.SubItems[1].Text + "\n" + _items_Objects.SubItems[3].Text + " via Process: "
                            + _items_Objects.SubItems[2].Text.Replace('\r', ' ').Replace('\n', ' ') + " Detected by ETWPM2Monitor2 (Detection Medium level)!\n"
                         + "------------------------------------------------------------\n";

                        if (lastETW_Alarms_Detection2 != simpledescription + st.ToString())
                        {
                            if (-1 == Form1._List_of_Alarm_Events_Raised.FindIndex(index => index == lastETW_Alarms_Detection2))
                                ETW2MON.WriteEntry(simpledescription + st.ToString(), EventLogEntryType.Information, 3);
                        }

                        lastETW_Alarms_Detection2 = simpledescription + st.ToString();

                        if (-1 == Form1._List_of_Alarm_Events_Raised.FindIndex(index => index == lastETW_Alarms_Detection2))
                            Form1._List_of_Alarm_Events_Raised.Add(lastETW_Alarms_Detection2);

                        Task.Delay(50);

                    }
                }
                catch (Exception ee)
                {
                   // if (Form1.IsSystemDeveloperLogs_on) Form.ActiveForm.BeginInvoke(new Form1.__core2(MainForm1.AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [_Save_New_DetectionLogs_TCP_Shell_Events_to_WinEventLog] Method Call: error1 => " + ee.Message);


                }
            });
        }
        public async void AsyncRun__SaveNewETW_Alarms_to_WinEventLog(object obj)
        {
            await _SaveNewETW_Alarms_to_WinEventLog(obj);
        }

        /// <summary>
        ///  save all Alarms like "Terminated,Suspended,Scannedfound,Detected" by Memory scanners etc to windows eventlog "ETWPM2Monitor2". Event ID1 (Medium Level) , Event ID2 (High Level)
        /// </summary>
        /// <param name="AlarmObjects"></param>
        public async Task _SaveNewETW_Alarms_to_WinEventLog(object AlarmObjects)
        {
            await Task.Run(() =>
            {
                try
                {
                    //if (Form1.IsSystemDeveloperLogs_on) Form.ActiveForm.BeginInvoke(new Form1.__core2(MainForm1.AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [_SaveNewETW_Alarms_to_WinEventLog] Method Call: Started");
                    //if(IsSystemDeveloperLogIson) BeginInvoke(new __core2(AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [_SaveNewETW_Alarms_to_WinEventLog] Method Call: error1 => " + ee.Message);

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

                    st.AppendLine("MemoryScanner:\n");
                    st.AppendLine(xitem.Name);
                    bool IsValidMemoryScannerString = false;
                    try
                    {

                        Task.Delay(10);
                        int __TargetPID = Convert.ToInt32(xitem.SubItems[2].Text.Split(':')[1]);
                        int __TargetMemoryScannerPIdChecking = Convert.ToInt32(xitem.Name.Split('\n')[1].Split(':')[1]);

                        if (__TargetPID == __TargetMemoryScannerPIdChecking) IsValidMemoryScannerString = true;
                        Task.Delay(10);
                    }
                    catch (Exception)
                    {


                    }

                    if (IsValidMemoryScannerString)
                    {

                        if (__AlarmObject.SubItems[5].Text.Contains("Terminated") ||
                            __AlarmObject.SubItems[5].Text.Contains("Suspended") ||
                            __AlarmObject.SubItems[5].Text.Contains("Scanned & Found") ||
                             __AlarmObject.SubItems[7].Text.Contains(">>Detected") ||
                            Convert.ToInt32(string.Join("", ("0" + __AlarmObject.SubItems[6].Text).Where(char.IsDigit)).ToString()) > 0)
                        {
                            Task.Delay(50);
                            string simpledescription = "[#] Time: " + xitem.SubItems[1].Text + "\nProcess: " + xitem.SubItems[2].Text + " Detected by ETWPM2Monitor2 (Detection High level)!\n"
                                + "------------------------------------------------------------\n";

                            if (lastETW_Alarms_Detection != simpledescription + st.ToString()
                            && !st.ToString().ToLower().Contains("[skipped[not scanned:0:0:0]")
                            && !st.ToString().ToLower().Contains("[not scanned:0]"))
                            {
                                ETW2MON.WriteEntry(simpledescription + st.ToString(), EventLogEntryType.Warning, 2);
                                Form1._DetectedItemsByWindowEventLogSaved.Add(xitem);
                            }
                            lastETW_Alarms_Detection = simpledescription + st.ToString();
                            Task.Delay(50);

                        }
                        else if (!__AlarmObject.SubItems[5].Text.Contains("Terminated") &&
                           !__AlarmObject.SubItems[5].Text.Contains("Suspended") &&
                           !__AlarmObject.SubItems[5].Text.Contains("Scanned & Found") &&
                           !__AlarmObject.SubItems[7].Text.Contains(">>Detected") &&
                           Convert.ToInt32(string.Join("", ("0" + __AlarmObject.SubItems[6].Text).Where(char.IsDigit)).ToString()) == 0)
                        {
                            Task.Delay(50);
                            string simpledescription = "[#] Time: " + xitem.SubItems[1].Text + "\nProcess: " + xitem.SubItems[2].Text + " Detected by ETWPM2Monitor2 (Detection Medium level)!\n"
                              + "------------------------------------------------------------\n";

                            if (lastETW_Alarms_Detection != simpledescription + st.ToString()
                            && !st.ToString().ToLower().Contains("[skipped[not scanned:0:0:0]")
                            && !st.ToString().ToLower().Contains("[not scanned:0]"))
                            {
                                ETW2MON.WriteEntry(simpledescription + st.ToString(), EventLogEntryType.Information, 1);
                                //_DetectedItemsByWindowEventLog.Add(__AlarmObject);
                            }

                            lastETW_Alarms_Detection = simpledescription + st.ToString();
                            Task.Delay(50);
                        }
                    }
                }
                catch (Exception ee)
                {
                   // if (Form1.IsSystemDeveloperLogs_on) Form.ActiveForm.BeginInvoke(new Form1.__core2(MainForm1.AsyncRun__Add_SystemDeveloperLogs), (object)" ==> [_SaveNewETW_Alarms_to_WinEventLog] Method Call: error1 => " + ee.Message);


                }
            });
        }
    }
}
