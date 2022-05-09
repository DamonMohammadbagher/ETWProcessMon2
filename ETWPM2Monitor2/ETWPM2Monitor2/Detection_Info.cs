using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace ETWPM2Monitor2
{
    class Detection_Info
    {
        public static Form1 MainForm1 = new Form1();       
        public static string lastETW_Alarms_Detection = "";
        public delegate void _AddItems(ListViewItem str);


        public static void _SaveNewETW_Alarms_to_WinEventLog(ListViewItem AlarmObjects)
        {
            try
            {
                EventLog _ETW2MON = new EventLog("ETWPM2Monitor2", ".", "ETWPM2Monitor2.1");
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
                        _ETW2MON.WriteEntry(simpledescription + st.ToString(), EventLogEntryType.Warning, 2);
                        Form1._DetectedItemsByWindowEventLogSaved.Add(__AlarmObject);
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
                        _ETW2MON.WriteEntry(simpledescription + st.ToString(), EventLogEntryType.Information, 1);

                    }
                    lastETW_Alarms_Detection = simpledescription + st.ToString();
                    Task.Delay(50);
                }

            }
            catch (Exception ee)
            {

            }

        }

        public static void Detection_Compare_to_WinEventLogSaved(List<ListViewItem> ETWDetectionRecords, List<ListViewItem> WinEventLogDetectionRecords)
        {
            try
            {
 
                ListViewItem xiList6 = new ListViewItem();
               
                foreach (ListViewItem item_of_ETWDetectionRecords in ETWDetectionRecords)
                {

                    string DetectionbyETW = item_of_ETWDetectionRecords.SubItems[2].Text.ToLower();
                     
                    int index = WinEventLogDetectionRecords.FindIndex(f => f.SubItems[2].Text.ToLower().Split(' ')[0] == DetectionbyETW);

                    if (index == -1)
                    {
                        try
                        {
                            _SaveNewETW_Alarms_to_WinEventLog(item_of_ETWDetectionRecords);                             
                        }
                        catch (Exception)
                        {

                        }

                    }
                    else
                    {

                    }

                }
            }
            catch (Exception ee)
            {
 
            }
        }
    }
}
