using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ETWPM2Monitor2
{
    public class ExtendedMemoryScanners_Info
    {
        public static string Task_RESULT_for_CobaltstrikeScanner = "";

        public static async void RunAsyn_CobaltstrikeScan(object pid)
        {
            Task_RESULT_for_CobaltstrikeScanner = await CobaltstrikeScan(Convert.ToString(pid));         
        }
        public static async Task<string> CobaltstrikeScan(string pid)
        {
            string result2 = "";
            await Task.Run(() =>
            {
                Task_RESULT_for_CobaltstrikeScanner = "";
                Process outputs = new Process();

                try
                {
                    if (File.Exists(@".\CobaltStrikeScan\CobaltStrikeScan.exe"))
                    {
                        try
                        {
                            if (!Process.GetProcessById(Convert.ToInt32(pid)).HasExited)
                            {
                                try
                                {
                                    outputs.StartInfo.FileName = @".\CobaltStrikeScan\CobaltStrikeScan.exe";
                                    /// -t added to the source code "CobaltStrikeScan" by me ;)
                                    /// scanning target process -t pid => syntax : CobaltStrikeScan.exe -t 1234
                                    outputs.StartInfo.Arguments = "-t " + pid.ToString();
                                    outputs.StartInfo.CreateNoWindow = true;
                                    outputs.StartInfo.UseShellExecute = false;
                                    outputs.StartInfo.RedirectStandardOutput = true;
                                    outputs.StartInfo.RedirectStandardInput = true;
                                    outputs.StartInfo.RedirectStandardError = true;
                                    outputs.Start();
                                    string strOutput = outputs.StandardOutput.ReadToEnd();
                                    result2 = strOutput;
                                }
                                catch (Exception)
                                {

                                }

                            }
                            else
                            {
                                result2 = "Process Not Found!";
                            }

                        }
                        catch (Exception ee)
                        {

                        }
                    }
                    else
                    {
                        result2 = @"Memory Scanner => .\CobaltStrikeScan\CobaltStrikeScan.exe Not Found!";
                    }
                }
                catch (Exception)
                {
                }

                return result2;
            });

            return result2;

        }
    }
}
