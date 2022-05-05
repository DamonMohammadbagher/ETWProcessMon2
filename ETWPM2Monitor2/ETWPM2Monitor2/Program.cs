using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace ETWPM2Monitor2
{
    static class Program
    {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main()
        {
            try
            {


                //ThreadStart __MainThread = new ThreadStart(delegate
                //{
                //    Application.EnableVisualStyles();
                //    Application.SetCompatibleTextRenderingDefault(false);
                //    Application.Run(new Form1());
                //});

                //Thread _MainThreadRun = new Thread(__MainThread);
                //_MainThreadRun.Priority = ThreadPriority.AboveNormal;
                //_MainThreadRun.Start();


                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                Application.Run(new Form1());

            }
            catch (Exception ee)
            {


            }
            
        }
    }
}
