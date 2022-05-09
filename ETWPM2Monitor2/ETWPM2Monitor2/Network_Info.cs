using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace ETWPM2Monitor2
{
    public static class Network_Info
    {
               
        /// TCPView4.0 Codes Monitoring RealTime TCP/UDP Connections (only tcp in this code)
        
        #region Managed IP Helper API

        public class TcpTable : IEnumerable<TcpRow>
        {
            #region Private Fields

            private IEnumerable<TcpRow> tcpRows;

            #endregion

            #region Constructors

            public TcpTable(IEnumerable<TcpRow> tcpRows)
            {
                this.tcpRows = tcpRows;
            }

            #endregion

            #region Public Properties

            public IEnumerable<TcpRow> Rows
            {
                get { return this.tcpRows; }
            }

            #endregion

            #region IEnumerable<TcpRow> Members

            public IEnumerator<TcpRow> GetEnumerator()
            {
                return this.tcpRows.GetEnumerator();
            }

            #endregion

            #region IEnumerable Members

            IEnumerator IEnumerable.GetEnumerator()
            {
                return this.tcpRows.GetEnumerator();
            }

            #endregion
        }

        public class TcpRow
        {
            #region Private Fields

            private IPEndPoint localEndPoint;
            private IPEndPoint remoteEndPoint;
            private TcpState state;
            private int processId;

            #endregion

            #region Constructors

            public TcpRow(IpHelper.TcpRow tcpRow)
            {
                this.state = tcpRow.state;
                this.processId = tcpRow.owningPid;

                int localPort = (tcpRow.localPort1 << 8) + (tcpRow.localPort2) + (tcpRow.localPort3 << 24) + (tcpRow.localPort4 << 16);
                long localAddress = tcpRow.localAddr;
                this.localEndPoint = new IPEndPoint(localAddress, localPort);

                int remotePort = (tcpRow.remotePort1 << 8) + (tcpRow.remotePort2) + (tcpRow.remotePort3 << 24) + (tcpRow.remotePort4 << 16);
                long remoteAddress = tcpRow.remoteAddr;
                this.remoteEndPoint = new IPEndPoint(remoteAddress, remotePort);
            }

            #endregion

            #region Public Properties

            public IPEndPoint LocalEndPoint
            {
                get { return this.localEndPoint; }
            }

            public IPEndPoint RemoteEndPoint
            {
                get { return this.remoteEndPoint; }
            }

            public TcpState State
            {
                get { return this.state; }
            }

            public int ProcessId
            {
                get { return this.processId; }
            }

            #endregion
        }

        public static class ManagedIpHelper
        {
            #region Public Methods

            public static TcpTable GetExtendedTcpTable(bool sorted)
            {
                List<TcpRow> tcpRows = new List<TcpRow>();

                IntPtr tcpTable = IntPtr.Zero;
                int tcpTableLength = 0;

                if (IpHelper.GetExtendedTcpTable(tcpTable, ref tcpTableLength, sorted, IpHelper.AfInet, IpHelper.TcpTableType.OwnerPidAll, 0) != 0)
                {
                    try
                    {
                        tcpTable = Marshal.AllocHGlobal(tcpTableLength);

                        if (IpHelper.GetExtendedTcpTable(tcpTable, ref tcpTableLength, true, IpHelper.AfInet, IpHelper.TcpTableType.OwnerPidAll, 0) == 0)
                        {
                            IpHelper.TcpTable table = (IpHelper.TcpTable)Marshal.PtrToStructure(tcpTable, typeof(IpHelper.TcpTable));

                            IntPtr rowPtr = (IntPtr)((long)tcpTable + Marshal.SizeOf(table.length));

                            for (int i = 0; i < table.length; ++i)
                            {
                                tcpRows.Add(new TcpRow((IpHelper.TcpRow)Marshal.PtrToStructure(rowPtr, typeof(IpHelper.TcpRow))));
                                rowPtr = (IntPtr)((long)rowPtr + Marshal.SizeOf(typeof(IpHelper.TcpRow)));
                            }
                        }
                    }
                    finally
                    {
                        if (tcpTable != IntPtr.Zero)
                        {
                            Marshal.FreeHGlobal(tcpTable);
                        }
                    }
                }

                return new TcpTable(tcpRows);
            }

            #endregion
        }

        #endregion

        #region P/Invoke IP Helper API

        /// <summary>
        /// <see cref="http://msdn2.microsoft.com/en-us/library/aa366073.aspx"/>
        /// </summary>
        public static class IpHelper
        {
            #region Public Fields

            public const string DllName = "iphlpapi.dll";
            public const int AfInet = 2;

            #endregion

            #region Public Methods

            /// <summary>
            /// <see cref="http://msdn2.microsoft.com/en-us/library/aa365928.aspx"/>
            /// </summary>
            [DllImport(IpHelper.DllName, SetLastError = true)]
            public static extern uint GetExtendedTcpTable(IntPtr tcpTable, ref int tcpTableLength, bool sort, int ipVersion, TcpTableType tcpTableType, int reserved);


            #endregion

            #region Public Enums

            /// <summary>
            /// <see cref="http://msdn2.microsoft.com/en-us/library/aa366386.aspx"/>
            /// </summary>
            public enum TcpTableType
            {
                BasicListener,
                BasicConnections,
                BasicAll,
                OwnerPidListener,
                OwnerPidConnections,
                OwnerPidAll,
                OwnerModuleListener,
                OwnerModuleConnections,
                OwnerModuleAll,
            }

            #endregion

            #region Public Structs

            /// <summary>
            /// <see cref="http://msdn2.microsoft.com/en-us/library/aa366921.aspx"/>
            /// </summary>
            [StructLayout(LayoutKind.Sequential)]
            public struct TcpTable
            {
                public uint length;
                public TcpRow row;
            }

            /// <summary>
            /// <see cref="http://msdn2.microsoft.com/en-us/library/aa366913.aspx"/>
            /// </summary>
            [StructLayout(LayoutKind.Sequential)]
            public struct TcpRow
            {
                public TcpState state;
                public uint localAddr;
                public byte localPort1;
                public byte localPort2;
                public byte localPort3;
                public byte localPort4;
                public uint remoteAddr;
                public byte remotePort1;
                public byte remotePort2;
                public byte remotePort3;
                public byte remotePort4;
                public int owningPid;
            }

            #endregion
        }

        #endregion
        [StructLayout(LayoutKind.Sequential)]
        public struct PIDRows
        {
            public int ID;
            public string ProcessName;
        }
        public struct _Table
        {
            public IPEndPoint LocalIP;
            public int LPORT;
            public IPEndPoint RemoteIP;
            public int RPORT;
            public int states;
            public string states_String;
            public int PID;
            public string ProcessName;
            public string FullSTR;
            public int IsLive;
            public string ProcessPath { set; get; }
        }

        public static _Table[] Table1;
        public static _Table[] Table2;
        // x64 code
        public static _Table[] Table1_x64;
        public static _Table[] Table2_x64;
        //x64 code
        public static PIDRows[] PIDTable;

        public static List<TcpConnectionInformation> _ActiveTCP_Connections_List = new List<TcpConnectionInformation>();
        public static List<TcpConnectionInformation> _ActiveTCP_Connections_List_History = new List<TcpConnectionInformation>();
        public static DataTable dt = new DataTable();
        public static DataRow dr;
        public static ArrayList _PIDTable = new ArrayList();
        public static int Endpoits, Estab, Sync, Listen, TotalLogs;
        public static bool find;
        public static Thread Core = null;
        static Form1 MainForm1 = new Form1();
        public static int Before_after;
        public static int PublicID;
        public static string PROCESSNAME;
        public delegate void DeleteItem(object id);        
        public delegate void Additem(object Table_to_Add);
        public delegate void information();

        public struct _Table_of_FileSystem_for_Processes_Watcher
        {
            private string _File_MD5;
            public string Eventtime { set; get; }
            public string FileName { set; get; }
            public string FileName_Path { set; get; }
            public int PID { set; get; }
            public string ProcessCommandLine { set; get; }
            

        }

        public static List<_Table_of_FileSystem_for_Processes_Watcher> Processes_FileSystemList2 = new List<_Table_of_FileSystem_for_Processes_Watcher>();
      
    

        public static void _Run_Core_Method()
        {
            Core = new Thread(Core_Method);
            Core.Priority = ThreadPriority.AboveNormal;
            Core.Start();
        }
        
        private static void Core_Method()
        {
            bool initial = true;
            Network_Info_DataTables.Filtering_IS_127001 = false;

            Network_Info_DataTables.Settable();
            Network_Info_DataTables.TCPIP_settable();

            GetProcessesPaths();

            while (true)
            {
                if (Network_Info_DataTables.StopThread)
                {
                    break;
                }

                try
                {

                    try
                    {

                        Endpoits = 0;
                        Listen = 0;
                        Sync = 0;
                        Estab = 0;

                        //x64 code
                        int _x64_counter = 0;
                        int _x64_counter_tmp = 0;

                        foreach (TcpRow _X64_TcpRows_tmp in ManagedIpHelper.GetExtendedTcpTable(true))
                        {
                            _x64_counter_tmp++;
                        }

                        Table1_x64 = new _Table[_x64_counter_tmp];

                        foreach (TcpRow _X64_TcpRows in ManagedIpHelper.GetExtendedTcpTable(true))
                        {

                            if (Network_Info_DataTables.StopThread)
                            {
                                Core.Abort();
                                break;
                            }

                            try
                            {
                                switch (Network_Info_DataTables.Filtering_ISEstablished)
                                {

                                    case false:
                                        {
                                            // add to x64 table code
                                            switch (Network_Info_DataTables.Filtering_IS_127001)
                                            {
                                                case true:
                                                    {
                                                        if (_X64_TcpRows.LocalEndPoint.Address.ToString() != "127.0.0.1")
                                                        {
                                                            Table1_x64[_x64_counter].LocalIP = _X64_TcpRows.LocalEndPoint;
                                                            Table1_x64[_x64_counter].LPORT = _X64_TcpRows.LocalEndPoint.Port;
                                                            Table1_x64[_x64_counter].RemoteIP = _X64_TcpRows.RemoteEndPoint;
                                                            Table1_x64[_x64_counter].RPORT = _X64_TcpRows.RemoteEndPoint.Port;

                                                            switch (_X64_TcpRows.State)
                                                            {
                                                                case TcpState.Established:
                                                                    Estab++; Table1_x64[_x64_counter].states = 5;
                                                                    break;
                                                                case TcpState.Listen:
                                                                    Listen++; Table1_x64[_x64_counter].states = 2;
                                                                    break;
                                                                case TcpState.SynSent:
                                                                    Sync++; Table1_x64[_x64_counter].states = 3;
                                                                    break;
                                                            }

                                                            Table1_x64[_x64_counter].states_String = _X64_TcpRows.State.ToString().ToUpper();
                                                            Table1_x64[_x64_counter].PID = _X64_TcpRows.ProcessId;
                                                            Table1_x64[_x64_counter].ProcessName = Network_Info_DataTables.SetRow(_X64_TcpRows.ProcessId);

                                                            Int32 PPath_index = Processes_FileSystemList2.FindIndex(x => x.PID == _X64_TcpRows.ProcessId
                                                            /*&& x.FileName == Network_Info_DataTables.SetRow(_X64_TcpRows.ProcessId)*/);

                                                            if (PPath_index != -1)
                                                            {
                                                                Table1_x64[_x64_counter].ProcessPath = Processes_FileSystemList2[PPath_index].FileName_Path;
                                                            }
                                                            else
                                                            {
                                                                Table1_x64[_x64_counter].ProcessPath = "@";
                                                            }

                                                            Table1_x64[_x64_counter].IsLive = 2;
                                                            Table1_x64[_x64_counter].FullSTR = Table1_x64[_x64_counter].ProcessName.ToString() + Table1_x64[_x64_counter].PID.ToString()
                                                                + Table1_x64[_x64_counter].RemoteIP.Address.ToString() + Table1_x64[_x64_counter].RPORT.ToString() + Table1_x64[_x64_counter].states.ToString();
                                                        }
                                                        break;
                                                    }
                                                case false:
                                                    {
                                                        Table1_x64[_x64_counter].LocalIP = _X64_TcpRows.LocalEndPoint;
                                                        Table1_x64[_x64_counter].LPORT = _X64_TcpRows.LocalEndPoint.Port;
                                                        Table1_x64[_x64_counter].RemoteIP = _X64_TcpRows.RemoteEndPoint;
                                                        Table1_x64[_x64_counter].RPORT = _X64_TcpRows.RemoteEndPoint.Port;

                                                        switch (_X64_TcpRows.State)
                                                        {
                                                            case TcpState.Established:
                                                                Estab++; Table1_x64[_x64_counter].states = 5;
                                                                break;
                                                            case TcpState.Listen:
                                                                Listen++; Table1_x64[_x64_counter].states = 2;
                                                                break;
                                                            case TcpState.SynSent:
                                                                Sync++; Table1_x64[_x64_counter].states = 3;
                                                                break;
                                                        }

                                                        Table1_x64[_x64_counter].states_String = _X64_TcpRows.State.ToString().ToUpper();
                                                        Table1_x64[_x64_counter].PID = _X64_TcpRows.ProcessId;
                                                        Table1_x64[_x64_counter].ProcessName = Network_Info_DataTables.SetRow(_X64_TcpRows.ProcessId);

                                                        Int32 PPath_index = Processes_FileSystemList2.FindIndex(x => x.PID == _X64_TcpRows.ProcessId
                                                          /* && x.FileName == Network_Info_DataTables.SetRow(_X64_TcpRows.ProcessId)*/);

                                                        if (PPath_index != -1)
                                                        {
                                                            Table1_x64[_x64_counter].ProcessPath = Processes_FileSystemList2[PPath_index].FileName_Path;
                                                        }
                                                        else
                                                        {
                                                            Table1_x64[_x64_counter].ProcessPath = "@";
                                                        }

                                                        Table1_x64[_x64_counter].IsLive = 2;
                                                        Table1_x64[_x64_counter].FullSTR = Table1_x64[_x64_counter].ProcessName.ToString() + Table1_x64[_x64_counter].PID.ToString()
                                                            + Table1_x64[_x64_counter].RemoteIP.Address.ToString() + Table1_x64[_x64_counter].RPORT.ToString() + Table1_x64[_x64_counter].states.ToString();


                                                        break;
                                                    }

                                            }
                                        }
                                        break;
                                    case true:
                                        {
                                            switch (Network_Info_DataTables.Filtering_IS_127001)
                                            {
                                                case true:
                                                    {
                                                        if (_X64_TcpRows.LocalEndPoint.Address.ToString() != "127.0.0.1" && _X64_TcpRows.State == TcpState.Established)
                                                        {
                                                            Table1_x64[_x64_counter].LocalIP = _X64_TcpRows.LocalEndPoint;
                                                            Table1_x64[_x64_counter].LPORT = _X64_TcpRows.LocalEndPoint.Port;
                                                            Table1_x64[_x64_counter].RemoteIP = _X64_TcpRows.RemoteEndPoint;
                                                            Table1_x64[_x64_counter].RPORT = _X64_TcpRows.RemoteEndPoint.Port;

                                                            switch (_X64_TcpRows.State)
                                                            {
                                                                case TcpState.Established:
                                                                    Estab++; Table1_x64[_x64_counter].states = 5;
                                                                    break;
                                                                case TcpState.Listen:
                                                                    Listen++; Table1_x64[_x64_counter].states = 2;
                                                                    break;
                                                                case TcpState.SynSent:
                                                                    Sync++; Table1_x64[_x64_counter].states = 3;
                                                                    break;
                                                            }

                                                            Table1_x64[_x64_counter].states_String = _X64_TcpRows.State.ToString().ToUpper();
                                                            Table1_x64[_x64_counter].PID = _X64_TcpRows.ProcessId;
                                                            Table1_x64[_x64_counter].ProcessName = Network_Info_DataTables.SetRow(_X64_TcpRows.ProcessId);

                                                            Int32 PPath_index = Processes_FileSystemList2.FindIndex(x => x.PID == _X64_TcpRows.ProcessId
                                                           /*&& x.FileName == Network_Info_DataTables.SetRow(_X64_TcpRows.ProcessId)*/);

                                                            if (PPath_index != -1)
                                                            {
                                                                Table1_x64[_x64_counter].ProcessPath = Processes_FileSystemList2[PPath_index].FileName_Path;
                                                            }
                                                            else
                                                            {
                                                                Table1_x64[_x64_counter].ProcessPath = "@";
                                                            }

                                                            Table1_x64[_x64_counter].IsLive = 2;
                                                            Table1_x64[_x64_counter].FullSTR = Table1_x64[_x64_counter].ProcessName.ToString() + Table1_x64[_x64_counter].PID.ToString()
                                                                + Table1_x64[_x64_counter].RemoteIP.Address.ToString() + Table1_x64[_x64_counter].RPORT.ToString() + Table1_x64[_x64_counter].states.ToString();
                                                        }
                                                        break;
                                                    }
                                                case false:
                                                    {
                                                        if (_X64_TcpRows.State == TcpState.Established)
                                                        {
                                                            Table1_x64[_x64_counter].LocalIP = _X64_TcpRows.LocalEndPoint;
                                                            Table1_x64[_x64_counter].LPORT = _X64_TcpRows.LocalEndPoint.Port;
                                                            Table1_x64[_x64_counter].RemoteIP = _X64_TcpRows.RemoteEndPoint;
                                                            Table1_x64[_x64_counter].RPORT = _X64_TcpRows.RemoteEndPoint.Port;

                                                            switch (_X64_TcpRows.State)
                                                            {
                                                                case TcpState.Established:
                                                                    Estab++; Table1_x64[_x64_counter].states = 5;
                                                                    break;
                                                                case TcpState.Listen:
                                                                    Listen++; Table1_x64[_x64_counter].states = 2;
                                                                    break;
                                                                case TcpState.SynSent:
                                                                    Sync++; Table1_x64[_x64_counter].states = 3;
                                                                    break;
                                                            }

                                                            Table1_x64[_x64_counter].states_String = _X64_TcpRows.State.ToString().ToUpper();
                                                            Table1_x64[_x64_counter].PID = _X64_TcpRows.ProcessId;
                                                            Table1_x64[_x64_counter].ProcessName = Network_Info_DataTables.SetRow(_X64_TcpRows.ProcessId);

                                                            Int32 PPath_index = Processes_FileSystemList2.FindIndex(x => x.PID == _X64_TcpRows.ProcessId
                                                           /*&& x.FileName == Network_Info_DataTables.SetRow(_X64_TcpRows.ProcessId)*/);

                                                            if (PPath_index != -1)
                                                            {
                                                                Table1_x64[_x64_counter].ProcessPath = Processes_FileSystemList2[PPath_index].FileName_Path;
                                                            }
                                                            else
                                                            {
                                                                Table1_x64[_x64_counter].ProcessPath = "@";
                                                            }

                                                            Table1_x64[_x64_counter].IsLive = 2;
                                                            Table1_x64[_x64_counter].FullSTR = Table1_x64[_x64_counter].ProcessName.ToString() + Table1_x64[_x64_counter].PID.ToString()
                                                                + Table1_x64[_x64_counter].RemoteIP.Address.ToString() + Table1_x64[_x64_counter].RPORT.ToString() + Table1_x64[_x64_counter].states.ToString();
                                                        }

                                                        break;
                                                    }

                                            }
                                        }
                                        break;




                                }

                                if (initial)
                                {

                                    // BeginInvoke(new Additem(Additems), Table1_x64[_x64_counter]);
                                   // Additems(Table1_x64[_x64_counter]);
                                }

                            }
                            catch (Exception e)
                            {

                            }
                            _x64_counter++;
                        }


                    }
                    catch (Exception err)
                    {

                    }



                    try
                    {

                        if (!initial)
                        {
                            for (int i = 0; i < Table1_x64.Length; i++)
                            {
                                if (Network_Info_DataTables.StopThread)
                                {
                                    Core.Abort();
                                    break;
                                }
                                for (int b = 0; b < Table2_x64.Length; b++)
                                {
                                    if (Table1_x64[i].IsLive != 1)
                                    {
                                        if (Table1_x64[i].FullSTR == Table2_x64[b].FullSTR)
                                        {
                                            Table2_x64[b].IsLive = 1;
                                            Table1_x64[i].IsLive = 1;

                                        }
                                    }
                                }
                                if (Table1_x64[i].IsLive != 1)
                                {
                                    try
                                    {
                                        // BeginInvoke(new Additem(Additems), Table1_x64[i]);
                                       // Additems(Table1_x64[i]);

                                        Table1_x64[i].IsLive = 1;
                                    }
                                    catch (Exception err)
                                    {


                                    }

                                }
                                Thread.Sleep(1);
                            }
                        }

                    }
                    catch (Exception err)
                    {


                    }



                    initial = false;

                    try
                    {
                        Before_after = 0;
                        //BeginInvoke(new DeleteItem(_DeleteItems), (object)1);
                        // _DeleteItems((object)1);

                    }
                    catch (Exception err)
                    {

                    }

                    //BeginInvoke(new information(Information));

                    Thread.Sleep(2);

                    Endpoits = 0;
                    Listen = 0;
                    Sync = 0;
                    Estab = 0;

                    try
                    {

                        //x64 code
                        int _x64_counter_2 = 0;
                        int _x64_counter_tmp_2 = 0;
                        foreach (TcpRow _X64_TcpRows_tmp in ManagedIpHelper.GetExtendedTcpTable(true))
                        {
                            _x64_counter_tmp_2++;

                        }
                        Table2_x64 = new _Table[_x64_counter_tmp_2];

                        foreach (TcpRow _X64_TcpRows in ManagedIpHelper.GetExtendedTcpTable(true))
                        {

                            if (Network_Info_DataTables.StopThread)
                            {
                                Core.Abort();
                                break;
                            }
                            try
                            {
                                switch (Network_Info_DataTables.Filtering_ISEstablished)
                                {

                                    case false:
                                        {
                                            // add to x64 table code
                                            switch (Network_Info_DataTables.Filtering_IS_127001)
                                            {
                                                case true:
                                                    {
                                                        if (_X64_TcpRows.LocalEndPoint.Address.ToString() != "127.0.0.1")
                                                        {
                                                            // add to x64 table code
                                                            Table2_x64[_x64_counter_2].LocalIP = _X64_TcpRows.LocalEndPoint;
                                                            Table2_x64[_x64_counter_2].LPORT = _X64_TcpRows.LocalEndPoint.Port;
                                                            Table2_x64[_x64_counter_2].RemoteIP = _X64_TcpRows.RemoteEndPoint;
                                                            Table2_x64[_x64_counter_2].RPORT = _X64_TcpRows.RemoteEndPoint.Port;

                                                            switch (_X64_TcpRows.State)
                                                            {
                                                                case TcpState.Established:
                                                                    Estab++; Table2_x64[_x64_counter_2].states = 5;
                                                                    break;
                                                                case TcpState.Listen:
                                                                    Listen++; Table2_x64[_x64_counter_2].states = 2;
                                                                    break;
                                                                case TcpState.SynSent:
                                                                    Sync++; Table2_x64[_x64_counter_2].states = 3;
                                                                    break;
                                                            }

                                                            Table2_x64[_x64_counter_2].states_String = _X64_TcpRows.State.ToString().ToUpper();
                                                            Table2_x64[_x64_counter_2].PID = _X64_TcpRows.ProcessId;
                                                            Table2_x64[_x64_counter_2].ProcessName = Network_Info_DataTables.SetRow(_X64_TcpRows.ProcessId);

                                                            Int32 PPath_index = Processes_FileSystemList2.FindIndex(x => x.PID == _X64_TcpRows.ProcessId
                                                           /*&& x.FileName == Network_Info_DataTables.SetRow(_X64_TcpRows.ProcessId)*/);

                                                            if (PPath_index != -1)
                                                            {
                                                                Table2_x64[_x64_counter_2].ProcessPath = Processes_FileSystemList2[PPath_index].FileName_Path;
                                                            }
                                                            else
                                                            {
                                                                Table2_x64[_x64_counter_2].ProcessPath = "@";
                                                            }

                                                            Table2_x64[_x64_counter_2].IsLive = 2;
                                                            Table2_x64[_x64_counter_2].FullSTR = Table1_x64[_x64_counter_2].LPORT.ToString() + Table1_x64[_x64_counter_2].RemoteIP.Address.ToString() + Table1_x64[_x64_counter_2].RPORT.ToString() + Table1_x64[_x64_counter_2].states.ToString();
                                                        }
                                                        break;
                                                    }
                                                case false:
                                                    {
                                                        Table2_x64[_x64_counter_2].LocalIP = _X64_TcpRows.LocalEndPoint;
                                                        Table2_x64[_x64_counter_2].LPORT = _X64_TcpRows.LocalEndPoint.Port;
                                                        Table2_x64[_x64_counter_2].RemoteIP = _X64_TcpRows.RemoteEndPoint;
                                                        Table2_x64[_x64_counter_2].RPORT = _X64_TcpRows.RemoteEndPoint.Port;

                                                        switch (_X64_TcpRows.State)
                                                        {
                                                            case TcpState.Established:
                                                                Estab++; Table2_x64[_x64_counter_2].states = 5;
                                                                break;
                                                            case TcpState.Listen:
                                                                Listen++; Table2_x64[_x64_counter_2].states = 2;
                                                                break;
                                                            case TcpState.SynSent:
                                                                Sync++; Table2_x64[_x64_counter_2].states = 3;
                                                                break;
                                                        }
                                                        Table2_x64[_x64_counter_2].states_String = _X64_TcpRows.State.ToString().ToUpper();
                                                        Table2_x64[_x64_counter_2].PID = _X64_TcpRows.ProcessId;
                                                        Table2_x64[_x64_counter_2].ProcessName = Network_Info_DataTables.SetRow(_X64_TcpRows.ProcessId);

                                                        Int32 PPath_index = Processes_FileSystemList2.FindIndex(x => x.PID == _X64_TcpRows.ProcessId
                                                       /*&& x.FileName == Network_Info_DataTables.SetRow(_X64_TcpRows.ProcessId)*/);

                                                        if (PPath_index != -1)
                                                        {
                                                            Table2_x64[_x64_counter_2].ProcessPath = Processes_FileSystemList2[PPath_index].FileName_Path;
                                                        }
                                                        else
                                                        {
                                                            Table2_x64[_x64_counter_2].ProcessPath = "@";
                                                        }

                                                        Table2_x64[_x64_counter_2].IsLive = 2;
                                                        Table2_x64[_x64_counter_2].FullSTR = Table1_x64[_x64_counter_2].LPORT.ToString() + Table1_x64[_x64_counter_2].RemoteIP.Address.ToString() + Table1_x64[_x64_counter_2].RPORT.ToString() + Table1_x64[_x64_counter_2].states.ToString();
                                                        break;
                                                    }
                                            }
                                        }
                                        break;
                                    case true:
                                        {

                                            switch (Network_Info_DataTables.Filtering_IS_127001)
                                            {
                                                case true:
                                                    {
                                                        if (_X64_TcpRows.LocalEndPoint.Address.ToString() != "127.0.0.1" && _X64_TcpRows.State == TcpState.Established)
                                                        {
                                                            Table2_x64[_x64_counter_2].LocalIP = _X64_TcpRows.LocalEndPoint;
                                                            Table2_x64[_x64_counter_2].LPORT = _X64_TcpRows.LocalEndPoint.Port;
                                                            Table2_x64[_x64_counter_2].RemoteIP = _X64_TcpRows.RemoteEndPoint;
                                                            Table2_x64[_x64_counter_2].RPORT = _X64_TcpRows.RemoteEndPoint.Port;
                                                            switch (_X64_TcpRows.State)
                                                            {
                                                                case TcpState.Established:
                                                                    Estab++; Table2_x64[_x64_counter_2].states = 5;
                                                                    break;
                                                                case TcpState.Listen:
                                                                    Listen++; Table2_x64[_x64_counter_2].states = 2;
                                                                    break;
                                                                case TcpState.SynSent:
                                                                    Sync++; Table2_x64[_x64_counter_2].states = 3;
                                                                    break;
                                                            }
                                                            Table2_x64[_x64_counter_2].states_String = _X64_TcpRows.State.ToString().ToUpper();
                                                            Table2_x64[_x64_counter_2].PID = _X64_TcpRows.ProcessId;
                                                            Table2_x64[_x64_counter_2].ProcessName = Network_Info_DataTables.SetRow(_X64_TcpRows.ProcessId);

                                                            Int32 PPath_index = Processes_FileSystemList2.FindIndex(x => x.PID == _X64_TcpRows.ProcessId
                                                      /* && x.FileName == Network_Info_DataTables.SetRow(_X64_TcpRows.ProcessId)*/);

                                                            if (PPath_index != -1)
                                                            {
                                                                Table2_x64[_x64_counter_2].ProcessPath = Processes_FileSystemList2[PPath_index].FileName_Path;
                                                            }
                                                            else
                                                            {
                                                                Table2_x64[_x64_counter_2].ProcessPath = "@";
                                                            }

                                                            Table2_x64[_x64_counter_2].IsLive = 2;
                                                            Table2_x64[_x64_counter_2].FullSTR = Table1_x64[_x64_counter_2].LPORT.ToString() + Table1_x64[_x64_counter_2].RemoteIP.Address.ToString() + Table1_x64[_x64_counter_2].RPORT.ToString() + Table1_x64[_x64_counter_2].states.ToString();
                                                        }
                                                        break;
                                                    }
                                                case false:
                                                    {
                                                        if (_X64_TcpRows.State == TcpState.Established)
                                                        {
                                                            Table2_x64[_x64_counter_2].LocalIP = _X64_TcpRows.LocalEndPoint;
                                                            Table2_x64[_x64_counter_2].LPORT = _X64_TcpRows.LocalEndPoint.Port;
                                                            Table2_x64[_x64_counter_2].RemoteIP = _X64_TcpRows.RemoteEndPoint;
                                                            Table2_x64[_x64_counter_2].RPORT = _X64_TcpRows.RemoteEndPoint.Port;
                                                            switch (_X64_TcpRows.State)
                                                            {
                                                                case TcpState.Established:
                                                                    Estab++; Table2_x64[_x64_counter_2].states = 5;
                                                                    break;
                                                                case TcpState.Listen:
                                                                    Listen++; Table2_x64[_x64_counter_2].states = 2;
                                                                    break;
                                                                case TcpState.SynSent:
                                                                    Sync++; Table2_x64[_x64_counter_2].states = 3;
                                                                    break;
                                                            }
                                                            Table2_x64[_x64_counter_2].states_String = _X64_TcpRows.State.ToString().ToUpper();
                                                            Table2_x64[_x64_counter_2].PID = _X64_TcpRows.ProcessId;
                                                            Table2_x64[_x64_counter_2].ProcessName = Network_Info_DataTables.SetRow(_X64_TcpRows.ProcessId);

                                                            Int32 PPath_index = Processes_FileSystemList2.FindIndex(x => x.PID == _X64_TcpRows.ProcessId
                                                       /*&& x.FileName == Network_Info_DataTables.SetRow(_X64_TcpRows.ProcessId)*/);

                                                            if (PPath_index != -1)
                                                            {
                                                                Table2_x64[_x64_counter_2].ProcessPath = Processes_FileSystemList2[PPath_index].FileName_Path;
                                                            }
                                                            else
                                                            {
                                                                Table2_x64[_x64_counter_2].ProcessPath = "@";
                                                            }

                                                            Table2_x64[_x64_counter_2].IsLive = 2;
                                                            Table2_x64[_x64_counter_2].FullSTR = Table1_x64[_x64_counter_2].LPORT.ToString() + Table1_x64[_x64_counter_2].RemoteIP.Address.ToString() + Table1_x64[_x64_counter_2].RPORT.ToString() + Table1_x64[_x64_counter_2].states.ToString();
                                                        }
                                                        break;
                                                    }
                                            }
                                        }
                                        break;
                                }

                            }
                            catch (Exception e)
                            {


                            }
                            _x64_counter_2++;
                        }

                    }
                    catch (Exception err)
                    {


                    }


                    try
                    {

                        for (int i = 0; i < Table2_x64.Length; i++)
                        {
                            if (Network_Info_DataTables.StopThread)
                            {
                                Core.Abort();
                                break;
                            }
                            for (int b = 0; b < Table1_x64.Length; b++)
                            {
                                if (Table2_x64[i].IsLive != 1)
                                {
                                    if (Table2_x64[i].FullSTR == Table1_x64[b].FullSTR)
                                    {
                                        Table1_x64[b].IsLive = 1;
                                        Table2_x64[i].IsLive = 1;

                                    }
                                }
                            }
                            if (Table2_x64[i].IsLive != 1)
                            {
                                try
                                {

                                    // BeginInvoke(new Additem(Additems), Table2_x64[i]);
                                    // Additems(Table2_x64[i]);
                                    Table2_x64[i].IsLive = 1;
                                }
                                catch (Exception err)
                                {


                                }

                            }

                        }
                    }
                    catch (Exception err)
                    {


                    }




                    try
                    {
                        Before_after = 1;
                        //BeginInvoke(new DeleteItem(_DeleteItems), (object)1);
                       // _DeleteItems((object)1);
                    }
                    catch (Exception err)
                    {


                    }


                    //BeginInvoke(new information(Information));
                    Thread.Sleep(10);

                }
                catch (Exception err)
                {


                }


                Table1_x64.ToList().RemoveAll(x => x.IsLive > 0);
                Table2_x64.ToList().RemoveAll(x => x.IsLive > 0);


            }
        }

        public static void GetProcessesPaths()
        {
            
                bool init = false;

                if (!init)
                {

                    var wmiQueryString = "SELECT ProcessId, ExecutablePath, CommandLine FROM Win32_Process";
                    /// this System.Management should add to "References" in the project
                    using (var searcher = new ManagementObjectSearcher(wmiQueryString))
                    using (var results = searcher.Get())
                    {
                        var query = from _Process in Process.GetProcesses()
                                    join Obj in results.Cast<ManagementObject>()
                                    on _Process.Id equals (int)(uint)Obj["ProcessId"]
                                    select new
                                    {
                                        Process = _Process,
                                        Path = (string)Obj["ExecutablePath"],
                                        CommandLine = (string)Obj["CommandLine"],
                                        ProcessId = (int)(uint)Obj["ProcessId"]
                                    };
                        foreach (var item in query)
                        {
                            Task.Delay(10);
                            Processes_FileSystemList2.Add(new _Table_of_FileSystem_for_Processes_Watcher
                            {
                                Eventtime = DateTime.Now.ToString(),
                                FileName = item.Process.ProcessName + ":" + item.Process.Id,
                                FileName_Path = item.Path,
                                ProcessCommandLine = item.CommandLine,
                                PID = item.ProcessId

                            });
                        }
                    }
                    init = true;
                }

          
        }
       
    }

    public class Network_Info_DataTables
    {

        public static string SCHEMA = "<?xml version=\"1.0\" standalone=\"yes\"?><xs:schema id=\"NewDataSet\" xmlns=\"\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:msdata=\"urn:schemas-microsoft-com:xml-msdata\"> <xs:element name=\"NewDataSet\" msdata:IsDataSet=\"true\" msdata:MainDataTable=\"TCPIP\" msdata:UseCurrentLocale=\"true\"><xs:complexType><xs:choice minOccurs=\"0\" maxOccurs=\"unbounded\"><xs:element name=\"TCPIP\">" +
           "<xs:complexType><xs:sequence><xs:element name=\"TIME\" type=\"xs:dateTime\" minOccurs=\"0\" />" +
               "<xs:element name=\"Local_IP\" type=\"xs:string\" minOccurs=\"0\" />" +
               "<xs:element name=\"Local_Port\" type=\"xs:int\" minOccurs=\"0\" />" +
               "<xs:element name=\"Remote_IP\" type=\"xs:string\" minOccurs=\"0\" />" +
               "<xs:element name=\"Remote_Port\" type=\"xs:int\" minOccurs=\"0\" />" +
               "<xs:element name=\"State\" type=\"xs:string\" minOccurs=\"0\" />" +
               "<xs:element name=\"State_Code\" type=\"xs:int\" minOccurs=\"0\" />" +
               "<xs:element name=\"Pid\" type=\"xs:int\" minOccurs=\"0\" />" +
               "<xs:element name=\"ProcessName\" type=\"xs:string\" minOccurs=\"0\" />" +
             "</xs:sequence>" + "</xs:complexType>" + "</xs:element>" + "</xs:choice>" + "</xs:complexType>" + "</xs:element>" + "</xs:schema>";

        private static bool _IsProcessNameActive;
        public static bool IsProcessNameActive
        {
            get { return _IsProcessNameActive; }
            set { _IsProcessNameActive = value; }
        }

        private static int _ProcessPID_TO_Properties;
        public static int ProcessPID_TO_Properties
        {
            get { return _ProcessPID_TO_Properties; }
            set { _ProcessPID_TO_Properties = value; }
        }

        private static bool _IsLogActive;
        public static bool IsLogActive
        {
            get { return _IsLogActive; }
            set { _IsLogActive = value; }
        }

        private static bool _Filtering_IS_Established;
        public static bool Filtering_ISEstablished
        {
            get { return _Filtering_IS_Established; }
            set { _Filtering_IS_Established = value; }
        }

        private static bool _Filtering_IS_127001;
        public static bool Filtering_IS_127001
        {
            get { return _Filtering_IS_127001; }
            set { _Filtering_IS_127001 = value; }
        }

        private static bool _StopThread;
        public static bool StopThread
        {
            get { return _StopThread; }
            set { _StopThread = value; }
        }

        public static DataTable table = new DataTable("MasterTable");
        public static DataColumn column;
        public static DataRow row;
        public static DataTable TCPIPTable = new DataTable("TCPIP");
        public static DataColumn TCPIPcolumn;
        public static DataRow TCPIProw;
        public static DataTable Load_XML_TCPIPTable = new DataTable("TCPIP");
        public static DataColumn Load_XML_TCPIPcolumn;
        public static DataRow Load_XML_TCPIProw;


        public static void Settable()
        {

            try
            {


                table.Columns.Clear();
                table.Rows.Clear();
                column = new DataColumn();
                column.DataType = System.Type.GetType("System.Int32");
                column.ColumnName = "Pid";
                table.Columns.Add(column);

                // Create second column.
                column = new DataColumn();
                column.DataType = Type.GetType("System.String");
                column.ColumnName = "ProcessName";
                table.Columns.Add(column);

                //// Create second column.
                //column = new DataColumn();
                //column.DataType = Type.GetType("System.String");
                //column.ColumnName = "ProcessPath";
                //table.Columns.Add(column);
            }
            catch (Exception err)
            {
                System.Diagnostics.Debug.WriteLine(err.Message);
            }
        }

        public static string SetRow(int Pid)
        {
            string Process_Name = " ";
            try
            {
                Process_Name = GetProcessName(Pid);

            }
            catch (Exception err)
            {
               
                row = table.NewRow();
                row["Pid"] = Pid;

                try
                {
                    //Int32 index = Form1.Processes_FileSystemList.FindIndex(x => Convert.ToInt32(x.FileName.Split(':')[1]) == Pid);
                    //if (index != -1)
                    //{
                    //    row["ProcessPath"] = Form1.Processes_FileSystemList[index].FileName_Path;
                    //    Process_Name = Process.GetProcessById(Pid).ProcessName;
                    //    row["ProcessName"] = Process_Name;
                    //    table.Rows.Add(row);
                    //}



                    Process_Name = Process.GetProcessById(Pid).ProcessName;
                    row["ProcessName"] = Process_Name;
                    table.Rows.Add(row);

                }
                catch (Exception)
                {


                }

              
            }

            return Process_Name;


        }

        public static string GetProcessName(int Pid)
        {
            string expression;
            string result = "";


            DataRow[] foundRows;
            expression = "Pid = " + Pid.ToString() + "";
            // Use the Select method to find all rows matching the filter.
            if (table.Rows != null)
            {
                foundRows = table.Select(expression);
                result = foundRows[0][1].ToString();
            }

            //// Print column 0 of each returned row.


            return result;
        }
       
        public static void TCPIP_settable()
        {
            try
            {

                TCPIPTable.Columns.Clear();
                TCPIPTable.Rows.Clear();

                TCPIPcolumn = new DataColumn();
                TCPIPcolumn.DataType = System.Type.GetType("System.DateTime");
                TCPIPcolumn.ColumnName = "TIME";
                TCPIPTable.Columns.Add(TCPIPcolumn);

                // Create second column.
                TCPIPcolumn = new DataColumn();
                TCPIPcolumn.DataType = Type.GetType("System.String");
                TCPIPcolumn.ColumnName = "ProcessName";
                TCPIPTable.Columns.Add(TCPIPcolumn);

                TCPIPcolumn = new DataColumn();
                TCPIPcolumn.DataType = System.Type.GetType("System.Int32");
                TCPIPcolumn.ColumnName = "Pid";
                TCPIPTable.Columns.Add(TCPIPcolumn);

                TCPIPcolumn = new DataColumn();
                TCPIPcolumn.DataType = System.Type.GetType("System.String");
                TCPIPcolumn.ColumnName = "State";
                TCPIPTable.Columns.Add(TCPIPcolumn);

                // Create second column.
                TCPIPcolumn = new DataColumn();
                TCPIPcolumn.DataType = Type.GetType("System.Int32");
                TCPIPcolumn.ColumnName = "State_Code";
                TCPIPTable.Columns.Add(TCPIPcolumn);

                // Create second column.
                TCPIPcolumn = new DataColumn();
                //TCPIPcolumn.DataType = Type.GetType("System.Net.IPAddress");
                TCPIPcolumn.DataType = Type.GetType("System.String");
                TCPIPcolumn.ColumnName = "Local_IP";
                TCPIPTable.Columns.Add(TCPIPcolumn);


                TCPIPcolumn = new DataColumn();
                TCPIPcolumn.DataType = System.Type.GetType("System.Int32");
                TCPIPcolumn.ColumnName = "Local_Port";
                TCPIPTable.Columns.Add(TCPIPcolumn);

                TCPIPcolumn = new DataColumn();
                TCPIPcolumn.DataType = Type.GetType("System.String");
                TCPIPcolumn.ColumnName = "Remote_IP";
                TCPIPTable.Columns.Add(TCPIPcolumn);


                TCPIPcolumn = new DataColumn();
                TCPIPcolumn.DataType = System.Type.GetType("System.Int32");
                TCPIPcolumn.ColumnName = "Remote_Port";
                TCPIPTable.Columns.Add(TCPIPcolumn);

               
            }
            catch (Exception err)
            {
                System.Diagnostics.Debug.WriteLine(err.Message);
            }
        }

        public static void GetRowsTODataTable(DateTime Time, string LIP, string LPORT, string RIP, string RPORT, string States, int State_Code, int pid, string Processname)
        {
            try
            {

                //TCPIProw = TCPIPTable.NewRow();
                //TCPIProw["TIME"] = Time;
                //TCPIProw["ProcessName"] = Processname;
                //TCPIProw["pid"] = pid;
                //TCPIProw["State"] = States;
                //TCPIProw["State_Code"] = State_Code;
                //TCPIProw["Local_IP"] = LIP;
                //TCPIProw["Local_Port"] = LPORT;
                //TCPIProw["Remote_IP"] = RIP;
                //TCPIProw["Remote_Port"] = RPORT;

                //TCPIPTable.Rows.Add(TCPIProw);

            }
            catch (Exception err)
            {


            }

        }

        public static void EventRaised_NewRows()
        {
            if (IsLogActive)
            {
                //   TCPIPTable.TableNewRow += new DataTableNewRowEventHandler(TCPIPTable_TableNewRow);
            }
        }

        public static void saveXml_Logs()
        {
            SaveFileDialog fs = new SaveFileDialog();
            fs.Filter = "XML files (*.xml)|*.xml|All files (*.*)|*.*";
            fs.FilterIndex = 1;
            fs.RestoreDirectory = true;

            if (fs.ShowDialog() == DialogResult.OK)
            {
                if (fs.FileName != null)
                {
                    // Insert code to read the stream here.
                    TCPIPTable.WriteXml(fs.FileName);
                    // TCPIPTable.WriteXmlSchema("test.xml");

                }
            }

        }

        public static void LoadXML_TCPIP_settable()
        {
            try
            {

                Load_XML_TCPIPTable.Columns.Clear();
                Load_XML_TCPIPTable.Rows.Clear();




                Load_XML_TCPIPcolumn = new DataColumn();
                Load_XML_TCPIPcolumn.DataType = System.Type.GetType("System.DateTime");
                Load_XML_TCPIPcolumn.ColumnName = "TIME";
                Load_XML_TCPIPTable.Columns.Add(Load_XML_TCPIPcolumn);

                // Create second column.
                Load_XML_TCPIPcolumn = new DataColumn();
                //TCPIPcolumn.DataType = Type.GetType("System.Net.IPAddress");
                Load_XML_TCPIPcolumn.DataType = Type.GetType("System.String");
                Load_XML_TCPIPcolumn.ColumnName = "Local_IP";
                Load_XML_TCPIPTable.Columns.Add(Load_XML_TCPIPcolumn);


                Load_XML_TCPIPcolumn = new DataColumn();
                Load_XML_TCPIPcolumn.DataType = System.Type.GetType("System.Int32");
                Load_XML_TCPIPcolumn.ColumnName = "Local_Port";
                Load_XML_TCPIPTable.Columns.Add(Load_XML_TCPIPcolumn);

                Load_XML_TCPIPcolumn = new DataColumn();
                Load_XML_TCPIPcolumn.DataType = Type.GetType("System.String");
                Load_XML_TCPIPcolumn.ColumnName = "Remote_IP";
                Load_XML_TCPIPTable.Columns.Add(Load_XML_TCPIPcolumn);


                Load_XML_TCPIPcolumn = new DataColumn();
                Load_XML_TCPIPcolumn.DataType = System.Type.GetType("System.Int32");
                Load_XML_TCPIPcolumn.ColumnName = "Remote_Port";
                Load_XML_TCPIPTable.Columns.Add(Load_XML_TCPIPcolumn);

                Load_XML_TCPIPcolumn = new DataColumn();
                Load_XML_TCPIPcolumn.DataType = System.Type.GetType("System.String");
                Load_XML_TCPIPcolumn.ColumnName = "State";
                Load_XML_TCPIPTable.Columns.Add(Load_XML_TCPIPcolumn);

                // Create second column.
                Load_XML_TCPIPcolumn = new DataColumn();
                Load_XML_TCPIPcolumn.DataType = Type.GetType("System.Int32");
                Load_XML_TCPIPcolumn.ColumnName = "State_Code";
                Load_XML_TCPIPTable.Columns.Add(Load_XML_TCPIPcolumn);

                Load_XML_TCPIPcolumn = new DataColumn();
                Load_XML_TCPIPcolumn.DataType = System.Type.GetType("System.Int32");
                Load_XML_TCPIPcolumn.ColumnName = "Pid";
                Load_XML_TCPIPTable.Columns.Add(Load_XML_TCPIPcolumn);

                // Create second column.
                Load_XML_TCPIPcolumn = new DataColumn();
                Load_XML_TCPIPcolumn.DataType = Type.GetType("System.String");
                Load_XML_TCPIPcolumn.ColumnName = "ProcessName";
                Load_XML_TCPIPTable.Columns.Add(Load_XML_TCPIPcolumn);


            }
            catch (Exception err)
            {
                System.Diagnostics.Debug.WriteLine(err.Message);
            }
        }

        public static void saveSchema()
        {
            try
            {
                if (File.Exists("TempSchema.xml"))
                {
                    File.Delete("TempSchema.xml");
                    File.AppendAllText("TempSchema.xml", SCHEMA);
                }
                if (!File.Exists("TempSchema.xml"))
                {
                    File.AppendAllText("TempSchema.xml", SCHEMA);
                }
            }
            catch (Exception err)
            {
                MessageBox.Show(null, err.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);

            }

        }
    }
}
