using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Net;
using System.Net.Sockets;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Collections.Generic;

namespace ETWPM2Monitor2
{
    class SocketClass
    {
        // source: ConPtyShell 

        public class DeadlockCheckHelper
        {

            private bool deadlockDetected;
            private IntPtr targetHandle;

            private delegate uint LPTHREAD_START_ROUTINE(uint lpParam);

            [DllImport("kernel32.dll")]
            private static extern bool CloseHandle(IntPtr hObject);

            [DllImport("kernel32.dll", SetLastError = true)]
            private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

            [DllImport("Kernel32.dll", SetLastError = true)]
            private static extern IntPtr CreateThread(uint lpThreadAttributes, uint dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

            private uint ThreadCheckDeadlock(uint threadParams)
            {
                IntPtr objPtr = IntPtr.Zero;
                objPtr = SocketHijacking.NtQueryObjectDynamic(this.targetHandle, SocketHijacking.OBJECT_INFORMATION_CLASS.ObjectNameInformation, 0);
                this.deadlockDetected = false;
                if (objPtr != IntPtr.Zero) Marshal.FreeHGlobal(objPtr);
                return 0;
            }

            public bool CheckDeadlockDetected(IntPtr tHandle)
            {
                this.deadlockDetected = true;
                this.targetHandle = tHandle;
                LPTHREAD_START_ROUTINE delegateThreadCheckDeadlock = new LPTHREAD_START_ROUTINE(this.ThreadCheckDeadlock);
                IntPtr hThread = IntPtr.Zero;
                uint threadId = 0;
                //we need native threads, C# threads hang and go in lock. We need to avoids hangs on named pipe so... No hangs no deadlocks... no pain no gains...
                hThread = CreateThread(0, 0, delegateThreadCheckDeadlock, IntPtr.Zero, 0, out threadId);
                WaitForSingleObject(hThread, 1500);
                //we do not kill the "pending" threads here with TerminateThread() because it will crash the whole process if we do it on locked threads.
                //just some waste of threads :(
                CloseHandle(hThread);
                return this.deadlockDetected;
            }
        }

        public static class SocketHijacking
        {

            private const uint NTSTATUS_SUCCESS = 0x00000000;
            private const uint NTSTATUS_INFOLENGTHMISMATCH = 0xc0000004;
            private const uint NTSTATUS_BUFFEROVERFLOW = 0x80000005;
            private const uint NTSTATUS_BUFFERTOOSMALL = 0xc0000023;
            private const int NTSTATUS_PENDING = 0x00000103;
            private const int WSA_FLAG_OVERLAPPED = 0x1;
            private const int DUPLICATE_SAME_ACCESS = 0x2;
            private const int SystemHandleInformation = 16;
            private const int PROCESS_DUP_HANDLE = 0x0040;
            private const int SIO_TCP_INFO = unchecked((int)0xD8000027);
            private const int SG_UNCONSTRAINED_GROUP = 0x1;
            private const int SG_CONSTRAINED_GROUP = 0x2;
            private const uint IOCTL_AFD_GET_CONTEXT = 0x12043;
            private const int EVENT_ALL_ACCESS = 0x1f0003;
            private const int SynchronizationEvent = 1;
            private const UInt32 INFINITE = 0xFFFFFFFF;


            private enum SOCKET_STATE : uint
            {
                SocketOpen = 0,
                SocketBound = 1,
                SocketBoundUdp = 2,
                SocketConnected = 3,
                SocketClosed = 3
            }

            private enum AFD_GROUP_TYPE : uint
            {
                GroupTypeNeither = 0,
                GroupTypeConstrained = SG_CONSTRAINED_GROUP,
                GroupTypeUnconstrained = SG_UNCONSTRAINED_GROUP
            }

            public enum OBJECT_INFORMATION_CLASS : int
            {
                ObjectBasicInformation = 0,
                ObjectNameInformation = 1,
                ObjectTypeInformation = 2,
                ObjectAllTypesInformation = 3,
                ObjectHandleInformation = 4
            }

            [StructLayout(LayoutKind.Sequential, Pack = 1)]
            private struct SYSTEM_HANDLE_TABLE_ENTRY_INFO
            {
                public ushort UniqueProcessId;
                public ushort CreatorBackTraceIndex;
                public byte ObjectTypeIndex;
                public byte HandleAttributes;
                public ushort HandleValue;
                public IntPtr Object;
                public IntPtr GrantedAccess;
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct GENERIC_MAPPING
            {
                public int GenericRead;
                public int GenericWrite;
                public int GenericExecute;
                public int GenericAll;
            }

            [StructLayout(LayoutKind.Sequential, Pack = 1)]
            private struct OBJECT_TYPE_INFORMATION_V2
            {
                public UNICODE_STRING TypeName;
                public uint TotalNumberOfObjects;
                public uint TotalNumberOfHandles;
                public uint TotalPagedPoolUsage;
                public uint TotalNonPagedPoolUsage;
                public uint TotalNamePoolUsage;
                public uint TotalHandleTableUsage;
                public uint HighWaterNumberOfObjects;// PeakObjectCount;
                public uint HighWaterNumberOfHandles;// PeakHandleCount;
                public uint HighWaterPagedPoolUsage;
                public uint HighWaterNonPagedPoolUsage;
                public uint HighWaterNamePoolUsage;
                public uint HighWaterHandleTableUsage;
                public uint InvalidAttributes;
                public GENERIC_MAPPING GenericMapping;
                public uint ValidAccessMask;
                public byte SecurityRequired;//bool
                public byte MaintainHandleCount;//bool
                public byte TypeIndex;
                public byte ReservedByte;
                public uint PoolType;
                public uint DefaultPagedPoolCharge;// PagedPoolUsage;
                public uint DefaultNonPagedPoolCharge;//NonPagedPoolUsage;
            }

            [StructLayout(LayoutKind.Sequential, Pack = 1)]
            private struct OBJECT_NAME_INFORMATION
            {
                public UNICODE_STRING Name;
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct UNICODE_STRING
            {
                public ushort Length;
                public ushort MaximumLength;
                public IntPtr Buffer;
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct WSAData
            {
                public short wVersion;
                public short wHighVersion;
                public short iMaxSockets;
                public short iMaxUdpDg;
                public IntPtr lpVendorInfo;
                [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 257)]
                public string szDescription;
                [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 129)]
                public string szSystemStatus;
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
            private struct WSAPROTOCOLCHAIN
            {
                public int ChainLen;
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 7)]
                public uint[] ChainEntries;
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
            private struct WSAPROTOCOL_INFO
            {
                public uint dwServiceFlags1;
                public uint dwServiceFlags2;
                public uint dwServiceFlags3;
                public uint dwServiceFlags4;
                public uint dwProviderFlags;
                public Guid ProviderId;
                public uint dwCatalogEntryId;
                public WSAPROTOCOLCHAIN ProtocolChain;
                public int iVersion;
                public int iAddressFamily;
                public int iMaxSockAddr;
                public int iMinSockAddr;
                public int iSocketType;
                public int iProtocol;
                public int iProtocolMaxOffset;
                public int iNetworkByteOrder;
                public int iSecurityScheme;
                public uint dwMessageSize;
                public uint dwProviderReserved;
                [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
                public string szProtocol;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct SOCKADDR_IN
            {
                public short sin_family;
                public short sin_port;
                public uint sin_addr;
                public long sin_zero;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct TCP_INFO_v0
            {
                public TcpState State;
                public UInt32 Mss;
                public UInt64 ConnectionTimeMs;
                public byte TimestampsEnabled;
                public UInt32 RttUs;
                public UInt32 MinRttUs;
                public UInt32 BytesInFlight;
                public UInt32 Cwnd;
                public UInt32 SndWnd;
                public UInt32 RcvWnd;
                public UInt32 RcvBuf;
                public UInt64 BytesOut;
                public UInt64 BytesIn;
                public UInt32 BytesReordered;
                public UInt32 BytesRetrans;
                public UInt32 FastRetrans;
                public UInt32 DupAcksIn;
                public UInt32 TimeoutEpisodes;
                public byte SynRetrans;
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct linger
            {
                public UInt16 l_onoff;
                public UInt16 l_linger;
            }

            [StructLayout(LayoutKind.Sequential, Pack = 0)]
            private struct IO_STATUS_BLOCK
            {
                public int status;
                public IntPtr information;
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct SOCK_SHARED_INFO
            {
                public SOCKET_STATE State;
                public Int32 AddressFamily;
                public Int32 SocketType;
                public Int32 Protocol;
                public Int32 LocalAddressLength;
                public Int32 RemoteAddressLength;

                // Socket options controlled by getsockopt(), setsockopt().
                public linger LingerInfo;
                public UInt32 SendTimeout;
                public UInt32 ReceiveTimeout;
                public UInt32 ReceiveBufferSize;
                public UInt32 SendBufferSize;
                /* Those are the bits in the SocketProerty, proper order:
                    Listening;
                    Broadcast;
                    Debug;
                    OobInline;
                    ReuseAddresses;
                    ExclusiveAddressUse;
                    NonBlocking;
                    DontUseWildcard;
                    ReceiveShutdown;
                    SendShutdown;
                    ConditionalAccept;
                */
                public ushort SocketProperty;
                // Snapshot of several parameters passed into WSPSocket() when creating this socket
                public UInt32 CreationFlags;
                public UInt32 CatalogEntryId;
                public UInt32 ServiceFlags1;
                public UInt32 ProviderFlags;
                public UInt32 GroupID;
                public AFD_GROUP_TYPE GroupType;
                public Int32 GroupPriority;
                // Last error set on this socket
                public Int32 LastError;
                // Info stored for WSAAsyncSelect()
                public IntPtr AsyncSelecthWnd;
                public UInt32 AsyncSelectSerialNumber;
                public UInt32 AsyncSelectwMsg;
                public Int32 AsyncSelectlEvent;
                public Int32 DisabledAsyncSelectEvents;
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct SOCKADDR
            {
                public UInt16 sa_family;
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 14)]
                public byte[] sa_data;
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct SOCKET_CONTEXT
            {
                public SOCK_SHARED_INFO SharedData;
                public UInt32 SizeOfHelperData;
                public UInt32 Padding;
                public SOCKADDR LocalAddress;
                public SOCKADDR RemoteAddress;
                // Helper Data - found out with some reversing
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 24)]
                public byte[] HelperData;
            }

            private struct SOCKET_BYTESIN
            {
                public IntPtr handle;
                public UInt64 BytesIn;
            }


            [DllImport("WS2_32.DLL", CharSet = CharSet.Auto, SetLastError = true)]
            private static extern int WSADuplicateSocket(IntPtr socketHandle, int processId, ref WSAPROTOCOL_INFO pinnedBuffer);

            [DllImport("ws2_32.dll", CharSet = CharSet.Auto, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
            private static extern IntPtr WSASocket([In] int addressFamily, [In] int socketType, [In] int protocolType, ref WSAPROTOCOL_INFO lpProtocolInfo, Int32 group1, int dwFlags);

            //[DllImport("ws2_32.dll", CharSet = CharSet.Auto)]
            //private static extern Int32 WSAGetLastError();

            //[DllImport("ws2_32.dll", CharSet = CharSet.Auto, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
            //public static extern int getpeername(IntPtr s, ref SOCKADDR_IN name, ref int namelen);

            // WSAIoctl1 implementation specific for SIO_TCP_INFO control code
            [DllImport("Ws2_32.dll", CharSet = CharSet.Auto, SetLastError = true, EntryPoint = "WSAIoctl")]
            public static extern int WSAIoctl1(IntPtr s, int dwIoControlCode, ref UInt32 lpvInBuffer, int cbInBuffer, IntPtr lpvOutBuffer, int cbOutBuffer, ref int lpcbBytesReturned, IntPtr lpOverlapped, IntPtr lpCompletionRoutine);

            [DllImport("ws2_32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            public static extern int closesocket(IntPtr s);

            [DllImport("ws2_32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            public static extern int shutdown(IntPtr s, int how);

            [DllImport("kernel32.dll", SetLastError = true)]
            private static extern IntPtr OpenProcess(int processAccess, bool bInheritHandle, int processId);

            [DllImport("kernel32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            private static extern bool DuplicateHandle(IntPtr hSourceProcessHandle, IntPtr hSourceHandle, IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle, uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);

            [DllImport("kernel32.dll")]
            private static extern bool CloseHandle(IntPtr hObject);

            [DllImport("kernel32.dll")]
            private static extern IntPtr GetCurrentProcess();

            [DllImport("ntdll.dll")]
            private static extern uint NtQueryObject(IntPtr objectHandle, OBJECT_INFORMATION_CLASS informationClass, IntPtr informationPtr, uint informationLength, ref int returnLength);

            [DllImport("ntdll.dll")]
            private static extern uint NtQuerySystemInformation(int SystemInformationClass, IntPtr SystemInformation, int SystemInformationLength, ref int returnLength);

            //[DllImport("kernel32.dll", SetLastError = true)]
            //private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

            //[DllImport("ntdll.dll")]
            //private static extern int NtCreateEvent(ref IntPtr EventHandle, int DesiredAccess, IntPtr ObjectAttributes, int EventType, bool InitialState);

            // NtDeviceIoControlFile1 implementation specific for IOCTL_AFD_GET_CONTEXT IoControlCode
            //[DllImport("ntdll.dll", EntryPoint = "NtDeviceIoControlFile")]
            //private static extern int NtDeviceIoControlFile1(IntPtr FileHandle, IntPtr Event, IntPtr ApcRoutine, IntPtr ApcContext, ref IO_STATUS_BLOCK IoStatusBlock, uint IoControlCode, IntPtr InputBuffer, int InputBufferLength, ref SOCKET_CONTEXT OutputBuffer, int OutputBufferLength);


            //helper method with "dynamic" buffer allocation
            private static IntPtr NtQuerySystemInformationDynamic(int infoClass, int infoLength)
            {
                if (infoLength == 0)
                    infoLength = 0x10000;
                IntPtr infoPtr = Marshal.AllocHGlobal(infoLength);
                while (true)
                {
                    uint result = (uint)NtQuerySystemInformation(infoClass, infoPtr, infoLength, ref infoLength);
                    if (result == NTSTATUS_SUCCESS)
                        return infoPtr;
                    Marshal.FreeHGlobal(infoPtr);  //free pointer when not Successful
                    if (result != NTSTATUS_INFOLENGTHMISMATCH && result != NTSTATUS_BUFFEROVERFLOW && result != NTSTATUS_BUFFERTOOSMALL)
                    {
                        //throw new Exception("Unhandled NtStatus " + result);
                        return IntPtr.Zero;
                    }
                    infoPtr = Marshal.AllocHGlobal(infoLength);
                }
            }

            private static IntPtr QueryObjectTypesInfo()
            {
                IntPtr ptrObjectTypesInformation = IntPtr.Zero;
                ptrObjectTypesInformation = NtQueryObjectDynamic(IntPtr.Zero, OBJECT_INFORMATION_CLASS.ObjectAllTypesInformation, 0);
                return ptrObjectTypesInformation;
            }

            // this from --> https://github.com/hfiref0x/UACME/blob/master/Source/Shared/ntos.h
            private static long AlignUp(long address, long align)
            {
                return (((address) + (align) - 1) & ~((align) - 1));
            }

            // this works only from win8 and above. If you need a more generic solution you need to use the (i+2) "way" of counting index types.
            // credits for this goes to @0xrepnz
            // more information here --> https://twitter.com/splinter_code/status/1400873009121013765
            private static byte GetTypeIndexByName(string ObjectName)
            {
                byte TypeIndex = 0;
                long TypesCount = 0;
                IntPtr ptrTypesInfo = IntPtr.Zero;
                ptrTypesInfo = QueryObjectTypesInfo();
                TypesCount = Marshal.ReadIntPtr(ptrTypesInfo).ToInt64();
                // create a pointer to the first element address of OBJECT_TYPE_INFORMATION_V2
                IntPtr ptrTypesInfoCurrent = new IntPtr(ptrTypesInfo.ToInt64() + IntPtr.Size);
                for (int i = 0; i < TypesCount; i++)
                {
                    OBJECT_TYPE_INFORMATION_V2 Type = (OBJECT_TYPE_INFORMATION_V2)Marshal.PtrToStructure(ptrTypesInfoCurrent, typeof(OBJECT_TYPE_INFORMATION_V2));
                    // move pointer to next the OBJECT_TYPE_INFORMATION_V2 object
                    ptrTypesInfoCurrent = (IntPtr)(ptrTypesInfoCurrent.ToInt64() + AlignUp(Type.TypeName.MaximumLength, (long)IntPtr.Size) + Marshal.SizeOf(typeof(OBJECT_TYPE_INFORMATION_V2)));
                    if (Type.TypeName.Length > 0 && Marshal.PtrToStringUni(Type.TypeName.Buffer, Type.TypeName.Length / 2) == ObjectName)
                    {
                        TypeIndex = Type.TypeIndex;
                        break;
                    }
                }
                Marshal.FreeHGlobal(ptrTypesInfo);
                return TypeIndex;
            }

            private static List<IntPtr> DuplicateSocketsFromHandles(List<IntPtr> sockets)
            {
                List<IntPtr> dupedSocketsOut = new List<IntPtr>();
                if (sockets.Count < 1) return dupedSocketsOut;
                foreach (IntPtr sock in sockets)
                {
                    IntPtr dupedSocket = DuplicateSocketFromHandle(sock);
                    if (dupedSocket != IntPtr.Zero) dupedSocketsOut.Add(dupedSocket);
                }
                // cleaning all socket handles
                foreach (IntPtr sock in sockets)
                    CloseHandle(sock);
                return dupedSocketsOut;
            }

            public static List<IntPtr> FilterAndOrderSocketsByBytesIn(List<IntPtr> sockets)
            {
                List<SOCKET_BYTESIN> socketsBytesIn = new List<SOCKET_BYTESIN>();
                List<IntPtr> socketsOut = new List<IntPtr>();
                foreach (IntPtr sock in sockets)
                {
                    TCP_INFO_v0 sockInfo = new TCP_INFO_v0();
                    if (!GetSocketTcpInfo(sock, out sockInfo))
                    {
                        closesocket(sock);
                        continue;
                    }
                    // Console.WriteLine("debug: Socket handle 0x" + sock.ToString("X4") + " is in tcpstate " + sockInfo.State.ToString());
                    // we need only active sockets, the remaing sockets are filtered out
                    if (sockInfo.State == TcpState.SynReceived || sockInfo.State == TcpState.Established)
                    {
                        SOCKET_BYTESIN sockBytesIn = new SOCKET_BYTESIN();
                        sockBytesIn.handle = sock;
                        sockBytesIn.BytesIn = sockInfo.BytesIn;
                        socketsBytesIn.Add(sockBytesIn);
                    }
                    else
                        closesocket(sock);
                }
                if (socketsBytesIn.Count < 1) return socketsOut;
                if (socketsBytesIn.Count >= 2)
                    // ordering for fewer bytes received by the sockets we have a higher chance to get the proper socket
                    socketsBytesIn.Sort(delegate (SOCKET_BYTESIN a, SOCKET_BYTESIN b) { return (a.BytesIn.CompareTo(b.BytesIn)); });
                foreach (SOCKET_BYTESIN sockBytesIn in socketsBytesIn)
                {
                    socketsOut.Add(sockBytesIn.handle);
                    Debug.WriteLine("debug: Socket handle 0x" + sockBytesIn.handle.ToString("X4") + " total bytes received: " + sockBytesIn.BytesIn.ToString());
                }
                return socketsOut;
            }

            public static bool GetSocketTcpInfo(IntPtr socket, out TCP_INFO_v0 tcpInfoOut)
            {
                int result = -1;
                UInt32 tcpInfoVersion = 0;
                int bytesReturned = 0;
                int tcpInfoSize = Marshal.SizeOf(typeof(TCP_INFO_v0));
                IntPtr tcpInfoPtr = Marshal.AllocHGlobal(tcpInfoSize);
                result = WSAIoctl1(socket, SIO_TCP_INFO, ref tcpInfoVersion, Marshal.SizeOf(tcpInfoVersion), tcpInfoPtr, tcpInfoSize, ref bytesReturned, IntPtr.Zero, IntPtr.Zero);
                if (result != 0)
                {
                    // Console.WriteLine("debug: WSAIoctl1 failed with return code " + result.ToString() + " and wsalasterror: " + WSAGetLastError().ToString());
                    tcpInfoOut = new TCP_INFO_v0();
                    return false;
                }
                TCP_INFO_v0 tcpInfoV0 = (TCP_INFO_v0)Marshal.PtrToStructure(tcpInfoPtr, typeof(TCP_INFO_v0));
                tcpInfoOut = tcpInfoV0;
                Marshal.FreeHGlobal(tcpInfoPtr);
                return true;
            }

            // this function take a raw handle to a \Device\Afd object as a parameter and returns a handle to a duplicated socket
            private static IntPtr DuplicateSocketFromHandle(IntPtr socketHandle)
            {
                IntPtr retSocket = IntPtr.Zero;
                IntPtr duplicatedSocket = IntPtr.Zero;
                WSAPROTOCOL_INFO wsaProtocolInfo = new WSAPROTOCOL_INFO();
                int status = WSADuplicateSocket(socketHandle, Process.GetCurrentProcess().Id, ref wsaProtocolInfo);
                if (status == 0)
                {
                    // we need an overlapped socket for the conpty process but we don't need to specify the WSA_FLAG_OVERLAPPED flag here because it will be ignored (and automatically set) by WSASocket() function if we set the WSAPROTOCOL_INFO structure and if the original socket has been created with the overlapped flag.
                    duplicatedSocket = WSASocket(wsaProtocolInfo.iAddressFamily, wsaProtocolInfo.iSocketType, wsaProtocolInfo.iProtocol, ref wsaProtocolInfo, 0, 0);
                    if (duplicatedSocket.ToInt64() > 0)
                    {
                        retSocket = duplicatedSocket;
                    }
                }
                return retSocket;
            }

            //helper method with "dynamic" buffer allocation
            public static IntPtr NtQueryObjectDynamic(IntPtr handle, OBJECT_INFORMATION_CLASS infoClass, int infoLength)
            {
                if (infoLength == 0)
                    infoLength = Marshal.SizeOf(typeof(int));
                IntPtr infoPtr = Marshal.AllocHGlobal(infoLength);
                uint result;
                while (true)
                {
                    result = (uint)NtQueryObject(handle, infoClass, infoPtr, (uint)infoLength, ref infoLength);
                    if (result == NTSTATUS_INFOLENGTHMISMATCH || result == NTSTATUS_BUFFEROVERFLOW || result == NTSTATUS_BUFFERTOOSMALL)
                    {
                        Marshal.FreeHGlobal(infoPtr);
                        infoPtr = Marshal.AllocHGlobal((int)infoLength);
                        continue;
                    }
                    else if (result == NTSTATUS_SUCCESS)
                        break;
                    else
                    {
                        //throw new Exception("Unhandled NtStatus " + result);
                        break;
                    }
                }
                if (result == NTSTATUS_SUCCESS)
                    return infoPtr;//don't forget to free the pointer with Marshal.FreeHGlobal after you're done with it
                else
                    Marshal.FreeHGlobal(infoPtr);//free pointer when not Successful
                return IntPtr.Zero;
            }

            public static List<IntPtr> GetSocketsTargetProcess(Process targetProcess)
            {
                OBJECT_NAME_INFORMATION objNameInfo;
                long HandlesCount = 0;
                IntPtr dupHandle;
                IntPtr ptrObjectName;
                IntPtr ptrHandlesInfo;
                IntPtr hTargetProcess;
                string strObjectName;
                List<IntPtr> socketsHandles = new List<IntPtr>();
                DeadlockCheckHelper deadlockCheckHelperObj = new DeadlockCheckHelper();
                hTargetProcess = OpenProcess(PROCESS_DUP_HANDLE, false, targetProcess.Id);
                if (hTargetProcess == IntPtr.Zero)
                {
                    Console.WriteLine("Cannot open target process with pid " + targetProcess.Id.ToString() + " for DuplicateHandle access");
                    return socketsHandles;
                }
                ptrHandlesInfo = NtQuerySystemInformationDynamic(SystemHandleInformation, 0);
                HandlesCount = Marshal.ReadIntPtr(ptrHandlesInfo).ToInt64();
                // create a pointer at the beginning of the address of SYSTEM_HANDLE_TABLE_ENTRY_INFO[]
                IntPtr ptrHandlesInfoCurrent = new IntPtr(ptrHandlesInfo.ToInt64() + IntPtr.Size);
                // get TypeIndex for "File" objects, needed to filter only sockets objects
                byte TypeIndexFileObject = GetTypeIndexByName("File");
                for (int i = 0; i < HandlesCount; i++)
                {
                    SYSTEM_HANDLE_TABLE_ENTRY_INFO sysHandle;
                    try
                    {
                        sysHandle = (SYSTEM_HANDLE_TABLE_ENTRY_INFO)Marshal.PtrToStructure(ptrHandlesInfoCurrent, typeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO));
                    }
                    catch
                    {
                        break;
                    }
                    //move pointer to next SYSTEM_HANDLE_TABLE_ENTRY_INFO
                    ptrHandlesInfoCurrent = (IntPtr)(ptrHandlesInfoCurrent.ToInt64() + Marshal.SizeOf(typeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO)));
                    if (sysHandle.UniqueProcessId != targetProcess.Id || sysHandle.ObjectTypeIndex != TypeIndexFileObject)
                        continue;
                    if (DuplicateHandle(hTargetProcess, (IntPtr)sysHandle.HandleValue, GetCurrentProcess(), out dupHandle, 0, false, DUPLICATE_SAME_ACCESS))
                    {
                        if (deadlockCheckHelperObj.CheckDeadlockDetected(dupHandle))
                        { // this will avoids deadlocks on special named pipe handles
                          // Console.WriteLine("debug: Deadlock detected");
                            CloseHandle(dupHandle);
                            continue;
                        }
                        ptrObjectName = NtQueryObjectDynamic(dupHandle, OBJECT_INFORMATION_CLASS.ObjectNameInformation, 0);
                        if (ptrObjectName == IntPtr.Zero)
                        {
                            CloseHandle(dupHandle);
                            continue;
                        }
                        try
                        {
                            objNameInfo = (OBJECT_NAME_INFORMATION)Marshal.PtrToStructure(ptrObjectName, typeof(OBJECT_NAME_INFORMATION));
                        }
                        catch
                        {
                            continue;
                        }
                        if (objNameInfo.Name.Buffer != IntPtr.Zero && objNameInfo.Name.Length > 0)
                        {
                            strObjectName = Marshal.PtrToStringUni(objNameInfo.Name.Buffer, objNameInfo.Name.Length / 2);
                            // Console.WriteLine("debug: strObjectName " + strObjectName);
                            if (strObjectName == "\\Device\\Afd")
                                socketsHandles.Add(dupHandle);
                            else
                                CloseHandle(dupHandle);
                        }
                        else
                            CloseHandle(dupHandle);
                        Marshal.FreeHGlobal(ptrObjectName);
                        ptrObjectName = IntPtr.Zero;
                    }
                }
                Marshal.FreeHGlobal(ptrHandlesInfo);
                List<IntPtr> dupedSocketsHandles = DuplicateSocketsFromHandles(socketsHandles);
                if (dupedSocketsHandles.Count >= 1)
                    dupedSocketsHandles = FilterAndOrderSocketsByBytesIn(dupedSocketsHandles);
                socketsHandles = dupedSocketsHandles;
                return socketsHandles;
            }

            //public static bool IsSocketInherited(IntPtr socketHandle, Process parentProcess)
            //{
            //    bool inherited = false;
            //    List<IntPtr> parentSocketsHandles = GetSocketsTargetProcess(parentProcess);
            //    if (parentSocketsHandles.Count < 1)
            //        return inherited;
            //    foreach (IntPtr parentSocketHandle in parentSocketsHandles)
            //    {
            //        SOCKADDR_IN sockaddrTargetProcess = new SOCKADDR_IN();
            //        SOCKADDR_IN sockaddrParentProcess = new SOCKADDR_IN();
            //        int sockaddrTargetProcessLen = Marshal.SizeOf(sockaddrTargetProcess);
            //        int sockaddrParentProcessLen = Marshal.SizeOf(sockaddrParentProcess);
            //        if (
            //            (getpeername(socketHandle, ref sockaddrTargetProcess, ref sockaddrTargetProcessLen) == 0) &&
            //            (getpeername(parentSocketHandle, ref sockaddrParentProcess, ref sockaddrParentProcessLen) == 0) &&
            //            (sockaddrTargetProcess.sin_addr == sockaddrParentProcess.sin_addr && sockaddrTargetProcess.sin_port == sockaddrParentProcess.sin_port)
            //           )
            //        {
            //            // Console.WriteLine("debug: found inherited socket! handle --> 0x" + parentSocketHandle.ToString("X4"));
            //            inherited = true;
            //            closesocket(parentSocketHandle);
            //            break;
            //        }
            //        closesocket(parentSocketHandle);
            //    }
            //    return inherited;
            //}

            //public static bool IsSocketOverlapped(IntPtr socket)
            //{
            //    bool ret = false;
            //    IntPtr sockEvent = IntPtr.Zero;
            //    int ntStatus = -1;
            //    SOCKET_CONTEXT contextData = new SOCKET_CONTEXT();
            //    ntStatus = NtCreateEvent(ref sockEvent, EVENT_ALL_ACCESS, IntPtr.Zero, SynchronizationEvent, false);
            //    if (ntStatus != NTSTATUS_SUCCESS)
            //    {
            //        // Console.WriteLine("debug: NtCreateEvent failed with error code 0x" + ntStatus.ToString("X8")); ;
            //        return ret;
            //    }
            //    IO_STATUS_BLOCK IOSB = new IO_STATUS_BLOCK();
            //    ntStatus = NtDeviceIoControlFile1(socket, sockEvent, IntPtr.Zero, IntPtr.Zero, ref IOSB, IOCTL_AFD_GET_CONTEXT, IntPtr.Zero, 0, ref contextData, Marshal.SizeOf(contextData));
            //    // Wait for Completion 
            //    if (ntStatus == NTSTATUS_PENDING)
            //    {
            //        WaitForSingleObject(sockEvent, INFINITE);
            //        ntStatus = IOSB.status;
            //    }
            //    CloseHandle(sockEvent);

            //    if (ntStatus != NTSTATUS_SUCCESS)
            //    {
            //        // Console.WriteLine("debug: NtDeviceIoControlFile failed with error code 0x" + ntStatus.ToString("X8")); ;
            //        return ret;
            //    }
            //    if ((contextData.SharedData.CreationFlags & WSA_FLAG_OVERLAPPED) != 0) ret = true;
            //    return ret;
            //}

            //public static IntPtr DuplicateTargetProcessSocket(Process targetProcess)
            //{
            //    IntPtr targetSocketHandle = IntPtr.Zero;
            //    List<IntPtr> targetProcessSockets = GetSocketsTargetProcess(targetProcess);
            //    if (targetProcessSockets.Count < 1) return targetSocketHandle;
            //    else
            //    {
            //        foreach (IntPtr socketHandle in targetProcessSockets)
            //        {
            //            if (!IsSocketOverlapped(socketHandle))
            //            {
            //                Console.WriteLine("Found a usable socket, but it has not been created with the flag WSA_FLAG_OVERLAPPED, skipping...");
            //                closesocket(socketHandle);
            //                continue;
            //            }
            //            targetSocketHandle = socketHandle;
            //            break;
            //        }
            //    }
            //    if (targetSocketHandle == IntPtr.Zero)
            //        throw new ConPtyShellException("No overlapped sockets found, so no hijackable sockets found :( Exiting...");
            //    return targetSocketHandle;
            //}
        }
      
    }
}
