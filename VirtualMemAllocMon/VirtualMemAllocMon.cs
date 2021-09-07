using System;
using System.Collections.Generic;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Diagnostics.Tracing.Parsers;

namespace VirtualMemAllocMon
{

    class Program
    {
     
        [DllImport("kernelbase.dll")]
        public static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, bool bInheritHandle, Int32 dwProcessId);

        [DllImport("kernelbase.dll")]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern NtStatus NtReadVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, UInt32 NumberOfBytesToRead, ref UInt32 NumberOfBytesRead);

        //[DllImport("kernelbase.dll")]
        //public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

        //[DllImport("kernel32.dll", SetLastError = true)]
        //public static extern bool ReadProcessMemory(IntPtr hProcess, uint lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, IntPtr lpNumberOfBytesRead);

        //[DllImport("kernel32.dll", SetLastError = true)]
        //public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, IntPtr lpNumberOfBytesRead);

        public static bool VaxFound, BytesFound = false;
        public static bool initdotmemoalloc = false;
        public static string ETW_VAx_Event_RealtimeChangedStrings = string.Empty;
        public static string dumpmem,tempMemAllocInfo, tempETWdetails, templastinfo = "";
        public static Int32 tempPIDMemoAlloca,_v1;        
        public static int result = 0;
        public static UInt32 temp;
        public static string[] Flag_to_detection_VAx = new string[5];
        public static string[] Flag_to_detection_Bytes = new string[4];
        public static byte[] buf = new byte[208];
        public static event EventHandler _Event_VirtualMemAlloc_etw_evt;
        public static System.Threading.Thread Bingo;

        public static bool _SearchVAxEvents(string input_to_search)
        {

            VaxFound = false;
            foreach (string item in Flag_to_detection_VAx)
            {
                if (input_to_search.Contains(item))
                {
                    VaxFound = true;
                    break;
                }
            }
            return VaxFound;
        }
        public static int _SearchBytes(string input_to_search)
        {
            int count = 0;
            BytesFound = false;
            foreach (string item in Flag_to_detection_Bytes)
            {
                if (input_to_search.Contains(item))
                {
                    BytesFound = true;
                    count++;
                    if (count >= 4) break;
                }
            }
            return count;
        }
        public static void _ShowDetailsBytes(string RealtimeChangedStrings)
        {
            try
            {

                Flag_to_detection_Bytes[0] = "is program canno";
                Flag_to_detection_Bytes[1] = "t be run in DOS";
                Flag_to_detection_Bytes[2] = "00000000   4D 5A 41";
                Flag_to_detection_Bytes[3] = "00000000   4D 5A";
                Console.ForegroundColor = ConsoleColor.DarkGreen;
                Console.WriteLine(RealtimeChangedStrings);

                string _ProcessName = System.Diagnostics.Process.GetProcessById((int)Convert.ToInt32(RealtimeChangedStrings.Split('(')[1].Split(')')[0])).MainModule.FileName;
                string __PID = RealtimeChangedStrings.Split('(')[1].Split(')')[0];

                IntPtr ph = OpenProcess(ProcessAccessFlags.All, false, Convert.ToInt32(RealtimeChangedStrings.Split('(')[1].Split(')')[0]));

                temp = 0;
                NtReadVirtualMemory(ph, ((IntPtr)Convert.ToUInt64(RealtimeChangedStrings.Split(':')[4])), buf, (uint)buf.Length, ref temp);

                Console.ForegroundColor = ConsoleColor.Gray;
                Console.WriteLine("[{2}] Something Detected, VirtualMemAlloc Memory Address {0} in Process: {1} with PID: {3} ", RealtimeChangedStrings.Split(':')[4], _ProcessName, DateTime.Now, __PID);

                dumpmem = HexDump(buf);

                result = _SearchBytes(dumpmem);

                if (result > 0)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("[!] Found {0} of 4", result.ToString());
                    Console.WriteLine(dumpmem);
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.DarkYellow;
                    Console.WriteLine("[!] Found {0} of 4", result.ToString());
                    Console.WriteLine(dumpmem);
                }
                CloseHandle(ph);
            }
            catch (Exception error)
            {
                Console.WriteLine(error.Message);
               
            }
        }
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
            return UTF8Encoding.UTF8.GetString(UTF8Encoding.UTF8.GetBytes(result.ToString()));

            // return result.ToString();
        }


        private static void Program__Event_VirtualMemAlloc_etw_evt(object sender, EventArgs e)
        {

            string ETW_VAx_Event_RealtimeChangedStrings = sender.ToString();

            if (_SearchVAxEvents(ETW_VAx_Event_RealtimeChangedStrings))
            {

                if (ETW_VAx_Event_RealtimeChangedStrings.Contains("[Injected by "))
                { Console.ForegroundColor = ConsoleColor.DarkYellow; }
                else
                { Console.ForegroundColor = ConsoleColor.Green; }

                _ShowDetailsBytes(ETW_VAx_Event_RealtimeChangedStrings);
            }
            else
            {

            }

        }

        public static void ETWCoreI()
        {
            using (var KS = new TraceEventSession(KernelTraceEventParser.KernelSessionName))
            {
                Console.CancelKeyPress += delegate (object s, ConsoleCancelEventArgs e) { KS.Dispose(); };

                KS.EnableKernelProvider(KernelTraceEventParser.Keywords.VirtualAlloc          
                // | KernelTraceEventParser.Keywords.ImageLoad
                 );

               
                KS.Source.Kernel.MemoryVirtualAllocDCStart += Kernel_MemoryVirtualAllocDCStart; 
                KS.Source.Kernel.VirtualMemAlloc += Kernel_VirtualMemAlloc; 

                //KS.Source.Kernel.ImageLoad += Kernel_ImageLoad;

                KS.Source.Process();
               
            }
        }

        private static void Kernel_VirtualMemAlloc(Microsoft.Diagnostics.Tracing.Parsers.Kernel.VirtualAllocTraceData obj)
        {
            // GC.Collect();
            tempMemAllocInfo = "";
            tempPIDMemoAlloca = 0;

                    if ((!initdotmemoalloc) && (tempPIDMemoAlloca != obj.ProcessID))
                    {

                        initdotmemoalloc = true;
                    }

                _v1 = 0;
                if (obj.ProcessID != tempPIDMemoAlloca)
                {
                    initdotmemoalloc = false;
                    foreach (var item in obj.PayloadNames)
                    {

                        tempMemAllocInfo += "[" + item + ": " + obj.PayloadValue(_v1).ToString() + "]";
                        tempETWdetails += ":" + obj.PayloadValue(_v1).ToString();

                        _v1++;
                    }
                    tempPIDMemoAlloca = obj.ProcessID;
                    if (templastinfo != tempMemAllocInfo)
                    {
                        templastinfo = tempMemAllocInfo;

                    _Event_VirtualMemAlloc_etw_evt.Invoke((object)("[" + obj.TimeStamp.ToString() + "] PID:(" + obj.ProcessID +
                            ") TID(" + obj.ThreadID + ") " + tempETWdetails + " [VirtualMemAlloc]"), null);
                    }

                    tempETWdetails = "";

                }
   
        }

        private static void Kernel_MemoryVirtualAllocDCStart(Microsoft.Diagnostics.Tracing.EmptyTraceData obj)
        {
            // GC.Collect();
            tempMemAllocInfo = "";
            tempPIDMemoAlloca = 0;

            if ((!initdotmemoalloc) && (tempPIDMemoAlloca != obj.ProcessID))
            {
                initdotmemoalloc = true;
            }

            _v1 = 0;
            if (obj.ProcessID != tempPIDMemoAlloca)
            {
                /////Console.WriteLine();
                initdotmemoalloc = false;
                foreach (var item in obj.PayloadNames)
                {

                    tempMemAllocInfo += "[" + item + ": " + obj.PayloadValue(_v1).ToString() + "]";
                    tempETWdetails += ":" + obj.PayloadValue(_v1).ToString();

                    _v1++;
                }
                tempPIDMemoAlloca = obj.ProcessID;
                if (templastinfo != tempMemAllocInfo)
                {
                    templastinfo = tempMemAllocInfo;

                    _Event_VirtualMemAlloc_etw_evt.Invoke((object)("[" + obj.TimeStamp.ToString() + "] PID:(" + obj.ProcessID +
                            ") TID(" + obj.ThreadID + ") " + tempETWdetails + " [VirtualMemAlloc]"), null);
                }

                tempETWdetails = "";

            }
        }

        static void Main(string[] args)
        {

            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("VirtualMemAllocMon v1.1 Tool , Published by Damon Mohammadbagher , Jun-Jul 2021");
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine("VirtualMemAllocMon, ETW VirtualMemAlloc Events Realtime Monitor tool (Payload Detection by ETW Events)");
            Console.WriteLine();
            Thread.Sleep(1000);

            /// x64 payloads/events (only)
            /// note: for x86 payloads your x86 payloads will have new sizes...
            Flag_to_detection_VAx[0] = ":434176:MEM_COMMIT, MEM_RESERVE:";
            Flag_to_detection_VAx[1] = ":155648:MEM_COMMIT, MEM_RESERVE:";
            Flag_to_detection_VAx[2] = ":200704:MEM_COMMIT, MEM_RESERVE:";
            Flag_to_detection_VAx[3] = ":233472:MEM_COMMIT, MEM_RESERVE:";
            ///
            Flag_to_detection_VAx[4] = "[Injected by ";


            Thread.Sleep(250);

            _Event_VirtualMemAlloc_etw_evt += Program__Event_VirtualMemAlloc_etw_evt;

                
            if (args.Length > 0 && args[0].ToLower() == "help")
            {
                Console.WriteLine("Syntax: VirtualMemAllocMon.exe ");
                Console.WriteLine("Description: VirtualMemAllocMon.exe will monitor all VirtualMemAlloc ETW Events for All Processes");
              
                Console.WriteLine();
            }
            else
            {
                Bingo = new System.Threading.Thread(ETWCoreI)
                {
                    Priority = System.Threading.ThreadPriority.AboveNormal
                };
                Bingo.Start();
                Thread.Sleep(1000);

                GC.GetTotalMemory(true);
            }

        }

        [Flags]
        public enum ProcessAccessFlags : uint
        {
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VMOperation = 0x00000008,
            VMRead = 0x00000010,
            VMWrite = 0x00000020,
            DupHandle = 0x00000040,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            Synchronize = 0x00100000,
            All = 0x001F0FFF
        }
        [Flags]
        public enum AllocationType
        {
            Commit = 0x00001000,
            Reserve = 0x00002000,
            Decommit = 0x00004000,
            Release = 0x00008000,
            Reset = 0x00080000,
            TopDown = 0x00100000,
            WriteWatch = 0x00200000,
            Physical = 0x00400000,
            LargePages = 0x20000000
        }
        [Flags]
        public enum MemoryProtection
        {
            NoAccess = 0x0001,
            ReadOnly = 0x0002,
            ReadWrite = 0x0004,
            WriteCopy = 0x0008,
            Execute = 0x0010,
            ExecuteRead = 0x0020,
            ExecuteReadWrite = 0x0040,
            ExecuteWriteCopy = 0x0080,
            GuardModifierflag = 0x0100,
            NoCacheModifierflag = 0x0200,
            WriteCombineModifierflag = 0x0400
        }
        [Flags]
        public enum ThreadAccess : int
        {
            Terminate = 0x0001,
            SuspendResume = 0x0002,
            GetContext = 0x0008,
            SetContext = 0x0010,
            SetInformation = 0x0020,
            QueryInformation = 0x0040,
            SetThreadToken = 0x0080,
            Impersonate = 0x0100,
            DirectImpersonation = 0x0200
        }
        public enum NtStatus : uint
        {

            // Success
            Success = 0x00000000,
            Wait0 = 0x00000000,
            Wait1 = 0x00000001,
            Wait2 = 0x00000002,
            Wait3 = 0x00000003,
            Wait63 = 0x0000003f,
            Abandoned = 0x00000080,
            AbandonedWait0 = 0x00000080,
            AbandonedWait1 = 0x00000081,
            AbandonedWait2 = 0x00000082,
            AbandonedWait3 = 0x00000083,
            AbandonedWait63 = 0x000000bf,
            UserApc = 0x000000c0,
            KernelApc = 0x00000100,
            Alerted = 0x00000101,
            Timeout = 0x00000102,
            Pending = 0x00000103,
            Reparse = 0x00000104,
            MoreEntries = 0x00000105,
            NotAllAssigned = 0x00000106,
            SomeNotMapped = 0x00000107,
            OpLockBreakInProgress = 0x00000108,
            VolumeMounted = 0x00000109,
            RxActCommitted = 0x0000010a,
            NotifyCleanup = 0x0000010b,
            NotifyEnumDir = 0x0000010c,
            NoQuotasForAccount = 0x0000010d,
            PrimaryTransportConnectFailed = 0x0000010e,
            PageFaultTransition = 0x00000110,
            PageFaultDemandZero = 0x00000111,
            PageFaultCopyOnWrite = 0x00000112,
            PageFaultGuardPage = 0x00000113,
            PageFaultPagingFile = 0x00000114,
            CrashDump = 0x00000116,
            ReparseObject = 0x00000118,
            NothingToTerminate = 0x00000122,
            ProcessNotInJob = 0x00000123,
            ProcessInJob = 0x00000124,
            ProcessCloned = 0x00000129,
            FileLockedWithOnlyReaders = 0x0000012a,
            FileLockedWithWriters = 0x0000012b,

            // Informational
            Informational = 0x40000000,
            ObjectNameExists = 0x40000000,
            ThreadWasSuspended = 0x40000001,
            WorkingSetLimitRange = 0x40000002,
            ImageNotAtBase = 0x40000003,
            RegistryRecovered = 0x40000009,

            // Warning
            Warning = 0x80000000,
            GuardPageViolation = 0x80000001,
            DatatypeMisalignment = 0x80000002,
            Breakpoint = 0x80000003,
            SingleStep = 0x80000004,
            BufferOverflow = 0x80000005,
            NoMoreFiles = 0x80000006,
            HandlesClosed = 0x8000000a,
            PartialCopy = 0x8000000d,
            DeviceBusy = 0x80000011,
            InvalidEaName = 0x80000013,
            EaListInconsistent = 0x80000014,
            NoMoreEntries = 0x8000001a,
            LongJump = 0x80000026,
            DllMightBeInsecure = 0x8000002b,

            // Error
            Error = 0xc0000000,
            Unsuccessful = 0xc0000001,
            NotImplemented = 0xc0000002,
            InvalidInfoClass = 0xc0000003,
            InfoLengthMismatch = 0xc0000004,
            AccessViolation = 0xc0000005,
            InPageError = 0xc0000006,
            PagefileQuota = 0xc0000007,
            InvalidHandle = 0xc0000008,
            BadInitialStack = 0xc0000009,
            BadInitialPc = 0xc000000a,
            InvalidCid = 0xc000000b,
            TimerNotCanceled = 0xc000000c,
            InvalidParameter = 0xc000000d,
            NoSuchDevice = 0xc000000e,
            NoSuchFile = 0xc000000f,
            InvalidDeviceRequest = 0xc0000010,
            EndOfFile = 0xc0000011,
            WrongVolume = 0xc0000012,
            NoMediaInDevice = 0xc0000013,
            NoMemory = 0xc0000017,
            NotMappedView = 0xc0000019,
            UnableToFreeVm = 0xc000001a,
            UnableToDeleteSection = 0xc000001b,
            IllegalInstruction = 0xc000001d,
            AlreadyCommitted = 0xc0000021,
            AccessDenied = 0xc0000022,
            BufferTooSmall = 0xc0000023,
            ObjectTypeMismatch = 0xc0000024,
            NonContinuableException = 0xc0000025,
            BadStack = 0xc0000028,
            NotLocked = 0xc000002a,
            NotCommitted = 0xc000002d,
            InvalidParameterMix = 0xc0000030,
            ObjectNameInvalid = 0xc0000033,
            ObjectNameNotFound = 0xc0000034,
            ObjectNameCollision = 0xc0000035,
            ObjectPathInvalid = 0xc0000039,
            ObjectPathNotFound = 0xc000003a,
            ObjectPathSyntaxBad = 0xc000003b,
            DataOverrun = 0xc000003c,
            DataLate = 0xc000003d,
            DataError = 0xc000003e,
            CrcError = 0xc000003f,
            SectionTooBig = 0xc0000040,
            PortConnectionRefused = 0xc0000041,
            InvalidPortHandle = 0xc0000042,
            SharingViolation = 0xc0000043,
            QuotaExceeded = 0xc0000044,
            InvalidPageProtection = 0xc0000045,
            MutantNotOwned = 0xc0000046,
            SemaphoreLimitExceeded = 0xc0000047,
            PortAlreadySet = 0xc0000048,
            SectionNotImage = 0xc0000049,
            SuspendCountExceeded = 0xc000004a,
            ThreadIsTerminating = 0xc000004b,
            BadWorkingSetLimit = 0xc000004c,
            IncompatibleFileMap = 0xc000004d,
            SectionProtection = 0xc000004e,
            EasNotSupported = 0xc000004f,
            EaTooLarge = 0xc0000050,
            NonExistentEaEntry = 0xc0000051,
            NoEasOnFile = 0xc0000052,
            EaCorruptError = 0xc0000053,
            FileLockConflict = 0xc0000054,
            LockNotGranted = 0xc0000055,
            DeletePending = 0xc0000056,
            CtlFileNotSupported = 0xc0000057,
            UnknownRevision = 0xc0000058,
            RevisionMismatch = 0xc0000059,
            InvalidOwner = 0xc000005a,
            InvalidPrimaryGroup = 0xc000005b,
            NoImpersonationToken = 0xc000005c,
            CantDisableMandatory = 0xc000005d,
            NoLogonServers = 0xc000005e,
            NoSuchLogonSession = 0xc000005f,
            NoSuchPrivilege = 0xc0000060,
            PrivilegeNotHeld = 0xc0000061,
            InvalidAccountName = 0xc0000062,
            UserExists = 0xc0000063,
            NoSuchUser = 0xc0000064,
            GroupExists = 0xc0000065,
            NoSuchGroup = 0xc0000066,
            MemberInGroup = 0xc0000067,
            MemberNotInGroup = 0xc0000068,
            LastAdmin = 0xc0000069,
            WrongPassword = 0xc000006a,
            IllFormedPassword = 0xc000006b,
            PasswordRestriction = 0xc000006c,
            LogonFailure = 0xc000006d,
            AccountRestriction = 0xc000006e,
            InvalidLogonHours = 0xc000006f,
            InvalidWorkstation = 0xc0000070,
            PasswordExpired = 0xc0000071,
            AccountDisabled = 0xc0000072,
            NoneMapped = 0xc0000073,
            TooManyLuidsRequested = 0xc0000074,
            LuidsExhausted = 0xc0000075,
            InvalidSubAuthority = 0xc0000076,
            InvalidAcl = 0xc0000077,
            InvalidSid = 0xc0000078,
            InvalidSecurityDescr = 0xc0000079,
            ProcedureNotFound = 0xc000007a,
            InvalidImageFormat = 0xc000007b,
            NoToken = 0xc000007c,
            BadInheritanceAcl = 0xc000007d,
            RangeNotLocked = 0xc000007e,
            DiskFull = 0xc000007f,
            ServerDisabled = 0xc0000080,
            ServerNotDisabled = 0xc0000081,
            TooManyGuidsRequested = 0xc0000082,
            GuidsExhausted = 0xc0000083,
            InvalidIdAuthority = 0xc0000084,
            AgentsExhausted = 0xc0000085,
            InvalidVolumeLabel = 0xc0000086,
            SectionNotExtended = 0xc0000087,
            NotMappedData = 0xc0000088,
            ResourceDataNotFound = 0xc0000089,
            ResourceTypeNotFound = 0xc000008a,
            ResourceNameNotFound = 0xc000008b,
            ArrayBoundsExceeded = 0xc000008c,
            FloatDenormalOperand = 0xc000008d,
            FloatDivideByZero = 0xc000008e,
            FloatInexactResult = 0xc000008f,
            FloatInvalidOperation = 0xc0000090,
            FloatOverflow = 0xc0000091,
            FloatStackCheck = 0xc0000092,
            FloatUnderflow = 0xc0000093,
            IntegerDivideByZero = 0xc0000094,
            IntegerOverflow = 0xc0000095,
            PrivilegedInstruction = 0xc0000096,
            TooManyPagingFiles = 0xc0000097,
            FileInvalid = 0xc0000098,
            InstanceNotAvailable = 0xc00000ab,
            PipeNotAvailable = 0xc00000ac,
            InvalidPipeState = 0xc00000ad,
            PipeBusy = 0xc00000ae,
            IllegalFunction = 0xc00000af,
            PipeDisconnected = 0xc00000b0,
            PipeClosing = 0xc00000b1,
            PipeConnected = 0xc00000b2,
            PipeListening = 0xc00000b3,
            InvalidReadMode = 0xc00000b4,
            IoTimeout = 0xc00000b5,
            FileForcedClosed = 0xc00000b6,
            ProfilingNotStarted = 0xc00000b7,
            ProfilingNotStopped = 0xc00000b8,
            NotSameDevice = 0xc00000d4,
            FileRenamed = 0xc00000d5,
            CantWait = 0xc00000d8,
            PipeEmpty = 0xc00000d9,
            CantTerminateSelf = 0xc00000db,
            InternalError = 0xc00000e5,
            InvalidParameter1 = 0xc00000ef,
            InvalidParameter2 = 0xc00000f0,
            InvalidParameter3 = 0xc00000f1,
            InvalidParameter4 = 0xc00000f2,
            InvalidParameter5 = 0xc00000f3,
            InvalidParameter6 = 0xc00000f4,
            InvalidParameter7 = 0xc00000f5,
            InvalidParameter8 = 0xc00000f6,
            InvalidParameter9 = 0xc00000f7,
            InvalidParameter10 = 0xc00000f8,
            InvalidParameter11 = 0xc00000f9,
            InvalidParameter12 = 0xc00000fa,
            MappedFileSizeZero = 0xc000011e,
            TooManyOpenedFiles = 0xc000011f,
            Cancelled = 0xc0000120,
            CannotDelete = 0xc0000121,
            InvalidComputerName = 0xc0000122,
            FileDeleted = 0xc0000123,
            SpecialAccount = 0xc0000124,
            SpecialGroup = 0xc0000125,
            SpecialUser = 0xc0000126,
            MembersPrimaryGroup = 0xc0000127,
            FileClosed = 0xc0000128,
            TooManyThreads = 0xc0000129,
            ThreadNotInProcess = 0xc000012a,
            TokenAlreadyInUse = 0xc000012b,
            PagefileQuotaExceeded = 0xc000012c,
            CommitmentLimit = 0xc000012d,
            InvalidImageLeFormat = 0xc000012e,
            InvalidImageNotMz = 0xc000012f,
            InvalidImageProtect = 0xc0000130,
            InvalidImageWin16 = 0xc0000131,
            LogonServer = 0xc0000132,
            DifferenceAtDc = 0xc0000133,
            SynchronizationRequired = 0xc0000134,
            DllNotFound = 0xc0000135,
            IoPrivilegeFailed = 0xc0000137,
            OrdinalNotFound = 0xc0000138,
            EntryPointNotFound = 0xc0000139,
            ControlCExit = 0xc000013a,
            PortNotSet = 0xc0000353,
            DebuggerInactive = 0xc0000354,
            CallbackBypass = 0xc0000503,
            PortClosed = 0xc0000700,
            MessageLost = 0xc0000701,
            InvalidMessage = 0xc0000702,
            RequestCanceled = 0xc0000703,
            RecursiveDispatch = 0xc0000704,
            LpcReceiveBufferExpected = 0xc0000705,
            LpcInvalidConnectionUsage = 0xc0000706,
            LpcRequestsNotAllowed = 0xc0000707,
            ResourceInUse = 0xc0000708,
            ProcessIsProtected = 0xc0000712,
            VolumeDirty = 0xc0000806,
            FileCheckedOut = 0xc0000901,
            CheckOutRequired = 0xc0000902,
            BadFileType = 0xc0000903,
            FileTooLarge = 0xc0000904,
            FormsAuthRequired = 0xc0000905,
            VirusInfected = 0xc0000906,
            VirusDeleted = 0xc0000907,
            TransactionalConflict = 0xc0190001,
            InvalidTransaction = 0xc0190002,
            TransactionNotActive = 0xc0190003,
            TmInitializationFailed = 0xc0190004,
            RmNotActive = 0xc0190005,
            RmMetadataCorrupt = 0xc0190006,
            TransactionNotJoined = 0xc0190007,
            DirectoryNotRm = 0xc0190008,
            CouldNotResizeLog = 0xc0190009,
            TransactionsUnsupportedRemote = 0xc019000a,
            LogResizeInvalidSize = 0xc019000b,
            RemoteFileVersionMismatch = 0xc019000c,
            CrmProtocolAlreadyExists = 0xc019000f,
            TransactionPropagationFailed = 0xc0190010,
            CrmProtocolNotFound = 0xc0190011,
            TransactionSuperiorExists = 0xc0190012,
            TransactionRequestNotValid = 0xc0190013,
            TransactionNotRequested = 0xc0190014,
            TransactionAlreadyAborted = 0xc0190015,
            TransactionAlreadyCommitted = 0xc0190016,
            TransactionInvalidMarshallBuffer = 0xc0190017,
            CurrentTransactionNotValid = 0xc0190018,
            LogGrowthFailed = 0xc0190019,
            ObjectNoLongerExists = 0xc0190021,
            StreamMiniversionNotFound = 0xc0190022,
            StreamMiniversionNotValid = 0xc0190023,
            MiniversionInaccessibleFromSpecifiedTransaction = 0xc0190024,
            CantOpenMiniversionWithModifyIntent = 0xc0190025,
            CantCreateMoreStreamMiniversions = 0xc0190026,
            HandleNoLongerValid = 0xc0190028,
            NoTxfMetadata = 0xc0190029,
            LogCorruptionDetected = 0xc0190030,
            CantRecoverWithHandleOpen = 0xc0190031,
            RmDisconnected = 0xc0190032,
            EnlistmentNotSuperior = 0xc0190033,
            RecoveryNotNeeded = 0xc0190034,
            RmAlreadyStarted = 0xc0190035,
            FileIdentityNotPersistent = 0xc0190036,
            CantBreakTransactionalDependency = 0xc0190037,
            CantCrossRmBoundary = 0xc0190038,
            TxfDirNotEmpty = 0xc0190039,
            IndoubtTransactionsExist = 0xc019003a,
            TmVolatile = 0xc019003b,
            RollbackTimerExpired = 0xc019003c,
            TxfAttributeCorrupt = 0xc019003d,
            EfsNotAllowedInTransaction = 0xc019003e,
            TransactionalOpenNotAllowed = 0xc019003f,
            TransactedMappingUnsupportedRemote = 0xc0190040,
            TxfMetadataAlreadyPresent = 0xc0190041,
            TransactionScopeCallbacksNotSet = 0xc0190042,
            TransactionRequiredPromotion = 0xc0190043,
            CannotExecuteFileInTransaction = 0xc0190044,
            TransactionsNotFrozen = 0xc0190045,

            MaximumNtStatus = 0xffffffff
        }
        public enum ThreadInfoClass : int
        {
            ThreadQuerySetWin32StartAddress = 9
        }
    }
}
