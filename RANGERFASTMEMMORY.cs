using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace RANGER
{
    public class RANGERFASTMEMMORY
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, IntPtr nSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, IntPtr nSize, IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll")]
        public static extern int ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll")]
        public static extern int CloseHandle(IntPtr hObject);

        public struct PatternData
        {
            public byte[] pattern { get; set; }
            public byte[] mask { get; set; }
        }

        public struct MemoryPage
        {
            public IntPtr Start;
            public int Size;

            public MemoryPage(IntPtr start, int size)
            {
                Start = start;
                Size = size;
            }
        }

        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public UIntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        public bool isPrivate;
        public int processId;
        public IntPtr _processHandle;

        private bool _enableCheck = true;

        public const uint MEM_COMMIT = 4096u;
        public const uint MEM_PRIVATE = 131072u;
        public const uint PAGE_READWRITE = 4u;

        public bool SetProcess(string[] processNames)
        {
            processId = 0;
            Process[] processes = Process.GetProcesses();
            foreach (Process process in processes)
            {
                string processName = process.ProcessName;
                if (Array.Exists(processNames, (string name) => name.Equals(processName, StringComparison.CurrentCultureIgnoreCase)))
                {
                    processId = process.Id;
                    break;
                }
            }
            if (processId <= 0)
            {
                return false;
            }

            if (_processHandle != IntPtr.Zero)
            {
                try { CloseHandle(_processHandle); } catch { }
                _processHandle = IntPtr.Zero;
            }

            _processHandle = OpenProcess(ProcessAccessFlags.AllAccess, bInheritHandle: false, processId);
            if (_processHandle == IntPtr.Zero)
            {
                return false;
            }
            return true;
        }

        public void CheckProcess()
        {
            if (!_enableCheck) return;
            foreach (ProcessThread thread in Process.GetProcessById(processId).Threads)
            {
                IntPtr intPtr = OpenThread(ThreadAccess.SUSPEND_RESUME, bInheritHandle: false, (uint)thread.Id);
                if (intPtr != IntPtr.Zero)
                {
                    int num = 0;
                    do
                    {
                        num = ResumeThread(intPtr);
                    }
                    while (num > 0);
                    CloseHandle(intPtr);
                }
            }
        }

        public async Task<IEnumerable<long>> AoBScan(string bytePattern)
        {
            return await AobScan(bytePattern);
        }

        private async Task<IEnumerable<long>> AobScan(string pattern)
        {
            PatternData patternData = GetPatternDataFromPattern(pattern);
            List<long> addressRet = new List<long>();

            await Task.Run(delegate
            {
                List<MemoryPage> list = new List<MemoryPage>();
                IntPtr intPtr = IntPtr.Zero;
                MEMORY_BASIC_INFORMATION lpBuffer;
                while (VirtualQueryEx(_processHandle, intPtr, out lpBuffer, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) == (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)))
                {
                    if (CanReadPage(lpBuffer))
                    {
                        list.Add(new MemoryPage(intPtr, (int)lpBuffer.RegionSize.ToUInt64()));
                    }
                    intPtr = (IntPtr)((long)lpBuffer.BaseAddress + (long)(ulong)lpBuffer.RegionSize);
                }

                int patternLength = patternData.pattern.Length;

                foreach (MemoryPage addresss in list.OrderBy(p => (long)p.Start))
                {
                    byte[] array = new byte[addresss.Size];
                    IntPtr bytesRead;
                    if (ReadProcessMemory(_processHandle, addresss.Start, array, (IntPtr)addresss.Size, out bytesRead))
                    {
                        int offset = 0;
                        while (offset <= array.Length - patternLength)
                        {
                            int found = FindPattern(array, patternData.pattern, patternData.mask, offset);
                            if (found < 0) break;

                            long foundAddress = (long)addresss.Start + found;
                            lock (addressRet)
                            {
                                if (!addressRet.Contains(foundAddress))
                                    addressRet.Add(foundAddress);
                            }
                            offset = found + 1;
                        }
                    }
                }
            });

            return addressRet.OrderBy((long c) => c).AsEnumerable();
        }

        public bool CanReadPage(MEMORY_BASIC_INFORMATION page)
        {
            if (page.State != MEM_COMMIT) return false;
            if ((page.Protect & 0x01) != 0) return false;
            if ((page.Protect & 0x100) != 0) return false;

            if (page.Type == 0x20000)
            {
                return (page.Protect == 0x04) || (page.Protect == 0x08) ||
                       (page.Protect == 0x40) || (page.Protect == 0x80);
            }

            if (page.Type == 0x1000000)
            {
                return (page.Protect == 0x02) || (page.Protect == 0x04) ||
                       (page.Protect == 0x20) || (page.Protect == 0x40);
            }

            if (page.Type == 0x40000)
            {
                return (page.Protect == 0x02) || (page.Protect == 0x04);
            }

            return false;
        }

        private PatternData GetPatternDataFromPattern(string pattern)
        {
            string[] patternParts = pattern.Split(' ');

            PatternData patternData = new PatternData
            {
                pattern = patternParts.Select(s => s.Contains("??") ? (byte)0x00 : byte.Parse(s, NumberStyles.HexNumber)).ToArray(),
                mask = patternParts.Select(s => s.Contains("??") ? (byte)0x00 : (byte)0xFF).ToArray()
            };

            return patternData;
        }

        public bool AobReplace(long address, string bytePattern)
        {
            try
            {
                byte[] array = StringToByteArray(bytePattern);
                return WriteProcessMemory(_processHandle, (IntPtr)address, array, (IntPtr)array.Length, IntPtr.Zero);
            }
            catch (Exception)
            {
            }
            return false;
        }

        public bool AobReplace(long address, int bytePattern)
        {
            byte[] bytes = BitConverter.GetBytes(bytePattern);
            return WriteProcessMemory(_processHandle, (IntPtr)address, bytes, (IntPtr)bytes.Length, IntPtr.Zero);
        }

        public int ReadInt(long addressToRead)
        {
            byte[] array = new byte[4];
            if (ReadProcessMemory(_processHandle, (IntPtr)addressToRead, array, (IntPtr)array.Length, out var _))
            {
                return BitConverter.ToInt32(array, 0);
            }
            return 0;
        }

        private byte[] StringToByteArray(string hexString)
        {
            return (from hex in hexString.Split(' ')
                    select byte.Parse(hex, NumberStyles.HexNumber)).ToArray();
        }

        private int FindPattern(byte[] body, byte[] pattern, byte[] masks, int start = 0)
        {
            int result = -1;
            if (body.Length == 0 || pattern.Length == 0 || start > body.Length - pattern.Length || pattern.Length > body.Length)
            {
                return result;
            }
            for (int i = start; i <= body.Length - pattern.Length; i++)
            {
                if ((body[i] & masks[0]) != (pattern[0] & masks[0]))
                {
                    continue;
                }
                bool flag = true;
                for (int num = pattern.Length - 1; num >= 1; num--)
                {
                    if ((body[i + num] & masks[num]) != (pattern[num] & masks[num]))
                    {
                        flag = false;
                        break;
                    }
                }
                if (flag)
                {
                    result = i;
                    break;
                }
            }
            return result;
        }
    }

    [Flags]
    public enum ProcessAccessFlags
    {
        AllAccess = 0x001F0FFF,
        CreateProcess = 0x0080,
        CreateThread = 0x0002,
        DupHandle = 0x0040,
        QueryInformation = 0x0400,
        QueryLimitedInformation = 0x1000,
        SetInformation = 0x0200,
        SetQuota = 0x0100,
        SuspendResume = 0x0800,
        Terminate = 0x0001,
        VmOperation = 0x0008,
        VmRead = 0x0010,
        VmWrite = 0x0020,
        Synchronize = 0x00100000
    }

    [Flags]
    public enum ThreadAccess : int
    {
        TERMINATE = (0x0001),
        SUSPEND_RESUME = (0x0002),
        GET_CONTEXT = (0x0008),
        SET_CONTEXT = (0x0010),
        SET_INFORMATION = (0x0020),
        QUERY_INFORMATION = (0x0040),
        SET_THREAD_TOKEN = (0x0080),
        IMPERSONATE = (0x0100),
        DIRECT_IMPERSONATION = (0x0200)
    }
}