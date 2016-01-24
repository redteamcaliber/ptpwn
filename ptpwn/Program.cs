using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ptpwn
{
    class Program
    {
        static void Main(string[] args)
        {
            foreach (var process in Process.GetProcesses())
            {
                if (process.ProcessName != "PacketTracer6")
                    continue;

                var ptr = NativeMethods.OpenProcess(0x001F0FFF, true, process.Id);

                if (ptr == IntPtr.Zero)
                    Die();

                DoMagic(ptr);
            }
        }

        static void DoMagic(IntPtr handle)
        {
            // don't jump: jz -> jnz
            WriteMemory(handle, new IntPtr(0x00C78633), new byte[] { 0x0F, 0x85 });

            // don't jump: jz -> jnz
            WriteMemory(handle, new IntPtr(0x00C786AB), 0x75);

            //jump to 0x00C78880 to save the name but skip resetting progress
            WriteMemory(handle, new IntPtr(0x00C78726), new byte[] { 0xE9, 0x55, 0x01, 0x00, 0x00 });
        }

        static byte[] ReadMemory(IntPtr process, IntPtr address, uint length)
        {
            uint read = 0;
            byte[] buffer = new byte[length];

            if (!NativeMethods.ReadProcessMemory(process, address, buffer, length, ref read))
                Die();

            if (read != length)
                Die("could not read requested amount of bytes");

            return buffer;
        }

        static void WriteMemory(IntPtr process, IntPtr address, byte[] buffer)
        {
            uint written = 0;
            if (!NativeMethods.WriteProcessMemory(process, address, buffer, (uint)buffer.Length, ref written))
                Die();

            if (written != (uint)buffer.Length)
                Die("could not write requested amount of bytes");
        }

        static void WriteMemory(IntPtr process, IntPtr address, byte b)
        {
            WriteMemory(process, address, new byte[] { b });
        }

        static void Die()
        {
            throw new Exception(string.Format("fuck: 0x{0:X}", Marshal.GetLastWin32Error()));
        }

        static void Die(string message)
        {
            throw new Exception(message);
        }
    }
    
    static class NativeMethods
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr process, IntPtr address, byte[] buffer, uint size, ref uint read);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr process, IntPtr address, byte[] buffer, uint size, ref uint written);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint access, bool inheritHandle, int processId);
    }
}
