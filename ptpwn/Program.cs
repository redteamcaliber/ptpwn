using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace ptpwn
{
    class Program
    {
        static PacketTracer _version62 = new PacketTracer
        (
            new IntPtr(0x0281F628),
            new IntPtr(0x00C78633),
            "6.2.0.0052"
        );

        static PacketTracer _version63 = new PacketTracer
        (
            new IntPtr(0x02D97670),
            new IntPtr(0x00C823C3),
            "6.3.0.0009"
        );

        static void Main(string[] args)
        {
            foreach (var process in Process.GetProcesses())
            {
                if (process.ProcessName != "PacketTracer6")
                    continue;

                var ptr = NativeMethods.OpenProcess(0x001F0FFF, true, process.Id);
                if (ptr == IntPtr.Zero)
                    Die();

                var version = ReadVersion(ptr);
                if (version == null)
                    Die("unknown packet tracer version");

                DoMagic(ptr, version.TargetPtr);
            }
        }

        static void DoMagic(IntPtr handle, IntPtr target)
        {
            //jump to 0x00C78726 or 0x00C824B6 immediately to skip all of the checks and warnings

            //dist:
            //(0x00C78726 or 0x00C824B6) - target = 0x24D
            //0x24D - 0x5 (len of jmp rel32) = 0x248
            WriteMemory(handle, target, new byte[] { 0xE9, 0x48, 0x02, 0x00, 0x00 });
        }

        static PacketTracer ReadVersion(IntPtr process)
        {
            byte[] version62Bytes = ReadMemory(process, _version62.VersionPtr, (uint)_version62.ToString().Length);
            byte[] version63Bytes = ReadMemory(process, _version63.VersionPtr, (uint)_version63.ToString().Length);

            try
            {
                if (Encoding.ASCII.GetString(version62Bytes) == _version62.ToString())
                    return _version62;
            }
            catch { }

            try
            {
                if (Encoding.ASCII.GetString(version63Bytes) == _version63.ToString())
                    return _version63;
            }
            catch { }

            return null;
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

    class PacketTracer
    {
        public readonly IntPtr VersionPtr;
        public readonly IntPtr TargetPtr;

        private string _version;

        public PacketTracer(IntPtr versionPtr, IntPtr targetPtr, string versionString)
        {
            VersionPtr = versionPtr;
            TargetPtr = targetPtr;
            _version = versionString;
        }

        public override string ToString()
        {
            return _version;
        }
    }
}