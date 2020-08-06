/* Copyright (C) 2020 FireEye, Inc. All Rights Reserved. */
 
using System;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;

namespace jitm
{
    class jitm
    {
        [DllImport("jitmhook.dll", CallingConvention=System.Runtime.InteropServices.CallingConvention.Cdecl)]
        private static extern bool Hook();

        [DllImport("jitmhook.dll", CallingConvention=System.Runtime.InteropServices.CallingConvention.Cdecl)]
        private static extern void HookManaged(IntPtr MyDelegate);

        [DllImport("jitmhook.dll", CallingConvention=System.Runtime.InteropServices.CallingConvention.Cdecl)]
        private static extern bool Init([MarshalAs(UnmanagedType.LPStr)] string pszFilename);

        [DllImport("jitmhook.dll", CallingConvention=System.Runtime.InteropServices.CallingConvention.Cdecl)]
        private static extern bool Fini();

        private static Assembly TargetAssembly;

        public static void PrintHelpAndExit()
        {
            string me = System.AppDomain.CurrentDomain.FriendlyName;
            Console.WriteLine(String.Format("Usage: {0} <target assembly> [timeout]", me));
            System.Environment.Exit(0);
        }

        private static int nTimeout = 60 * 1000;
        
        public static void PrepareMethods(Assembly asm)
        {
            Module[] mods = asm.GetLoadedModules();
            foreach (Module mod in mods)
            {
                Type[] classes = mod.GetTypes();
                foreach (Type c in classes)
                {
                    MethodInfo[] methods = c.GetMethods();
                    foreach (MethodInfo method in methods)
                    {
                        try
                        {
                            RuntimeHelpers.PrepareMethod(method.MethodHandle);
                        }
                        catch (Exception)
                        {
                            Console.WriteLine("[!] Failed to prepare method 0x{0:X}", method.MetadataToken);
                        }
                    }
                }
            }
        }

        public static void mythread()
        {
            Console.WriteLine("[!] Waiting for {0} miliseconds", nTimeout);
            System.Threading.Thread.Sleep(nTimeout);
            Fini();
            Environment.Exit(0);
        }

        public static void Main(string[] args)
        {
            if (args.Length < 1 || args.Length > 2)
                PrintHelpAndExit();

            if (args.Length == 2) nTimeout = int.Parse(args[1]);

            // Start a worker thread to wait for the main thread and call Fini()
            Thread thread = new Thread(mythread);
            thread.Start();
            string pFilepath;
            if (Path.IsPathRooted(args[0]))
            {
                pFilepath = args[0];
            }
            else
            {
                string cwd = Directory.GetCurrentDirectory();
                string[] path = { cwd, args[0] };
                pFilepath = Path.Combine(path);
            }

            Init(pFilepath);
            if (!Hook())
            {
                Console.WriteLine("[E] Failed to hook");
            }

            TargetAssembly = Assembly.LoadFile(pFilepath);
            Console.WriteLine("[+] Assembly loaded from {0}", pFilepath);
            PrepareMethods(TargetAssembly);

            object[] parameters = null;
            if (TargetAssembly.EntryPoint.GetParameters().Length != 0)
            {
                parameters = new object[]
                {
                    new string[1]
                };
            }
            Console.WriteLine("[+] Calling target entry point! This will take a while...");
            TargetAssembly.EntryPoint.Invoke(null, new object[] { });
            return;
        }
    }
}
