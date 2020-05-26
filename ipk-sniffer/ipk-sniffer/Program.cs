using CommandLine;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using System;

namespace ipk_sniffer
{
    class Program
    {
        public class Options
        {
            [Option('t', "tcp", Default = false)]
            public bool tcp { get; set; }

            [Option('u', "udp", Default = false)]
            public bool udp { get; set; }

            [Option('n', Default = 1)]
            public int number { get; set; }

            [Option('i', Default = null)]
            public string rozhrani { get; set; }

            [Option('p', Default = -1)]
            public int port { get; set; }

            [Option('h', "help", Default = false)]
            public bool help { get; set; }
        }

        static void PrintHelp()
        {
            Console.WriteLine("Jedna se o síťový analyzátor, který je schopný na určitém síťovém rozhraním zachytávat a filtrovat pakety\n");
            Console.WriteLine("Volání programu:\n");
            Console.WriteLine("./ipk-sniffer -i rozhraní [-p ­­port] [--tcp|-t] [--udp|-u] [-n num]");
            Console.WriteLine("kde\n");
            Console.WriteLine("-i eth0 (rozhraní, na kterém se bude poslouchat.Nebude - li tento parametr uveden, vypíše se seznam aktivních rozhraní)");
            Console.WriteLine("-p 23 (bude filtrování paketů na daném rozhraní podle portu; nebude - li tento parametr uveden, uvažují se všechny porty)");
            Console.WriteLine("-t nebo --tcp (bude zobrazovat pouze tcp pakety)");
            Console.WriteLine("-u nebo --udp (bude zobrazovat pouze udp pakety)");
            Console.WriteLine("Pokud nebude -tcp ani - udp specifikováno, uvažují se TCP a UDP pakety zároveň");
            Console.WriteLine("-n 10 (určuje počet paketů, které se mají zobrazit; pokud není uvedeno, uvažujte zobrazení pouze 1 paket)");
            Console.WriteLine("-h nebo --help vypise napovedu (toto)");
        }

        static void Main(string[] args)
        {
            bool tcp = false;
            bool udp = false;
            int number = 1; // defaultni hodnota poctu vypisovanych packetu, pokud argument neni pritomny
            string rozhrani = null;
            int port = -1;
            bool help = false;


            Parser.Default.ParseArguments<Options>(args).WithParsed<Options>(o =>
            {
                tcp = o.tcp;
                udp = o.udp;
                number = o.number;
                rozhrani = o.rozhrani;
                port = o.port;
                help = o.help;
            });

            if (!tcp && !udp) // pokud nemam tcp ani udp, budu zachatavat oboje
            {
                tcp = true;
                udp = true;
            }
      
            if (help) // pokud je jeden z argumentu -h nebo -help, vypisu napovedu
            {
                PrintHelp();
                return;
            }
                        
            var devices = CaptureDeviceList.Instance;

            if (rozhrani == null) // pokud neni uveden zadny interface
            {
                foreach (var item in devices)
                {
                    Console.WriteLine(item.ToString());
                }
                return;
            }

            try
            {
                var device = devices[rozhrani];

                device.OnPacketArrival += new PacketArrivalEventHandler(device_OnPacketArrival);

                var livePcapDevice = device as LibPcapLiveDevice;
                livePcapDevice.Open(DeviceMode.Promiscuous);


                string filter = "";

                if (tcp && udp)
                {
                    filter = (port == -1) ? ("") : ("port " + port);
                    Console.WriteLine(filter);
                }
                else if (tcp)
                {
                    filter = (port == -1) ? ("tcp") : ("tcp and port " + port);
                    Console.WriteLine(filter);
                }
                else if (udp)
                {
                    filter = (port == -1) ? ("udp") : ("udp and port " + port);
                    Console.WriteLine(filter);
                }

                device.Filter = filter;
                livePcapDevice.Capture(number);
                device.Close();
            }
            catch (Exception)
            {

                Console.WriteLine("Neexistujici rozhrani");
                Console.WriteLine("-h nebo --help");
                return;
            }                        
        }

        private static void device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            var time = e.Packet.Timeval.Date;
            var len = e.Packet.Data.Length;

            var packet = PacketDotNet.Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            var tcpPacket = packet.Extract<PacketDotNet.TcpPacket>();
            var udpPacket = packet.Extract<PacketDotNet.UdpPacket>();

            if (tcpPacket != null)
            {
                var ipPacket = (PacketDotNet.IPPacket)tcpPacket.ParentPacket;
                System.Net.IPAddress srcIP = ipPacket.SourceAddress;
                System.Net.IPAddress dstIP = ipPacket.DestinationAddress;

                int srcPort = tcpPacket.SourcePort;
                int dstPort = tcpPacket.DestinationPort;

                Console.WriteLine("{0}:{1}:{2}.{3} {5}:{6} > {7}:{8}\n",
                    time.Hour, time.Minute, time.Second, time.Millisecond, len,
                    srcIP, srcPort, dstIP, dstPort);                                

                int radek = 0;
                string str = "";

                for (int i = 0; i < packet.Bytes.Length; i++)
                {
                    if (i == 0)
                    {
                        Console.Write("0x{0}:  ", radek.ToString("x4"));                        
                    }

                    else if (i % 16 == 0)
                    {
                        Console.WriteLine(str);
                        str = "";
                        radek += 16;
                        Console.Write("0x{0}:  ", radek.ToString("x4"));
                    }

                    else if (i % 8 == 0)
                    {
                        Console.Write(" ");

                    }

                    Console.Write("{0} ", packet.Bytes[i].ToString("x2"));

                    char ch = Convert.ToChar(packet.Bytes[i]);
                    if ((char.IsLetterOrDigit(ch) || char.IsSymbol(ch) || char.IsPunctuation(ch)) && ch < 127) // kontrola tisknutelnych znaku
                    {
                        str += ch;
                    }
                    else
                    {
                        str += ".";
                    }

                    if (i == packet.Bytes.Length -1)
                    {
                        Console.WriteLine(str);
                    }
                }

                Console.WriteLine();
                Console.WriteLine("==========================================\n"); // kvuli prehlednosti oddeluju packety pomoci teto "cary"
            }

            if (udpPacket != null)
            {
                var ipPacket = (PacketDotNet.IPPacket)udpPacket.ParentPacket;
                System.Net.IPAddress srcIP = ipPacket.SourceAddress;
                System.Net.IPAddress dstIP = ipPacket.DestinationAddress;

                int srcPort = udpPacket.SourcePort;
                int dstPort = udpPacket.DestinationPort;

                Console.WriteLine("{0}:{1}:{2}.{3} {5}:{6} > {7}:{8}\n",
                    time.Hour, time.Minute, time.Second, time.Millisecond, len,
                    srcIP, srcPort, dstIP, dstPort);

                int radek = 0;
                string str = "";

                for (int i = 0; i < packet.Bytes.Length; i++)
                {
                    if (i == 0)
                    {
                        Console.Write("0x{0}:  ", radek.ToString("x4"));
                    }

                    else if (i % 16 == 0)
                    {
                        Console.WriteLine(str);
                        str = "";
                        radek += 16;
                        Console.Write("0x{0}:  ", radek.ToString("x4"));
                    }

                    else if (i % 8 == 0)
                    {
                        Console.Write(" ");

                    }

                    Console.Write("{0} ", packet.Bytes[i].ToString("x2"));

                    char ch = Convert.ToChar(packet.Bytes[i]);
                    if ((char.IsLetterOrDigit(ch) || char.IsSymbol(ch) || char.IsPunctuation(ch)) && ch < 127) // kontrola tisknutelnych znaku
                    {
                        str += ch;
                    }
                    else
                    {
                        str += ".";
                    }

                    if (i == packet.Bytes.Length - 1)
                    {
                        Console.WriteLine(str);
                    }
                }

                Console.WriteLine();
                Console.WriteLine("==========================================\n"); // kvuli prehlednosti oddeluju packety pomoci teto "cary"
            }
        }
    }
}
