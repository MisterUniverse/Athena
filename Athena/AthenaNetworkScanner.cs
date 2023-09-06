using PacketDotNet;
using SharpPcap;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using static Athena.AthenaNetworkScanner;
using static Athena.NetworkScanner;

namespace Athena
{
    internal interface Observer
    {
        Device Update();
        Dictionary<string, Device> GetDevices();
    }

    internal class AthenaNetworkScanner
    {
        public NetworkScanner scanner = new NetworkScanner();
        public Watcher watcher = new Watcher();

        public delegate void PacketArrivalEventHandler(object sender, EventArgs e);
        public event PacketArrivalEventHandler PacketArrivalEvent;
        public static Dictionary<string, Device> DiscoveredDevices = new Dictionary<string, Device>();

        private delegate void FunctionWithParameter(object parameter);
        private Dictionary<PROTOCOL, FunctionWithParameter> _protocolDispatcher = new Dictionary<PROTOCOL, FunctionWithParameter>();

        private static CaptureDeviceList _captureDevices = CaptureDeviceList.Instance;
        private static Device foundDevice;
        private static string _id = String.Empty;

        protected virtual void PacketHasArrivedEvent(EventArgs e)
        {
            PacketArrivalEvent?.Invoke(this, e);
        }

        public AthenaNetworkScanner()
        {
            _protocolDispatcher.Add(NetworkScanner.PROTOCOL.ARP, parseARP);
            _protocolDispatcher.Add(NetworkScanner.PROTOCOL.DHCP, parseDHCP);
            _protocolDispatcher.Add(NetworkScanner.PROTOCOL.UDP, parseUDP);
        }

        public enum DeviceType
        {
            FLIR,
            OPTRIS,
        }

        public struct Device
        {
            public string Name;
            public string IPAddress;
            public string MacAddress;
            public string Operation;
            public string Target;
            public string SrcPort;
            public string DstPort;
            public ushort CheckSum;
            public bool ValidCheckSum;
            public bool ValidUdpCheckSum;
            public int TotalPacketLength;
            public DeviceType DeviceType;
        }

        public struct Watcher : Observer
        {
            public Dictionary<string, Device> GetDevices()
            {
                return DiscoveredDevices;
            }

            public Device Update()
            {
                return foundDevice;
            }
        }

        public CaptureDeviceList EthernetAdapterList
        {
            get => _captureDevices;
            private set => _captureDevices = value;
        }

        public string Id
        {
            get => _id;
            private set => _id = value;
        }

        private void searchForDevices(Dictionary<string, string> ouiMap)
        {
            foreach (var pair in ouiMap)
            {
                if (scanner.OUIList == null || !scanner.OUIList.ContainsKey(pair.Key))
                {
                    scanner.OUIList.Add(pair.Key, pair.Value);
                }
            }

            scanner.Adapter.OnPacketArrival += Adapter_OnPacketArrival;
            scanner.DiscoverDevices();
        }

        public void SearchForArpDevices(Dictionary<string, string> ouiMap)
        {
            scanner.Protocol = PROTOCOL.ARP;
            scanner.SearchProtocol = new NetworkScanner.ARPProtocol();
            searchForDevices(ouiMap);
        }

        public void SearchForUdpDevices(Dictionary<string, string> ouiMap)
        {
            scanner.Protocol = PROTOCOL.UDP;
            scanner.SearchProtocol = new NetworkScanner.UDPProtocol();
            searchForDevices(ouiMap);
        }

        public void SetAdapterInfo(string adapterName)
        {
            _id = getInterfaceByName(adapterName);
            var adapter = _captureDevices.FirstOrDefault(c => c.Name.Contains(_id));

            if (adapter != null)
            {
                scanner.Adapter = adapter;
            }
        }

        public void StopDeviceSearch()
        {
            scanner.Adapter.OnPacketArrival -= Adapter_OnPacketArrival;
            scanner.StopCapture();
        }

        private void Adapter_OnPacketArrival(object sender, PacketCapture e)
        {
            var packet = Packet.ParsePacket(e.GetPacket().LinkLayerType, e.GetPacket().Data);

            _protocolDispatcher[scanner.Protocol](packet);
        }

        private void parseARP(object packet)
        {
            if (packet is Packet p && p.PayloadPacket is ArpPacket arpPacket)
            {
                if (scanner.OUIList.ContainsKey(arpPacket.SenderHardwareAddress.ToString()))
                {
                    string arpIP = arpPacket.SenderProtocolAddress.ToString();

                    if (!DiscoveredDevices.ContainsKey(arpIP))
                    {
                        // TODO: Add factory class
                        Device device = new Device()
                        {
                            IPAddress = arpIP,
                            MacAddress = arpPacket.SenderHardwareAddress.ToString(),
                            Operation = arpPacket.Operation.ToString(),
                            Target = arpPacket.TargetHardwareAddress.ToString(),
                            // define device type
                        };

                        DiscoveredDevices.Add(arpIP, device);
                        foundDevice = device;
                        PacketHasArrivedEvent(EventArgs.Empty);
                    }
                }
            }
        }

        private void parseDHCP(object packet)
        {
            throw new NotImplementedException();
        }

        private void parseUDP(object packet)
        {
            if (packet is EthernetPacket ethernetPacket)
            {
                string srcMac = ethernetPacket.SourceHardwareAddress.ToString();
                string srcOui = srcMac.Substring(0, 8); // First 24 bits

                if (scanner.OUIList.ContainsKey(srcOui) && ethernetPacket.PayloadPacket is IPPacket ipPacket)
                {
                    if (!DiscoveredDevices.ContainsKey(ipPacket.SourceAddress.ToString()) && ipPacket.PayloadPacket is UdpPacket udpPacket)
                    {
                        // TODO: Add factory class
                        Device device = new Device()
                        {
                            IPAddress = ipPacket.SourceAddress.ToString(),
                            MacAddress = srcMac,
                            SrcPort = udpPacket.SourcePort.ToString(),
                            DstPort = udpPacket.DestinationPort.ToString(),
                            TotalPacketLength = udpPacket.TotalPacketLength,
                            CheckSum = udpPacket.Checksum,
                            ValidCheckSum = udpPacket.ValidChecksum,
                            ValidUdpCheckSum = udpPacket.ValidUdpChecksum
                            // define device type
                        };

                        DiscoveredDevices.Add(device.IPAddress, device);
                        foundDevice = device;
                        PacketHasArrivedEvent(EventArgs.Empty);
                    }
                }
            }
        }

        private string getInterfaceByName(string adapterName)
        {
            string result = String.Empty;
            // Get a list of all network interfaces on the machine
            NetworkInterface[] interfaces = NetworkInterface.GetAllNetworkInterfaces();

            foreach (NetworkInterface ni in interfaces)
            {
                if (ni.Name.ToString() == adapterName)
                {
                    result = ni.Id;
                    return result;
                }
            }

            return result;
        }
    }
}
