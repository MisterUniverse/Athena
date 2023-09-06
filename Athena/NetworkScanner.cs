using SharpPcap;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Athena
{
    public class NetworkScanner
    {
        private static ILiveDevice _ethernetAdapter;
        private INetworkProtocol _searchProtocol;
        private static PROTOCOL _networkProtocol;
        private static Dictionary<string, string> _ouiList;

        public NetworkScanner()
        {
            _ouiList = new Dictionary<string, string>();
        }

        internal Dictionary<string, string> OUIList
        {
            get => _ouiList;
            set => _ouiList = value;
        }

        internal INetworkProtocol SearchProtocol
        {
            get => _searchProtocol;
            set => _searchProtocol = value;
        }

        internal ILiveDevice Adapter
        {
            get => _ethernetAdapter;
            set => _ethernetAdapter = value;
        }

        internal PROTOCOL Protocol
        {
            get => _networkProtocol;
            set => _networkProtocol = value;
        }

        public enum PROTOCOL
        {
            ARP,
            DHCP,
            UDP
        }

        internal struct ARPProtocol : INetworkProtocol
        {
            public void DiscoverDevices()
            {
                startCapture();
            }
        }

        internal struct UDPProtocol : INetworkProtocol
        {
            public void DiscoverDevices()
            {
                startCapture();
            }
        }

        internal void DiscoverDevices()
        {
            try
            {
                _searchProtocol.DiscoverDevices();
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        internal void StopCapture()
        {
            _ethernetAdapter.StopCapture();
        }

        private static void startCapture()
        {
            int readTimeoutMilliseconds = 1000;
            _ethernetAdapter.Open(mode: DeviceModes.Promiscuous | DeviceModes.DataTransferUdp | DeviceModes.NoCaptureLocal, read_timeout: readTimeoutMilliseconds);

            _ethernetAdapter.StartCapture();
        }
    }
}
