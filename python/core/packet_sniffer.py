"""Paket Yakalama Modülü"""
import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw
from typing import Callable, List, Optional
import time


class PacketSniffer:
    """Ağ paketlerini yakalayan sınıf"""
    
    def __init__(self, callback: Callable = None, filter_str: str = None):
        """
        PacketSniffer'ı başlat
        
        Args:
            callback: Her paket yakalandığında çağrılacak fonksiyon
            filter_str: Scapy filtre stringi (örn: "tcp port 80")
        """
        self.callback = callback
        self.filter_str = filter_str
        self.is_sniffing = False
        self.packet_count = 0
        self.packets: List = []
        self.thread: Optional[threading.Thread] = None
    
    def packet_callback(self, packet):
        """Her paket için çağrılan callback"""
        self.packet_count += 1
        packet_info = self.parse_packet(packet)
        self.packets.append(packet_info)
        
        if self.callback:
            self.callback(packet_info)
    
    @staticmethod
    def parse_packet(packet) -> dict:
        """Paketi parse et ve bilgilerini döndür"""
        packet_data = {
            'timestamp': time.time(),
            'size': len(packet),
            'layers': [],
            'src_ip': None,
            'dst_ip': None,
            'protocol': 'Unknown',
            'src_port': None,
            'dst_port': None,
            'info': ''
        }
        
        # IP Layer
        if IP in packet:
            packet_data['src_ip'] = packet[IP].src
            packet_data['dst_ip'] = packet[IP].dst
            packet_data['protocol'] = packet[IP].proto
            packet_data['layers'].append('IP')
        
        # TCP Layer
        if TCP in packet:
            packet_data['src_port'] = packet[TCP].sport
            packet_data['dst_port'] = packet[TCP].dport
            packet_data['protocol'] = 'TCP'
            packet_data['info'] = f"TCP {packet[TCP].sport} -> {packet[TCP].dport}"
            packet_data['layers'].append('TCP')
        
        # UDP Layer
        elif UDP in packet:
            packet_data['src_port'] = packet[UDP].sport
            packet_data['dst_port'] = packet[UDP].dport
            packet_data['protocol'] = 'UDP'
            packet_data['info'] = f"UDP {packet[UDP].sport} -> {packet[UDP].dport}"
            packet_data['layers'].append('UDP')
        
        # ICMP Layer
        if ICMP in packet:
            packet_data['protocol'] = 'ICMP'
            packet_data['info'] = f"ICMP {packet[ICMP].type}"
            packet_data['layers'].append('ICMP')
        
        # DNS Layer
        if DNS in packet and DNSQR in packet:
            packet_data['protocol'] = 'DNS'
            dns_query = packet[DNSQR].qname.decode() if isinstance(packet[DNSQR].qname, bytes) else packet[DNSQR].qname
            packet_data['info'] = f"DNS Query: {dns_query}"
            packet_data['layers'].append('DNS')
        
        # Raw Data
        if Raw in packet:
            packet_data['layers'].append('Raw')
        
        return packet_data
    
    def start(self, interface: Optional[str] = None, packet_count: int = 0):
        """Paket yakalamaya başla"""
        if self.is_sniffing:
            return
        
        self.is_sniffing = True
        self.thread = threading.Thread(
            target=self._sniff_packets,
            args=(interface, packet_count),
            daemon=True
        )
        self.thread.start()
    
    def _sniff_packets(self, interface: Optional[str] = None, packet_count: int = 0):
        """Arka planda paket yakala"""
        try:
            sniff(
                prn=self.packet_callback,
                iface=interface,
                filter=self.filter_str,
                store=False,
                count=packet_count if packet_count > 0 else 0,
                stop_filter=lambda x: not self.is_sniffing
            )
        except Exception as e:
            print(f"Hata: {e}")
        finally:
            self.is_sniffing = False
    
    def stop(self):
        """Paket yakalamayı durdur"""
        self.is_sniffing = False
        if self.thread:
            self.thread.join(timeout=5)
    
    def get_packets(self) -> List[dict]:
        """Yakalanan paketleri döndür"""
        return self.packets
    
    def clear_packets(self):
        """Yakalanan paketleri temizle"""
        self.packets = []
        self.packet_count = 0
    
    def get_statistics(self) -> dict:
        """Paket istatistiklerini hesapla"""
        if not self.packets:
            return {}
        
        protocols = {}
        ports = {'src': {}, 'dst': {}}
        ips = {'src': {}, 'dst': {}}
        total_size = 0
        
        for pkt in self.packets:
            # Protocol istatistikleri
            proto = pkt['protocol']
            protocols[proto] = protocols.get(proto, 0) + 1
            
            # Port istatistikleri
            if pkt['src_port']:
                ports['src'][pkt['src_port']] = ports['src'].get(pkt['src_port'], 0) + 1
            if pkt['dst_port']:
                ports['dst'][pkt['dst_port']] = ports['dst'].get(pkt['dst_port'], 0) + 1
            
            # IP istatistikleri
            if pkt['src_ip']:
                ips['src'][pkt['src_ip']] = ips['src'].get(pkt['src_ip'], 0) + 1
            if pkt['dst_ip']:
                ips['dst'][pkt['dst_ip']] = ips['dst'].get(pkt['dst_ip'], 0) + 1
            
            total_size += pkt['size']
        
        return {
            'total_packets': len(self.packets),
            'total_size': total_size,
            'protocols': protocols,
            'ports': ports,
            'ips': ips,
            'avg_packet_size': total_size / len(self.packets) if self.packets else 0
        }
