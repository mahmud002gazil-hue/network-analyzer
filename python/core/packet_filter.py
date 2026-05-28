"""Paket Filtreleme Modülü"""
from typing import List, Dict, Optional


class PacketFilter:
    """Paketleri filtreleyen sınıf"""
    
    def __init__(self):
        self.filters = []
    
    def add_filter(self, filter_type: str, value: str, operator: str = '=='):
        """
        Filtre ekle
        
        Args:
            filter_type: Filtre türü (src_ip, dst_ip, protocol, port, vb.)
            value: Filtre değeri
            operator: Operatör (==, !=, >, <, in, vb.)
        """
        self.filters.append({
            'type': filter_type,
            'value': value,
            'operator': operator
        })
    
    def remove_filter(self, index: int):
        """Filtreyi kaldır"""
        if 0 <= index < len(self.filters):
            self.filters.pop(index)
    
    def clear_filters(self):
        """Tüm filtreleri temizle"""
        self.filters = []
    
    def apply_filters(self, packets: List[Dict]) -> List[Dict]:
        """Filtreleri paketlere uygula"""
        result = packets
        
        for filter_obj in self.filters:
            result = self._apply_single_filter(result, filter_obj)
        
        return result
    
    @staticmethod
    def _apply_single_filter(packets: List[Dict], filter_obj: Dict) -> List[Dict]:
        """Tek bir filtreyi uygula"""
        filter_type = filter_obj['type']
        value = filter_obj['value']
        operator = filter_obj['operator']
        
        filtered = []
        
        for packet in packets:
            if filter_type == 'src_ip':
                packet_value = packet.get('src_ip')
            elif filter_type == 'dst_ip':
                packet_value = packet.get('dst_ip')
            elif filter_type == 'protocol':
                packet_value = packet.get('protocol')
            elif filter_type == 'src_port':
                packet_value = packet.get('src_port')
            elif filter_type == 'dst_port':
                packet_value = packet.get('dst_port')
            elif filter_type == 'size':
                packet_value = packet.get('size')
            else:
                continue
            
            if PacketFilter._match_filter(packet_value, value, operator):
                filtered.append(packet)
        
        return filtered
    
    @staticmethod
    def _match_filter(packet_value, filter_value, operator: str) -> bool:
        """Filtre koşulunu kontrol et"""
        if packet_value is None:
            return False
        
        try:
            if operator == '==':
                return str(packet_value) == str(filter_value)
            elif operator == '!=':
                return str(packet_value) != str(filter_value)
            elif operator == '>':
                return int(packet_value) > int(filter_value)
            elif operator == '<':
                return int(packet_value) < int(filter_value)
            elif operator == '>=':
                return int(packet_value) >= int(filter_value)
            elif operator == '<=':
                return int(packet_value) <= int(filter_value)
            elif operator == 'in':
                return str(filter_value) in str(packet_value)
            elif operator == 'contains':
                return str(filter_value) in str(packet_value)
            else:
                return False
        except (ValueError, TypeError):
            return False
    
    def get_scapy_filter(self) -> Optional[str]:
        """Scapy filtre stringi oluştur"""
        if not self.filters:
            return None
        
        # Basit filtreler için Scapy formatına dönüştür
        scapy_filters = []
        
        for f in self.filters:
            if f['type'] == 'protocol':
                scapy_filters.append(f['value'].lower())
            elif f['type'] == 'src_ip':
                scapy_filters.append(f"src {f['value']}")
            elif f['type'] == 'dst_ip':
                scapy_filters.append(f"dst {f['value']}")
            elif f['type'] in ['src_port', 'dst_port']:
                scapy_filters.append(f"port {f['value']}")
        
        return " and ".join(scapy_filters) if scapy_filters else None
