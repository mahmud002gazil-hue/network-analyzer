"""Protokol Analiz Modülü"""
from typing import Dict, Any
from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, HTTP, HTTPRequest


class ProtocolAnalyzer:
    """Paket protokollerini analiz eden sınıf"""
    
    @staticmethod
    def analyze(packet) -> Dict[str, Any]:
        """Paketi protokol seviyesinde analiz et"""
        analysis = {
            'layers': [],
            'details': {}
        }
        
        # IP Layer
        if IP in packet:
            analysis['layers'].append('IP')
            analysis['details']['IP'] = ProtocolAnalyzer._analyze_ip(packet[IP])
        
        # TCP Layer
        if TCP in packet:
            analysis['layers'].append('TCP')
            analysis['details']['TCP'] = ProtocolAnalyzer._analyze_tcp(packet[TCP])
        
        # UDP Layer
        if UDP in packet:
            analysis['layers'].append('UDP')
            analysis['details']['UDP'] = ProtocolAnalyzer._analyze_udp(packet[UDP])
        
        # ICMP Layer
        if ICMP in packet:
            analysis['layers'].append('ICMP')
            analysis['details']['ICMP'] = ProtocolAnalyzer._analyze_icmp(packet[ICMP])
        
        # DNS Layer
        if DNS in packet:
            analysis['layers'].append('DNS')
            analysis['details']['DNS'] = ProtocolAnalyzer._analyze_dns(packet)
        
        return analysis
    
    @staticmethod
    def _analyze_ip(ip_layer) -> Dict[str, Any]:
        """IP katmanını analiz et"""
        return {
            'version': ip_layer.version,
            'header_length': ip_layer.ihl * 4,
            'tos': ip_layer.tos,
            'total_length': ip_layer.len,
            'identification': ip_layer.id,
            'flags': str(ip_layer.flags),
            'ttl': ip_layer.ttl,
            'protocol': ip_layer.proto,
            'checksum': ip_layer.chksum,
            'src': ip_layer.src,
            'dst': ip_layer.dst,
        }
    
    @staticmethod
    def _analyze_tcp(tcp_layer) -> Dict[str, Any]:
        """TCP katmanını analiz et"""
        return {
            'sport': tcp_layer.sport,
            'dport': tcp_layer.dport,
            'seq': tcp_layer.seq,
            'ack': tcp_layer.ack,
            'flags': str(tcp_layer.flags),
            'window': tcp_layer.window,
            'checksum': tcp_layer.chksum,
            'urgent_pointer': tcp_layer.urgptr,
        }
    
    @staticmethod
    def _analyze_udp(udp_layer) -> Dict[str, Any]:
        """UDP katmanını analiz et"""
        return {
            'sport': udp_layer.sport,
            'dport': udp_layer.dport,
            'length': udp_layer.len,
            'checksum': udp_layer.chksum,
        }
    
    @staticmethod
    def _analyze_icmp(icmp_layer) -> Dict[str, Any]:
        """ICMP katmanını analiz et"""
        return {
            'type': icmp_layer.type,
            'code': icmp_layer.code,
            'checksum': icmp_layer.chksum,
        }
    
    @staticmethod
    def _analyze_dns(packet) -> Dict[str, Any]:
        """DNS katmanını analiz et"""
        dns_info = {
            'queries': [],
            'answers': []
        }
        
        if DNSQR in packet:
            dns_info['queries'].append({
                'qname': packet[DNSQR].qname.decode() if isinstance(packet[DNSQR].qname, bytes) else packet[DNSQR].qname,
                'qtype': packet[DNSQR].qtype,
            })
        
        return dns_info
