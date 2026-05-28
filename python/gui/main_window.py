"""Ana Pencere - Network Analyzer GUI"""
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, 
    QTableWidget, QTableWidgetItem, QLabel, QComboBox, QLineEdit,
    QTabWidget, QTextEdit, QSpinBox, QCheckBox
)
from PyQt5.QtCore import Qt, pyqtSignal, QThread
from PyQt5.QtGui import QFont
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.packet_sniffer import PacketSniffer
from core.packet_filter import PacketFilter
from core.protocol_analyzer import ProtocolAnalyzer


class SniffThread(QThread):
    """Paket yakalama thread'i"""
    packet_received = pyqtSignal(dict)
    
    def __init__(self, sniffer):
        super().__init__()
        self.sniffer = sniffer
    
    def run(self):
        self.sniffer.start()


class MainWindow(QMainWindow):
    """Ana pencere sınıfı"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Analyzer 🔍")
        self.setGeometry(100, 100, 1400, 800)
        
        self.sniffer = None
        self.packet_filter = PacketFilter()
        self.all_packets = []
        
        self.init_ui()
    
    def init_ui(self):
        """Arayüzü başlat"""
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        
        main_layout = QVBoxLayout()
        
        # Kontrol paneli
        control_layout = self._create_control_panel()
        main_layout.addLayout(control_layout)
        
        # Tab widget
        tabs = QTabWidget()
        
        # Paket Listesi Tab
        self.packet_table = self._create_packet_table()
        tabs.addTab(self.packet_table, "Paketler")
        
        # İstatistikler Tab
        self.stats_text = QTextEdit()
        self.stats_text.setReadOnly(True)
        tabs.addTab(self.stats_text, "İstatistikler")
        
        # Paket Detayları Tab
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        tabs.addTab(self.details_text, "Paket Detayları")
        
        main_layout.addWidget(tabs)
        main_widget.setLayout(main_layout)
    
    def _create_control_panel(self) -> QHBoxLayout:
        """Kontrol panelini oluştur"""
        layout = QHBoxLayout()
        
        # Başlat/Durdur düğmeleri
        self.start_btn = QPushButton("▶ Başlat")
        self.start_btn.clicked.connect(self.start_sniffing)
        layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("⏹ Durdur")
        self.stop_btn.clicked.connect(self.stop_sniffing)
        self.stop_btn.setEnabled(False)
        layout.addWidget(self.stop_btn)
        
        # Temizle düğmesi
        clear_btn = QPushButton("🗑 Temizle")
        clear_btn.clicked.connect(self.clear_packets)
        layout.addWidget(clear_btn)
        
        layout.addSpacing(20)
        
        # Filtre seçeneği
        layout.addWidget(QLabel("Filtre:"))
        self.filter_type = QComboBox()
        self.filter_type.addItems(["Protokol", "Kaynak IP", "Hedef IP", "Bağlantı Noktası"])
        layout.addWidget(self.filter_type)
        
        self.filter_value = QLineEdit()
        self.filter_value.setPlaceholderText("Filtre değeri...")
        layout.addWidget(self.filter_value)
        
        filter_btn = QPushButton("🔍 Filtrele")
        filter_btn.clicked.connect(self.apply_filter)
        layout.addWidget(filter_btn)
        
        layout.addStretch()
        
        return layout
    
    def _create_packet_table(self) -> QTableWidget:
        """Paket tablosunu oluştur"""
        table = QTableWidget()
        table.setColumnCount(7)
        table.setHorizontalHeaderLabels([
            "No", "Kaynak IP", "Hedef IP", "Protokol", "Kaynak Port", "Hedef Port", "Boyut"
        ])
        table.itemSelectionChanged.connect(self.on_packet_selected)
        return table
    
    def start_sniffing(self):
        """Paket yakalamayı başlat"""
        self.sniffer = PacketSniffer(callback=self.on_packet_received)
        self.sniffer.start()
        
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
    
    def stop_sniffing(self):
        """Paket yakalamayı durdur"""
        if self.sniffer:
            self.sniffer.stop()
        
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
    
    def on_packet_received(self, packet_info: dict):
        """Paket alındığında çağrıl"""
        self.all_packets.append(packet_info)
        self.add_packet_to_table(packet_info)
        self.update_statistics()
    
    def add_packet_to_table(self, packet_info: dict):
        """Tabloya paket ekle"""
        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)
        
        self.packet_table.setItem(row, 0, QTableWidgetItem(str(row + 1)))
        self.packet_table.setItem(row, 1, QTableWidgetItem(packet_info.get('src_ip', 'N/A')))
        self.packet_table.setItem(row, 2, QTableWidgetItem(packet_info.get('dst_ip', 'N/A')))
        self.packet_table.setItem(row, 3, QTableWidgetItem(packet_info.get('protocol', 'N/A')))
        self.packet_table.setItem(row, 4, QTableWidgetItem(str(packet_info.get('src_port', 'N/A'))))
        self.packet_table.setItem(row, 5, QTableWidgetItem(str(packet_info.get('dst_port', 'N/A'))))
        self.packet_table.setItem(row, 6, QTableWidgetItem(str(packet_info.get('size', 0))))
        
        # Tablonun en altına scroll et
        self.packet_table.scrollToBottom()
    
    def on_packet_selected(self):
        """Paket seçildiğinde detayları göster"""
        current_row = self.packet_table.currentRow()
        if current_row >= 0 and current_row < len(self.all_packets):
            packet = self.all_packets[current_row]
            self.show_packet_details(packet)
    
    def show_packet_details(self, packet: dict):
        """Paket detaylarını göster"""
        details = f"""
📦 PAKET DETAYLARI
{'='*50}

Genel Bilgiler:
  • Zaman: {packet.get('timestamp', 'N/A')}
  • Boyut: {packet.get('size', 0)} bytes
  • Protokol: {packet.get('protocol', 'N/A')}
  • Katmanlar: {', '.join(packet.get('layers', []))}

IP Bilgileri:
  • Kaynak: {packet.get('src_ip', 'N/A')}
  • Hedef: {packet.get('dst_ip', 'N/A')}

Port Bilgileri:
  • Kaynak Port: {packet.get('src_port', 'N/A')}
  • Hedef Port: {packet.get('dst_port', 'N/A')}

Ek Bilgi: {packet.get('info', 'N/A')}
        """
        self.details_text.setText(details)
    
    def update_statistics(self):
        """İstatistikleri güncelle"""
        if self.sniffer:
            stats = self.sniffer.get_statistics()
            
            stats_text = f"""
📊 PAKET İSTATİSTİKLERİ
{'='*50}

Genel:
  • Toplam Paketler: {stats.get('total_packets', 0)}
  • Toplam Boyut: {stats.get('total_size', 0)} bytes
  • Ortalama Boyut: {stats.get('avg_packet_size', 0):.2f} bytes

Protokoller:
"""
            for proto, count in stats.get('protocols', {}).items():
                stats_text += f"  • {proto}: {count}\n"
            
            self.stats_text.setText(stats_text)
    
    def apply_filter(self):
        """Filtre uygula"""
        filter_type = self.filter_type.currentText()
        filter_value = self.filter_value.text()
        
        if not filter_value:
            return
        
        # Filtreyi temizle
        self.packet_table.setRowCount(0)
        self.packet_filter.clear_filters()
        
        # Filtre türüne göre ekle
        if filter_type == "Protokol":
            self.packet_filter.add_filter('protocol', filter_value, '==')
        elif filter_type == "Kaynak IP":
            self.packet_filter.add_filter('src_ip', filter_value, '==')
        elif filter_type == "Hedef IP":
            self.packet_filter.add_filter('dst_ip', filter_value, '==')
        elif filter_type == "Bağlantı Noktası":
            self.packet_filter.add_filter('src_port', filter_value, '==')
        
        # Filtreyi uygula
        filtered_packets = self.packet_filter.apply_filters(self.all_packets)
        
        # Filtrelenmiş paketleri göster
        for packet in filtered_packets:
            self.add_packet_to_table(packet)
    
    def clear_packets(self):
        """Paketleri temizle"""
        self.packet_table.setRowCount(0)
        self.all_packets = []
        self.stats_text.clear()
        self.details_text.clear()
        if self.sniffer:
            self.sniffer.clear_packets()
