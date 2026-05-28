"""Komut Satırı Arayüzü"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.packet_sniffer import PacketSniffer
from core.packet_filter import PacketFilter
import time


class CLIApp:
    """Komut satırı uygulaması"""
    
    def __init__(self):
        self.sniffer = None
        self.packet_filter = PacketFilter()
        self.running = False
    
    def print_banner(self):
        """Banner göster"""
        banner = """
╔══════════════════════════════════════════╗
║      NETWORK ANALYZER - CLI 🔍           ║
║   Paket Yakalama ve Analiz Aracı         ║
╚══════════════════════════════════════════╝
        """
        print(banner)
    
    def print_menu(self):
        """Menüyü göster"""
        menu = """
[1] Paket Yakalamayı Başlat
[2] Paket Yakalamayı Durdur
[3] İstatistikleri Göster
[4] Paketleri Göster
[5] Filtre Ekle
[6] Filtreleri Temizle
[7] Çıkış

Seçiminiz: """
        return menu
    
    def start_capture(self):
        """Paket yakalamayı başlat"""
        print("\n🟢 Paket yakalama başlıyor...")
        self.sniffer = PacketSniffer(callback=self.on_packet)
        
        # Filtre stringi oluştur
        filter_str = self.packet_filter.get_scapy_filter()
        self.sniffer.filter_str = filter_str
        
        self.sniffer.start()
        self.running = True
        print("✓ Yakalama başladı. Paketleri görmek için 'Paketleri Göster' seçeneğini kullanın.")
    
    def stop_capture(self):
        """Paket yakalamayı durdur"""
        if self.sniffer and self.running:
            print("\n🛑 Paket yakalama durduruluyor...")
            self.sniffer.stop()
            self.running = False
            print("✓ Yakalama durduruldu.")
        else:
            print("❌ Yakalama başlatılmamış.")
    
    def on_packet(self, packet_info):
        """Paket alındığında"""
        pass  # CLI'de gerçek zamanlı gösterim yok
    
    def show_statistics(self):
        """İstatistikleri göster"""
        if not self.sniffer:
            print("❌ Önce paket yakalamayı başlatınız.")
            return
        
        stats = self.sniffer.get_statistics()
        
        print("\n📊 PAKET İSTATİSTİKLERİ")
        print("="*50)
        print(f"Toplam Paketler: {stats.get('total_packets', 0)}")
        print(f"Toplam Boyut: {stats.get('total_size', 0)} bytes")
        print(f"Ortalama Boyut: {stats.get('avg_packet_size', 0):.2f} bytes")
        print("\nProtokoller:")
        for proto, count in stats.get('protocols', {}).items():
            print(f"  • {proto}: {count}")
    
    def show_packets(self):
        """Paketleri göster"""
        if not self.sniffer:
            print("❌ Önce paket yakalamayı başlatınız.")
            return
        
        packets = self.sniffer.get_packets()
        
        if not packets:
            print("❌ Henüz paket yakalanmadı.")
            return
        
        print("\n📦 YAKALANAN PAKETLER")
        print("="*50)
        print(f"{'No':<5} {'Kaynak IP':<20} {'Hedef IP':<20} {'Protokol':<10} {'Boyut':<10}")
        print("-"*50)
        
        for idx, packet in enumerate(packets[-20:], 1):  # Son 20 paketi göster
            print(f"{idx:<5} {packet.get('src_ip', 'N/A'):<20} {packet.get('dst_ip', 'N/A'):<20} {packet.get('protocol', 'N/A'):<10} {packet.get('size', 0):<10}")
    
    def add_filter(self):
        """Filtre ekle"""
        print("\n🔍 Filtre Ekleme")
        print("Filtre Türü: [1] Protokol, [2] Kaynak IP, [3] Hedef IP, [4] Port")
        choice = input("Seçiminiz: ").strip()
        
        filter_types = {
            '1': ('protocol', input("Protokol adı (TCP/UDP/ICMP): ").strip().upper()),
            '2': ('src_ip', input("Kaynak IP: ").strip()),
            '3': ('dst_ip', input("Hedef IP: ").strip()),
            '4': ('src_port', input("Port numarası: ").strip())
        }
        
        if choice in filter_types:
            filter_type, value = filter_types[choice]
            self.packet_filter.add_filter(filter_type, value, '==')
            print("✓ Filtre eklendi.")
        else:
            print("❌ Geçersiz seçim.")
    
    def clear_filters(self):
        """Filtreleri temizle"""
        self.packet_filter.clear_filters()
        print("✓ Tüm filtreler temizlendi.")
    
    def run(self):
        """Uygulamayı çalıştır"""
        self.print_banner()
        
        while True:
            try:
                choice = input(self.print_menu()).strip()
                
                if choice == '1':
                    self.start_capture()
                elif choice == '2':
                    self.stop_capture()
                elif choice == '3':
                    self.show_statistics()
                elif choice == '4':
                    self.show_packets()
                elif choice == '5':
                    self.add_filter()
                elif choice == '6':
                    self.clear_filters()
                elif choice == '7':
                    print("\n👋 Çıkılıyor...")
                    if self.sniffer:
                        self.sniffer.stop()
                    break
                else:
                    print("❌ Geçersiz seçim.")
            except KeyboardInterrupt:
                print("\n👋 Çıkılıyor...")
                if self.sniffer:
                    self.sniffer.stop()
                break
            except Exception as e:
                print(f"❌ Hata: {e}")


def main():
    app = CLIApp()
    app.run()


if __name__ == '__main__':
    main()
