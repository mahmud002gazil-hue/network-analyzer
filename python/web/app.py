"""Flask Web Uygulaması"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
from core.packet_sniffer import PacketSniffer
from core.packet_filter import PacketFilter
import threading

app = Flask(__name__)
CORS(app)

sniffer = None
packet_filter = PacketFilter()
sniff_thread = None


@app.route('/')
def index():
    return jsonify({
        'app': 'Network Analyzer Web',
        'version': '1.0',
        'endpoints': [
            '/api/start',
            '/api/stop',
            '/api/packets',
            '/api/statistics',
            '/api/filters/add',
            '/api/filters/clear'
        ]
    })


@app.route('/api/start', methods=['POST'])
def start_capture():
    """Paket yakalamayı başlat"""
    global sniffer, sniff_thread
    
    try:
        sniffer = PacketSniffer()
        sniff_thread = threading.Thread(target=sniffer.start, daemon=True)
        sniff_thread.start()
        
        return jsonify({
            'status': 'success',
            'message': 'Paket yakalama başladı'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/stop', methods=['POST'])
def stop_capture():
    """Paket yakalamayı durdur"""
    global sniffer
    
    try:
        if sniffer:
            sniffer.stop()
        
        return jsonify({
            'status': 'success',
            'message': 'Paket yakalama durduruldu'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/packets', methods=['GET'])
def get_packets():
    """Paketleri döndür"""
    global sniffer
    
    try:
        if not sniffer:
            return jsonify({
                'status': 'error',
                'message': 'Yakalama başlatılmamış'
            }), 400
        
        packets = sniffer.get_packets()
        return jsonify({
            'status': 'success',
            'total': len(packets),
            'packets': packets[-100:]  # Son 100 paketi döndür
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/statistics', methods=['GET'])
def get_statistics():
    """İstatistikleri döndür"""
    global sniffer
    
    try:
        if not sniffer:
            return jsonify({
                'status': 'error',
                'message': 'Yakalama başlatılmamış'
            }), 400
        
        stats = sniffer.get_statistics()
        return jsonify({
            'status': 'success',
            'statistics': stats
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/filters/add', methods=['POST'])
def add_filter():
    """Filtre ekle"""
    global packet_filter
    
    try:
        data = request.get_json()
        filter_type = data.get('type')
        value = data.get('value')
        operator = data.get('operator', '==')
        
        packet_filter.add_filter(filter_type, value, operator)
        
        return jsonify({
            'status': 'success',
            'message': 'Filtre eklendi'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/filters/clear', methods=['POST'])
def clear_filters():
    """Filtreleri temizle"""
    global packet_filter
    
    try:
        packet_filter.clear_filters()
        
        return jsonify({
            'status': 'success',
            'message': 'Filtreler temizlendi'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'status': 'error',
        'message': 'Endpoint bulunamadı'
    }), 404


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
