from scapy.all import *
import time
import csv
import ssl
import socket  # Import socket module
import sys

WINDOW_SIZE = 60  # Adjust this value based on your monitoring needs

packet_count = 0
total_bytes = 0
start_time = time.time()

def packet_size(packet):
    packet_size = len(packet)
    if (packet_size>1400):
        print(f"Packet size: {packet_size} bytes")

def find_mal():
    port = 50000
    host = '10.1.21.228'

    
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('server.crt', 'server.key')  # Load your SSL certificate and key

    server_socket = context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_side=True)

    server_socket.bind((host, port))
    server_socket.listen(5)
    print('Server listening....')
 
    while True:
        conn, address = server_socket.accept()  # Establish connection with client.
    
        while True:
            try:
                
                print('Malicious connection from', address)
                print('Terminating connection')
                sys.exit()
                break
    
            except Exception as e:
                print(e)
                break
    for i in row:
        if(i in decoded.split(' ')):
            print("Malicious data")
    file.close() 
    conn.close()
    
packet_counts={} 
mal_addr=0
def calculate_traffic_rate(packet):
    global packet_count, total_bytes, start_time
    
    current_time = time.time()
    elapsed_time = current_time - start_time
    
    packets_per_second = packet_count / elapsed_time
    bytes_per_second = total_bytes / elapsed_time
    avg_packet_size = total_bytes / packet_count   # Calculate average packet size
    if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            pack_size=len(packet);
            if(pack_size>1400 and bytes_per_second>1000000):
                packet_counts[src_ip] = packet_counts.get(src_ip, 0) + 1
                
            if packet_counts.get(src_ip, 0) > 15:
                print(f"Potential malicious activity from {src_ip}") 
                mal_addr=src_ip
                find_mal()
                return
    packet_count = 0
    total_bytes = 0
    start_time = current_time

def packet_callback(packet):
    global packet_count, total_bytes
    
    packet_count += 1
    total_bytes += len(packet)
    
    calculate_traffic_rate(packet)
print("Scanning for malicious activity in the network")
sniff(prn=packet_callback, store=0)
