from scapy.all import *



def send_file(file_path, destination_ip):
    with open(file_path, 'rb') as f:
        file_data = f.read()
    max_packet_size = 1459

    chunks = [file_data[i:i+max_packet_size] for i in range(0, len(file_data), max_packet_size)]

    for i, chunk in enumerate(chunks):
        packet = IP(dst=destination_ip) / TCP(dport=12345) / Raw(load=chunk)

        send(packet)
        print(f"Sent chunk {i+1}/{len(chunks)}")

send_file('/Users/anuhya/Desktop/22/MALI.txt', '10.1.21.228')

