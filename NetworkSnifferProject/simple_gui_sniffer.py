
import tkinter as tk
from tkinter import scrolledtext
from scapy.all import sniff, IP, TCP, UDP, Raw
import threading
import datetime

class SimpleSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Simple Network Sniffer")
        self.root.geometry("900x600")

        self.sniffing = False
        self.packet_count = 0

        self.build_gui()

    def build_gui(self):
        self.start_button = tk.Button(self.root, text="Start Capture", command=self.start_sniffing, bg="green", fg="white", width=20, height=2)
        self.start_button.pack(pady=10)

        self.stop_button = tk.Button(self.root, text="Stop Capture", command=self.stop_sniffing, bg="red", fg="white", width=20, height=2, state=tk.DISABLED)
        self.stop_button.pack(pady=5)

        self.text_area = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, font=("Courier", 10))
        self.text_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        self.counter_label = tk.Label(self.root, text="Packets Captured: 0", font=("Arial", 12))
        self.counter_label.pack(pady=5)

    def start_sniffing(self):
        if not self.sniffing:
            self.sniffing = True
            self.packet_count = 0
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            t = threading.Thread(target=self.sniff_packets)
            t.daemon = True
            t.start()

    def stop_sniffing(self):
        if self.sniffing:
            self.sniffing = False
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)

    def sniff_packets(self):
        sniff(prn=self.process_packet, store=False, stop_filter=lambda x: not self.sniffing)

    def process_packet(self, packet):
        if IP in packet:
            self.packet_count += 1
            info = f"\n{'='*80}\n"
            info += f"Time: {datetime.datetime.now().strftime('%H:%M:%S')}\n"
            info += f"Source IP: {packet[IP].src}\n"
            info += f"Destination IP: {packet[IP].dst}\n"
            info += f"Protocol: {packet[IP].proto}\n"

            if TCP in packet:
                info += f"[TCP] Src Port: {packet[TCP].sport}, Dst Port: {packet[TCP].dport}\n"
            elif UDP in packet:
                info += f"[UDP] Src Port: {packet[UDP].sport}, Dst Port: {packet[UDP].dport}\n"

            if Raw in packet:
                try:
                    raw_data = packet[Raw].load[:80]
                    info += f"[Payload] {raw_data}\n"
                except:
                    info += "[Payload] (Unable to decode)\n"

            self.text_area.insert(tk.END, info)
            self.text_area.see(tk.END)
            self.counter_label.config(text=f"Packets Captured: {self.packet_count}")

if __name__ == "__main__":
    root = tk.Tk()
    app = SimpleSnifferGUI(root)
    root.mainloop()
