import scapy.all as scapy
import tkinter as tk
from tkinter import ttk
import threading
import subprocess

class NetworkTrafficMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title("Traffic Monitoring System")
        self.root.geometry("1300x400")

        # State variables
        self.ip_counter = {}
        self.suspicious_ips = set()
        self.blocked_ips = set()
        self.monitoring_active = False

        # Frames
        main_frame = tk.Frame(root, padx=10, pady=10)
        main_frame.pack(fill="both", expand=True)

        all_ips_frame = tk.LabelFrame(main_frame, text="All Incoming IPs", padx=10, pady=5)
        all_ips_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        suspicious_ips_frame = tk.LabelFrame(main_frame, text="Suspicious IPs", padx=10, pady=5)
        suspicious_ips_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")

        blocked_ips_frame = tk.LabelFrame(main_frame, text="Blocked IPs", padx=10, pady=5)
        blocked_ips_frame.grid(row=0, column=2, padx=10, pady=10, sticky="nsew")

        # IP Tables
        self.all_ips_table = ttk.Treeview(all_ips_frame, columns=("IP", "Port", "Size"), show="headings", height=10)
        self.all_ips_table.heading("IP", text="IP Address")
        self.all_ips_table.heading("Port", text="Port")
        self.all_ips_table.heading("Size", text="Size (bytes)")
        self.all_ips_table.pack(side="top", fill="both", expand=True)

        self.suspicious_ips_table = ttk.Treeview(suspicious_ips_frame, columns=("IP", "Reason"), show="headings", height=10)
        self.suspicious_ips_table.heading("IP", text="IP Address")
        self.suspicious_ips_table.heading("Reason", text="Reason")
        self.suspicious_ips_table.pack(side="top", fill="both", expand=True)

        self.blocked_ips_table = ttk.Treeview(blocked_ips_frame, columns=("IP",), show="headings", height=10)
        self.blocked_ips_table.heading("IP", text="IP Address")
        self.blocked_ips_table.pack(side="top", fill="both", expand=True)

        # Buttons
        controls_frame = tk.Frame(main_frame)
        controls_frame.grid(row=1, column=0, columnspan=3, pady=10, sticky="ew")

        self.start_button = tk.Button(controls_frame, text="Start Monitoring", command=self.start_monitoring, width=20)
        self.start_button.grid(row=0, column=0, padx=5)

        self.stop_button = tk.Button(controls_frame, text="Stop Monitoring", command=self.stop_monitoring, state="disabled", width=20)
        self.stop_button.grid(row=0, column=1, padx=5)

        self.block_button = tk.Button(suspicious_ips_frame, text="Block Selected IP", command=self.block_ip, width=20)
        self.block_button.pack(fill="x", pady=5)

        self.unblock_button = tk.Button(blocked_ips_frame, text="Unblock Selected IP", command=self.unblock_ip, width=20)
        self.unblock_button.pack(fill="x", pady=5)

        # Status Bar
        self.status_var = tk.StringVar(value="Status: Idle")
        status_bar = tk.Label(root, textvariable=self.status_var, bd=1, relief="sunken", anchor="w")
        status_bar.pack(side="bottom", fill="x")

    def packet_callback(self, packet):
        if packet.haslayer(scapy.IP):
            ip_address = packet[scapy.IP].src
            packet_size = len(packet)

            if ip_address not in self.ip_counter:
                self.ip_counter[ip_address] = 0

            self.ip_counter[ip_address] += packet_size

            # Mark IP as suspicious if packet size exceeds 350 bytes
            if self.ip_counter[ip_address] > 350:
                if ip_address not in self.suspicious_ips:
                    self.suspicious_ips.add(ip_address)
                    self.suspicious_ips_table.insert("", "end", values=(ip_address, "High traffic"))

            if ip_address not in self.blocked_ips:
                self.all_ips_table.insert("", "end", values=(ip_address, packet[scapy.IP].sport, packet_size))

    def start_monitoring(self):
        self.clear_tables()
        self.monitoring_active = True
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.status_var.set("Status: Monitoring")

        monitoring_thread = threading.Thread(target=self.monitor_traffic)
        monitoring_thread.daemon = True
        monitoring_thread.start()

    def monitor_traffic(self):
        scapy.sniff(prn=self.packet_callback, store=0)

    def stop_monitoring(self):
        self.monitoring_active = False
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.status_var.set("Status: Stopped")

    def block_ip(self):
        selected_item = self.suspicious_ips_table.selection()
        if selected_item:
            ip_address = self.suspicious_ips_table.item(selected_item[0])['values'][0]
            if ip_address not in self.blocked_ips:
                self.blocked_ips.add(ip_address)
                self.blocked_ips_table.insert("", "end", values=(ip_address,))
                self.add_iptables_rule(ip_address)
                self.suspicious_ips_table.delete(selected_item)
                self.status_var.set(f"Blocked IP: {ip_address}")

    def unblock_ip(self):
        selected_item = self.blocked_ips_table.selection()
        if selected_item:
            ip_address = self.blocked_ips_table.item(selected_item[0])['values'][0]
            if ip_address in self.blocked_ips:
                self.blocked_ips.remove(ip_address)
                self.remove_iptables_rule(ip_address)
                self.blocked_ips_table.delete(selected_item)
                self.status_var.set(f"Unblocked IP: {ip_address}")

    def add_iptables_rule(self, ip_address):
        try:
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
            print(f"Blocked IP with iptables: {ip_address}")
        except subprocess.CalledProcessError as e:
            print(f"Error blocking IP {ip_address}: {e}")

    def remove_iptables_rule(self, ip_address):
        try:
            subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
            print(f"Unblocked IP with iptables: {ip_address}")
        except subprocess.CalledProcessError as e:
            print(f"Error unblocking IP {ip_address}: {e}")

    def clear_tables(self):
        for table in [self.all_ips_table, self.suspicious_ips_table, self.blocked_ips_table]:
            table.delete(*table.get_children())

if __name__ == "__main__":
    root = tk.Tk()
    monitor = NetworkTrafficMonitor(root)
    root.mainloop()
