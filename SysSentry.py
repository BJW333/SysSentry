import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
import time
import psutil
import datetime
import locale
import subprocess
from scapy.all import sniff, IP, IPv6, ARP
from scapy.utils import wrpcap

#GLOBAL CONSTANTS & HELPER FUNCTIONS

locale.setlocale(locale.LC_ALL, '')

LOG_FILE = "activity_monitor.log"

#Suspicious-activity thresholds
CPU_THRESHOLD = 75.0                     #CPU usage percentage
MEM_THRESHOLD_BYTES = int(3 * 1024 * 1024 * 1024) #3 gb

def human_readable_bytes(num, suffix="B"):
    """
    Convert a size in bytes to a more readable format (e.g., 2.5G, 57.3M, etc.)
    """
    for unit in ["", "K", "M", "G", "T", "P"]:
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}P{suffix}"


def log_suspicious_activity(msg):
    """
    Write a timestamped message to the log file.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {msg}\n")


def notify_mac(message, title="Activity Monitor Alert"):
    """
    Use macOS 'osascript' to display a notification.
    """
    subprocess.run([
        "osascript", "-e", f'display notification "{message}" with title "{title}"'
    ])


def check_for_suspicious_activity(process_info, consecutive_hits, process_hits_count):
    """
    Checks if a process crosses CPU or memory thresholds repeatedly.
    If suspicious, logs & notifies on macOS.
    """
    pid = process_info['pid']
    name = process_info['name'] or "?"
    cpu_percent = process_info['cpu_percent']
    mem_info = process_info['memory_info']

    #if mem_info doesn't exist, set RSS to 0
    mem_rss = mem_info.rss if mem_info else 0

    #if cpu_percent is None, treat it as 0.0
    if cpu_percent is None:
        cpu_percent = 0.0

    #compare with thresholds
    if cpu_percent > CPU_THRESHOLD or mem_rss > MEM_THRESHOLD_BYTES:
        process_hits_count[pid] = process_hits_count.get(pid, 0) + 1
        if process_hits_count[pid] >= consecutive_hits:
            msg = (f"Suspicious Activity Detected: PID={pid}, Name={name}, "
                   f"CPU={cpu_percent:.2f}%, Mem={human_readable_bytes(mem_rss)}")
            log_suspicious_activity(msg)
            notify_mac(msg)
            #reset so it doesn't spam notifications
            process_hits_count[pid] = 0
    else:
        #usage is under threshold, reset the hit count
        process_hits_count[pid] = 0


#ACTIVITY MONITOR GUI

class ActivityMonitorGUI(tk.Frame):
    def __init__(self, master=None, update_interval=4.0):
        super().__init__(master)
        self.master = master
        self.update_interval = update_interval

        #for small popup detailed windows
        self.detail_window = None
        
        self.pack(fill="both", expand=True)

        #track suspicious processes hits across updates
        self.process_hits_count = {}

        #filters and sort
        self.search_query = tk.StringVar()
        self.sort_mode = tk.StringVar(value="CPU")  # default sort by CPU
        self.sort_options = ["CPU", "Memory", "Name", "PID"]

        self.stop_flag = False
        self.create_widgets()

        #launch background thread for updates
        self.update_thread = threading.Thread(target=self.update_info_loop, daemon=True)
        self.update_thread.start()
        
    def show_process_details(self, event):
        """
        Open a pop-up window displaying detailed information about the selected process.
        Only one detailed window opens at a time. Close the previous one if another process is clicked.
        """
        selected_item = self.proc_tree.selection()
        if not selected_item:
            return

        #if a detail window exists close it
        if self.detail_window is not None and self.detail_window.winfo_exists():
            self.detail_window.destroy()

        #get the selected process details
        pid = self.proc_tree.item(selected_item, "values")[0]
        try:
            pid = int(pid)
            proc = psutil.Process(pid)

            #gather process details
            details = {
                "PID": pid,
                "Name": proc.name(),
                "Status": proc.status(),
                "Start Time": datetime.datetime.fromtimestamp(proc.create_time()).strftime("%Y-%m-%d %H:%M:%S"),
                "File Path": proc.exe(),
                "Command Line": " ".join(proc.cmdline()),
                "Number of Threads": proc.num_threads(),
                "Priority": proc.nice(),
                "Memory (RSS)": human_readable_bytes(proc.memory_info().rss),
                "Memory (VMS)": human_readable_bytes(proc.memory_info().vms),
                "CPU Usage": f"{proc.cpu_percent(interval=0.1):.2f}%",
            }

            #safely include IO counters if available
            if hasattr(proc, 'io_counters'):
                io_counters = proc.io_counters()
                details["IO Counters"] = f"Read: {human_readable_bytes(io_counters.read_bytes)}, " \
                                        f"Write: {human_readable_bytes(io_counters.write_bytes)}"
            else:
                details["IO Counters"] = "N/A"

        except psutil.AccessDenied:
            details = {"Error": "Access Denied"}
        except psutil.NoSuchProcess:
            details = {"Error": "Process no longer exists"}

        #create the detailed window
        self.detail_window = tk.Toplevel(self)
        self.detail_window.title(f"Process Details: PID {pid}")
        self.detail_window.geometry("500x400")
        self.detail_window.attributes("-topmost", True)  #bring to front

        #display the details in the new window
        for key, value in details.items():
            label = tk.Label(self.detail_window, text=f"{key}: {value}", anchor="w", justify="left")
            label.pack(fill="x", padx=10, pady=2)
            
    def create_widgets(self):
        #title
        self.title_label = tk.Label(self, text="Advanced Activity Monitor", font=("Helvetica", 16, "bold"))
        self.title_label.pack(pady=5)

        #CPU usage
        self.cpu_label = tk.Label(self, text="", font=("Helvetica", 12))
        self.cpu_label.pack()

        #Memory usage
        self.mem_label = tk.Label(self, text="", font=("Helvetica", 12))
        self.mem_label.pack()

        #Swap usage
        self.swap_label = tk.Label(self, text="", font=("Helvetica", 12))
        self.swap_label.pack()

        #Disk usage
        self.disk_label = tk.Label(self, text="", font=("Helvetica", 12))
        self.disk_label.pack()

        #Network usage
        self.net_label = tk.Label(self, text="", font=("Helvetica", 12))
        self.net_label.pack()

        #Filtering & Sorting Controls 
        filter_frame = tk.Frame(self)
        filter_frame.pack(pady=5)

        tk.Label(filter_frame, text="Search (PID or name):").pack(side=tk.LEFT, padx=2)
        search_entry = tk.Entry(filter_frame, textvariable=self.search_query)
        search_entry.pack(side=tk.LEFT, padx=2)

        tk.Label(filter_frame, text="Sort By:").pack(side=tk.LEFT, padx=2)
        sort_combobox = ttk.Combobox(filter_frame, values=self.sort_options, textvariable=self.sort_mode, width=7)
        sort_combobox.pack(side=tk.LEFT, padx=2)

        #Processes display (Treeview)
        self.proc_label = tk.Label(self, text="All Processes:", font=("Helvetica", 12, "bold"))
        self.proc_label.pack(pady=(10, 0))

        self.tree_frame = tk.Frame(self)
        self.tree_frame.pack(fill="both", expand=True, padx=10, pady=5)

        columns = ("PID", "Name", "CPU", "Memory")
        self.proc_tree = ttk.Treeview(self.tree_frame, columns=columns, show="headings", height=15)
        for col in columns:
            self.proc_tree.heading(col, text=col)
            self.proc_tree.column(col, stretch=True, width=100)

        #add a scrollbar
        scrollbar = ttk.Scrollbar(self.tree_frame, orient=tk.VERTICAL, command=self.proc_tree.yview)
        self.proc_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.proc_tree.pack(side=tk.LEFT, fill="both", expand=True)

        #bind double-click to show details
        self.proc_tree.bind("<Double-1>", self.show_process_details)

        #quit button
        self.quit_button = tk.Button(self, text="Quit", command=self.on_quit)
        self.quit_button.pack(pady=5)

    def update_info_loop(self):
        """
        Continuously update the stats in the GUI in a background thread.
        """
        def update():
            while not self.stop_flag:
                self.update_system_info()
                time.sleep(self.update_interval)
        threading.Thread(target=update, daemon=True).start()

    def update_system_info(self):
        #CPU usage
        cpu_percent = psutil.cpu_percent(interval=0.1)  #lower interval for responsiveness

        #Memory usage
        mem = psutil.virtual_memory()
        mem_str = f"Memory Usage: {mem.percent:.2f}%  ({human_readable_bytes(mem.used)}/{human_readable_bytes(mem.total)})"

        #Swap usage
        swap = psutil.swap_memory()
        swap_str = f"Swap Usage: {swap.percent:.2f}%  ({human_readable_bytes(swap.used)}/{human_readable_bytes(swap.total)})"

        #Disk usage
        disk = psutil.disk_usage('/')
        disk_str = f"Disk Usage: {disk.percent:.2f}%  ({human_readable_bytes(disk.used)}/{human_readable_bytes(disk.total)})"

        #Network I/O
        net = psutil.net_io_counters()
        net_str = (
            f"Network I/O => Sent: {human_readable_bytes(net.bytes_sent)}, "
            f"Received: {human_readable_bytes(net.bytes_recv)}"
        )

        #update labels in the GUI (must happen in main thread, so use .after or direct call from same thread)
        def gui_update():
            self.cpu_label.config(text=f"CPU Usage: {cpu_percent:.2f}%")
            self.mem_label.config(text=mem_str)
            self.swap_label.config(text=swap_str)
            self.disk_label.config(text=disk_str)
            self.net_label.config(text=net_str)

        self.master.after(0, gui_update)

        #get all processes
        processes = []
        for proc in psutil.process_iter(attrs=['pid', 'name', 'cpu_percent', 'memory_info']):
            try:
                processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        #check suspicious build up a final list
        for proc_info in processes:
            check_for_suspicious_activity(proc_info, consecutive_hits=3, process_hits_count=self.process_hits_count)

        #filter and sort processes
        filtered_processes = self.filter_processes(processes)
        sorted_processes = self.sort_processes(filtered_processes)

        #update the Treeview with all processes
        self.master.after(0, lambda: self.populate_tree(sorted_processes))

    def populate_tree(self, processes):
        """
        Clear and populate the Treeview with the given list of processes.
        """
        self.proc_tree.delete(*self.proc_tree.get_children())

        for proc_info in processes:
            pid = proc_info.get('pid', 0)
            name = proc_info.get('name') or "?"
            
            #Safely convert None -> 0.0
            cpu_val = proc_info.get('cpu_percent')
            if cpu_val is None:
                cpu_val = 0.0
            
            cpu_str = f"{cpu_val:.2f}%"

            mem_info = proc_info.get('memory_info')
            mem_used = human_readable_bytes(mem_info.rss) if mem_info else "0B"

            self.proc_tree.insert("", tk.END, values=(pid, name, cpu_str, mem_used))
        
    def filter_processes(self, processes):
        """
        Filter processes by search query (either partial PID or partial name).
        """
        query = self.search_query.get().strip().lower()
        if not query:
            return processes

        filtered = []
        for p in processes:
            pid_str = str(p['pid'])
            name_str = (p['name'] or "").lower()

            #if the query is numeric, match PID exactly or partially
            #if the query is text, match name
            if query.isdigit():
                if query in pid_str:
                    filtered.append(p)
            else:
                if query in name_str:
                    filtered.append(p)
        return filtered

    def sort_processes(self, processes):
        mode = self.sort_mode.get()
        if mode == "CPU":
            #Sort by CPU descending
            processes.sort(key=lambda p: (p['cpu_percent'] or 0), reverse=True)

        elif mode == "Memory":
            #Sort by memory usage descending
            processes.sort(key=lambda p: (p['memory_info'].rss if p['memory_info'] else 0), reverse=True)

        elif mode == "Name":
            #Sort by name ascending
            processes.sort(key=lambda p: p['name'] or "")

        elif mode == "PID":
            #Sort by PID ascending
            processes.sort(key=lambda p: p['pid'] or 0)

        return processes

    def on_quit(self):
        self.stop_flag = True
        #self.master.destroy() # old line 
        self.winfo_toplevel().destroy()

#NETWORK SNIFFER GUI 

class NetworkSnifferGUI(tk.Frame):
    def __init__(self, master):
        super().__init__(master)

        self.stop_sniff = False
        self.sniff_thread = None
        self.packets = []  #store captured packets

        #filters for IP and protocol
        self.ip_filter_var = tk.StringVar()
        self.proto_filter_var = tk.StringVar()

        #create scrolled text to display packets
        self.results_text = scrolledtext.ScrolledText(self, width=100, height=30)
        self.results_text.pack(side=tk.TOP, fill="both", expand=True)

        #configure color coded tags
        self.results_text.tag_config('light_blue', foreground='#33b9ff')  #IPv4
        self.results_text.tag_config('light_purple', foreground='#9370DB')  #IPv6
        self.results_text.tag_config('yellow', foreground='#FFE36E')  #Protocol names

        #Filter inputs
        filter_frame = tk.Frame(self)
        filter_frame.pack(side=tk.TOP, fill="x", padx=5, pady=5)

        tk.Label(filter_frame, text="Filter by IP:").pack(side=tk.LEFT, padx=5)
        tk.Entry(filter_frame, textvariable=self.ip_filter_var).pack(side=tk.LEFT, padx=5)

        tk.Label(filter_frame, text="Filter by Protocol:").pack(side=tk.LEFT, padx=5)
        tk.Entry(filter_frame, textvariable=self.proto_filter_var).pack(side=tk.LEFT, padx=5)

        #Add Start/Stop Sniff buttons
        self.sniff_button = ttk.Button(self, text="Start Sniffing", command=self.start_sniffing)
        self.sniff_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.stop_button = ttk.Button(self, text="Stop Sniffing", command=self.stop_sniffing)
        self.stop_button.pack(side=tk.LEFT, padx=5, pady=5)

        #Add Save Packets button
        self.save_button = ttk.Button(self, text="Save Packets", command=self.save_packets)
        self.save_button.pack(side=tk.LEFT, padx=5, pady=5)

    def start_sniffing(self):
        if self.sniff_thread and self.sniff_thread.is_alive():
            return  #Already sniffing
        self.stop_sniff = False
        filters = self.get_filters()
        self.sniff_thread = threading.Thread(target=self.run_sniffer, args=(filters,), daemon=True)
        self.sniff_thread.start()

    def stop_sniffing(self):
        self.stop_sniff = True
        messagebox.showinfo("Info", "Sniffing has stopped.")         #("Stopped", "Sniffing has stopped.", title="Info")


    def run_sniffer(self, filters=None):
        """
        Sniff packets in small bursts to periodically check `self.stop_sniff`.
        """
        while not self.stop_sniff:
            sniff(count=25, prn=lambda pkt: self.packet_callback(pkt, filters), store=False)

    def get_filters(self):
        """
        Retrieve filter settings from user inputs.
        """
        return {
            "ip": self.ip_filter_var.get(),
            "protocol": self.proto_filter_var.get()
        }

    def packet_callback(self, packet, filters):
        """
        Process captured packets and apply filters.
        """
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            proto_num = packet[IP].proto
        elif IPv6 in packet:
            ip_src = packet[IPv6].src
            ip_dst = packet[IPv6].dst
            proto_num = packet[IPv6].nh
        elif ARP in packet:
            ip_src = packet[ARP].psrc
            ip_dst = packet[ARP].pdst
            proto_num = 2054
        else:
            return

        #apply filters
        if filters["ip"] and filters["ip"] not in (ip_src, ip_dst):
            return
        if filters["protocol"] and filters["protocol"].lower() not in self.get_protocol_name(proto_num).lower():
            return

        protocol_name = self.get_protocol_name(proto_num)
        text_line = f"Source: {ip_src} | Destination: {ip_dst} | Protocol: {protocol_name}\n"

        #store packet for saving
        self.packets.append(packet)

        #Update UI with captured packet
        self.after(0, lambda: self.append_packet_text(text_line, ip_src, ip_dst, protocol_name))

    def append_packet_text(self, text_line, ip_src, ip_dst, protocol_name):
        """
        Safely update the scrolled text widget with packet details.
        """
        self.results_text.insert(tk.END, text_line)

        #color IP addresses and protocol names
        self.highlight_text(ip_src, 'light_purple' if ':' in ip_src else 'light_blue')  # IPv6 vs IPv4
        self.highlight_text(ip_dst, 'light_purple' if ':' in ip_dst else 'light_blue')  # IPv6 vs IPv4
        self.highlight_text(protocol_name, 'yellow')  # Protocol name

    def highlight_text(self, text, tag):
        """
        Highlight specific text in the scrolled text widget.
        """
        start_idx = '1.0'
        while True:
            start_idx = self.results_text.search(text, start_idx, stopindex=tk.END)
            if not start_idx:
                break
            end_idx = f"{start_idx}+{len(text)}c"
            self.results_text.tag_add(tag, start_idx, end_idx)
            start_idx = end_idx

    def save_packets(self):
        """
        Save captured packets to a .pcap file.
        """
        if not self.packets:
            messagebox.showinfo("No Packets", "No packets captured to save.", title="Info")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP Files", "*.pcap")])
        if file_path:
            wrpcap(file_path, self.packets)
            messagebox.showinfo("Save Successful", f"Packets saved to {file_path}", title="Info")

    def get_protocol_name(self, proto_num):
        """
        Return a user-friendly protocol name for given protocol number.
        Extend or modify as desired.
        """
                
        core_protocols = {
            50: ["ESP", "IPsec"],
            88: ["EIGRP", "Kerberos"],
            443: ["SSL/TLS", "HTTPS"],
            
            0: "HOPOPT",
            1: "ICMP",
            2: "IGMP",
            3: "GGP",
            4: "IPv4",
            5: "ST",
            6: "TCP",
            7: "CBT",
            8: "EGP", 
            9: "IGP",
            17: "UDP",
            20: "HMP",
            27: "RDP",
            41: "IPv6",
            42: "SDRP",
            43: "IPv6-Route",
            44: "IPv6-Frag",
            46: "RSVP",
            #47: "GRE",
            #50: "ESP",
            51: "AH",
            58: "IPv6-ICMP",
            59: "IPv6-NoNxt",
            60: "IPv6-Opts",
            #88: "EIGRP",
            89: "OSPF",
            115: "L2TP",
            132: "SCTP",
            136: "UDPLite",
            137: "MPLS-in-IP",
            4789: "VXLAN",
            47: "GRE",
            502: "Modbus",
            20000: "DNP3",
            #443: "SSL/TLS",
            #50: "IPsec",
            #88: "Kerberos",
            1194: "OpenVPN",
            1701: "L2TP",
            1723: "PPTP",
            80: "HTTP",
            #443: "HTTPS",
            21: "FTP",
            25: "SMTP",
            110: "POP3",
            143: "IMAP",
            53: "DNS",
            67: "DHCP",
            161: "SNMP",
            23: "Telnet",
            22: "SSH",
            5060: "SIP",
            5004: "RTP",
            5005: "RTCP",
            2054: "ARP"  
        }


        #return core_protocols.get(proto_num, f"Unknown({proto_num})") # old line here new lines below
        protocol = core_protocols.get(proto_num, f"Unknown({proto_num})")
        if isinstance(protocol, list):
            return ", ".join(protocol)
        return protocol


#MAIN APPLICATION WINDOW

class AdvancedMonitorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SysSentry")
        self.geometry("900x700")

        #create a Notebook for multiple tabs
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True)

        #TAB 1: Activity Monitor
        self.activity_frame = ActivityMonitorGUI(self.notebook)
        self.notebook.add(self.activity_frame, text="System Monitor")

        #TAB 2: Network Sniffer
        self.sniffer_frame = NetworkSnifferGUI(self.notebook)
        self.notebook.add(self.sniffer_frame, text="Network Sniffer")


def main():
    app = AdvancedMonitorApp()
    app.mainloop()


if __name__ == "__main__":
    main()