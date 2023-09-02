# Apache 2.0
#
# Copyright 2021-2023 Zhao Zhe(Alex)
#
# ARP Entries monitored in realtime
#
import threading
import subprocess
import re

class ArpEntries:
    def __init__(self, mac_dev_tbl):
        """
        Initialization of ArpEntries class
        """
        self.debug = False
        self.arp_entries = {}
        self.arp_entries_lock = threading.Lock()
        self.running = False
        self.mac_dev_entries = mac_dev_tbl

    def arp_monitor(self):
        arp_mon = subprocess.Popen(['ip', 'monitor', 'neigh'], stdout=subprocess.PIPE)
        arp_filter = re.compile("([\d\.]+) dev ([\w]+) ([\w]+) ([\w\:]+) ([\w]+)", re.IGNORECASE)
        while self.running:
            arp_mon_update = arp_mon.stdout.readline().decode("utf-8").strip()
            arp_match = arp_filter.match(arp_mon_update)
            if arp_match:
                ip_addr = arp_match.group(1)
                intf = arp_match.group(2)
                proto = arp_match.group(3)
                mac_addr = arp_match.group(4)
                status = arp_match.group(5)
                self.arp_entries_lock.acquire()
                self.arp_entries[ip_addr] = {"mac_addr": mac_addr, "status": status}
                self.arp_entries_lock.release()

    def start_mon(self):
        """
        Start Monitoring of ARP table changes
        """
        arp_process = subprocess.Popen(['arp', '-an'],
                                    stdout=subprocess.PIPE)
        arp_filter = re.compile("^\? \(([\d\.]+)\) at ([\w\:]+)", re.IGNORECASE)

        arp_output = arp_process.stdout.readline()
        while arp_output:
            arp_match = arp_filter.match(arp_output.decode("utf-8").strip())
            if arp_match:
                ip_addr = arp_match.group(1)
                mac_addr = arp_match.group(2)
                self.arp_entries_lock.acquire()
                self.arp_entries[ip_addr] = {"mac_addr": mac_addr, "status": "REACHABLE"}
                self.arp_entries_lock.release()
            arp_output = arp_process.stdout.readline()

        self.running = True
        self.arp_mon_th = threading.Thread(name="dns mon", target=self.arp_monitor)
        self.arp_mon_th.start()

    def stop_mon(self):
        self.running = False

    def list_entries(self):
        self.arp_entries_lock.acquire()
        for entry in self.arp_entries:
            print(entry, "  ", self.arp_entries[entry]["mac_addr"], "  status ", self.arp_entries[entry]["status"])
        self.arp_entries_lock.release()

    def get_entry(self, ip_addr):
        mac_addr = None
        status = None
        self.arp_entries_lock.acquire()
        if ip_addr in self.arp_entries:
            mac_addr = str(self.arp_entries[ip_addr]["mac_addr"])
            status = str(self.arp_entries[ip_addr]["status"])
        self.arp_entries_lock.release()
        return mac_addr, status

    def get_dev(self, ip_addr):
        mac_addr = None
        dev = None
        self.arp_entries_lock.acquire()
        if ip_addr in self.arp_entries:
            mac_addr = str(self.arp_entries[ip_addr]["mac_addr"])
        self.arp_entries_lock.release()

        if mac_addr:
            if mac_addr in self.mac_dev_entries:
                dev = str(self.mac_dev_entries[mac_addr])
            else:
                dev = "Unknown"
        
        return mac_addr, dev


def load_device_list(device_list):
    device_map = {}
    device_list_filter = re.compile("([\w\:]+)[ \t]+\"([\w\W]+)\"\s*(\w+)*", re.IGNORECASE)
    if device_list != "":
        f = open(device_list, "r")
        lines = f.readlines()
        for line in lines:
            device_match = device_list_filter.match(line)
            if device_match:
                if device_match.group(1) and device_match.group(2):
                    mac_addr = device_match.group(1)
                    device_name = device_match.group(2)
                    if device_match.group(3):
                        if device_match.group(3) == "ignore":
                            continue
                    device_map[mac_addr] = device_name
    return device_map

