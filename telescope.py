#!/usr/bin/python
#
# Apache 2.0
# Copyright 2021-2023 Zhao Zhe(Alex)
#
# Umbrella Telescope DMZ controlling internal network monitoring
#
# Copyright 2012-2023 Zhao Zhe(Alex)
# You don't need it except you want to record every access from your internal network
# Daemon process to monitoring device according to its
# defined list
#
# Database table dhcp_leases for recording internal connected devices: 
# +-------------+--------------+------+-----+---------+----------------+
# | Field       | Type         | Null | Key | Default | Extra          |
# +-------------+--------------+------+-----+---------+----------------+
# | id          | int(11)      | NO   | PRI | NULL    | auto_increment |
# | mac_addr    | varchar(20)  | YES  |     | NULL    |                |
# | ip_addr     | varchar(128) | YES  |     | NULL    |                |
# | lease_start | datetime     | YES  |     | NULL    |                |
# | lease_end   | datetime     | YES  |     | NULL    |                |
# | comments    | varchar(255) | YES  |     | NULL    |                |
# | state       | varchar(255) | YES  |     | NULL    |                |
# +-------------+--------------+------+-----+---------+----------------+
#
import sys
from arp_entries import ArpEntries
import threading

from flask import Flask
from flask_restful import reqparse, Resource, Api

import subprocess
import re
import time
import datetime
import json
import copy

import os
import subprocess

from MySQLdb import _mysql
import MySQLdb

STRICT_MON_MODE = 1
NORMAL_MON_MODE = 2

class DeviceUnderMonitor:
    def __init__(self, device_ip, mac_addr, device_name, mode):
        # dict to store all access record
        self.domain_name_access_record = {}
        # target access IP store by LPM TRIE
        # category by protocol, port, packet send out count,
        # timestamp
        self.target_ip_access_record = {"UDP": dict({}), "TCP": dict({})}
        self.lookup_target_ip = dict({})
        self.device_src_ip = copy.deepcopy(device_ip)
        self.device_mac_addr = copy.deepcopy(mac_addr)
        self.device_name = copy.deepcopy(device_name)
        self.lock = threading.Lock()
        if mode == "strict":
            self.mode = STRICT_MON_MODE
        else:
            self.mode = NORMAL_MON_MODE

    def is_strict_monitored(self):
        if self.mode == STRICT_MON_MODE:
            return True

        return False

    def update_out_traffic(self, target_ip, proto, port):
        """
        Update out traffic associate to this device
        """
        if proto == "UDP":
            self.lock.acquire()
            if target_ip in self.target_ip_access_record["UDP"]:
                if port in self.target_ip_access_record["UDP"][target_ip]:
                    self.target_ip_access_record["UDP"][target_ip][port] += 1
                else:
                    self.target_ip_access_record["UDP"][target_ip][port] = 1
            else:
                self.target_ip_access_record["UDP"][target_ip] = dict({port: 1})
            self.lock.release()
        elif proto == "TCP":
            self.lock.acquire()
            if target_ip in self.target_ip_access_record["TCP"]:
                if port in self.target_ip_access_record["TCP"][target_ip]:
                    self.target_ip_access_record["TCP"][target_ip][port] += 1
                else:
                    self.target_ip_access_record["TCP"][target_ip][port] = 1
            else:
                self.target_ip_access_record["TCP"][target_ip] = dict({port: 1})
            self.lock.release()

    def update_dns_lookup(self, name, ip):
        """
        Update dns lookup initiated by this device and record its target IPs
        """
        self.lock.acquire()
        id = len(self.domain_name_access_record)
        if not name in self.domain_name_access_record:
            self.domain_name_access_record[name] = dict({"ID": id, "Count": 1})
        else:
            id = self.domain_name_access_record[name]["ID"]
            self.domain_name_access_record[name]["Count"] += 1
        
        if not ip in self.lookup_target_ip:
            self.lookup_target_ip[ip] = id
        self.lock.release()

    def dump_details(self):
        """
        Print the details of under tracking Device access pattern
        """
        dump_result = {}
        # Basic info
        basic_info = {}
        basic_info["source_ip"] = self.device_src_ip
        basic_info["mac_addr"] = self.device_mac_addr
        basic_info["device_name"] = self.device_name
        basic_info["strict_mode"] = self.is_strict_monitored()

        dump_result["basic_info"] = basic_info

        # UDP
        udp_details = []
        self.lock.acquire()
        for target_ip in self.target_ip_access_record["UDP"]:
            udp_target = {}
            port_list = []
            for target_port in self.target_ip_access_record["UDP"][target_ip]:
                port_target = {}
                port_target[target_port] = self.target_ip_access_record["UDP"][target_ip][target_port]
                port_list.append(port_target)
            udp_target[target_ip] = port_list
            udp_details.append(udp_target)
        self.lock.release()
        dump_result["udp_details"] = udp_details

        # TCP
        tcp_details = []
        self.lock.acquire()
        for target_ip in self.target_ip_access_record["TCP"]:
            tcp_target = {}
            port_list = []
            for target_port in self.target_ip_access_record["TCP"][target_ip]:
                port_target = {}
                port_target[target_port] = self.target_ip_access_record["TCP"][target_ip][target_port]
                port_list.append(port_target)
            tcp_target[target_ip] = port_list
            tcp_details.append(tcp_target)
        self.lock.release()
        dump_result["tcp_details"] = tcp_details

        # Domain Names
        lookup_details = []
        self.lock.acquire()
        for name in self.domain_name_access_record:
            info = {}
            info[name] = self.domain_name_access_record[name]["Count"]
            lookup_details.append(info)
        self.lock.release()
        dump_result["lookup_details"] = lookup_details

        # Cross Reference 
        direct_udp_access_details = []
        self.lock.acquire()
        for target_ip in self.target_ip_access_record["UDP"]:
            if not target_ip in self.lookup_target_ip:
                direct_access = {}
                port_list = []
                for target_port in self.target_ip_access_record["UDP"][target_ip]:
                    info = {}
                    info["port"] = target_port
                    info["count"] = self.target_ip_access_record["UDP"][target_ip][target_port]
                    port_list.append(info)
                direct_access[target_ip] = port_list
                direct_udp_access_details.append(direct_access)
        self.lock.release()
        dump_result["direct_udp_access"] = direct_udp_access_details
        
        direct_tcp_access_details = []                
        self.lock.acquire()
        for target_ip in self.target_ip_access_record["TCP"]:
            if not target_ip in self.lookup_target_ip:
                direct_access = {}
                port_list = []
                for target_port in self.target_ip_access_record["TCP"][target_ip]:
                    info = {}
                    info["port"] = target_port
                    info["count"] = self.target_ip_access_record["TCP"][target_ip][target_port]
                    port_list.append(info)
                direct_access[target_ip] = port_list
                direct_tcp_access_details.append(direct_access)
        self.lock.release()
        dump_result["direct_tcp_access"] = direct_tcp_access_details

        return dump_result

    def restore_access_record(self):
        """
        Restore the access records 
        """
        access_record = self.dump_details()
        self.lock.acquire()
        self.target_ip_access_record.clear()
        self.lookup_target_ip.clear()

        self.target_ip_access_record = {"UDP": dict({}), "TCP": dict({})}
        self.lock.release()

        return self.device_src_ip, self.device_mac_addr, self.device_name, access_record

    def persist_in_db(self):
        """
        Persist the buffered tracking data to database
        """

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

class DynamicFWIntf:
    # Need to add share pre key to increase security, and switch to use https
    # current all security based on ipfw firewall access right, easy to be override
    def __init__(self):
        self.debug = False
        self.uri = "https://127.0.0.1:6466"
        self.psk = None
    
    def config_firewall_uri(self, firewall_endpoint):
        umbrella_firewall_uri = "https://127.0.0.1:6466"
        firewall_psk = None
        try:
            firewall_ip = firewall_endpoint["ip"]
            firewall_port = firewall_endpoint["port"]
            umbrella_firewall_uri = "https://{ip}:{port}".format(ip=firewall_ip, port=firewall_port)

            if "psk" in firewall_endpoint:
                firewall_psk = firewall_endpoint["psk"]
        except BaseException as e:
            print("wrong configuration of umbrella firewall ", e)

        self.uri = umbrella_firewall_uri
        self.psk = firewall_psk

    def add_host_to_strict_monitor(self, ip_addr):
        if self.psk:
            target_uri = "curl -k -X POST {uri}/add_strict_mon_host?\"ip_addr={addr}&psk={psk}\"".format(uri=self.uri, addr=ip_addr, psk=self.psk)
        else:
            target_uri = "curl -k -X POST {uri}/add_strict_mon_host?ip_addr={addr}".format(uri=self.uri, addr=ip_addr)
        status = os.system(target_uri)
        if status != 0:
            print("Add Host to Strict Monitor failed")

    def del_host_from_strict_monitor(self, ip_addr):
        if self.psk:
            target_uri = "curl -k -X POST {uri}/del_strict_mon_host?\"ip_addr={addr}&psk={psk}\"".format(uri=self.uri, addr=ip_addr, psk=self.psk)
        else:
            target_uri = "curl -k -X POST {uri}/del_strict_mon_host?ip_addr={addr}".format(uri=self.uri, addr=ip_addr)
        status = os.system(target_uri)
        if status != 0:
            print("Del Host from Strict Monitor failed")

    def list_host_from_strict_monitor(self):
        target_uri = "{uri}/list_strict_mon_host".format(uri=self.uri)
        list_host = subprocess.Popen(['curl', '-s', '-k', target_uri], stdout=subprocess.PIPE)
        output = list_host.stdout.readline().decode("utf-8")
        result = "" + output
        while output:
            output = list_host.stdout.readline().decode("utf-8")
            result = result + output
        
        return result

    def add_target_to_mon_host(self, mon_addr, ip_addr):
        if self.psk:
            target_uri = "curl -k -X POST {uri}/add_target_for_strict_host?\"mon_addr={m_addr}&ip_addr={i_addr}&psk={psk}\"".format(uri=self.uri, m_addr=mon_addr, i_addr=ip_addr, psk=self.psk)
        else:    
            target_uri = "curl -k -X POST {uri}/add_target_for_strict_host?\"mon_addr={m_addr}&ip_addr={i_addr}\"".format(uri=self.uri, m_addr=mon_addr, i_addr=ip_addr)       
        status = os.system(target_uri)
        if status != 0:
            print("Add allowed target IP to Strict Access Host failed")
            return False
        
        return True

    def del_target_from_mon_host(self, mon_addr, ip_addr):
        if self.psk:
            target_uri = "curl -k -X POST {uri}/del_target_for_strict_host?\"mon_addr={m_addr}&ip_addr={i_addr}&psk={psk}\"".format(uri=self.uri, m_addr=mon_addr, i_addr=ip_addr, psk=self.psk)
        else:
            target_uri = "curl -k -X POST {uri}/del_target_for_strict_host?\"mon_addr={m_addr}&ip_addr={i_addr}\"".format(uri=self.uri, m_addr=mon_addr, i_addr=ip_addr)
        status = os.system(target_uri)
        if status != 0:
            print("Del allowed target IP from Strict Access Host failed")
            return False
        
        return True

    def list_target_from_mon_host(self, mon_addr):
        target_uri = "{uri}/list_target_for_strict_host?mon_addr={m_addr}".format(uri=self.uri, m_addr=mon_addr)
        list_target = subprocess.Popen(['curl', '-s', '-k', target_uri], stdout=subprocess.PIPE)
        output = list_target.stdout.readline().decode("utf-8")
        result = "" + output
        while output:
            output = list_target.stdout.readline().decode("utf-8")
            result = result + output
        
        return result

    def clean_target_from_mon_host(self, mon_addr):
        if self.psk:
            target_uri = "curl -k -X POST {uri}/clean_target_for_strict_host?\"mon_addr={m_addr}&psk={psk}\"".format(uri=self.uri, m_addr=mon_addr, psk=self.psk)
        else:
            target_uri = "curl -k -X POST {uri}/clean_target_for_strict_host?mon_addr={m_addr}".format(uri=self.uri, m_addr=mon_addr)
        status = os.system(target_uri)
        if status != 0:
            print("Clean all allowed target IP from strict Access Host failed")
            return False
        return True

class Telescope:
    def __init__(self):
        # associate with device identification
        self.under_monitor = {}
        
        # RedEye
        self.redeye_mon_start = datetime.time(0, 0, 0)
        self.redeye_mon_end = datetime.time(6, 0, 0)
        self.redeye_monitor = {}
        self.redeye_lookup = {}

        self.neigh_entries = ArpEntries(dict({}))        

        self.lock = threading.Lock()
        self.under_out_traffic_monitor = False
        self.under_dns_traffic_monitor = False
        self.restore_log_activate = False
        self.neigh_change_monitor = False
        self.restore_log_path = "/var/log/telescope/"
        self.config = dict({"neigh_change_mon": dict({"enabled": False})})
        
        self.config = None
        self.under_nf_monitor = False

        # Input logs
        self.auditor_log_file = None 
        self.dns_log_file = None

        self.dmz_lock = threading.Lock()
        self.dmz_access_record = {"UDP": dict({}), 
                                  "TCP": dict({}),
                                  "ICMP": dict({})}
        self.fw_intf = DynamicFWIntf()

    def update_telescope_config(self, config_file):
        try:
            file = open(config_file, 'r')
            self.config = json.load(file)
            file.close()
        except:
            print("Not able to load config from ", config_file)

    def add_device(self, ip_addr, mode):
        if ip_addr in self.under_monitor:
            return False
        else:
            mac_addr = "Unknown"
            device_name = "Unknown"
            n_mac_addr, n_device_name = self.neigh_entries.get_dev(ip_addr)
            if n_mac_addr:
                mac_addr = copy.deepcopy(n_mac_addr)
            if n_device_name:
                device_name = copy.deepcopy(n_device_name)
            self.lock.acquire()
            self.under_monitor[ip_addr] = DeviceUnderMonitor(ip_addr, mac_addr, device_name, mode)
            self.lock.release()

            # strict monitor mode update for host 
            if self.under_monitor[ip_addr].is_strict_monitored():
                self.fw_intf.add_host_to_strict_monitor(ip_addr)

            return True

    def list_device(self):
        self.lock.acquire()
        dev_under_monitor = {}
        for ip_addr in self.under_monitor:
            mac_addr, device_name = self.neigh_entries.get_dev(ip_addr)
            data = {}
            data["status"] = "monitoring"
            if mac_addr:
                data["mac_addr"] = mac_addr
            if device_name:
                data["device"] = device_name
            dev_under_monitor[ip_addr] = data
        self.lock.release()
        return dev_under_monitor

    def del_device(self, ip_addr):
        need_del = False
        self.lock.acquire()
        if ip_addr in self.under_monitor:
            self.under_monitor.pop(ip_addr)
            need_del = True
        self.lock.release()

        if need_del:
            self.fw_intf.del_host_from_strict_monitor(ip_addr)
            return True

        return False

    def dump_device(self, ip_addr):
        dump_result = {}
        self.lock.acquire()
        if ip_addr in self.under_monitor:
            dump_result = self.under_monitor[ip_addr].dump_details()
        self.lock.release()
        return dump_result

    def dump_redeye(self):
        dump_result = {}
        self.lock.acquire()
        dump_result["traffic"] = self.redeye_monitor
        dump_result["lookup"] = self.redeye_lookup
        self.lock.release()
        
        return dump_result

    def dmz_details(self):
        dmz_access_result = {}
        self.dmz_lock.acquire()
        dmz_access_result["udp"] = self.dmz_access_record["UDP"]
        dmz_access_result["tcp"] = self.dmz_access_record["TCP"]
        self.dmz_lock.release()

        return dmz_access_result

    def analysis_log(self, log_file):
        """
        Loop process to monitoring traffic log
        """
        self.auditor_log_file = log_file
        try:
            auditor_log_process = subprocess.Popen(['tail', '-f', self.auditor_log_file], stdout=subprocess.PIPE)
            log_filter = re.compile("\[([\w\W]+)\] NAT OUT: <110>ipfw: ([\d]+) Nat ([\w]+) ([\d\.]+)\:([\d]+) ([\d\.]+):([\d]+) ([\w]+) via ([\w\d]+)", re.IGNORECASE)
        except BaseException as e:
            print("Not able to open NAT outing traffic log, NAT recording disabled with error  ", e)
            return

        while self.under_out_traffic_monitor:
            output = auditor_log_process.stdout.readline().decode("utf-8").strip()
            dnat_match = log_filter.match(output)
            if dnat_match:
                nat_dst_ip = dnat_match.group(6).strip()
                nat_src_ip = dnat_match.group(4).strip()
                nat_protocol = dnat_match.group(3).strip()
                nat_dst_port = dnat_match.group(7).strip()

                # Update the traffic under monitoring
                self.lock.acquire()
                if nat_src_ip in self.under_monitor:
                    self.under_monitor[nat_src_ip].update_out_traffic(nat_dst_ip, nat_protocol, nat_dst_port)
                self.lock.release()

                # Redeye link monitor 00:00 --> 06:00
                if datetime.datetime.now().time() > self.redeye_mon_start and datetime.datetime.now().time() < self.redeye_mon_end:
                    self.lock.acquire()
                    if nat_dst_ip in self.redeye_monitor:
                        if nat_src_ip in self.redeye_monitor[nat_dst_ip]:
                            if nat_protocol in self.redeye_monitor[nat_dst_ip][nat_src_ip]:
                                self.redeye_monitor[nat_dst_ip][nat_src_ip][nat_protocol][nat_dst_port] = datetime.datetime.now().isoformat()
                            else:
                                port = {}
                                port[nat_dst_port] = datetime.datetime.now().isoformat()
                                self.redeye_monitor[nat_dst_ip][nat_src_ip][nat_protocol] = port
                        else:
                            protocol = {}
                            port = {}
                            port[nat_dst_port] = datetime.datetime.now().isoformat()
                            protocol[nat_protocol] = port
                            self.redeye_monitor[nat_dst_ip][nat_src_ip] = protocol
                    else:
                        access_src = {}
                        protocol = {}
                        port = {}
                        port[nat_dst_port] = datetime.datetime.now().isoformat()
                        protocol[nat_protocol] = port
                        access_src[nat_src_ip] = protocol
                        self.redeye_monitor[nat_dst_ip] = access_src 
                    self.lock.release()

    def analysis_nw_pkt_mon(self, nw_pkt_mon_file):
        """
        Loop process to monitoring all DNS traffic captured by Umbrealla NW
        No tcpdump required 
        """
        monitored_dns_servers = dict({})
        try:
            self.dns_log_file = nw_pkt_mon_file["log_file"]
            for dns_server in nw_pkt_mon_file["dns_servers"]:
                monitored_dns_servers[dns_server] = True
            dns_pkt_process = subprocess.Popen(['tail', '-f', self.dns_log_file], stdout=subprocess.PIPE)
        except BaseException as e:
            print("Not able to open DNS packet monitor file, DNS packet monitor failed with error  ", e)
            return 

        while self.under_dns_traffic_monitor:
            output = dns_pkt_process.stdout.readline().decode("utf-8").strip()
            try:
                dns_pkt = json.loads(output)
                if dns_pkt["pkt_type"] == "dns_response":
                    dst_ip = dns_pkt["ip_header"]["dst"]
                    src_ip = dns_pkt["ip_header"]["src"]
                    if src_ip in monitored_dns_servers:
                        self.lock.acquire()
                        # For each records within DNS.RR
                        if dst_ip in self.under_monitor:
                            for r in dns_pkt["rrs"]:
                                records = r.split()
                                if records[3] == "A":
                                    self.under_monitor[dst_ip].update_dns_lookup(records[0], records[4])
                                    if self.under_monitor[dst_ip].is_strict_monitored():
                                        self.fw_intf.add_target_to_mon_host(dst_ip, records[4])
                        self.lock.release()
            except BaseException as e:
                print("Wrong format of the DNS packet recording  ", e)


    def analysis_tcpdump(self):
        """
        Loop process to monitoring all dns and filter according to Telescope config
        """
        dns_ans_filter = re.compile("([\d\.]+) > ([\d\.]+): ([\d]+) ([\d]+)\/([\d]+)\/([\d]+) ([\w\.\,\s\-]+) (\([\d]+\))", re.IGNORECASE)

        dns_ans_record_filter = re.compile("([\w\d\.\-]+\s[\w]+\s[\w\d\.\-]+)", re.IGNORECASE)
        dns_ans_record_split = re.compile("([\w\d\-\.]+)\s([\w]+)\s([\w\.\-]+)", re.IGNORECASE)

        ip_spliter = re.compile("(\d+\.\d+\.\d+\.\d+).(\d+)", re.IGNORECASE)

        dns_dump_process = subprocess.Popen(['tcpdump', '-vnnttl', '--immediate-mode', 'udp and host 192.168.10.84 and port 53 and not host 192.168.1.1'],
                                          stdout=subprocess.PIPE)

        while self.under_dns_traffic_monitor:
            output = dns_dump_process.stdout.readline().decode("utf-8").strip()
            dns_ans_match = dns_ans_filter.match(output)
            if dns_ans_match:
                src_ip = dns_ans_match.group(2)
                src_ip = src_ip[:src_ip.rfind('.')]

                self.lock.acquire()
                if src_ip in self.under_monitor:
                    if dns_ans_match.group(4):
                        ans_count = int(dns_ans_match.group(4))
                        if ans_count > 0:
                            answers = dns_ans_match.group(7)
                            if answers:
                                updated_ans_count = 0
                                for record in re.finditer(dns_ans_record_filter, answers):
                                    record_match = dns_ans_record_split.match(record.group(1))
                                    name = record_match.group(1)
                                    record_type = record_match.group(2)
                                    record_content = record_match.group(3)
                                    # Only update A record
                                    if record_type == "A":
                                        self.under_monitor[src_ip].update_dns_lookup(name, record_content)
                                        # If Host client under strict monitor, add the firewall allow access
                                        if self.under_monitor[src_ip].is_strict_monitored():
                                            self.fw_intf.add_target_to_mon_host(src_ip, record_content)
                                            #Timeout process need to remove the target IP
                                    updated_ans_count = updated_ans_count + 1
                
                # Redeye lookup

                self.lock.release()

    def analysis_nf(self):
        """
        All traffic initiated from DMZ or pass through DMZ will be audited by Linux builtin Netfilter
        """
        event_classify_re = re.compile("([NEW|UPDATE|DELETE|UNKNOW]+) ([\w]+) ([\w\W]+)", re.IGNORECASE)
        str_con_no_nat_re = re.compile("([\w]+) ([\d\.]+):([\d]+) <-> ([\d\.]+):([\d]+)", re.IGNORECASE)
        str_con_nat_re = re.compile("([\w]+) ([\d\.]+):([\d]+) -> ([\d\.]+):([\d]+) ([\d\.]+):([\d]+) <- ([\d\.]+):([\d]+)", re.IGNORECASE)

        packet_no_nat_re = re.compile("([\d\.]+):([\d]+) <-> ([\d\.]+):([\d]+)", re.IGNORECASE)
        packet_nat_re = re.compile("([\d\.]+):([\d]+) -> ([\d\.]+):([\d]+) ([\d\.]+):([\d]+) <- ([\d\.]+):([\d]+)", re.IGNORECASE)

        nf_dump_process = subprocess.Popen(['nf-ct-events'], stdout=subprocess.PIPE)
        while self.under_nf_monitor:
            output = nf_dump_process.stdout.readline().decode("utf-8").strip()
            event_need_analysis = event_classify_re.match(output)
            if event_need_analysis:
                operation = event_need_analysis.group(1)
                protocol = event_need_analysis.group(2)
                details = event_need_analysis.group(3)
                if protocol == "udp":
                    packet_details = packet_no_nat_re.match(details)
                    if packet_details:
                        src_ip = packet_details.group(1)
                        src_port = packet_details.group(2)
                        dst_ip = packet_details.group(3)
                        dst_port = packet_details.group(4)

                        # DNS lookup will be filter and record by DNS tcpdump monitor
                        if dst_port != "53" and dst_ip != "127.0.0.1":
                            self.dmz_lock.acquire()
                            if dst_ip in self.dmz_access_record["UDP"]:
                                if dst_port in self.dmz_access_record["UDP"][dst_ip]:
                                    if src_ip in self.dmz_access_record["UDP"][dst_ip][dst_port]:
                                        self.dmz_access_record["UDP"][dst_ip][dst_port][src_ip] += 1
                                    else:
                                        self.dmz_access_record["UDP"][dst_ip][dst_port][src_ip] = 1
                                else:
                                    self.dmz_access_record["UDP"][dst_ip][dst_port] = dict({src_ip: 1})
                            else:
                                access_list = dict({src_ip: 1})
                                self.dmz_access_record["UDP"][dst_ip] = dict({dst_port: access_list})
                            self.dmz_lock.release()
                    else:
                        nat_packet_details = packet_nat_re.match(details)
                        if nat_packet_details:
                            src_ip = nat_packet_details.group(1)
                            src_port = nat_packet_details.group(2)
                            dst_ip = nat_packet_details.group(3)
                            dst_port = nat_packet_details.group(4)

                            if dst_port != "53" and dst_ip != "127.0.0.1":
                                self.dmz_lock.acquire()
                                if dst_ip in self.dmz_access_record["UDP"]:
                                    if dst_port in self.dmz_access_record["UDP"][dst_ip]:
                                        if src_ip in self.dmz_access_record["UDP"][dst_ip][dst_port]:
                                            self.dmz_access_record["UDP"][dst_ip][dst_port][src_ip] += 1
                                        else:
                                            self.dmz_access_record["UDP"][dst_ip][dst_port][src_ip] = 1
                                    else:
                                        self.dmz_access_record["UDP"][dst_ip][dst_port] = dict({src_ip: 1})
                                else:
                                    access_list = dict({src_ip: 1})
                                    self.dmz_access_record["UDP"][dst_ip] = dict({dst_port: access_list})
                                self.dmz_lock.release()
                elif protocol == "tcp":
                    stream_details = str_con_no_nat_re.match(details)
                    if stream_details:
                        src_ip = stream_details.group(2)
                        src_port = stream_details.group(3)
                        dst_ip = stream_details.group(4)
                        dst_port = stream_details.group(5)
                        if dst_ip != "127.0.0.1":
                            self.dmz_lock.acquire()
                            if dst_ip in self.dmz_access_record["TCP"]:
                                if dst_port in self.dmz_access_record["TCP"][dst_ip]:
                                    if src_ip in self.dmz_access_record["TCP"][dst_ip][dst_port]:
                                        self.dmz_access_record["TCP"][dst_ip][dst_port][src_ip] += 1
                                    else:
                                        self.dmz_access_record["TCP"][dst_ip][dst_port][src_ip] = 1
                                else:
                                    self.dmz_access_record["TCP"][dst_ip][dst_port] = dict({src_ip: 1})
                            else:
                                access_list = dict({src_ip: 1})
                                self.dmz_access_record["TCP"][dst_ip] = dict({dst_port: access_list})
                            self.dmz_lock.release()
                    else:
                        nat_stream_details = str_con_nat_re.match(details)
                        if nat_stream_details:
                            src_ip = nat_stream_details.group(2)
                            src_port = nat_stream_details.group(3)
                            dst_ip = nat_stream_details.group(4)
                            dst_port = nat_stream_details.group(5)
                            if dst_ip != "127.0.0.1":
                                self.dmz_lock.acquire()
                                if dst_ip in self.dmz_access_record["TCP"]:
                                    if dst_port in self.dmz_access_record["TCP"][dst_ip]:
                                        if src_ip in self.dmz_access_record["TCP"][dst_ip][dst_port]:
                                            self.dmz_access_record["TCP"][dst_ip][dst_port][src_ip] += 1
                                        else:
                                            self.dmz_access_record["TCP"][dst_ip][dst_port][src_ip] = 1
                                    else:
                                        self.dmz_access_record["TCP"][dst_ip][dst_port] = dict({src_ip: 1})
                                else:
                                    access_list = dict({src_ip: 1})
                                    self.dmz_access_record["TCP"][dst_ip] = dict({dst_port: access_list})
                                self.dmz_lock.release()

    def restore_log(self):
        while self.restore_log_activate:
            if datetime.datetime.now().time().hour == 9:
                # Dump access records per day 9:00 AM
                dmz_records = self.dmz_details()
                redeye_records = self.dump_redeye()
                # clearn access 
                self.dmz_lock.acquire()
                self.dmz_access_record.clear()
                self.dmz_access_record = {"UDP": dict({}), 
                                          "TCP": dict({}),
                                          "ICMP": dict({})}
                self.dmz_lock.release()
                
                self.lock.acquire()
                self.redeye_monitor.clear()
                self.redeye_lookup.clear()
                self.lock.release()
                # restore access records to folder
                dmz_file_name = "dmz_access_{timestamp}.log".format(timestamp=datetime.datetime.now().strftime('%m-%d-%Y'))
                with open("{dir}/{file}".format(dir=self.restore_log_path, file=dmz_file_name), "w") as outputfile:
                    json.dump(dmz_records, outputfile)

                redeye_file_name = "redeye_access_{timestamp}.log".format(timestamp=datetime.datetime.now().strftime('%m-%d-%Y'))
                with open("{dir}/{file}".format(dir=self.restore_log_path, file=redeye_file_name), "w") as outputfile:
                    json.dump(redeye_records, outputfile)


                self.lock.acquire()
                for dev in self.under_monitor.values():
                    dev_src_ip, dev_mac, dev_name, record = dev.restore_access_record()
                    dev_file_name = "{src_ip}_{mac}_{name}_{timestamp}.log".format(src_ip=dev_src_ip, mac=dev_mac, name=dev_name, timestamp=datetime.datetime.now().strftime('%m-%d-%Y'))                    
                    with open("{dir}/{file}".format(dir=self.restore_log_path, file=dev_file_name), "w") as outputfile:
                        json.dump(record, outputfile)
                self.lock.release()

            time.sleep(60*60)

    def neigh_change_mon(self):
        """
        Monitoring the ARP/IP Neighbour table, check is the device a registered device, if the device is unknow
        Direct put under telescope strict monitoring mode.
            Disable GFW bypass
            Record Access
            Use DoH DNS proxy for its name resolution
        """
        db_config = self.config["neigh_change_mon"]["router_service_db"]
        if "db" in db_config and "user" in db_config and "password" in db_config:
            router_db = _mysql.connect(host="localhost", user=db_config["user"], 
                password=db_config["password"], 
                database=db_config["db"])
        else:
            print("Not correct configuration within neigh_change_mon ", db_config)
            return 

        # 30 mins STALE without refresh, it works as if the database updated the device
        # it will remove the device from strict monitor mode
        # {
        #     "ip mac": { "registered": true, "timestamp": "datetime", "status": "reachable/stale" }  
        # }
        ip_neigh_cache_mon = dict({})

        ip_neigh_mon = subprocess.Popen(['ip', 'monitor', 'neigh'], stdout=subprocess.PIPE)
        ip_neigh_event_filter = re.compile("([\d\.]+) dev ([\w]+) ([\w]+) ([\w\:]+) ([\w]+)", re.IGNORECASE)
        while self.neigh_change_monitor:
            arp_mon_update = ip_neigh_mon.stdout.readline().decode("utf-8").strip()
            arp_match = ip_neigh_event_filter.match(arp_mon_update)
            if arp_match:
                ip_addr = arp_match.group(1)
                intf = arp_match.group(2)
                proto = arp_match.group(3)
                mac_addr = arp_match.group(4)
                status = arp_match.group(5)
                ip_mac_pair = "{ip} {mac}".format(ip=ip_addr, mac=mac_addr)
                if status == "REACHABLE":
                    if not ip_mac_pair in ip_neigh_cache_mon:
                        query_str = "select comments from dhcp_leases where mac_addr=\"{mac}\" and ip_addr=\"{ip}\"".format(mac=mac_addr, ip=ip_addr)
                        try:
                            router_db.query(query_str)

                            lease_info = router_db.store_result()
                            dev_register_info = lease_info.fetch_row()
                            if dev_register_info:
                                dev_status = dev_register_info[0][0].decode("utf-8")
                                if dev_status == "Unknown":
                                    ip_neigh_cache_mon[ip_mac_pair] = dict({
                                        "registered": False,
                                        "timestamp": datetime.datetime.now().strftime('%m-%d-%Y %H:%M%S'),
                                        "status": "reachable"
                                    })
                                else:
                                    ip_neigh_cache_mon[ip_mac_pair] = dict({
                                        "registered": True,
                                        "timestamp": datetime.datetime.now().strftime('%m-%d-%Y %H:%M%S'),
                                        "status": "reachable"
                                    })
                                    print("Registered Device ", ip_mac_pair, " up ", ip_neigh_cache_mon[ip_mac_pair])
                            else:
                                ip_neigh_cache_mon[ip_mac_pair] = dict({
                                    "registered": False,
                                    "timestamp": datetime.datetime.now().strftime('%m-%d-%Y %H:%M%S'),
                                    "status": "reachable"
                                })
                        except (MySQLdb.Error, MySQLdb.Warning) as e:
                            router_db = _mysql.connect(host="localhost", user=db_config["user"], 
                                            password=db_config["password"], 
                                            database=db_config["db"]) 
                            
                            print("Query failed with error ", e)                           
                        
                        # Device discovered in IP neigh table, without registered to database lease table
                        if ip_mac_pair in ip_neigh_cache_mon:
                            if ip_neigh_cache_mon[ip_mac_pair]["registered"] == False:
                                self.add_device(ip_addr, "strict")
                                print("Unregistered Device ", ip_mac_pair, " up ", ip_neigh_cache_mon[ip_mac_pair], "Under strict monitoring of its device access")

                elif status == "STALE":
                    if ip_mac_pair in ip_neigh_cache_mon:
                        ip_neigh_cache_mon[ip_mac_pair]["status"] = "stable"
                        ip_neigh_cache_mon[ip_mac_pair]["timestamp"] = datetime.datetime.now().strftime('%m-%d-%Y %H:%M%S')
                    

    def start_mon(self, config_file):
        try:
            file = open(config_file, 'r')
            self.config = json.load(file)
            file.close()
        except BaseException as e :
            print("No workable configuration used ", e)
            sys.exit()
        
        if "umbrella_firewall_endpoint" in self.config:
            self.fw_intf.config_firewall_uri(self.config["umbrella_firewall_endpoint"])

        if "known_devices_list" in self.config:
            # Neighbour Info
            self.neigh_entries = ArpEntries(load_device_list(self.config["known_devices_list"]))
            self.neigh_entries.start_mon()

        # port 8483 = TS short for Telescope
        if "input_logs" in self.config:
            if "analysis_log" in self.config["input_logs"]:
                self.under_out_traffic_monitor = True
                self.log_mon_th = threading.Thread(name="out traffic mon", target=self.analysis_log, args=[self.config["input_logs"]["analysis_log"]])
                self.log_mon_th.start()

        if not self.under_out_traffic_monitor:
            print("WARNING: Main out traffic monitor misconfigured, check configuration ", self.config)
            print("Require to proper configure inpput_logs:analysis_log section")

        # Check if Umbrella NW enabled to parse log from configured inputs  
        if "input_logs" in self.config:
            if "nw_dns_log" in self.config["input_logs"]:
                self.dns_mon_th = threading.Thread(name="dns_mon", target=self.analysis_nw_pkt_mon, args=[self.config["input_logs"]["nw_dns_log"]])
                self.dns_mon_th.start()
                self.under_dns_traffic_monitor = True

        if not self.under_dns_traffic_monitor: 
            self.dns_mon_th = threading.Thread(name="dns mon", target=self.analysis_tcpdump)
            self.dns_mon_th.start()
            self.under_dns_traffic_monitor = True

        self.under_nf_monitor = True
        self.nf_mon_th = threading.Thread(name="nf mon", target=self.analysis_nf)
        self.nf_mon_th.start()

        self.restore_log_activate = True
        self.restore_th = threading.Thread(name="restore log", target=self.restore_log)
        self.restore_th.start()

        if self.config["neigh_change_mon"] and "enabled" in self.config["neigh_change_mon"] and "router_service_db" in self.config["neigh_change_mon"]:
            if self.config["neigh_change_mon"]["enabled"]:
                self.neigh_change_monitor = True
                self.neigh_th = threading.Thread(name="neigh mon", target=self.neigh_change_mon)
                self.neigh_th.start()

        print("Start to monitoring system...")

telescope = Telescope()

parser = reqparse.RequestParser()
parser.add_argument('ip_addr', type=str, location='args')
parser.add_argument('mode', type=str, location='args')

class AddDevice(Resource):
    def get(self):
        return {'usage': "POST to add device IP under monitor"}
    def post(self):
        """
        Post add device IP under monitor
        """
        add_ip_addr = parser.parse_args()['ip_addr']
        add_ip_mode = parser.parse_args()['mode']
        if add_ip_addr:
            mode = "normal"
            if add_ip_mode:
                mode = add_ip_mode
            result = telescope.add_device(add_ip_addr, mode)
            if result:
                return {'result': "add device {ip} to monitor success {mode}".format(ip=add_ip_addr, mode=mode)}
            else:
                return {'result': "device {ip} already under monitor".format(ip=add_ip_addr)}

class ListDevice(Resource):
    def get(self):
        """
        List all devices under telescope monitoring
        """
        dev_under_mon = telescope.list_device()
        return {'result': "success", 
                'devices': dev_under_mon}

class DelDevice(Resource):
    def get(self):
        return {'usage': "POST to delete device IP under monitor"}
    def post(self):
        """
        POST del device IP under monitor
        """
        del_ip_addr = parser.parse_args()['ip_addr']
        if del_ip_addr:
            telescope.del_device(del_ip_addr)
            return {'result': "delete device {ip} from monitor success".format(ip=del_ip_addr)}

class DumpDevice(Resource):
    def get(self):
        return {'usage': "POST to dump device details under monitor"}
    def post(self):
        """
        POST dump device monitoring details
        """
        dump_ip_addr = parser.parse_args()['ip_addr']
        if dump_ip_addr:
            dump_result = telescope.dump_device(dump_ip_addr)
            return {'result': "success", "details": dump_result}

class DumpRedeye(Resource):
    def get(self):
        dump_result = telescope.dump_redeye()
        return {'result': 'success', "details": dump_result}

class DMZAccess(Resource):
    def get(self):
        dmz_access_result = telescope.dmz_details()
        return {'result': 'success', 'details': dmz_access_result}

app = Flask(__name__)
api = Api(app)

api.add_resource(AddDevice, '/add_device')
api.add_resource(DelDevice, '/del_device')
api.add_resource(ListDevice, '/list_device')
api.add_resource(DumpDevice, '/dump_device')
api.add_resource(DumpRedeye, '/dump_redeye')
api.add_resource(DMZAccess, '/dmz_details')


if __name__ ==  '__main__':
    config_file = "/etc/umbrella/telescope/telescope.conf"

    if sys.argv[1]:
        config_file = sys.argv[1]

    telescope.start_mon(config_file)
    
    app.run(ssl_context='adhoc', port=8483)

    while True:
        time.sleep(10)
