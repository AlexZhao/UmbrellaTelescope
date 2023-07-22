#!/usr/bin/python
# Apache 2.0
# Copyright 2021-2023 Zhao Zhe (Alex)
# Python Script to Monitor all remote IP address outbound link
# which syslog-ng from FreeBSD main router and insert the all 
# links destination IP/Source Pair to MySQL with its frequency
# and updated nearest timestamp
# Just A slow home use prototype to enhance my home wifi router   
#
import re;
import subprocess;

from datetime import datetime;

from MySQLdb import _mysql;
import MySQLdb;

class AuditorDestination(object):
    """
    Python based auditor based on syslog, on FreeBSD main router it use ipfw to write all traffic 
    link built up to syslog which received by this Linux DMZ host, all log processed within this VM
    """

    def __init__(self):
        """
        Initialization Python Based syslog destination to log all traffic from FreeBSD router's syslog-ng 
        """
        self.debug = False
        self.service_monitor_db = _mysql.connect(host="localhost", user="auditor", password="?", database="RouterServiceMonitor")
        self.out_traffic_db = _mysql.connect(host="localhost", user="auditor", password="?", database="OutTrafficMonitor")
        self._is_opened = False
        self.dev_config_file = "/etc/syslog-ng/python/known_device.list"
        self.log_file = open("/var/log/auditor_python.log", 'w')
        self.traffic_filter = re.compile("([\w\W]+)ipfw: (\d+) (\w+) (\w+) ([\d+\.]+):(\d+) ([\d+\.]+):(\d+) (\w+) (\w+) ([\w\d]+)", re.IGNORECASE)
        self.arp_filter = re.compile("^\? \((\d+\.\d+\.\d+\.\d+)\) at ((\w+\:\w+\:\w+\:\w+\:\w+\:\w+) \[ether\]|(<\w+>)) on (\w+)", re.IGNORECASE)
        self.dhcp_filter = re.compile("DHCP(\w+)\((\w+)\) ([\d+\.]+) ([\d+\w+\:]+)")
        self.device_mac_pair = {"00:a0:98:0c:5a:8b":"DMZ Controller"}
        self.device_ignore = {}


    def print_log(self, msg):
        self.log_file.write(msg)
        self.log_file.write("\r\n")
        self.log_file.flush()

    def printdebug(self, msg):
        """
        Print debug message for debug enabled
        """
        if self.debug:
            self.print_log(msg)

    def load_device_list(self):
        device_list_filter = re.compile("([\w\:]+)[ \t]+\"([\w\W]+)\"\s*(\w+)*", re.IGNORECASE)
        f = open(self.dev_config_file, "r")
        lines = f.readlines()
        for line in lines:
            device_match = device_list_filter.match(line)
            if device_match:
                if device_match.group(1) and device_match.group(2):
                    mac_addr = device_match.group(1)
                    device_name = device_match.group(2)
                    self.device_mac_pair[mac_addr] = device_name
                    if device_match.group(3):
                        if device_match.group(3) == "ignore":
                            self.device_ignore[mac_addr] = True 

    def init(self, options):
        """
        Initialize Mysql Database Connection
        """
        self.load_device_list()

        try: 
            self.service_monitor_db.query("select version();")
        except:
            self.service_monitor_db = _mysql.connect(host="localhost", user="auditor", password="?", database="RouterServiceMonitor")
        
        try:
            self.out_traffic_db.query("select version();")
        except:
            self.out_traffic_db = _mysql.connect(host="localhost", user="auditor", password="?", database="OutTrafficMonitor")
        
        return True

    def is_opened(self):
        """
        Checks if destination is available
        """
        return self._is_opened

    def open(self):
        """
        Open Connection to Mysql Database for record traffic
        """
        self.load_device_list()

        try: 
            self.service_monitor_db.query("select version();")
        except:
            self.service_monitor_db = _mysql.connect(host="localhost", user="auditor", password="?", database="RouterServiceMonitor")
        
        try:
            self.out_traffic_db.query("select version();")
        except:
            self.out_traffic_db = _mysql.connect(host="localhost", user="auditor", password="?", database="OutTrafficMonitor")

        self._is_opened = True
        return True


    def close(self):
        """
        Close Mysql Database Connection
        """
        self.service_monitor_db.close()
        self.out_traffic_db.close()
        self._is_opened = False

    def deinit(self):
        """
        Deinitialization of Python based destination
        """
        self.service_monitor_db.close()
        self.out_traffic_db.close()

    def send(self, msg):
        """
        Analysis the received FreeBSD main router traffic log, and record it in mysql database for
        further audit its connection period.
        """
        decoded_msg = msg['MESSAGE'].decode('utf-8')

        matches = self.traffic_filter.match(decoded_msg)
        if matches:
            op = matches.group(3)
            proto = matches.group(4)
            src_ip = matches.group(5)
            src_port = matches.group(6)
            dst_ip = matches.group(7)
            dst_port = matches.group(8)
            direct = matches.group(9)
            way = matches.group(10)
            device = matches.group(11)

            mac_addr = "Unknown"

            arp_process = subprocess.Popen(['arp', '-an', src_ip],
                                    stdout=subprocess.PIPE)
            arp_output = arp_process.stdout.readline()
            arp_match = self.arp_filter.match(arp_output.decode("utf-8"))
            if arp_match:
                mac_addr = arp_match.group(3)

            device_comment = "Unknown"
            if mac_addr in self.device_mac_pair:
                device_comment = self.device_mac_pair[mac_addr]

            # There shall be no access to 192.168.10.1 through re0
            # except ntp, DNS be redirect to 84
            if device == "re0":
                if direct == "in" and dst_ip == "192.168.10.1":
                    query_str = "insert into alert_access values (0, \"\", \"{ip}\", \"{dst_ip}\", \"{dst_port}\", current_timestamp, \"{comments}\");".format(ip=src_ip, dst_ip=dst_ip, dst_port=dst_port, comments=device_comment)
                    try:
                        self.printdebug(query_str)
                        self.service_monitor_db.query(query_str)
                    except:
                        self._is_opened = False
                    return True

            if direct == "in" and device == "bridge0":
                # FreeBSD main router provided service
                query_str = "" 
                if dst_ip == "192.168.10.1" and src_ip != "192.168.10.1":
                    if proto == "TCP":
                        # HTTPS management
                        if dst_port == "443" or dst_port == "80":
                            check_existed_str = "select * from management_service where mac_address=\"{mac_addr}\" and ip_address=\"{ip}\";".format(mac_addr=mac_addr, ip=src_ip)
                            self.service_monitor_db.query(check_existed_str)
                            r = self.service_monitor_db.store_result()
                            if r.fetch_row():
                                query_str = "update management_service set counts = counts + 1, last_lookup=current_timestamp where mac_address=\"{mac_addr}\" and ip_address=\"{ip}\";".format(mac_addr=mac_addr, ip=src_ip)
                            else:
                                query_str = "insert into management_service values (0, \"{mac_addr}\", \"\", 1, current_timestamp, \"{ip}\");".format(mac_addr=mac_addr, ip=src_ip) 
                        # SMB service
                        elif dst_port == "445" or dst_port == "139":
                            check_existed_str = "select * from smb_service where mac_address=\"{mac_addr}\" and ip_address=\"{ip}\";".format(mac_addr=mac_addr, ip=src_ip)
                            self.service_monitor_db.query(check_existed_str)
                            r = self.service_monitor_db.store_result()
                            if r.fetch_row():
                                query_str = "update smb_service set counts = counts + 1, last_lookup=current_timestamp where mac_address=\"{mac_addr}\" and ip_address=\"{ip}\";".format(mac_addr=mac_addr, ip=src_ip)
                            else:
                                query_str = "insert into smb_service values (0, \"{mac_addr}\", \"{comments}\", 1, current_timestamp, \"{ip}\");".format(mac_addr=mac_addr, comments=device_comment, ip=src_ip)
                        # iSCSI service
                        elif dst_port == "3260":
                            check_existed_str = "select * from iscsi_service where mac_address=\"{mac_addr}\" and ip_address=\"{ip}\";".format(mac_addr=mac_addr, ip=src_ip)
                            self.service_monitor_db.query(check_existed_str)
                            r = self.service_monitor_db.store_result()
                            if r.fetch_row():
                                query_str = "update iscsi_service set counts = counts + 1, last_lookup=current_timestamp where mac_address=\"{mac_addr}\" and ip_address=\"{ip}\";".format(mac_addr=mac_addr, ip=src_ip)
                            else:
                                query_str = "insert into iscsi_service values (0, \"{mac_addr}\", \"{comments}\", 1, current_timestamp, \"{ip}\");".format(mac_addr=mac_addr, comments=device_comment, ip=src_ip)
                        # Sock5 Proxy
                        elif dst_port == "1080":
                            check_existed_str = "select * from sock5_service where mac_address=\"{mac_addr}\" and ip_address=\"{ip}\";".format(mac_addr=mac_addr, ip=src_ip)
                            self.service_monitor_db.query(check_existed_str)
                            r = self.service_monitor_db.store_result()
                            if r.fetch_row():
                                query_str = "update sock5_service set counts = counts + 1, last_lookup=current_timestamp where mac_address=\"{mac_addr}\" and ip_address=\"{ip}\";".format(mac_addr=mac_addr, ip=src_ip)
                            else:
                                query_str = "insert into sock5_service values (0, \"{mac_addr}\", \"{comments}\", 1, current_timestamp, \"{ip}\");".format(mac_addr=mac_addr, comments=device_comment, ip=src_ip)
                        else:
                            self.print_log("Unknown Access {msg}".format(msg=decoded_msg))
                            return True
                    elif proto == "UDP":
                        # NTP
                        self.print_log(decoded_msg)
                elif dst_ip != "192.168.10.1" and src_ip != "192.168.10.1" and "192.168.10." in dst_ip and "192.168.10." in src_ip:
                    # Internal network cross access
                    query_str = "insert into alert_access values (0, \"{mac_addr}\", \"{ip}\", \"{dst_ip}\", \"{dst_port}\", current_timestamp, \"{comments}\");".format(mac_addr=mac_addr, ip=src_ip, dst_ip=dst_ip, dst_port=dst_port, comments=device_comment)

                if query_str != "":
                    try:
                        self.printdebug(query_str)
                        self.service_monitor_db.query(query_str)
                    except:
                        self._is_opened = False
                    return True
                else:
                    self.printdebug("op={op} proto={proto} src_ip={src_ip} src_port={src_port} dst_ip={dst_ip} dst_port={dst_port} direct={direct} way={way} device={device}"
                            .format(op=op, proto=proto, src_ip=src_ip, src_port=src_port, dst_ip=dst_ip, dst_port=dst_port, direct=direct, way=way, device=device))
            else:
                self.printdebug("op={op} proto={proto} src_ip={src_ip} src_port={src_port} dst_ip={dst_ip} dst_port={dst_port} direct={direct} way={way} device={device}"
                    .format(op=op, proto=proto, src_ip=src_ip, src_port=src_port, dst_ip=dst_ip, dst_port=dst_port, direct=direct, way=way, device=device))

            # Nat traffic out through main router, record all target IP addresses which referenced from internal network
            if op == "Nat":
                self.print_log("[{timestamp}] NAT OUT: {msg}".format(timestamp=datetime.now().isoformat(), msg=decoded_msg))
            else:
                self.printdebug("op={op} proto={proto} src_ip={src_ip} src_port={src_port} dst_ip={dst_ip} dst_port={dst_port} direct={direct} way={way} device={device}"
                    .format(op=op, proto=proto, src_ip=src_ip, src_port=src_port, dst_ip=dst_ip, dst_port=dst_port, direct=direct, way=way, device=device))                    
        else:
            dhcp_matches = self.dhcp_filter.match(decoded_msg)
            if dhcp_matches:
                dhcp_type = dhcp_matches.group(1)
                dhcp_dev = dhcp_matches.group(2)
                client_ip = dhcp_matches.group(3)
                client_mac = dhcp_matches.group(4)

                if dhcp_dev != "bridge0":
                    self.print_log("Alert DHCP not on internal device bridge0")
                    self.print_log(decoded_msg)
                else:
                    update_dhcp_lease = False
                    check_existed_lease = "select * from dhcp_leases where mac_addr=\"{mac_addr}\" and ip_addr=\"{ip_addr}\";".format(mac_addr=client_mac, ip_addr=client_ip)
                    self.service_monitor_db.query(check_existed_lease)
                    r = self.service_monitor_db.store_result()
                    if r.fetch_row():
                        update_dhcp_lease = True                        
                    else:
                        update_dhcp_lease = False
                    
                    if dhcp_type == "ACK" or dhcp_type == "OFFER":
                        device_comment = "Unknown"
                        if client_mac in self.device_mac_pair:
                            device_comment = self.device_mac_pair[client_mac]

                        if update_dhcp_lease:
                            # refresh lease
                            update_existed_lease = "update dhcp_leases set lease_start=current_timestamp, lease_end=timestampadd(hour, 1, current_timestamp), state=\"Refresh lease\" where mac_addr=\"{mac_addr}\" and ip_addr=\"{ip_addr}\";".format(mac_addr=client_mac, ip_addr=client_ip)
                            self.service_monitor_db.query(update_existed_lease)
                        else:
                            # new lease
                            new_lease = "insert into dhcp_leases values (0, \"{mac_addr}\", \"{ip_addr}\", current_timestamp, timestampadd(hour, 1, current_timestamp), \"{comment}\", \"New lease\");".format(mac_addr=client_mac, ip_addr=client_ip, comment=device_comment)
                            self.service_monitor_db.query(new_lease)
            else:    
                self.print_log(decoded_msg)

        return True
