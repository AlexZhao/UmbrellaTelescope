#!/usr/bin/python
# Apache 2.0
# Copyright 2021-2023 Zhao Zhe(Alex)
# LPM TRIE tree based NAT destination recording
# LPM TRIE tree based source IP address tree associate
# with NAT destination tree
# Not use MySQL for its slow performance and costly in CPU load
import sys;
import re;
import subprocess;

from arp_entries.arp_entries import ArpEntries;

from MySQLdb import _mysql;
import MySQLdb;

from datetime import date;

# Table needs to update
#     nat_out_dst_ips;
#     nat_src_ips;
def update_daily_access_report_to_db(access_rec):
    try:
        db = _mysql.connect(host="localhost", user="auditor", password="?", database="OutTrafficMonitor")
        for target_ip in access_rec_tree:
            for src_ip in access_rec_tree[target_ip]:
                for proto in access_rec_tree[target_ip][src_ip]:
                    for port in access_rec_tree[target_ip][src_ip][proto]:
                        try:
                            query_cmd = "select * from nat_out_dst_ips where ip=\"{dst_ip}\" and protocol=\"{proto}\" and port={port}".format(dst_ip=target_ip, proto=proto, port=port)
                            db.query(query_cmd)
                        
                            r = db.store_result()
                            dst_id_row = r.fetch_row()
                            if not dst_id_row:
                                insert_cmd = "insert into nat_out_dst_ips values (\"{dst_ip}\", {port}, 0, current_timestamp, \"{proto}\")".format(dst_ip=target_ip, port=port, proto=proto)
                                db.query(insert_cmd)
                            else:
                                dst_id = int(dst_id_row[0][2])
                                update_cmd = "update nat_out_dst_ips set latest_access=current_timestamp where ip=\"{dst_ip}\" and protocol=\"{proto}\" and port={port}".format(dst_ip=target_ip, proto=proto, port=port)
                                db.query(update_cmd)

                                query_cmd = "select packets_cnt from nat_src_ips where dst_id={dst_id} and src_ip=\"{src_ip}\"".format(dst_id=dst_id, src_ip=src_ip)
                                db.query(query_cmd)

                                r = db.store_result()
                                packets = r.fetch_row()
                                if not packets:
                                    insert_cmd = "insert into nat_src_ips values ({dst_id}, \"{src_ip}\", {packets_cnt})".format(dst_id=dst_id, src_ip=src_ip, packets_cnt=access_rec_tree[target_ip][src_ip][proto][port])
                                    db.query(insert_cmd)
                                    access_rec_tree[target_ip][src_ip][proto][port] = 0
                                else:
                                    # reset packets snd count to 0
                                    packets_cnt = int(packets[0][0])
                                    packets_cnt = packets_cnt + access_rec_tree[target_ip][src_ip][proto][port]
                                    update_cmd = "update nat_src_ips set packets_cnt={packets_cnt} where dst_id={dst_id} and src_ip=\"{src_ip}\"".format(packets_cnt=packets_cnt, dst_id=dst_id, src_ip=src_ip)
                                    db.query(update_cmd)
                                    access_rec_tree[target_ip][src_ip][proto][port] = 0
                        except (MySQLdb.Error, MySQLdb.Warning) as e:
                            print("error happened during update database table ", e)
                            db = _mysql.connect(host="localhost", user="auditor", password="?", database="OutTrafficMonitor")
    except (MySQLdb.Error, MySQLdb.Warning) as e:
        print("wrong during query database error ", e, "reconnecting")
        db = _mysql.connect(host="localhost", user="auditor", password="?", database="OutTrafficMonitor")

if __name__ == '__main__':
    auditor_log_file = ""
    debug = False

    if sys.argv[1]:
        auditor_log_file = sys.argv[1]

    auditor_log_process = subprocess.Popen(['tail', '-f', auditor_log_file], stdout=subprocess.PIPE)
    access_rec_tree = dict({})

    log_filter = re.compile("\[([\w\W]+)\] NAT OUT: <110>ipfw: ([\d]+) Nat ([\w]+) ([\d\.]+)\:([\d]+) ([\d\.]+):([\d]+) ([\w]+) via ([\w\d]+)", re.IGNORECASE)

    current_date = date.today()
    
    arp_entries = ArpEntries({})
    arp_entries.start_mon()

    count = 0
    # Every Day update the recorded access to mysql database
    while True:
        output = auditor_log_process.stdout.readline().decode("utf-8").strip();
        dnat_match = log_filter.match(output)
        if dnat_match:
            nat_dst_ip = dnat_match.group(6).strip()
            nat_src_ip = dnat_match.group(4).strip()
            nat_protocol = dnat_match.group(3).strip()
            nat_dst_port = dnat_match.group(7).strip()

            if debug:
                count = count + 1

            if access_rec_tree.has_key(nat_dst_ip):
                if access_rec_tree[nat_dst_ip].has_key(nat_src_ip):
                    if nat_protocol in access_rec_tree[nat_dst_ip][nat_src_ip]:
                        if  nat_dst_port in access_rec_tree[nat_dst_ip][nat_src_ip][nat_protocol]:
                            access_rec_tree[nat_dst_ip][nat_src_ip][nat_protocol][nat_dst_port] += 1
                        else:
                            access_rec_tree[nat_dst_ip][nat_src_ip][nat_protocol][nat_dst_port] = 1
                    else:
                        access_rec_tree[nat_dst_ip][nat_src_ip][nat_protocol] = dict({nat_dst_port: 1})
                else:
                    protocols = {}
                    protocols[nat_protocol] = dict({nat_dst_port: 1})
                    access_rec_tree[nat_dst_ip].insert(nat_src_ip, protocols)
            else:
                nat_src_tree = dict({})
                protocols = {}
                protocols[nat_protocol] = dict({nat_dst_port: 1})
                nat_src_tree.insert(nat_src_ip, protocols)
                access_rec_tree.insert(nat_dst_ip, nat_src_tree)                

        if debug and count == 100:
            print("Debug Mode update mysql database")
            update_daily_access_report_to_db(access_rec_tree)
            count = 0
        else:
            if date.today() > current_date:
                print("Update access record to db for date changes from ", current_date, " to ", date.today())
                current_date = date.today()
                update_daily_access_report_to_db(access_rec_tree)

