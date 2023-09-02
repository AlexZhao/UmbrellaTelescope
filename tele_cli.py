#!/usr/bin/python
# Apache 2.0
# Copyright 2012-2023 Zhao Zhe(Alex)
# 
# Telescope Command Line interface
#
# Command line to operate with telescope
#   add  device to monitoring list
#   del  device from monitoring list
#   list  all current under monitoring devices
import click
import ipaddress

import subprocess

CONTEXT_SETTINGS = dict(
    default_map={
        'add': {},
        'delete': {},
        'list': {},
        'dump': {},
        'redeye': {},
        'dmz': {},
    }
)

TELE_URI = "https://127.0.0.1:8483"

@click.group(context_settings=CONTEXT_SETTINGS)
def tele_cli():
    pass

@tele_cli.command()
@click.option('--ip')
@click.option('--mode', default="normal")
def add(ip, mode):
    """Add Device IP to Telescope Monitoring list"""
    # curl -X POST http://127.0.0.1:8483/add_device?ip_addr=192.168.10.124
    try:

        try_ip = ipaddress.ip_address(ip)
        tel_mode = "normal"
        if mode == "strict":
            tel_mode = "strict"
        curl_str = "{tele_uri}/add_device?ip_addr={ip}&mode={mode}".format(tele_uri=TELE_URI, ip=ip, mode=tel_mode)
        add_target_ip_to_tele = subprocess.Popen(['curl', '-s', '-X', 'POST', curl_str], stdout=subprocess.PIPE)
        output = add_target_ip_to_tele.stdout.readline().decode("utf-8")
        while output:
            print(output)
            output = add_target_ip_to_tele.stdout.readline().decode("utf-8")
    except:
        click.echo("Add Device IP to Telescope Monitoring list Failed %s" %ip)

@tele_cli.command()
@click.option('--ip')
def delete(ip):
    """Delete Device IP from Telescope Monitoring list"""
    try:
        try_ip = ipaddress.ip_address(ip)
        curl_str = "{tele_uri}/del_device?ip_addr={ip}".format(tele_uri=TELE_URI, ip=ip)
        del_target_ip_from_tele = subprocess.Popen(['curl', '-s', '-X', 'POST', curl_str], stdout=subprocess.PIPE)
        output = del_target_ip_from_tele.stdout.readline().decode("utf-8")
        while output:
            print(output)
            output = del_target_ip_from_tele.stdout.readline().decode("utf-8")
    except:
        click.echo("Remove Device from Telescope Monitoring list Failed %s " %ip)

@tele_cli.command()
def list():
    """List all under Telescope monitoring Devices"""
    curl_str = "{tele_uri}/list_device".format(tele_uri=TELE_URI)
    list_dev = subprocess.Popen(['curl', '-s', curl_str], stdout=subprocess.PIPE)
    output = list_dev.stdout.readline().decode("utf-8")
    while output:
        print(output)
        output = list_dev.stdout.readline().decode("utf-8")

@tele_cli.command()
@click.option('--ip')
def dump(ip):
    """Dump Device details from telescope monitoring list"""
    try:
        try_ip = ipaddress.ip_address(ip)
        curl_str = "{tele_uri}/dump_device?ip_addr={ip}".format(tele_uri=TELE_URI, ip=ip)
        dump_target_ip_from_tele = subprocess.Popen(['curl', '-s', '-X', 'POST', curl_str], stdout=subprocess.PIPE)
        output = dump_target_ip_from_tele.stdout.readline().decode("utf-8")
        while output:
            print(output)
            output = dump_target_ip_from_tele.stdout.readline().decode("utf-8")
    except:
        click.echo("Dump Monitored Device from Telescope List format failed for %s" %ip)

@tele_cli.command()
def redeye():
    """Dump all redeye access from controlled internal network"""
    curl_str = "{tele_uri}/dump_redeye".format(tele_uri=TELE_URI)
    dump_redeye_from_tele = subprocess.Popen(['curl', '-s', curl_str], stdout=subprocess.PIPE)
    output = dump_redeye_from_tele.stdout.readline().decode("utf-8")
    while output:
        print(output)
        output = dump_redeye_from_tele.stdout.readline().decode("utf-8")

@tele_cli.command()
def dmz():
    """Dump all dmz access"""
    curl_str = "{tele_uri}/dmz_details".format(tele_uri=TELE_URI)
    dmz_from_tele = subprocess.Popen(['curl', '-s', curl_str], stdout=subprocess.PIPE)
    output = dmz_from_tele.stdout.readline().decode("utf-8")
    while output:
        print(output)
        output = dmz_from_tele.stdout.readline().decode("utf-8")

if __name__ == '__main__':
    tele_cli()
