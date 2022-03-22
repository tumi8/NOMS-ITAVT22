#!/usr/bin/env python3

MININET=True
try:
    from mininet.topo import Topo
    from mininet.net import Mininet
    from mininet.link import TCLink
    from mininet.log import lg, info, error
    from mininet.cli import CLI
    from mininet.clean import cleanup
    from mininet.node import Host
    from mininet.util import dumpNodeConnections
except ImportError:
    MININET=False
    print("Mininet is not available, disabling related functionality")
    
import os
import sys
import subprocess
import time
import argparse
import re
import glob

import gen_pcap


def delay_rise_fall(time_current):
    """Currently unused, showing possible way to pass a custom delay function to the flow"""
    if time_current < 4.0:
        #delay = 2 * 10**-3
        delay = 0
    if time_current >= 4.0:
        delay = 15 * 10**-3 * (time_current - 4) #+ 2 * 10**-3
    if time_current >= 5.0:
        delay = 15 * 10**-3 - 15 * 10**-3 * (time_current - 5) #+ 2 * 10**-3
    if time_current > 6.0:
        #delay = 2 * 10**-3
        delay = 0
        # hardcode:
    return delay

# Periodic flows from the table
# TODO: Change addresses and ports
flows_from_table = {
    'f0_cnc': {
        'period': 1000*10**-6,
        'flow_name': 'f0_cnc',
        'eth_src': "00:00:00:00:00:02",
        'eth_dst': "00:00:00:00:01:00",
        'ip_src': "192.168.2.2",
        'ip_dst': "192.168.2.100",
        'port_src': 8588,
        'port_dst': 81,
        'adu_size': 1024
        },
    'f1_cnc': {
        'period': 6000*10**-6,
        'flow_name': 'f1_cnc',
        'eth_src': "00:00:00:00:00:02",
        'eth_dst': "00:00:00:00:01:00",
        'ip_src': "192.168.2.2",
        'ip_dst': "192.168.2.100",
        'port_src': 8588,
        'port_dst': 81,
        'adu_size': 1024
        },
    'f2_video_adas': {
        'period': 600*10**-6,
        'flow_name': 'f1_cnc',
        'eth_src': "00:00:00:00:00:02",
        'eth_dst': "00:00:00:00:01:00",
        'ip_src': "192.168.2.2",
        'ip_dst': "192.168.2.100",
        'port_src': 8588,
        'port_dst': 81,
        'adu_size': 1500

        },
    'f3_video_vision': {
        'period': 400*10**-6,
        'flow_name': 'f1_cnc',
        'eth_src': "00:00:00:00:00:02",
        'eth_dst': "00:00:00:00:01:00",
        'ip_src': "192.168.2.2",
        'ip_dst': "192.168.2.100",
        'port_src': 8588,
        'port_dst': 81,
        'adu_size': 1500
        },
    'f4_audio': {
        'period': 10000*10**-6,
        'flow_name': 'f1_cnc',
        'eth_src': "00:00:00:00:00:02",
        'eth_dst': "00:00:00:00:01:00",
        'ip_src': "192.168.2.2",
        'ip_dst': "192.168.2.100",
        'port_src': 8588,
        'port_dst': 81,
        'adu_size': 256
    },
    'f10_audio_sr_class_c': {
        'period': 1451*10**-6,
        'flow_name': 'f1_cnc',
        'eth_src': "00:00:00:00:00:02",
        'eth_dst': "00:00:00:00:01:00",
        'ip_src': "192.168.2.2",
        'ip_dst': "192.168.2.100",
        'port_src': 8588,
        'port_dst': 81,
        'adu_size': 256
    },
    'f11_audio_sr_class_d': {
        'period': 1333*10**-6,
        'flow_name': 'f1_cnc',
        'eth_src': "00:00:00:00:00:02",
        'eth_dst': "00:00:00:00:01:00",
        'ip_src': "192.168.2.2",
        'ip_dst': "192.168.2.100",
        'port_src': 8588,
        'port_dst': 81,
        'adu_size': 256
    }
}

def gen_flows_from_table():
    for name, args in flows_from_table.items():
        print("Generating PCAP for flow " + name)
        q = gen_pcap.FifoQueue()
        flow = gen_pcap.PeriodicFlow(**args)    
        q.append_flow(flow.pkts)
        q.write(filename=name+".pcap")

class IVNEmu:
    def gen_flows(self):
        print("Flows not defined")

    def run_emu(self):
        print("No emulation defined/required")
        
class CamOnly(IVNEmu):
    def gen_fows(self):
        q = gen_pcap.FifoQueue()
        f1 = gen_pcap.CbrFlow(
            start = 0.0,
            stop = 0.95,
            flow_name = "cbr",
            eth_src = "00:00:00:00:00:02",
            eth_dst = "00:00:00:00:01:00",
            ip_src = "192.168.2.2",
            ip_dst = "192.168.2.100",
            port_src = 8888,
            port_dst = 80,
            rate = 1000,
            length = 777,
            jitter = 30 * 10**-6) # 30µs
        print("flow1")
        f2 = PeriodicFlow(
            start = 1.0,
            flow_name = "cam",
            eth_src = "00:00:00:00:00:02",
            eth_dst = "00:00:00:00:01:00",
            ip_src = "192.168.2.2",
            ip_dst = "192.168.2.100",
            port_src = 8588,
            port_dst = 81,
            period = 1/60,
            adu_size = 2000,
            # delay = delay_rise_fall
            #adu_jitter = 0,
            adu_jitter = 7000,
            period_jitter = 0)
        print("flow2")
        q.append_flow(f1.pkts)
        q.append_flow(f2.pkts)
        q.write(filename="camonly.pcap")

class CamWithBackground(IVNEmu):
    def gen_flows(self):
        q = gen_pcap.FifoQueue()
        f1 = gen_pcap.PeriodicFlow(
            start = 0.0,
            flow_name = "cam",
            eth_src = "00:00:00:00:00:02",
            eth_dst = "00:00:00:00:01:00",
            ip_src = "192.168.2.2",
            ip_dst = "192.168.2.100",
            port_src = 8588,
            port_dst = 81,
            period = 1/60,
            adu_size = 2000,
            #adu_jitter = 0,
            adu_jitter = 7000,
            period_jitter = 0)

        q.append_flow(f1.pkts)
        q.write(filename="camwithbackground_cam.pcap")
    
    def run_emu(self):
        cleanup()
        lg.setLogLevel('debug')
        #topo = SmartNICSwitchTopo()
        net = Mininet()
        c0 = net.addController( 'c0' )
        switch = net.addSwitch('s1')
        #replay0 = net.addHost('replay0', ip="192.168.2.1/24", mac="00:00:00:00:00:01")
        replay1 = net.addHost('replay1', ip="192.168.2.2/24", mac="00:00:00:00:00:02")
        iperf0 = net.addHost('iperf0', ip="192.168.2.3/24", mac="00:00:00:00:00:03")
        iperf1 = net.addHost('iperf1', ip="192.168.2.4/24", mac="00:00:00:00:00:04")
        dumper = net.addHost('dumper', ip="192.168.2.100/24", mac="00:00:00:00:01:00")

        #
        net.pingAll()
        # 10 Mbps, 5ms delay, no packet loss
        #net.addLink(replay0, switch)
        net.addLink(replay1, switch)
        net.addLink(iperf0, switch)
        net.addLink(iperf1, switch)
        net.addLink(dumper, switch)
        
        net.start()
        dumpNodeConnections(net.hosts)
        
        # connectivity test:
        #print(replay0.cmd('ping -vc 1 192.168.2.100'))
        #print(replay0.cmd('ifconfig'))
        print(replay1.cmd('ping -vc 1 192.168.2.100'))
        print(iperf0.cmd('ping -vc 1 192.168.2.100'))
        print(iperf1.cmd('ping -vc 1 192.168.2.100'))
        
        dumper.cmd('tcpdump -i dumper-eth0 -w camwithbackground.pcap &')
        dumper.cmd('iperf3 -s -p 9015 &')
        dumper.cmd('iperf3 -s -p 9016 &')
        iperf0.cmd('iperf3 -c 192.168.2.100 -u -B 192.168.2.3 -b 10M -p 9015 -t 60 &')
        iperf1.cmd('iperf3 -c 192.168.2.100 -u -B 192.168.2.4 -b 10M -p 9016 -t 60 &')
        #replay0.cmd('tcpreplay -i replay0-eth0 camwithbackground_cam.pcap &')
        replay1.cmd('tcpreplay -i replay1-eth0 camwithbackground_cam.pcap > replay1.log 2>&1 &')
        time.sleep(65)
        net.stop()
        cleanup()

class PeriodicTable(IVNEmu):
    def gen_flows(self):
        gen_flows_from_table()

class FPGANHM(IVNEmu):

    synth_pcap_filename = "synth_flow.pcap"
    output_pcap_filename = "fpganhm.pcap"

    def gen_flows(self):
        q = gen_pcap.FifoQueue(embedd_timestamps=True)
        f1 = gen_pcap.PeriodicFlow(
            start = 0.0,
            stop = 10.0,
            flow_name = "cam",
            eth_src = "00:00:00:00:00:02",
            eth_dst = "00:00:00:00:01:00",
            ip_src = "192.168.2.2",
            ip_dst = "192.168.2.100",
            port_src = 8588,
            port_dst = 81,
            period = 1/1000,
            adu_size = 800,
            adu_jitter = 0,
            period_jitter = 0,
            # after one second delay is 10ms
            # first second is zero for "synchronisation"
            delay = lambda timeCurrent: 0 if timeCurrent < 1.0 else 0.01
        )
        q.append_flow(f1.pkts)
        q.write(filename=self.synth_pcap_filename)

    def run_emu(self):
        cleanup()
        lg.setLogLevel('debug')
        #topo = SmartNICSwitchTopo()
        net = Mininet()
        c0 = net.addController( 'c0' )
        switch = net.addSwitch('s1')
        #replay0 = net.addHost('replay0', ip="192.168.2.1/24", mac="00:00:00:00:00:01")
        replay1 = net.addHost('replay1', ip="192.168.2.2/24", mac="00:00:00:00:00:02")
        #iperf0 = net.addHost('iperf0', ip="192.168.2.3/24", mac="00:00:00:00:00:03")
        iperf1 = net.addHost('iperf1', ip="192.168.2.4/24", mac="00:00:00:00:00:04")
        dumper = net.addHost('dumper', ip="192.168.2.100/24", mac="00:00:00:00:01:00")

        #
        net.pingAll()
        # 10 Mbps, 5ms delay, no packet loss
        #net.addLink(replay0, switch)
        net.addLink(replay1, switch)
        #net.addLink(iperf0, switch)
        net.addLink(iperf1, switch)
        net.addLink(dumper, switch)

        net.start()
        dumpNodeConnections(net.hosts)

        # connectivity test:
        #print(replay0.cmd('ping -vc 1 192.168.2.100'))
        #print(replay0.cmd('ifconfig'))
        print(replay1.cmd('ping -vc 1 192.168.2.100'))
        #print(iperf0.cmd('ping -vc 1 192.168.2.100'))
        print(iperf1.cmd('ping -vc 1 192.168.2.100'))

        dumper.cmd('tcpdump -i dumper-eth0 -w '+ self.output_pcap_filename  +' &')
        dumper.cmd('iperf3 -s -p 9015 &')
        dumper.cmd('iperf3 -s -p 9016 &')
        #iperf0.cmd('iperf3 -c 192.168.2.100 -u -B 192.168.2.3 -b 10M -p 9015 -t 60 &')
        iperf1.cmd('iperf3 -c 192.168.2.100 -u -B 192.168.2.4 -b 10M -p 9016 -t 60 &')
        #replay0.cmd('tcpreplay -i replay0-eth0 camwithbackground_cam.pcap &')
        replay1.cmd('tcpreplay -i replay1-eth0 '+ self.synth_pcap_filename +' > replay1.log 2>&1 &')
        time.sleep(15)
        net.stop()
        cleanup()

if __name__ == "__main__":
    scenarios = {scenario.__name__: scenario
                 for scenario in IVNEmu.__subclasses__() }
    parser = argparse.ArgumentParser(description="Emulate IVN scenarios using Mininet")
    parser.add_argument('scenario',
                        choices=scenarios.keys(),
                        help='Select scenario to run, some only generate single flows, others also have a second multiplexing step using mininet')
    parser.add_argument('steps',
                        choices=['full', 'gen-flows', 'run-emu'],
                        nargs='?', const='full', default='full',
                        help='Select wich of the steps to run, default is "full"')
    args = vars(parser.parse_args())
    scenario = scenarios[args['scenario']]()
    if args['steps'] == 'full' or args['steps'] == 'gen-flows':
        scenario.gen_flows()
    if (args['steps'] == 'full' or args['steps'] == 'run-emu') and MININET:
        scenario.run_emu()
    else:
        print("Mininet network emulation is disabled, python module import failed")
    
