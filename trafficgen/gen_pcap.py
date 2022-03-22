import math
from scapy.all import wrpcap, Ether, IP, UDP, Raw
import numpy as np
import random
import argparse
import struct
import json
import matplotlib.pyplot as plt

"""Makes sure that packets with overlapping timestamps are serialized with a FIFO policy"""
class FifoQueue:
    def __init__(self, line_rate=10**10, epoch=0, embedd_timestamps=False):
        self.line_rate = line_rate
        self.epoch = epoch
        self.queue = []
        self.embedd_timestamps = embedd_timestamps

    def append_flow(self, item):
        self.queue += item

    def sort(self):
        self.queue.sort(key=lambda pkt: pkt['packet'].time)

    """self packet timestamps matching the line rate"""
    def serialize(self):
        self.sort()
        backlog = 0
        next_dispatch_time = self.epoch

        for pkt in self.queue:
            sequencing_time = 8 * len(pkt['packet']) / self.line_rate
            if pkt['packet'].time < next_dispatch_time:
                pkt['packet'].time = next_dispatch_time
                backlog += next_dispatch_time - pkt['packet'].time
            else:
                backlog -= sequencing_time
            next_dispatch_time = pkt['packet'].time + sequencing_time

    def add_timestamps(self):
        for pkt in self.queue:
            payload = bytearray(bytes(pkt['packet'].lastlayer()))
            struct.pack_into("<d", payload, 0, pkt['packet'].time)
            pkt['packet']['Raw'] = Raw(load=payload)

    def add_delay(self):
        for pkt in self.queue:
           # print("Adding delay "+str(pkt['delay'])+" to packet at "+ str(pkt['packet'].time))
            pkt['packet'].time += pkt['delay']

    def write(self, filename="out.pcap"):
        if self.embedd_timestamps:
            self.add_timestamps()
        self.add_delay()

        self.serialize()

        pks = [ p['packet'] for p in self.queue ]
        delay_series = [ pkt['delay'] for pkt in self.queue if pkt['flow'] == 'cam']
        times = [ pkt['packet'].time for pkt in self.queue if pkt['flow'] == 'cam']
        #print(times)
        delay_series = np.array(delay_series, dtype='float')
        delay_series *= 10**3
        times = np.array(times, dtype='float')
        times -= 1

        # mark yellow and red area:
        yellow_bottom = [8] * len(delay_series)
        yellow_top = [10] * len(delay_series)
        red_top = [15] * len(delay_series)
        # green_fill = plt.fill_between(times, 0, yellow_bottom, color='green', alpha=.5)
        # yellow_fill = plt.fill_between(times, yellow_bottom, yellow_top, color='yellow', alpha=.8)
        # red_fill = plt.fill_between(times, yellow_top, red_top, color='red', alpha=.8)

        green_fill = plt.fill_between(times, 0, delay_series , color='lightgreen', alpha=1)
        yellow_fill = plt.fill_between(times, 0, delay_series, where=delay_series > 8, color='yellow', alpha=1)
        yellow_line = plt.fill_between(times, 7.9, 8.1, color='yellow', alpha=1)
        red_fill = plt.fill_between(times, 0, delay_series, where=delay_series > 10, color='orangered', alpha=1)
        red_fill2 = plt.fill_between(times, 9.9, 10.1, color='orangered', alpha=1)


        plt.legend([red_fill, yellow_fill, green_fill],
           ["flow has exceeded\nrequirements",
            "flow classified as\nclose to miss\nrequirements",
            "flow is healthy"],
           loc='upper right')

        plt.scatter(times, delay_series, s=1)
        plt.ylabel("delay [ms]")
        plt.xlabel("times [s]")
        plt.savefig("plot.pdf")

        wrpcap(filename, pks)

class Flow:
    def __init__(self, eth_src, eth_dst, ip_src, ip_dst, port_src, port_dst, flow_name, jitter=0, mtu=1500, start=0.0, stop=61, **kwargs):
        self.eth_src = eth_src
        self.eth_dst = eth_dst
        self.ip_src = ip_src
        self.ip_dst = ip_dst
        self.port_src = port_src
        self.port_dst = port_dst
        self.jitter = jitter
        self.pkts = []
        self.name = flow_name
        self.mtu = 1500
        self.stop = stop
        self.start = start
        
    def add_packet(self, time, length=1500, delay=0):
        eth = Ether(src=self.eth_src, dst=self.eth_dst)
        ip = IP(src=self.ip_src, dst=self.ip_dst)
        udp = UDP(sport=self.port_src, dport=self.port_dst)
        if length < 8:
            length = 8
        payload = b'a' * (math.ceil(length) - 42)
        pkt = eth/ip/udp/payload
        pkt.time = time + self.jitter * random.uniform(0.0, 1.0)
        self.pkts.append({'packet': pkt, 'delay': delay, 'flow': self.name})
        
class PeriodicFlow(Flow):
    def __init__(self, period, adu_size=1500, adu_jitter = 0, period_jitter = 0, **args):
        super().__init__(**args)
        self.add_periodic_packets(period, adu_size, adu_jitter, period_jitter, **args)

    def add_periodic_packets(self, period, adu_size=1500, adu_jitter = 0, period_jitter = 0,
                             delay = lambda _: 0, **kwargs):
        time_current = self.start
        adu_size_init = adu_size
        while(time_current < self.stop):
            burst_time = time_current + period_jitter * random.uniform(-1.0, 1.0)
            adu_delay = delay(time_current)
            this_adu_size = adu_size_init + math.ceil(adu_jitter * random.uniform(0.0, 1.0))
            num_pkts = math.ceil(adu_size / self.mtu)
            adu_pos = 0
            while(adu_pos < this_adu_size):
                if this_adu_size - adu_pos <= self.mtu:
                    packet_length = this_adu_size - adu_pos
                    if packet_length < 80:
                        packet_length = 80
                else:
                    packet_length = 1500
                self.add_packet(burst_time, packet_length, adu_delay)
                adu_pos += packet_length
            time_current += period

class CbrFlow(Flow):
    def __init__(self, rate, length=1500, **args):
        super().__init__(**args)
        self.add_cbr_packets(rate, length)

    """rate in pps"""
    def add_cbr_packets(self, rate, length):
        for time in np.arange(self.start, self.stop, 1/rate):
            self.add_packet(time, length)

