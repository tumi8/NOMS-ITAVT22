#!/usr/bin/env python2
''' gen_testdata.py '''
import functools
import itertools
import logging
import operator

import namedlist                # pylint: disable=import-error
import scapy.layers.l2 as l2    # pylint: disable=import-error
import scapy.layers.inet as l3  # pylint: disable=import-error
import scapy.layers.inet as l4  # pylint: disable=import-error
import scapy.utils              # pylint: disable=import-error
from scapy.packet import Raw    # pylint: disable=import-error

NF_SRC = 1
NF_DST_GOOD = 0
NF_DST_BAD = 'drop'
MAC0 = 'a0:36:9f:3b:6d:52'
MAC1 = 'a0:36:9f:3b:6d:52'
IP0 = '10.0.0.10'
IP1 = '10.0.0.11'
PORT0 = 1024
PORT1 = 23432
PCAP_RX = 'dst.pcap'
PCAP_TX = 'src.pcap'
PCAP_NF_TX = 'nf{nr}_applied.pcap'
PCAP_NF_RX = 'nf{nr}_expected.pcap'
TUPLE_RX = 'Tuple_in.txt'
TUPLE_TX = 'Tuple_expect.txt'

SumeTuple = namedlist.namedlist(  # pylint: disable=invalid-name
    'SumeTuple', ['dma_q_size', 'nf0_q_size', 'nf1_q_size', 'nf2_q_size',
                  'nf3_q_size', 'send_dig_to_cpu', 'drop', 'dst_port',
                  'src_port', 'pkt_len'])
SUME_FIELD_LEN = SumeTuple(16, 16, 16, 16, 16, 8, 8, 8, 8, 16)
DigestTuple = namedlist.namedlist(  # pylint: disable=invalid-name
    'DigestTuple', ['unused'])
NF_PORT = {
    0: 0b00000001,
    1: 0b00000100,
    2: 0b00010000,
    3: 0b01000000,
    'drop': 0b00000000,
}


def ethernet():
    ''' ethernet '''
    valid = l2.Ether(src=MAC0, dst=MAC1)
    return [valid]


def ip():
    ''' ip '''
    valid = l3.IP(src=IP0, dst=IP1)
    return [valid]


def udp():
    ''' udp '''
    valid = l4.UDP(sport=PORT0, dport=PORT1)
    return [valid]


def generic():
    ''' generic '''
    valid = Raw(load=('\x55' * 22))
    return [valid]


def tuple_lines(sume_tuples, length=None):
    ''' tuple_lines '''
    for entry in sume_tuples:
        binary = []
        for field, value in iter(entry._asdict().items()):
            as_binary = '{0:0%db}' % getattr(length, field)
            binary.append(as_binary.format(value))
        binary = ''.join(binary)
        assert len(binary) % 4 == 0, 'cannot 0b->0x'
        hexadecimal = []
        for i in range(0, len(binary), 4):
            hexadecimal.append('{0:1x}'.format(int(binary[i:i+4], 2)))
        yield ''.join(hexadecimal)


def main():  # pylint: disable=too-many-locals
    ''' main '''
    sume_rxs = []
    sume_txs = []

    digest_field_len = DigestTuple(80)
    digest_tuple_txs = []

    pkts_rx = []
    nf_rx = {i: [] for i in NF_PORT}
    pkts_tx = []
    nf_tx = {i: [] for i in NF_PORT}

    layers = [ethernet(), ip(), udp(), generic()]
    layers = itertools.product(*filter(None, layers))
    for (time, combination) in enumerate(layers):
        logging.debug('%d: %s', time, combination)
        pkt = functools.reduce(lambda l, u: l / u, combination)
        pkt.chksum = 0x1234
        pkt.time = time
        valid = functools.reduce(
            operator.and_, map(operator.truth, combination), True)
        logging.debug('c: %s', pkt.summary())
        pkts_tx.append(pkt)
        nf_tx[NF_SRC].append(pkt)
        sume_rx = SumeTuple(*([0]*10))
        sume_rx.src_port = NF_PORT[NF_SRC]
        sume_rx.pkt_len = len(pkt)
        sume_rxs.append(sume_rx)
        logging.debug('r: %s', pkt.summary())
        pkts_rx.append(pkt)
        nf_rx[NF_DST_GOOD if valid else NF_DST_BAD].append(pkt)
        sume_tx = SumeTuple(*([0]*10))
        sume_tx.src_port = NF_PORT[NF_SRC]
        sume_tx.dst_port = NF_PORT[NF_DST_GOOD if valid else NF_DST_BAD]
        sume_tx.pkt_len = len(pkt)
        sume_txs.append(sume_tx)
        digest_tuple_txs.append(DigestTuple(0))

    scapy.utils.wrpcap(PCAP_RX, pkts_rx)
    scapy.utils.wrpcap(PCAP_TX, pkts_tx)

    for port in NF_PORT:
        if nf_rx[port]:
            scapy.utils.wrpcap(PCAP_NF_RX.format(nr=port), nf_rx[port])
        if nf_tx[port]:
            scapy.utils.wrpcap(PCAP_NF_TX.format(nr=port), nf_tx[port])

    with open(TUPLE_RX, 'w') as txt:
        txt.write('\n'.join(tuple_lines(sume_rxs, length=SUME_FIELD_LEN)))
    with open(TUPLE_TX, 'w') as txt:
        txt.write('\n'.join([' '.join([d, s]) for (d, s) in zip(
            tuple_lines(digest_tuple_txs, length=digest_field_len),
            tuple_lines(sume_txs, length=SUME_FIELD_LEN),
        )]))


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    main()
