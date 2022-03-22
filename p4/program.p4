#include<core.p4>
#include<sume_switch.p4>

header flow_t {
    bit<48>        ethernet_addr_dst;
    bit<48>        ethernet_addr_src;
    bit<16>        ethernet_ethertype;
    bit< 8>        ipv4_version_ihl;
    bit< 8>        ipv4_tos;
    bit<56>        ipv4_fields0;
    bit< 8>        ipv4_protocol;
    bit<16>        ipv4_header_checksum;
    bit<64>        ipv4_identification;
    bit<16>        l4_port_src;
    bit<16>        l4_port_dst;
}

struct headers       { flow_t  flow; }
struct metadata_t    { bit< 8> parse_success; }
struct digest_data_t { bit<80> unused; }

#define REG_READ  8w0
#define REG_WRITE 8w1

@Xilinx_MaxLatency(1)
@Xilinx_ControlWidth(1)
extern void overload_reg_raw(in bit<1> index, in bit<8> newVal, in bit<8> incVal, in bit<8> opCode, out bit<8> result);

@Xilinx_MaxLatency(1)
@Xilinx_ControlWidth(0)
extern void get_timestamp(in bit<1> valid, out bit<64> result);

parser parse(packet_in p, out headers h, out metadata_t meta, out digest_data_t
    digest_data, inout sume_metadata_t sume_metadata) {
    state start      { meta.parse_success = 0; digest_data.unused = 0; transition parse_flow; }
    state parse_flow { p.extract(h.flow); transition parse_end; }
    state parse_end  { meta.parse_success = 1; transition accept; }
}
control pipeline(inout headers h, inout metadata_t meta, inout digest_data_t
    digest_data, inout sume_metadata_t sume_metadata){

    action drop() { sume_metadata.dst_port = 0b00000000; }
    action forward_action(port_t port) {
        sume_metadata.dst_port = port;
    }
    table forward {
        key = { h.flow.ethernet_addr_src: exact; }
        actions = { forward_action; drop; }
        default_action = drop;
    }
    table overload {
        key = { h.flow.ethernet_addr_src: exact; }
        actions = { forward_action; drop; }
        default_action = drop;
    }
    apply {
        if (meta.parse_success == 1 && h.flow.isValid()) {
            // this packet was parsed successfully
            // defaults for non-magic packet:
            bit<1> index = 0;
            bit<8> newVal = h.flow.ipv4_tos;
            bit<8> incVal = 0; // used only for REG_ADD
            bit<8> opCode = REG_READ;
            bit<1> tsCode = 0; // default: no timestamp requested
            bit<8> result = 0;
            if (h.flow.ethernet_ethertype == 0x1337) { // FIXME magic ethertype
                // this is a magic packet, trigger writing overload state
                opCode = REG_WRITE;
                tsCode = 1; // request timestamp
            }
            // depending on packet update it with timestamp
            get_timestamp(tsCode, h.flow.ipv4_identification);
            // depending on packet apply opCode to register
            overload_reg_raw(index, newVal, incVal, opCode, result);
            if (result == 0) { // apply table depending on overload state
                forward.apply();
            } else {
                overload.apply();
            }
            if (h.flow.ethernet_ethertype == 0x1337) { // FIXME magic ethertype
                // mirror packet to src port (^ = xor; keep existing rule in place)
                sume_metadata.dst_port = sume_metadata.dst_port ^ sume_metadata.src_port;
            }
        }
    }
}
control deparse(packet_out p, in headers h, in metadata_t meta, inout
    digest_data_t digest_data, inout sume_metadata_t sume_metadata){
    apply { p.emit(h.flow); }
}
SimpleSumeSwitch<headers,metadata_t,digest_data_t>(parse(), pipeline(), deparse())
main;
