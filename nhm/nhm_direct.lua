local function script_path()
   local str = debug.getinfo(2, "S").source:sub(2)
   return str:match("(.*/)")
end
package.path = script_path() .. "/?.lua;" .. package.path

local ffi = require "ffi"
local log = require "log"
local json = require "json"
local lm = require "libmoon"
local inspect = require "inspect"
local tracker = require "flowManagement"
local pktLib = require "packet"
local ethLib = require "proto.ethernet"
local ip4Lib = require "proto.ip4"
local ip6Lib = require "proto.ip6"
local tcpLib = require "proto.tcp"
local udpLib = require "proto.udp"

local module = {}

--- TODO: This might be not needed or use something like pl.tables
table.filter = function(t, filterIter)
   local out = {}
   for k, v in ipairs(t) do
      if filterIter(k, v) then
         table.insert(out, v)
      end
   end
   return out
end

function string.starts(String,Start)
   return string.sub(String, 1, string.len(Start)) == Start
end

function table.mean(t)
   if #t < 1 then return 0 end
   local sum = 0
   for _, v in pairs(t) do
      sum = sum + v
   end
   return sum / #t
end

function table.variance(t)
   if #t < 1 then return 0 end
   local mean = table.mean(t)
   local sum = 0
   for _, v in pairs(t) do
      sum = sum + (v - mean)^2
   end
   return sum / #t
end

function table.std(t)
   return math.sqrt(table.variance(t))
end

-- set log level
log:setLevel("INFO")

local n = 256

ffi.cdef( [[
struct nhm_state {
// UP
uint32_t pos_up; // position in the ringbuffer
uint64_t num_up;
uint64_t ts_up[ ]] .. n .. [[ ];
uint64_t iat_up[ ]] .. n .. [[ ];
uint16_t size_up[ ]] .. n .. [[ ];
uint64_t ts_up_enc[ ]] ..  n .. [[ ];
uint64_t last_burst_start_up;

// DOWN
uint32_t pos_down; // position in the ringbuffer
uint64_t num_down;
uint64_t ts_down[ ]] ..  n .. [[ ];
uint64_t iat_down[ ]] .. n .. [[ ];
uint16_t size_down[ ]] .. n .. [[ ];
uint64_t ts_down_enc[ ]] ..  n .. [[ ];
uint64_t last_burst_start_down;

int64_t offset;
uint64_t first_observed;
uint64_t last_seen; //Time Stamp last seen
uint8_t client_is_smaller;
uint8_t ignore;
};
]])

log:info("Structsize: %s" , ffi.sizeof("struct nhm_state"))


-- local function set_state_metatables(state)
--    return ffi.metatype(state, {
--                           __index = function(t1, k1)
--                              if string.starts(k1, "rb_") then
--                                 return setmetatable({k1}, {
--                                       __index = function(t2, k2)
--                                          local original_field = string.sub(k1, 4, string.len(k1))
--                                          local direction = string.sub(k1, string.len(k1) - 2, string.len(k1))
--                                          local index
--                                          if t1["num_" .. direction] ==
--                                          return t1[original_field][ t1["num_" .. direction]  k2]
--                                       end
--                              else
--                                 return nil
--                              end
-- end

-- local function iats(dat, state)
--    dat.iats = {}
--    if state["num_" .. dat.direction] < 2 then return end
--    if state["num_" .. dat.direction] < (n - 1) then -- less than n packets in buffers
--       for i = 1, tonumber(state["num_" .. dat.direction]) do
--          table.insert(dat.iats,
--                       tonumber(state["ts_" .. dat.direction][i] -
--                                   state["ts_" .. dat.direction][i-1])
--          )
--       end
--    else
--       for i = state["pos_" .. dat.direction] + 2, tonumber(state["pos_" .. dat.direction] + n - 1) do
--          table.insert(dat.iats,
--                       tonumber(state["ts_" .. dat.direction][i % n] -
--                                   state["ts_" .. dat.direction][(i-1) % n])
--          )
--       end
--    end
-- end

-- setup
module.mode = "direct"
module.flowKeys = tracker.flowKeys
module.extractFlowKey = tracker.extract5TupleBidirectional
module.stateType = "struct nhm_state"
module.checkInterval = 1
module.checkState = {["start_time"] = 0}
module.defaultState = {}

function module.handlePacket(flowKey, state, buf, isFirstPacket, rxTimestamp)
   local entry_ts = lm.getTime() * 10^6
   local dat = {json = {}}
   local ethPacket = pktLib.getEthernetPacket(buf)
   --state = set_state_metatables(state)
   local protocolStack = {"eth"}
   if ethPacket.eth:getType() == ethLib.TYPE_IP then -- ipv4
      local ip4Packet = pktLib.getIP4Packet(buf)
      table.insert(protocolStack, {proto = "ip4", pkt = ip4Packet})
      if ip4Packet.ip4:getProtocol() == ip4Lib.PROTO_TCP then
         table.insert(protocolStack, {proto = "tcp"})
      end
      if ip4Packet.ip4:getProtocol() == ip4Lib.PROTO_UDP then
         table.insert(protocolStack, {proto = "udp"})
      end
   elseif ethPacket.eth:getType() == ethLib.TYPE_IP6 then --ipv6
      local ip6Packet = pktLib.getIP6Packet(buf)
      table.insert(protocolStack, {proto = "ip6", pkt = ip6Packet})
      -- TODO NYI
   end
   --log:warn("Stack %s", inspect(protocolStack))

   -- extract timestamp (ugly version)
   -- ETH: 18
   -- IPv4: 20
   -- UDP: 8
   -- TODO: ffi.cast(double, pkt[18+20+8])
   -- into ts_rx_nic_s
   
   -- connection
   dat.size = buf:getSize()
   --dat.ts = buf:getTimestamp() * 10^6
   dat.ts = rxTimestamp * 10^6
   state.last_seen = dat.ts

   dat.last_seen = state.last_seen
   state.last_seen = dat.ts
   -- first packet
   if isFirstPacket then
      state.first_observed = dat.ts
      -- TODO if TCP then check if this also is a SYN
      -- ip_a is always higher than ip_b (flowManagement.lua)
      if flowKey.ip_version == 4 then
         if flowKey.ip_a.uint32 == protocolStack[2].pkt.ip4.src.uint32 then--the Client is smaller when he is not in ip_b as source
            state.client_is_smaller = 0
         elseif flowKey.ip_b.uint32 == protocolStack[2].pkt.ip4.src.uint32 then
            state.client_is_smaller = 1
         else
            state.ignore = 1
            dat.stop_flag = true
            log:warn("Flow state is damaged. Ignoring from now on")
            return false---The Flow State is damaged and this means we should ignore from here
         end
      elseif flowKey.ip_version == 6 then
         if flowKey.ip_a.uint64[0] == protocolStack[2].pkt.ip6.src.uint64[0] and
         flowKey.ip_a.uint64[1] == protocolStack[2].pkt.ip6.src.uint64[1] then--the Client is smaller when he is not in ip_b as source
            state.client_is_smaller = 0 --false
         elseif flowKey.ip_b.uint64[0] == protocolStack[2].pkt.src.uint64[0] and
         flowKey.ip_b.uint64[1] == protocolStack[2].pkt.src.uint64[1] then
            state.client_is_smaller = 1 --true
         else
            state.ignore = 1
            dat.stop_flag = true
            log:warn("Flow state is damaged. Ignoring from now on")
            return false---The Flow State is damaged and this means we should ignore from here
         end
      end
   end

   -- Direction of this packet
   if flowKey.ip_version == 4 then--Decide if the connection is up or down wards divided between ipv6 and ipv4
      if flowKey.ip_b.uint32 == protocolStack[2].pkt.ip4.src.uint32 and
      tonumber(state.client_is_smaller) ~= 0 then
         dat.direction = "up"
      elseif flowKey.ip_a.uint32 == protocolStack[2].pkt.ip4.src.uint32 and
      tonumber(state.client_is_smaller) == 0 then
         dat.direction = "up"
      else
         dat.direction = "up"
      end
   else
      if flowKey.ip_b.uint64[0] == protocolStack[2].pkt.ip6.src.uint64[0] and
         flowKey.ip_b.uint64[1] == protocolStack[2].pkt.ip6.src.uint64[1] and
      tonumber(state.client_is_smaller) ~= 0 then
         dat.direction = "up"
      elseif flowKey.ip_a.uint64[0] == protocolStack[2].pkt.ip6.src.uint64[0] and
         flowKey.ip_a.uint64[1] == protocolStack[2].pkt.ip6.src.uint64[1] and
      tonumber(state.client_is_smaller) == 0 then
         dat.direction = "up"
      else
         dat.direction = "down"
      end
   end

   local encap_ts = ffi.cast("double*", ffi.cast("void*", (buf:getBytes() + 0x2a)))[0]
   --if isFirstPacket then
   if state["num_" .. dat.direction] == 7 then
      state.offset = dat.ts - math.ceil(tonumber(encap_ts) * 10^6)
   end


   local pos = state["pos_" .. dat.direction]
   local last_pos = (pos - 1) % n
   local last_last_pos = (pos - 2) % n
   local num = state["num_" .. dat.direction]
   
   -- Add values to flow table
   state["ts_" .. dat.direction][pos] = dat.ts
   state["ts_" .. dat.direction .. "_enc"][pos] = math.ceil(tonumber(encap_ts)) * 10^6
   state["size_" .. dat.direction][pos] = dat.size
   if num > 0 then
      state["iat_" .. dat.direction][last_pos] =
	 dat.ts - state["ts_" .. dat.direction][last_pos]
   end

   -- Flight Time KPI
   local flight_time = dat.ts - (tonumber(state.offset) + math.ceil(tonumber(encap_ts) * 10^6))

   -- Burst detection
   local num_last_pkts = 16
   local epsilon = 1.0
   if state["num_" .. dat.direction] < num_last_pkts + 1 then
      num_last_pkts = state["num_" .. dat.direction] - 1
   end
   local count = 0
   local avg = 0
   for i = tonumber(last_pos-num_last_pkts+1), tonumber(last_pos) do
      avg = avg + state["iat_" .. dat.direction][i % n]
      count = count + 1
   end
   avg = avg / count
   if avg ~= avg then -- if avg == NaN
      avg = 0
   end
   dat.json.avg = tonumber(avg)
   dat.json.delta = tonumber(dat.ts - state["ts_" .. dat.direction][last_pos])
   -- new burst?
   if dat.ts - state["ts_" .. dat.direction][last_pos] > epsilon * avg then
      local last_burst = state["last_burst_start_" .. dat.direction]
      dat.burst_iat = tonumber(dat.ts - last_burst)
      dat.json.burst_iat = dat.burst_iat
      state["last_burst_start_" .. dat.direction]= dat.ts
   end
   
   -- increase indices
   state["pos_" .. dat.direction] = (pos + 1) % n
   state["num_" .. dat.direction] = state["num_" .. dat.direction] + 1

   -- JSON
   dat.json.n_up = tonumber(state.num_up)
   dat.json.n_down = tonumber(state.num_down)
   dat.json["ts_" .. dat.direction] = dat.ts
   dat.json["ts_" .. dat.direction .. "_encap"] = tonumber(encap_ts)
   dat.json["flight_time_" .. dat.direction] = tonumber(flight_time)
   dat.json["offset"] = tonumber(state.offset)
   dat.json["analyzer_backlog"] = tonumber(entry_ts - dat.ts)
   dat.json["analyzer_runtime"] = tonumber(lm.getTime() * 10^6 - entry_ts)
   --dat.json["iat_" .. dat.direction] = state["iat_" .. dat.direction]
   dat.json.direction = dat.direction
   local identifier = tostring(flowKey)

   dat.json.id = identifier
   --log:warn("JSON-Data %s", inspect(dat.json))
   local json_str = json.encode(dat.json)
   local file = io.open("nhm_"..identifier..".json", "a")
   file:write(json_str.."\n")
   file:close()
end

function module.checkExpiry(flowKey, state, checkState)
   checkState.start_time = lm.getTime()
end

function module.checkFinalizer(checkState, keptFlows, purgedFlows)
   
end
module.maxDumperRules = 50

-- Function that returns a packet filter string in pcap syntax from a given flow key
function module.buildPacketFilter(flowKey)
   return flowKey:getPflangBi()
end

return module
