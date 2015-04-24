-- Issue: Rping (DISMAN PING RFC2925) and Cisco ping MIB implementation
-- Copyright (C)2012 poslua <poslua@gmail.com>

_G.package.cpath = [[/usr/local/lua/lib/lua/5.1/?.so;]] .. _G.package.cpath
_G.package.path = [[/usr/local/lua/share/lua/5.1/?.lua;]] .. _G.package.path

local snmp = require "snmp"
local socket = require "socket"
local math = require "math"
local os = require "os"
local string = require "string"

local _M = { _VERSION = 0.1 }

math.randomseed(socket.gettime()*10000)
math.random();math.random();math.random();
local id = string.sub(math.random(),-3)

--[[
function default_cb(vb, status, index, reqid, session, magic)
    if magic == "local" then
      print("Callback: REQUEST SPECIFIC")
    else
      print("Callback: SESSION DEFAULT")
    end
    print(string.format("  status=%s index=%s reqid=%s magic=%s",
	  	      status or "nil", index or 0, reqid, magic or "nil"))
    print(string.format("  OID=%s type=%s value=%s",
	  	      vb.oid, vb.type, vb.value))
    done = done - 1
    session:close()
end

-- Trap callback function.
local function trap_cb(vlist, ip, host, session)
end
--]]

local vendor, oidgroup = {}, {{},{}}

-- H3C
oidgroup[1].set = {
    {oid = ".1.3.6.1.2.1.80.1.2.1.23.4.116.101.115.116.1.50", type = snmp.TYPE_INTEGER, value = 6},
    {oid = ".1.3.6.1.2.1.80.1.2.1.23.4.116.101.115.116.1.50", type = snmp.TYPE_INTEGER, value = 4},
    {oid = ".1.3.6.1.2.1.80.1.2.1.3.4.116.101.115.116.1.50", type = snmp.TYPE_INTEGER, value = 1},
    {oid = ".1.3.6.1.2.1.80.1.2.1.4.4.116.101.115.116.1.50", type = snmp.TYPE_OCTETSTR, value = "ip"},
    {oid = ".1.3.6.1.2.1.80.1.2.1.6.4.116.101.115.116.1.50", type = snmp.TYPE_GAUGE, value = "packetTimeout"},
    {oid = ".1.3.6.1.2.1.80.1.2.1.7.4.116.101.115.116.1.50", type = snmp.TYPE_GAUGE, value = "numPings"},
    {oid = ".1.3.6.1.2.1.80.1.2.1.5.4.116.101.115.116.1.50", type = snmp.TYPE_GAUGE, value = "packetSize"},
    {oid = ".1.3.6.1.2.1.80.1.2.1.8.4.116.101.115.116.1.50", type = snmp.TYPE_INTEGER, value = 1},
}
oidgroup[1].get = {
    ".1.3.6.1.2.1.80.1.3.1.7.4.116.101.115.116.1.50",
    ".1.3.6.1.2.1.80.1.3.1.5.4.116.101.115.116.1.50",
    ".1.3.6.1.2.1.80.1.3.1.4.4.116.101.115.116.1.50",
    ".1.3.6.1.2.1.80.1.3.1.6.4.116.101.115.116.1.50",
    "1.3.6.1.4.1.25506.2.3.1.1.1.0",
}

-- Cisco
oidgroup[2].set = {
    {oid = ".1.3.6.1.4.1.9.9.16.1.1.1.16." .. id, type = snmp.TYPE_INTEGER, value = 6},
    {oid = ".1.3.6.1.4.1.9.9.16.1.1.1.16." .. id, type = snmp.TYPE_INTEGER, value = 5},
    {oid = ".1.3.6.1.4.1.9.9.16.1.1.1.15." .. id, type = snmp.TYPE_OCTETSTR, value = "O." .. id},
    {oid = ".1.3.6.1.4.1.9.9.16.1.1.1.2." .. id, type = snmp.TYPE_INTEGER, value = 1},
    {oid = ".1.3.6.1.4.1.9.9.16.1.1.1.3." .. id, type = snmp.TYPE_OCTETSTR, value = "iphex"},
    {oid = ".1.3.6.1.4.1.9.9.16.1.1.1.4." .. id, type = snmp.TYPE_INTEGER, value = "numPings"},
    {oid = ".1.3.6.1.4.1.9.9.16.1.1.1.5." .. id, type = snmp.TYPE_INTEGER, value = "packetSize"},
    {oid = ".1.3.6.1.4.1.9.9.16.1.1.1.6." .. id, type = snmp.TYPE_INTEGER, value = "packetTimeout"},
--    {oid = ".1.3.6.1.4.1.9.9.16.1.1.1.16." .. id, type = snmp.TYPE_INTEGER, value = 1},
}
oidgroup[2].get = {
    ".1.3.6.1.4.1.9.9.16.1.1.1.10." .. id,
    ".1.3.6.1.4.1.9.9.16.1.1.1.13." .. id,
    ".1.3.6.1.4.1.9.9.16.1.1.1.11." .. id,
    ".1.3.6.1.4.1.9.9.16.1.1.1.12." .. id,
}

function _M.startRping(IP, PacketTimeout, NumPings, PackrtSize)

    local vlist, err, index, vout
    local numPacketRecv, maxRTT, minRTT, averageRTT, msg, info
    local date = os.date("%Y-%m-%d %X")
    
    -- check comment
    if string.byte(IP) ~= 35 then
    
    -- Open session
    local hub, err = assert(snmp.open{
      peer = b,
      community = "private",
    --  trap = trap_cb,
    --  callback = default_cb,
    })
    
    if err then
      info = string.format("Error: can't connect to the device:%s，please confirm the community or device status", b)
    else
    
    if not vendor[IP] then
    
        vlist, err, index = snmp.get(hub, {"1.3.6.1.2.1.1.1.0"})
    
        if err then
    
            if err:match("snmp: timeout") then
              info = string.format("Error: can't connect to the device:%s，please confirm the community or device status", b)
            else
              info = string.format("Error: fetch device:%sversion failed，please get it manually", b)
            end
    
        elseif string.match(vlist[1].value, "H3C") then
            vendor[IP] = 1
    
        elseif string.match(vlist[1].value, "Cisco") then
            vendor[IP] = 2
    
        else
            info = string.format("Error: cann't recognize the device:%s，please add the device OID manually", b)
    
        end
    
    end
    
    if not info then
    
        if vendor[IP] == 1 then
            oidgroup[1].set[4].value = IP
            oidgroup[1].set[5].value = tonumber(PacketTimeout)
            oidgroup[1].set[6].value = tonumber(NumPings)
            oidgroup[1].set[7].value = tonumber(PackrtSize)
            
            assert(hub:set(oidgroup[1].set[1]))
            vout, err, index = assert(hub:set(oidgroup[1].set))
        
        else
            local I1,I2,I3,I4 = string.match(IP,"(%d+).(%d+).(%d+).(%d+)")
            oidgroup[2].set[5].value = string.format("%X:%X:%X:%X", I1,I2,I3,I4)
            oidgroup[2].set[6].value = tonumber(NumPings)
            oidgroup[2].set[7].value = tonumber(PackrtSize)
            oidgroup[2].set[8].value = tonumber(PacketTimeout)
            
            assert(hub:set(oidgroup[2].set[1]))
            assert(hub:set(oidgroup[2].set))
            vout, err, index = assert(hub:set({oid = ".1.3.6.1.4.1.9.9.16.1.1.1.16." .. id, type = snmp.TYPE_INTEGER, value = 1}))
        
        end
    
        if not err then
            -- assert(os.execute("usleep 250000"))
            assert(socket.sleep(0.25)
            vlist, err, index = assert(snmp.get(hub,oidgroup[vendor[IP]].get))
    
            if err then
                info = string.format("Error: device:%s snnmp get failed", IP)
            else
                numPacketRecv = vlist[1].value or "null"
                maxRTT = vlist[2].value or "null"
                minRTT = vlist[3].value or "null"
                averageRTT = vlist[4].value or "null"
                info = string.format("packetTimeout:%s numPings:%s packetSize:%s numPacketRecv:%s maxRTT:%s minRTT:%s averageRTT:%s", PacketTimeout, NumPings, PackrtSize, numPacketRecv, maxRTT, minRTT, averageRTT)
    
                if vlist[5] then
                  local sy, sm, sd, sh, smi, shr = string.match(vlist[5].value,"(%w+%:%w+)%:(%w+)%:(%w+)%:(%w+)%:(%w+)%:(%w+)")
                  date = string.format("%d-%d-%d %02s:%02s:%02s", tonumber(sy:gsub(":",""),16), tonumber(sm,16), tonumber(sd,16), tonumber(sh,16), tonumber(smi,16),tonumber(shr,16)):gsub(": ",":0")
                end
    
            end
    
        else
            info = string.format("Error: device:%s snmp set failed，please check the OID or device status", b)
        end
    
    end
    
    hub:close()
    
    end
    
    msg = string.format("rping %s %s remoteHost:%s ", date, vendor[IP], IP) .. info
    -- print(msg)
    
    command = "echo " .. msg .. ">>/var/log/meassage"
    assert(os.execute(command))
    
    end
end

return _M
