-- Atomic current resource value, fenced by collector ownership and config version.
local function hex(s) return (string.gsub(s,'.',function(c) return string.format('%02X',string.byte(c)) end)) end
if #KEYS~=4 or #ARGV~=6 then return 'INVALID_ARGUMENT' end
local target,payload,interval,id,token,epoch=unpack(ARGV)
if not string.match(target,'^[1-9]%d*$') or #target>19 or (#target==19 and target>'9223372036854775807') or #id<1 or #id>80 or not string.match(id,'^[a-zA-Z0-9_%-]+$') or not string.match(token,'^[a-zA-Z0-9%-]+$') or not string.match(epoch,'^[1-9]%d*$') or not string.match(interval,'^[1-9]%d*$') then return 'INVALID_ARGUMENT' end
local period=tonumber(interval)
if not period or period>86400 or #payload>65536 then return 'INVALID_ARGUMENT' end
local segment=hex(id)
if KEYS[1]~='risk:monitor:resource:current:'..target or KEYS[2]~='risk:monitor:config' or KEYS[3]~='risk:monitor:lease:'..segment or KEYS[4]~='risk:heartbeat' then return 'INVALID_ARGUMENT' end
local types={'string','hash','string','hash'}
for index,key in ipairs(KEYS) do
 local typ=redis.call('TYPE',key).ok
 if typ~='none' and typ~=types[index] then return 'WRONG_TYPE' end
end
if redis.call('GET',KEYS[3])~=token..':'..epoch or redis.call('HGET',KEYS[4],'monitorEpoch:'..segment)~=epoch then return 'COLLECTOR_LEASE_LOST' end
local ok,body=pcall(cjson.decode,payload)
if not ok or type(body)~='table' or body.schemaVersion~=2 or body.targetId~=target or body.collectorId~=id or type(body.configVersion)~='string' or body.writtenAtMillis~='0' then return 'INVALID_ARGUMENT' end
if redis.call('HGET',KEYS[2],'version')~=body.configVersion then return 'CONFIG_VERSION_CHANGED' end
local clock=redis.call('TIME')
local millis=string.format('%.0f',tonumber(clock[1])*1000+math.floor(tonumber(clock[2])/1000))
local result,count=string.gsub(payload,'"writtenAtMillis":"0"','"writtenAtMillis":"'..millis..'"',1)
if count~=1 then return 'INVALID_ARGUMENT' end
redis.call('SET',KEYS[1],result,'EX',2*(2*period+10))
return 'OK'
