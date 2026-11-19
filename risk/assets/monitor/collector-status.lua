-- Fenced per-collector status update using Redis server time.
local function hex(value) return (string.gsub(value, '.', function(char) return string.format('%02X', string.byte(char)) end)) end
local function collector_guard(lease, heartbeat, id, token, epoch)
 if type(id)~='string' or #id<1 or #id>80 or not string.match(id,'^[a-zA-Z0-9_%-]+$') or type(token)~='string' or not string.match(token,'^[a-zA-Z0-9%-]+$') or type(epoch)~='string' or not string.match(epoch,'^[1-9]%d*$') then return 'INVALID_ARGUMENT' end
 local segment=hex(id)
 if lease~='risk:monitor:lease:'..segment or heartbeat~='risk:heartbeat' then return 'INVALID_ARGUMENT' end
 local a=redis.call('TYPE',lease).ok
 local b=redis.call('TYPE',heartbeat).ok
 if (a~='none' and a~='string') or (b~='none' and b~='hash') then return 'WRONG_TYPE' end
 if redis.call('GET',lease)~=token..':'..epoch or redis.call('HGET',heartbeat,'monitorEpoch:'..segment)~=epoch then return 'COLLECTOR_LEASE_LOST' end
 return nil
end
if #KEYS~=2 or #ARGV~=4 then return 'INVALID_ARGUMENT' end
local id,token,epoch,payload=unpack(ARGV)
local guard=collector_guard(KEYS[1],KEYS[2],id,token,epoch)
if guard then return guard end
if #payload>65536 then return 'INVALID_ARGUMENT' end
local ok,body=pcall(cjson.decode,payload)
if not ok or type(body)~='table' or body.schemaVersion~=2 or body.collectorId~=id or body.epoch~=epoch or body.updatedAtMillis~='0' then return 'INVALID_ARGUMENT' end
local clock=redis.call('TIME')
local millis=string.format('%.0f',tonumber(clock[1])*1000+math.floor(tonumber(clock[2])/1000))
local result,count=string.gsub(payload,'"updatedAtMillis":"0"','"updatedAtMillis":"'..millis..'"',1)
if count~=1 then return 'INVALID_ARGUMENT' end
redis.call('HSET',KEYS[2],'monitor:'..hex(id),result)
return result
