-- 独立单调心跳，不改变批次与检查点；KEYS[1]=risk:heartbeat，ARGV=now,lastEventTime(可空)
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
if #KEYS~=3 or #ARGV~=5 or KEYS[1]~='risk:heartbeat' then return 'INVALID_ARGUMENT' end
local guard=collector_guard(KEYS[2],KEYS[3],ARGV[3],ARGV[4],ARGV[5])
if guard then return guard end
local actual=redis.call('TYPE',KEYS[1]).ok
if actual~='none' and actual~='hash' then return 'WRONG_TYPE' end
local function valid(value)
 return string.match(value,'^%d%d%d%d%-%d%d%-%d%dT%d%d:%d%d:%d%d%.%d%d%d%+08:00$')
end
if not valid(ARGV[1]) or (ARGV[2]~='' and not valid(ARGV[2])) then return 'INVALID_ARGUMENT' end
local old=redis.call('HGET',KEYS[1],'collectorHeartbeatAt')
if not old or ARGV[1]>old then redis.call('HSET',KEYS[1],'collectorHeartbeatAt',ARGV[1]) end
local event=redis.call('HGET',KEYS[1],'lastEventTime')
if ARGV[2]~='' and (not event or ARGV[2]>event) then redis.call('HSET',KEYS[1],'lastEventTime',ARGV[2]) end
return 'OK'
