-- 独立单调心跳，不改变批次与检查点；KEYS[1]=risk:v1:heartbeat，ARGV=now,lastEventTime(可空)
if #KEYS~=1 or #ARGV~=2 or KEYS[1]~='risk:v1:heartbeat' then return 'INVALID_ARGUMENT' end
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
