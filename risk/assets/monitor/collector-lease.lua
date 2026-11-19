-- Atomic collector ownership; epochs persist in risk:heartbeat, lease has a 30-second TTL.
local op,id,token,epoch=unpack(ARGV)
local function hex(s) return (string.gsub(s,'.',function(c) return string.format('%02X',string.byte(c)) end)) end
if #KEYS~=2 or #ARGV~=4 or not id or #id<1 or #id>80 or not string.match(id,'^[a-zA-Z0-9_%-]+$') or not token or #token<1 or #token>80 or not string.match(token,'^[a-zA-Z0-9%-]+$') then return 'INVALID_ARGUMENT' end
local segment=hex(id)
if KEYS[1]~='risk:monitor:lease:'..segment or KEYS[2]~='risk:heartbeat' then return 'INVALID_ARGUMENT' end
local typ=redis.call('TYPE',KEYS[1]).ok
if typ~='none' and typ~='string' then return 'WRONG_TYPE' end
typ=redis.call('TYPE',KEYS[2]).ok
if typ~='none' and typ~='hash' then return 'WRONG_TYPE' end
local field='monitorEpoch:'..segment
if op=='ACQUIRE' then
 if redis.call('EXISTS',KEYS[1])~=0 then return 'LEASE_HELD' end
 local ok,n=pcall(redis.call,'HINCRBY',KEYS[2],field,1)
 if not ok then return 'INVALID_EPOCH' end
 local actual=redis.call('HGET',KEYS[2],field)
 redis.call('SET',KEYS[1],token..':'..actual,'PX',30000)
 return actual
end
if op~='RENEW' and op~='RELEASE' then return 'INVALID_ARGUMENT' end
if not epoch or not string.match(epoch,'^[1-9]%d*$') or redis.call('GET',KEYS[1])~=token..':'..epoch or redis.call('HGET',KEYS[2],field)~=epoch then return 'COLLECTOR_LEASE_LOST' end
if op=='RENEW' then redis.call('PEXPIRE',KEYS[1],30000) else redis.call('DEL',KEYS[1]) end
return 'OK'
