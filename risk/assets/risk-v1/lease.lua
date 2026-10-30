-- KEYS[1]=risk:v1:lease:{sourceId}; ARGV=operation(RENEW/RELEASE),sourceId,token,ttlMillis
if #KEYS~=1 or #ARGV~=4 or not string.match(ARGV[2],'^[a-zA-Z0-9_%-]+$') or #ARGV[2]>80 or KEYS[1]~='risk:v1:lease:'..ARGV[2] then return 'INVALID_ARGUMENT' end
local actual=redis.call('TYPE',KEYS[1]).ok
if actual~='none' and actual~='string' then return 'WRONG_TYPE' end
if ARGV[1]~='RENEW' and ARGV[1]~='RELEASE' then return 'INVALID_ARGUMENT' end
if ARGV[4]~='30000' then return 'INVALID_ARGUMENT' end
if redis.call('GET',KEYS[1])~=ARGV[3] then return 'LEASE_LOST' end
if ARGV[1]=='RENEW' then redis.call('PEXPIRE',KEYS[1],30000) else redis.call('DEL',KEYS[1]) end
return 'OK'
