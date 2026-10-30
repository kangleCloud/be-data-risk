-- Offline day-key-id migration. The existing checkpoint hash is validated and NEVER written.
if #KEYS~=4 or #ARGV~=1 then return 'INVALID_ARGUMENT' end
local expected={'risk:v1:checkpoints','risk:v1:active','risk:v1:directory','risk:v1:day-key-ids'}
for idx,key in ipairs(KEYS) do
 if key~=expected[idx] then return 'INVALID_ARGUMENT' end
 local actual=redis.call('TYPE',key).ok
 if actual~='none' and actual~='hash' then return 'WRONG_TYPE' end
end
local ok,plan=pcall(cjson.decode,ARGV[1])
if not ok or type(plan)~='table' or type(plan.checkpoints)~='table' or type(plan.dayKeyIds)~='table' then return 'INVALID_ARGUMENT' end
local fields=0
for key,_ in pairs(plan) do if key~='checkpoints' and key~='dayKeyIds' then return 'INVALID_ARGUMENT' end fields=fields+1 end
if fields~=2 then return 'INVALID_ARGUMENT' end
if redis.call('HLEN',KEYS[3])~=0 then return 'MIGRATION_REQUIRED' end
local checkpointCount=0
for source,value in pairs(plan.checkpoints) do
 if type(source)~='string' or #source<1 or #source>80 or not string.match(source,'^[a-zA-Z0-9_%-]+$') or type(value)~='string' then return 'INVALID_ARGUMENT' end
 local valid,cp=pcall(cjson.decode,value)
 if not valid or type(cp)~='table' or type(cp.generation)~='string' or #cp.generation<1 or #cp.generation>128 or not string.match(cp.generation,'^[a-zA-Z0-9_.:%-]+$') or type(cp.offset)~='string' or #cp.offset>20 or not string.match(cp.offset,'^%d+$') or (#cp.offset>1 and string.sub(cp.offset,1,1)=='0') then return 'INVALID_ARGUMENT' end
 local cpfields=0
 for key,_ in pairs(cp) do if key~='generation' and key~='offset' then return 'INVALID_ARGUMENT' end cpfields=cpfields+1 end
 if cpfields~=2 then return 'INVALID_ARGUMENT' end
 if redis.call('HGET',KEYS[1],source)~=value then return 'MIGRATION_SOURCE_CHANGED' end
 checkpointCount=checkpointCount+1
end
if redis.call('HLEN',KEYS[1])~=checkpointCount then return 'MIGRATION_SOURCE_CHANGED' end
local dayCount=0
for day,keyId in pairs(plan.dayKeyIds) do
 if type(day)~='string' or not string.match(day,'^%d%d%d%d%-%d%d%-%d%d$') or type(keyId)~='string' or #keyId<1 or #keyId>80 or not string.match(keyId,'^[a-zA-Z0-9_%-]+$') then return 'INVALID_ARGUMENT' end
 if redis.call('HGET',KEYS[2],day..':keyId')~=keyId then return 'MIGRATION_SOURCE_CHANGED' end
 local target=redis.call('HGET',KEYS[4],day)
 if target and target~=keyId then return 'MIGRATION_CONFLICT' end
 dayCount=dayCount+1
end
if redis.call('HLEN',KEYS[2])~=dayCount then return 'MIGRATION_REQUIRED' end
-- Every source/target/type check precedes the first and only destination write.
for day,keyId in pairs(plan.dayKeyIds) do redis.call('HSET',KEYS[4],day,keyId) end
return 'OK'
