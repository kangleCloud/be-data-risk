-- Immutable single-source segment publish. No commands that may type-error after validation.
if #KEYS~=6 or #ARGV~=9 then return 'INVALID_ARGUMENT' end
local function typ(key, expected)
 local actual=redis.call('TYPE',key).ok
 return actual=='none' or actual==expected
end
local types={'set','set','string','hash','string','hash'}
for idx,key in ipairs(KEYS) do if not typ(key,types[idx]) then return 'WRONG_TYPE' end end
local batch,day,source,token,old,new,payload,now,event=unpack(ARGV)
local function date(value)
 return type(value)=='string' and string.match(value,'^%d%d%d%d%-%d%d%-%d%d$')
end
local function instant(value)
 return type(value)=='string' and string.match(value,'^%d%d%d%d%-%d%d%-%d%dT%d%d:%d%d:%d%d%.%d%d%d%+08:00$')
end
local function ident(value)
 return type(value)=='string' and #value>=1 and #value<=80 and string.match(value,'^[a-zA-Z0-9_%-]+$')
end
local function uuid(value)
 if type(value)~='string' or #value~=36 then return false end
 return string.match(value,'^[a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9]%-[a-f0-9][a-f0-9][a-f0-9][a-f0-9]%-[a-f0-9][a-f0-9][a-f0-9][a-f0-9]%-[a-f0-9][a-f0-9][a-f0-9][a-f0-9]%-[a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9]$')
end
local function checkpoint(value)
 local ok,cp=pcall(cjson.decode,value)
 if not ok or type(cp)~='table' or type(cp.generation)~='string' or #cp.generation<1 or #cp.generation>128 or not string.match(cp.generation,'^[a-zA-Z0-9_.:%-]+$') or type(cp.offset)~='string' or #cp.offset>20 or not string.match(cp.offset,'^%d+$') or (#cp.offset>1 and string.sub(cp.offset,1,1)=='0') then return nil end
 local count=0
 for key,_ in pairs(cp) do if key~='generation' and key~='offset' then return nil end count=count+1 end
 if count~=2 then return nil end
 return cp
end
if not uuid(batch) or not date(day) or not ident(source) or #token<1 or #token>128 or not instant(now) or (event~='' and not instant(event)) or #payload>1048576 then return 'INVALID_ARGUMENT' end
local expected={'risk:v1:days','risk:v1:pending:'..day,'risk:v1:batch:'..day..':'..batch,'risk:v1:checkpoints','risk:v1:lease:'..source,'risk:v1:heartbeat'}
for idx,key in ipairs(KEYS) do if key~=expected[idx] then return 'INVALID_ARGUMENT' end end
local cp=checkpoint(new)
local prior=nil
if old~='' then prior=checkpoint(old) end
if not cp or (old~='' and not prior) or old==new then return 'INVALID_ARGUMENT' end
if prior and prior.generation==cp.generation and (#cp.offset<#prior.offset or (#cp.offset==#prior.offset and cp.offset<prior.offset)) then return 'CHECKPOINT_CONFLICT' end
if not string.find(payload,'"records":[',1,true) then return 'INVALID_ARGUMENT' end
local ok,envelope=pcall(cjson.decode,payload)
if not ok or type(envelope)~='table' then return 'INVALID_ARGUMENT' end
local allowed={schemaVersion=true,batchId=true,businessDate=true,createdAt=true,records=true}
local fields=0
for key,_ in pairs(envelope) do if not allowed[key] then return 'INVALID_ARGUMENT' end fields=fields+1 end
if fields~=5 or envelope.schemaVersion~=1 or envelope.batchId~=batch or envelope.businessDate~=day or envelope.createdAt~=now or type(envelope.records)~='table' or #envelope.records>500 then return 'INVALID_ARGUMENT' end
local rowFields={minuteAt=true,method=true,pathTemplate=true,sourceIp=true,httpStatus=true,requestCount=true,regionCode=true,countryCode=true,provinceCode=true,provinceName=true,cityCode=true,cityName=true}
local seen={}
for _,row in ipairs(envelope.records) do
 if type(row)~='table' then return 'INVALID_ARGUMENT' end
 local count=0
 for key,_ in pairs(row) do if not rowFields[key] then return 'INVALID_ARGUMENT' end count=count+1 end
 if count~=12 or not instant(row.minuteAt) or string.sub(row.minuteAt,1,10)~=day or string.sub(row.minuteAt,18,23)~='00.000' or type(row.method)~='string' or #row.method<2 or #row.method>12 or not string.match(row.method,'^[A-Z]+$') or type(row.pathTemplate)~='string' or string.sub(row.pathTemplate,1,1)~='/' or type(row.httpStatus)~='number' or row.httpStatus%1~=0 or (row.httpStatus~=0 and (row.httpStatus<100 or row.httpStatus>599)) then return 'INVALID_ARGUMENT' end
 local n=row.requestCount
 if type(n)~='string' or not string.match(n,'^[1-9]%d*$') or #n>19 or (#n==19 and n>'9223372036854775807') then return 'INVALID_ARGUMENT' end
 for _,name in ipairs({'sourceIp','countryCode','provinceCode','provinceName','cityCode','cityName'}) do if row[name]~=cjson.null and (type(row[name])~='string' or #row[name]==0) then return 'INVALID_ARGUMENT' end end
 if type(row.regionCode)~='string' then return 'INVALID_ARGUMENT' end
 local identity=cjson.encode({row.minuteAt,row.method,row.pathTemplate,row.sourceIp,row.httpStatus})
 if seen[identity] then return 'INVALID_ARGUMENT' end
 seen[identity]=true
end
local recordFields=0
for key,_ in pairs(envelope.records) do if type(key)~='number' or key<1 or key>#envelope.records or key%1~=0 then return 'INVALID_ARGUMENT' end recordFields=recordFields+1 end
if recordFields~=#envelope.records then return 'INVALID_ARGUMENT' end
if redis.call('GET',KEYS[5])~=token then return 'LEASE_LOST' end
local current=redis.call('HGET',KEYS[4],source) or ''
local existing=redis.call('GET',KEYS[3])
if current==new then
 if existing and existing~=payload then return 'BATCH_CONFLICT' end
 return 'ALREADY_COMMITTED'
end
if current~=old then return 'CHECKPOINT_CONFLICT' end
if existing then return 'BATCH_CONFLICT' end
-- First write only after all reject paths and type/shape checks.
redis.call('SET',KEYS[3],payload,'NX')
redis.call('SADD',KEYS[1],day)
redis.call('SADD',KEYS[2],batch)
redis.call('HSET',KEYS[4],source,new)
local heartbeat=redis.call('HGET',KEYS[6],'collectorHeartbeatAt')
if not heartbeat or now>heartbeat then redis.call('HSET',KEYS[6],'collectorHeartbeatAt',now) end
local last=redis.call('HGET',KEYS[6],'lastEventTime')
if event~='' and (not last or event>last) then redis.call('HSET',KEYS[6],'lastEventTime',event) end
return 'OK'
