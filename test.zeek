global uaTable:table[addr] of set[string];
global countTable:table[addr] of count=table();
global outputIPaddr:set[addr];

event http_header(c:connection,is_orig:bool,name:string,value:string)
{
local flag=1;
local uavalue:string;
if (name=="USER-AGENT"){
uavalue=to_lower(value);
if(c$id$orig_h in uaTable){
if(uavalue !in uaTable[c$id$orig_h]){
add uaTable[c$id$orig_h][uavalue];
countTable[c$id$orig_h]+=1;
}
}
else{
uaTable[c$id$orig_h]=set(uavalue);
countTable[c$id$orig_h]=1;
}
if (countTable[c$id$orig_h]==3) add outputIPaddr[c$id$orig_h];
}
}

event zeek_done()
{
for(s in outputIPaddr){
print fmt("%s is a proxy",s);
}
}
