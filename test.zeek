global useragent:set[string];
global my_count=0;
global ipaddr:addr;

event http_header(c:connection,is_orig:bool,name:string,value:string)
{ 
local flag=0; 
if (name=="USER-AGENT"){
for(s in useragent){ 
if (s==value) flag=1;
}
if (flag==0) {
my_count+=1;
add useragent[value];
}
}
ipaddr=c$id$orig_h;
}

event zeek_done(){
if(my_count>=3) {
print fmt("%s is a proxy",ipaddr);
}
}
