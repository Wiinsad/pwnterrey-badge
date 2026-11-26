
var B='',pid=null,tpid=null,gpid=null,hsT=null,spid=null,LS=null,aps=[],sel={},caps=[],selAp={ssid:'',ch:1},tpl='generic',snT='beacon',bk='apple';
var ATKS=[
{t:'deauth',n:'Deauth',d:'Desconecta clientes de redes seleccionadas',ns:true,ic:'<path d="M1 9l2 2c4.97-4.97 13.03-4.97 18 0l2-2C16.93 2.93 7.08 2.93 1 9z"/><path d="M8 12l2 2c1.66-1.66 4.34-1.66 6 0l2-2c-2.76-2.76-7.24-2.76-10 0z"/><line x1="4" y1="20" x2="20" y2="4" stroke-width="2"/>'},
{t:'beacon-random',n:'Beacon Spam',d:'Genera redes falsas al azar',ns:false,ic:'<path d="M5 12.55a11 11 0 0114 0"/><path d="M8.53 16.11a6 6 0 016.95 0"/><circle cx="12" cy="20" r="1"/><path d="M2 5l4 4M22 5l-4 4"/>'},
{t:'beacon-list',n:'Beacon Lista',d:'Transmite redes de la lista SSID',ns:true,ic:'<line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><circle cx="4" cy="6" r="1"/><circle cx="4" cy="12" r="1"/><circle cx="4" cy="18" r="1"/>'},
{t:'probe',n:'Probe Flood',d:'Solicitudes de conexión masivas (requiere AP seleccionado)',ns:true,ic:'<circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.5" y2="16.5"/>'},
{t:'rickroll',n:'Rick Roll',d:'Redes con la letra de Rick Astley',ns:false,ic:'<path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/>'}];
var SNT=[
{k:'beacon',d:'Captura beacons de APs (SSIDs, canales)'},
{k:'probe',d:'Registra probe requests de clientes buscando redes'},
{k:'deauth',d:'Detecta paquetes de desautenticación en el aire'},
{k:'raw',d:'Captura todo el tráfico WiFi sin filtro'},
{k:'esp',d:'Detecta dispositivos ESP cercanos (Marauder/Flipper)'},
{k:'pwn',d:'Busca redes pwned y dispositivos conocidos'}
];
var BKS=[['apple','Apple'],['google','Google'],['samsung','Samsung'],['windows','Windows'],['all','Todos']];
function api(u,o){return fetch(B+u,o||{}).then(function(r){return r.json()}).catch(function(){return null})}
function ap(u,b){return api(u,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)}).then(function(r){
if(r&&r.ok===false&&r.output)toast(r.output);
return r;
})}
function toast(m){var t=document.getElementById('toast');t.textContent=m;t.style.opacity='';t.classList.add('on');clearTimeout(t._t);t._t=setTimeout(function(){t.classList.remove('on')},3000)}
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
function fmt(s){s=Math.floor(s||0);var h=Math.floor(s/3600),m=Math.floor(s%3600/60);s%=60;return(h?h+'h ':'')+(m?m+'m ':'')+s+'s'}
function bars(r){var n=r>-50?4:r>-65?3:r>-75?2:1,h=[4,7,10,13],o='';for(var i=0;i<4;i++)o+='<span style="height:'+h[i]+'px"'+(i>=n?' class="off"':'')+'></span>';return o}

function openMor(){document.getElementById('morsheet').style.display='flex'}
function closeMor(){document.getElementById('morsheet').style.display='none'}
function morGo(p){closeMor();go(p)}
var NAV_MAP={home:'nb-home',wifi:'nb-wifi',attack:'nb-attack',monitor:'nb-mon',ble:'nb-ble',nfc:'nb-nfc',gps:'nb-mor',map:'nb-mor',term:'nb-mor',settings:'nb-mor'};
function go(p,b){document.querySelectorAll('.pg').forEach(function(e){e.classList.remove('on')});document.getElementById('p-'+p).classList.add('on');document.querySelectorAll('.nb').forEach(function(x){x.classList.remove('on')});var nbid=NAV_MAP[p];if(nbid)document.getElementById(nbid).classList.add('on');window.scrollTo(0,0);
if(gpid){clearInterval(gpid);gpid=null}
if(p!=='attack'&&hsT){clearInterval(hsT);hsT=null}
if(p!=='wifi'&&spid){clearInterval(spid);spid=null}
if(p!=='wifi'&&p!=='monitor')monLeave();
if(p==='wifi'){if(aps.length)rAL();else fAps()}
if(p==='gps'){fGps();gpid=setInterval(fGps,3000)}
if(p==='map'){wdPollData();wdPollGps();wdDraw()}
if(p==='settings'){fSettings();fSsids();fSpiffs()}
if(p==='nfc')fNfc();
if(p==='attack'){fHs();if(selAp.ssid){document.getElementById('essid').value=selAp.ssid;document.getElementById('ech').value=selAp.ch}fTplSt();fCap()}}

var _pollBusy=false,_pollBackoff=0,_pollOffline=false;
function _setOnline(v){if(_pollOffline===!v)return;_pollOffline=!v;document.getElementById('connbar').style.display=v?'none':'flex';}
function poll(){if(_pollBusy)return;if(document.visibilityState==='hidden'){_pollBackoff=Math.min(_pollBackoff+1,10);return}
_pollBusy=true;
fetch(B+'/api/state').then(function(r){return r.json()}).then(function(d){
_pollBusy=false;_pollBackoff=0;_setOnline(true);
if(!d)return;LS=d;rState(d);
var jk=(d.job&&d.job.kind)||'idle';var active=jk!=='idle';
clearInterval(pid);pid=setInterval(poll,active?1000:2000);
}).catch(function(){_pollBusy=false;_pollBackoff=Math.min(_pollBackoff+1,10);_setOnline(false);clearInterval(pid);pid=setTimeout(poll,Math.min(30000,2000*Math.pow(2,_pollBackoff)));});
}
function rState(d){

var job=d.job||{};
var jk=job.kind||d.mgmt_state||'idle';
var s=jk;
var pc='p-ok',dc='d-g',tx='Inactivo';
if(/^scan/.test(s)){pc='p-scan';dc='d-c';tx='Escaneando'}
else if(/^attack|^eviltwin/.test(s)){pc='p-atk';dc='d-r';tx='Atacando'}
else if(/^capture|^handshake|^sniff|^monitor/.test(s)){pc='p-cap';dc='d-a';tx='Capturando'}
else if(/^wardrive|^ble/.test(s)){pc='p-scan';dc='d-c';tx=/^ble/.test(s)?'BLE':'Wardrive'}
var hsEl=document.getElementById('hs');
if(s&&s!=='idle'){hsEl.style.display='';hsEl.innerHTML='<span class="pill '+pc+'"><span class="dot '+dc+'"></span>'+tx+'</span>'}
else{hsEl.style.display='none'}

var jobActive=(jk!=='idle'&&jk!=='');
var jbr=document.getElementById('jobbar');
if(jobActive){jbr.style.display='flex';var elapsed=job.elapsed!=null?job.elapsed+'s ':'';
var kindLabel=/^scan/.test(jk)?'Escaneando':/^attack/.test(jk)?'Ataque':/^eviltwin/.test(jk)?'Evil Twin':/^sniff/.test(jk)?'Sniffer':/^ble/.test(jk)?'BLE':/^wardrive/.test(jk)?'Wardrive':jk;
document.getElementById('jbtext').textContent=(job.type?job.type+' ':'')+kindLabel+'   '+elapsed+(job.remaining!=null?job.remaining+'s restantes':'activo');}
else jbr.style.display='none';

document.querySelectorAll('.b.bp,.b.bd').forEach(function(b){if(b.id==='jbstop'||b.id==='bscan'||b.closest('#aab')||b.closest('#p-nfc')||b.closest('#p-gps')||b.closest('#p-term')||b.closest('#p-settings')||b.closest('#p-evil')||b.closest('#p-map'))return;b.disabled=jobActive&&!b.dataset.alwaysEnabled;});
var dt=d.detail||{};
if(!snPending&&d.mgmt_state){var mode=s==='scanning'&&/^sniff-/.test(dt.kind||'')?dt.kind.slice(6):'';if(mode!==snActive)setSnifferActive(mode)}
document.getElementById('hrem').textContent=job.remaining!=null&&jobActive?(job.type||jk)+' - '+job.remaining+'s restantes':(dt.remaining_s!=null&&s!=='idle'?(dt.type||dt.kind||'')+' - '+dt.remaining_s+'s restantes':'');
var i='<div class="kv"><span class="kl">Versión FW</span><span class="kvv">'+esc(d.fw||'-')+'</span></div>';
i+='<div class="kv"><span class="kl">Placa</span><span class="kvv">'+esc(d.board||'-')+'</span></div>';
i+='<div class="kv"><span class="kl">Red AP</span><span class="kvv" style="color:var(--accent)">'+esc(d.ap_ssid||'-')+'</span></div>';
i+='<div class="kv"><span class="kl">IP</span><span class="kvv">'+esc(d.ip||'-')+'</span></div>';
i+='<div class="kv"><span class="kl">Tiempo activo</span><span class="kvv">'+fmt(d.uptime_s)+'</span></div>';
document.getElementById('hi').innerHTML=i;
var kb=d.heap?Math.round(d.heap/1024):0,pct=d.heap?Math.min(100,Math.round(d.heap/327680*100)):0;
document.getElementById('hram').textContent=d.heap?kb+' KB':'-';
document.getElementById('hramb').style.width=pct+'%';
if(d.heap_min){var hme=document.getElementById('hrammin');if(hme)hme.textContent=Math.round(d.heap_min/1024)+' KB';}
var aclie=document.getElementById('hapcli');if(aclie)aclie.textContent=d.ap_stations!=null?d.ap_stations+' cliente'+(d.ap_stations===1?'':'s'):'-';
var ab=document.getElementById('aab');
if(jobActive&&(s==='attack'||s==='eviltwin'||s==='sniffer'||s==='monitor')){ab.style.display='flex';document.getElementById('aabn').textContent=job.kind||dt.kind||dt.type||'Ataque';document.getElementById('aabt').textContent=job.remaining!=null?job.remaining+'s restantes':'Indefinido - detener manualmente'}
else ab.style.display='none'}

function qScan(){go('wifi');doScan()}
function qHs(){go('attack');doHs()}

function doScan(){
var b=document.getElementById('bscan');b.disabled=true;
var dEl=document.getElementById('sdur');
var dur=dEl?(parseInt(dEl.value,10)||10):10;
document.getElementById('ss').textContent='Escaneando... ⟳';
document.getElementById('cveout').style.display='none';
ap('/api/scan',{duration:dur}).then(function(r){

if(!r||!r.ok){b.disabled=false;toast(r&&r.output?r.output:'Error en escaneo');document.getElementById('ss').textContent='';return}
if(r.state==='scanning'||r.scanning){

var scanFails=0;if(spid)clearInterval(spid);spid=setInterval(function(){
api('/api/state').then(function(d){
if(!d){scanFails++;if(scanFails>20){clearInterval(spid);spid=null;b.disabled=false;document.getElementById('ss').textContent='Reconectando...';fAps()}return}
scanFails=0;var jk=(d.job&&d.job.kind)||d.mgmt_state||'idle';
if(!/scan/.test(jk)){
clearInterval(spid);spid=null;b.disabled=false;
document.getElementById('ss').textContent='Cargando resultados...';
fAps();
}else{
var sEl=(d.job&&d.job.elapsed)||0,sHk=d.heap?Math.round(d.heap/1024):0;
var sRm=(d.job&&d.job.remaining!=null)?d.job.remaining:null;
document.getElementById('ss').textContent='Escaneando... '+(sRm!=null?sRm+'s restantes':sEl+'s')+' · heap '+sHk+'KB ⟳';
}
});},1500);
}else{
b.disabled=false;
toast((r.count||0)+' redes encontradas');fAps();
}
})}
function restoreAps(){try{var c=JSON.parse(localStorage.getItem('wifiAps')||'null');if(!c||!c.aps||!c.aps.length)return;aps=c.aps;sel={};aps.forEach(function(a){if(a.sel)sel[a.i]=true});var mins=Math.round((Date.now()-c.t)/60000);document.getElementById('ss').textContent=aps.length+' redes (caché '+(mins<1?'reciente':mins+' min')+')';rAL();hsRenderTargets()}catch(e){}}
function fAps(retry){retry=retry||0;api('/api/aps').then(function(d){
if(!d){if(retry<8){var ms=Math.min(500*Math.pow(1.5,retry),4000);document.getElementById('ss').textContent='Reconectando... ('+Math.round(ms/1000)+'s)';setTimeout(function(){fAps(retry+1)},ms);return}document.getElementById('ss').textContent='Sin respuesta';return}
if(d.scanning){document.getElementById('ss').textContent='Escaneando... '+(d.count||0)+' redes hasta ahora ⟳';setTimeout(function(){fAps(0)},1000);return;}
if(!d.aps||!d.aps.length){document.getElementById('ss').textContent='Sin resultados';document.getElementById('al').innerHTML='<div class="le">Sin redes detectadas</div>';return}
aps=d.aps;sel={};
try{localStorage.setItem('wifiAps',JSON.stringify({t:Date.now(),aps:aps}))}catch(e){}
aps.forEach(function(a){if(a.sel)sel[a.i]=true});
document.getElementById('ss').textContent=aps.length+' redes encontradas';rAL();hsRenderTargets()})}
function rAL(){var e=document.getElementById('al');
if(!aps.length){e.innerHTML='<div class="le">Sin redes</div>';document.getElementById('ac').textContent='0 redes';monSigList();return}
var h='';aps.forEach(function(a){var s=!!sel[a.i],isOpen=(a.open===true||a.auth==='OPEN'||a.enc===0),lk=isOpen?'':'<svg class="lk" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 018 0v4"/></svg>',authBadge=a.auth?'<span class="chb" style="font-size:9px;padding:2px 5px;margin-left:2px">'+esc(a.auth)+'</span>':'';
h+='<div class="li'+(s?' sel':'')+(a.wpsPresent?' wps':'')+'" onclick="tAp('+a.i+')" role="button" aria-pressed="'+(s?'true':'false')+'"><div class="sig">'+bars(a.rssi)+'</div><div class="nfo"><div class="ss">'+esc(a.ssid||'(oculta)')+lk+authBadge+'</div><div class="mac">'+esc(a.bssid||'')+'</div></div><span class="chb">CH '+a.ch+'</span><span class="rss">'+a.rssi+' dBm</span></div>'});
e.innerHTML=h;
document.getElementById('ac').textContent=aps.length+' redes | '+Object.keys(sel).length+' seleccionadas';monSigList()}
function tAp(i){var newOn=!sel[i];ap('/api/select',{i:i,on:newOn}).then(function(r){
if(r&&r.ok===false){toast('Error AP');rAL();return}
var isSel=(r&&r.sel!=null)?r.sel:newOn;
if(isSel){sel[i]=true;var a=null;aps.forEach(function(x){if(x.i===i)a=x});if(a){selAp.ssid=a.ssid;selAp.ch=a.ch}}else delete sel[i];
rAL();});}
function selAll(){var queue=aps.slice(),idx=0;function next(){if(idx>=queue.length){rAL();toast('Todas seleccionadas');return}var a=queue[idx++];sel[a.i]=true;ap('/api/select',{i:a.i,on:true}).then(next).catch(next)};next()}
function doCve(){var c=document.getElementById('cveout');c.style.display='block';
c.innerHTML='<span style="color:var(--info)">Analizando vulnerabilidades...</span>';
api('/api/cvecheck').then(function(d){
if(!d||!d.results){c.innerHTML='<span style="color:var(--fg3)">Sin datos. Escanea primero.</span>';return}
if(!d.total){c.innerHTML='<span style="color:var(--ok)">Sin vulnerabilidades conocidas detectadas</span>';return}
var h='<div style="margin-bottom:6px"><span class="bdg">'+d.total+' vulnerables</span></div>';
d.results.forEach(function(r){h+='<div style="padding:8px 0;border-bottom:1px solid var(--bd)"><div style="font-weight:600">'+esc(r.ssid)+' <span class="chb">CH '+r.ch+'</span></div><div style="font-size:12px;color:var(--crit)">'+esc(r.cves)+'</div><div style="font-size:11px;color:var(--fg3)">'+esc(r.bssid)+'</div></div>'});
c.innerHTML=h})}

function rAtks(){var h='';ATKS.forEach(function(a){
h+='<div class="ac"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">'+a.ic+'</svg><div class="ac-n">'+a.n+'</div><div class="ac-d">'+a.d+'</div><div class="acon"><select class="inp bs" id="d-'+a.t+'"><option value="10">10s</option><option value="30" selected>30s</option><option value="60">1m</option><option value="120">2m</option><option value="300">5m</option><option value="0">Indefinido</option></select><button class="b bd bs" onclick="lAtk(\''+a.t+'\')">Iniciar</button></div></div>'});
document.getElementById('acs').innerHTML=h}
function lAtk(t){var a=null;ATKS.forEach(function(x){if(x.t===t)a=x});
if(a.ns&&!Object.keys(sel).length){toast('Necesita APs seleccionados');return}
var dur=parseInt(document.getElementById('d-'+t).value);
if(dur===0&&!confirm('Ataque indefinido: solo se detiene manualmente. Continuar?'))return;
ap('/api/attack',{type:t,duration:dur}).then(function(r){
if(r&&r.ok)toast(a.n+' iniciado');else toast('Error')})}
function doStop(){ap('/api/stop',{}).then(function(r){if(!r||!r.ok){toast('Error al detener');return}setSnifferActive('');deauthOwnsSniffer=false;toast('Detenido');stopHsPoll();poll()})}

var handshakeRows=[];
function handshakeUpsert(e){
var row=handshakeRows.find(function(r){return r.bssid===e.bssid&&r.type===e.type});
if(!row){row={bssid:e.bssid,type:e.type};handshakeRows.push(row);if(handshakeRows.length>=50)handshakeRows.shift()}
row.ssid=e.ssid||row.ssid||'(oculta)';
if(e.channel!=null||row.channel==null)row.channel=e.channel==null?null:e.channel;
if(e.rssi!=null||row.rssi==null)row.rssi=e.rssi==null?null:e.rssi;
if(e.msgs!=null)row.msgs=e.msgs;
if(row.status!=='capturado')row.status=e.status;
}
function handshakeIngest(line){
var m=String(line).match(/(?:PMKID|HANDSHAKE):\s*((?:[\da-f]{2}:){5}[\da-f]{2})\s+SSID:(.*?)(?:\s+Ch:\s*(\d+))?(?:\s+RSSI:\s*(-?\d+))?\s*$/i);
if(!m)return;
var bssid=m[1].toUpperCase(),ap=aps.find(function(a){return String(a.bssid).toUpperCase()===bssid});
handshakeUpsert({bssid:bssid,ssid:m[2].trim(),channel:m[3]?+m[3]:ap?ap.ch:null,rssi:m[4]?+m[4]:ap?ap.rssi:null,type:/PMKID:/i.test(m[0])?'PMKID':'WPA2',status:'capturado'});
}
function doHs(){
// Auto-scan if no APs loaded (needed for multi-channel hop + pre-population)
if(!aps||aps.length===0){toast('Escaneando redes primero...');
ap('/api/scan',{}).then(function(){
var tries=0;var poll=setInterval(function(){tries++;
api('/api/aps').then(function(d){if(!d||!d.aps)return;if(!d.scanning&&d.aps.length>0){clearInterval(poll);aps=d.aps;aps.forEach(function(a,i){a.i=i});
rAL();hsRenderTargets();toast(aps.length+' redes — iniciando captura');doHsReal()}
else if(tries>15){clearInterval(poll);toast('Scan timeout — captura sin datos de canales');doHsReal()}})},1500)});return}
doHsReal()}
function doHsReal(){var b={deauth:document.getElementById('hdea').checked,duration:parseInt(document.getElementById('hdur').value)};
var tgt=document.getElementById('htgt');
if(tgt&&tgt.value){var parts=tgt.value.split('|');b.bssid=parts[0];b.ch=parseInt(parts[1])||0}
ap('/api/handshake',b).then(function(r){
if(r&&r.ok){toast(r.mode==='targeted'?'Captura dirigida ch='+r.target_ch:'Captura pasiva ('+r.channels+' canales)');document.getElementById('hsw').style.display='block';startHsPoll()}
else toast('Error')})}
function hsRenderTargets(){var el=document.getElementById('htgt');if(!el)return;
var h='<option value="">Pasivo (todos los canales)</option>';
aps.forEach(function(a){h+='<option value="'+esc(a.bssid)+'|'+a.ch+'">'+esc(a.ssid||'(oculta)')+' — CH '+a.ch+' ('+a.rssi+' dBm)</option>'});
el.innerHTML=h}
function startHsPoll(){if(hsT)clearInterval(hsT);document.getElementById('hslive').textContent='Capturando en vivo';hsT=setInterval(fHs,2000);fHs()}
function stopHsPoll(){if(hsT){clearInterval(hsT);hsT=null}}
function clearHandshakes(){handshakeRows=[];renderHandshakes();toast('Capturas limpiadas')}
function renderHandshakes(){
var h='',count=0;handshakeRows.forEach(function(e){
if(e.status==='capturado')count++;
var msgsLabel='';
if(e.msgs){var m=e.msgs,parts=[];if(m&1)parts.push('M1');if(m&2)parts.push('M2');if(m&4)parts.push('M3');if(m&8)parts.push('M4');msgsLabel=' ('+parts.join('+')+')'}
var statusCls=e.status==='capturado'?'hg-full':'hg-pmkid';
h+='<tr><td class="mac">'+esc(e.bssid)+'</td><td>'+esc(e.ssid)+'</td><td>'+(e.channel==null?'-':e.channel)+'</td><td>'+signalSegments(e.rssi)+'</td><td><span class="hg '+(e.type==='PMKID'?'hg-pmkid':statusCls)+'">'+e.type+msgsLabel+'</span></td><td>'+e.status+'</td></tr>'});
document.getElementById('hsc').textContent=count+' handshakes capturados';
document.getElementById('hsb').innerHTML=h||'<tr><td colspan="6" class="le">Esperando capturas...</td></tr>';
}
function fHs(){api('/api/handshake').then(function(d){
if(!d)return;
document.getElementById('hslive').textContent=d.active?'Capturando en vivo':'Captura detenida';
if(d.active&&!hsT)hsT=setInterval(fHs,2000);else if(!d.active)stopHsPoll();
(d.entries||[]).forEach(function(e){
if(!/^(?:[\da-f]{2}:){5}[\da-f]{2}$/i.test(e.bssid||''))return;
var ssid=e.ssid;
if(!ssid){var ap=aps.find(function(a){return String(a.bssid).toUpperCase()===e.bssid.toUpperCase()});if(ap)ssid=ap.ssid}
handshakeUpsert({bssid:e.bssid.toUpperCase(),ssid:ssid,channel:e.ch||null,rssi:e.rssi==null?null:e.rssi,type:e.type==='pmkid'?'PMKID':'WPA2',status:e.type==='none'?'intentando':'capturado',msgs:e.msgs||0});
});renderHandshakes()})}

var snActive='',snLines=[],snPending=false,deauthOwnsSniffer=false;
function rSnp(){var h='';SNT.forEach(function(s){var k=s.k;h+='<button class="p sn-'+k+(k===snT?' on':'')+(k===snActive?' sn-live':'')+'" aria-pressed="'+(k===snT)+'" onclick="snSet(\''+k+'\')">'+k.charAt(0).toUpperCase()+k.slice(1)+'</button>'});var desc='';SNT.forEach(function(s){if(s.k===snT)desc=s.d});h+='<div style="font-size:11px;color:var(--fg2);margin-top:6px">'+desc+'</div>';document.getElementById('snp').innerHTML=h}
function snSet(s){snT=s;rSnp()}
function setSnifferActive(type){
snActive=type;rSnp();document.getElementById('snstatus').textContent=type?'Escuchando   '+type:'Sniffer detenido';
document.getElementById('snstop').disabled=!type;
if(type!=='deauth'&&monOn.deauth){monOn.deauth=false;deauthOwnsSniffer=false;document.getElementById('mb-deauth').classList.remove('on')}
fMonDeauth();
}
function snifferIngest(line){if(!snActive)return;
String(line).split(/\r?\n/).forEach(function(l){snLines.push(l)});if(snLines.length>200)snLines.splice(0,snLines.length-200)}
function renderSniffer(){var e=document.getElementById('snfeed');e.textContent=snLines.join('\n')||(snActive?'Escuchando...':'Inicia el sniffer para ver la captura en vivo.');e.scrollTop=e.scrollHeight;document.getElementById('sncount').textContent=snLines.length+' / 200 líneas'}
function clearSniffer(){snLines=[];renderSniffer()}
function exportSniffer(){if(!snLines.length){toast('Sin líneas para exportar');return}
var a=document.createElement('a'),url=URL.createObjectURL(new Blob([snLines.join('\n')+'\n'],{type:'text/plain;charset=utf-8'}));
a.href=url;a.download='pwnterrey-sniffer-'+new Date().toISOString().replace(/[:.]/g,'-')+'.txt';document.body.appendChild(a);a.click();a.remove();setTimeout(function(){URL.revokeObjectURL(url)},1000)}
function stopSniffer(){ap('/api/stop',{}).then(function(r){if(r&&r.ok){deauthOwnsSniffer=false;setSnifferActive('');deauthTail='';toast('Sniffer detenido');poll()}else toast('No se pudo detener el sniffer')})}
function doSniff(){if(snPending)return;var mode=snT;var dur=parseInt(document.getElementById('snd').value);
// UX: warn user that indefinite sniffer can exhaust memory
if(dur===0&&!confirm('Sniffer INDEFINIDO: correrá hasta que lo detengas manualmente. Puede agotar la memoria del badge con el tiempo. ¿Continuar?'))return;
snPending=true;
ap('/api/sniffer',{type:mode,duration:dur}).then(function(r){
snPending=false;if(r&&r.ok){deauthTail='';setSnifferActive(mode);renderSniffer();toast('Sniffer '+mode+' activo')}else toast('Error al iniciar sniffer; verifica si el badge está ocupado')})}

function tplSel(t,el){tpl=t;document.querySelectorAll('#etpg .tpc').forEach(function(x){x.classList.remove('on')});el.classList.add('on')}
var etCountdownT=null;
function doEvil(){var s=document.getElementById('essid').value.trim();
if(!s){toast('Escribe el SSID');return}
var edurEl=document.getElementById('edur');var dur=edurEl?parseInt(edurEl.value)||300:300;
var durTxt=dur===0?'indefinido':dur+'s';
if(!confirm('Activar Evil Twin en "'+s+'"? El dashboard se desconectará ~'+durTxt+' y regresará solo.'))return;
ap('/api/eviltwin',{ssid:s,channel:parseInt(document.getElementById('ech').value)||1,template:tpl,duration:dur}).then(function(r){
if(r&&r.ok){
var actualDur=(r.duration!=null?r.duration:dur);
document.getElementById('emsg').textContent='Evil Twin activo en "'+s+'". '+(actualDur?'Reconexión automática en '+actualDur+'s.':'Duración indefinida - usa RESET para volver.');
var cdwrap=document.getElementById('emod-cdwrap');
if(actualDur&&cdwrap){cdwrap.style.display='block';var rem=actualDur;
if(etCountdownT)clearInterval(etCountdownT);
function cdTick(){document.getElementById('emod-cd').textContent=rem;if(rem<=0){clearInterval(etCountdownT);etCountdownT=null;etWaitReconnect();return}rem--;}
cdTick();etCountdownT=setInterval(cdTick,1000);}
document.getElementById('emod').style.display='flex';}
else toast('Error al activar')})}
function etWaitReconnect(){var t=setInterval(function(){fetch(B+'/api/state').then(function(r){return r.json()}).then(function(d){if(d){clearInterval(t);document.getElementById('emod').style.display='none';toast('Reconectado');poll();}}).catch(function(){});},2000);}
function upTpl(){var h=document.getElementById('ehtml').value;
if(!h.trim()){toast('Pega el HTML');return}
ap('/api/evil_upload',{html:h}).then(function(r){
if(r&&r.ok){toast('Plantilla subida');fTplSt()}else toast('Error al subir')})}
function fTplSt(){api('/api/evil_templates').then(function(d){var e=document.getElementById('etst');
if(!d){e.textContent='';return}
// MED-7 fix: escape custom_size to prevent XSS
e.textContent=d.custom_size?('Plantilla personalizada: '+String(d.custom_size||0)+' bytes'):'Sin plantilla personalizada cargada'})}
function fCap(){api('/api/captures').then(function(d){
var e=document.getElementById('ecap'),n=document.getElementById('ecnt');
caps=d&&d.captures?d.captures:[];
if(!caps.length){e.innerHTML='<div class="le">Sin capturas</div>';n.style.display='none';return}
n.style.display='inline-flex';n.textContent=caps.length;
var h='';caps.forEach(function(c,i){
h+='<div class="kv"><div style="flex:1;min-width:0"><div style="font-weight:600;font-size:13px">'+esc(c.user||'-')+'</div><div style="font-size:12px;color:var(--fg3)">'+esc(c.ap||'-')+(c.t?' &middot; '+esc(c.t):'')+'</div></div><span class="cpw" id="cpw'+i+'" onclick="revCap('+i+')">'+esc(String(c.pass||'').replace(/./g,'*'))+'</span></div>'});
e.innerHTML=h})}
function revCap(i){var e=document.getElementById('cpw'+i);if(!e||!caps[i])return;
var p=String(caps[i].pass||'');
if(e.dataset.r){e.textContent=p.replace(/./g,'*');e.dataset.r=''}else{e.textContent=p;e.dataset.r='1'}}
function expCap(){if(!caps.length){toast('Sin capturas');return}
var t='PWNTERREY Evil Twin - Capturas\n\n';
caps.forEach(function(c){t+='AP: '+(c.ap||'-')+'\nUser: '+(c.user||'-')+'\nPass: '+(c.pass||'-')+'\nFecha: '+(c.t||'-')+'\n---\n'});
var b=new Blob([t],{type:'text/plain'}),a=document.createElement('a');
a.href=URL.createObjectURL(b);a.download='capturas.txt';document.body.appendChild(a);a.click();document.body.removeChild(a);URL.revokeObjectURL(a.href)}
function clrCap(){if(!confirm('Borrar todas las capturas?'))return;
ap('/api/captures',{action:'clear'}).then(function(){toast('Capturas borradas');fCap()})}

function rBkp(){var h='';BKS.forEach(function(k){h+='<button class="p'+(k[0]===bk?' on':'')+'" onclick="bkSet(\''+k[0]+'\')">'+k[1]+'</button>'});document.getElementById('bkp').innerHTML=h}
function bkSet(k){bk=k;rBkp()}
function doBle(){document.getElementById('bst').innerHTML='<span style="color:var(--info)">Iniciando...</span>';
ap('/api/ble',{action:'spam',kind:bk,duration:parseInt(document.getElementById('bdr').value)}).then(function(r){
if(r&&r.ok){document.getElementById('bst').innerHTML='<span style="color:var(--ok)">BLE spam activo</span>'+(r.note?'<div class="muted" style="margin-top:6px;font-size:12px">⚠ '+esc(r.note)+'</div>':'');toast(r.note||'BLE spam activo');}
else if(r&&r.code==='ble_no_memory'){document.getElementById('bst').innerHTML='<span style="color:var(--crit)">Memoria insuficiente para iniciar Bluetooth</span>';toast('Memoria insuficiente para BLE');}
else{document.getElementById('bst').innerHTML='<span style="color:var(--crit)">'+(r&&r.output?esc(r.output):'Error al iniciar')+'</span>';toast(r&&r.output||'Error al iniciar');}
})}
function doBScan(){ap('/api/blescan',{duration:parseInt(document.getElementById('bsd').value)}).then(function(r){
if(r&&r.ok)toast('Escaneo BLE iniciado - ver Terminal');
else if(r&&r.code==='ble_no_memory')toast('Memoria insuficiente para BLE');
else toast(r&&r.output||'Error');})}

function fNfc(){api('/api/nfc').then(function(d){var e=document.getElementById('nfo');
if(!d){e.innerHTML='Sin respuesta del lector';return}
if(d.type==='empty'||!d.uid){e.innerHTML='Sin tag. Acerca un tag NFC al lector.';return}
var tn={uri:'URL',text:'Texto',raw:'RAW'}[d.type]||d.type;
var h='<div class="kv"><span class="kl">UID</span><span class="kvv">'+esc(d.uid)+'</span></div>';
h+='<div class="kv"><span class="kl">Tipo</span><span class="kvv">'+esc(tn)+'</span></div>';
h+='<div class="kv"><span class="kl">Contenido</span><span class="kvv" style="max-width:60%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+esc(d.content||'-')+'</span></div>';
e.innerHTML=h})}
function nMsg(h){document.getElementById('ns').innerHTML=h}
function nWrite(act,id){var d=document.getElementById(id).value.trim();
if(!d){toast('Escribe el contenido');return}
nMsg('<span style="color:var(--info)">Escribiendo...</span>');
ap('/api/nfc',{action:act,data:d}).then(function(r){
nMsg(r&&r.ok?'<span style="color:var(--ok)">Escrito correctamente</span>':'<span style="color:var(--crit)">Error al escribir</span>')})}
function nRaw(){var h=document.getElementById('nhex').value.trim();
if(!h){toast('Escribe los bytes en hex');return}
nMsg('<span style="color:var(--info)">Escribiendo...</span>');
ap('/api/nfc',{action:'write-raw',hex:h,block:parseInt(document.getElementById('nblk').value)||1}).then(function(r){
nMsg(r&&r.ok?'<span style="color:var(--ok)">Escrito correctamente</span>':'<span style="color:var(--crit)">Error al escribir</span>')})}

function gpsRestart(){
  var btn=document.querySelector('#p-gps button[onclick]');if(!btn)return;
  btn.textContent='Reiniciando...';btn.disabled=true;btn.style.opacity='0.5';
  toast('Reiniciando GPS... (~8s)');
  fetch('/api/gps',{method:'POST'}).then(function(r){return r.json()}).then(function(d){
    btn.textContent='↻ Reiniciar GPS';btn.disabled=false;btn.style.opacity='1';
    toast(d.ok?'GPS reiniciado — espera ~30s para señal':(d.output||'Error: '+(d.code||'')))
  }).catch(function(){btn.textContent='↻ Reiniciar GPS';btn.disabled=false;btn.style.opacity='1';toast('Error al reiniciar GPS')})
}
function gpsSignalBars(sats){
  var el=document.getElementById('gpsSignalBar');if(!el)return;
  var maxBars=5,level=Math.min(maxBars,Math.floor(sats/2));
  var h='';for(var i=0;i<maxBars;i++){
    var height=4+(i*3);var active=i<level;
    h+='<div style="width:4px;height:'+height+'px;border-radius:1px;background:'+(active?'#34d399':'rgba(255,255,255,0.15)')+'"></div>';
  }
  el.innerHTML=h;
}
function gpsProgressBar(sats,hasFix){
  var el=document.getElementById('gpsProgress');if(!el)return;
  if(hasFix){el.style.display='none';return}
  el.style.display='block';
  var pct=Math.min(100,Math.round(sats/4*100));
  var col=pct>=100?'var(--ok)':pct>=50?'var(--warn)':'var(--crit)';
  el.innerHTML='<div style="font-size:11px;color:var(--fg3);margin-bottom:4px">Progreso hacia fix: '+sats+'/4 satélites mínimos</div><div style="height:4px;background:var(--bg3);border-radius:2px;overflow:hidden"><div style="height:100%;width:'+pct+'%;background:'+col+';border-radius:2px;transition:width .3s"></div></div>'+(sats>=4?'<div style="font-size:11px;color:var(--warn);margin-top:4px">Satélites suficientes — esperando convergencia de posición...</div>':'');
}
function fGps(){api('/api/gps').then(function(d){
var fx=document.getElementById('gfix');
if(!d){document.getElementById('gd').innerHTML='<span style="color:var(--fg3)">Sin datos GPS</span>';return}
if(d.fix){fx.className='fixb fix-ok';fx.innerHTML='<span class="fixd" style="background:var(--ok);box-shadow:0 0 10px var(--ok)"></span>GPS conectado'}
else{fx.className='fixb fix-no';fx.innerHTML='<span class="fixd" style="background:var(--crit);box-shadow:0 0 10px var(--crit)"></span>Buscando señal GPS'+(d.sats?' ('+d.sats+' satélites)':'')}
gpsSignalBars(d.sats||0);
gpsProgressBar(d.sats||0,d.fix);
var h='<div class="kv"><span class="kl">Satélites</span><span class="kvv">'+(d.sats||0)+'</span></div>';
h+='<div class="kv"><span class="kl">Latitud</span><span class="kvv">'+(d.lat||'--')+'</span></div>';
h+='<div class="kv"><span class="kl">Longitud</span><span class="kvv">'+(d.lon||'--')+'</span></div>';
h+='<div class="kv"><span class="kl">Altitud</span><span class="kvv">'+(d.alt||'--')+' m</span></div>';
document.getElementById('gd').innerHTML=h})}

var wdData=[],wdAutoT=null,wdIsActive=false,wdActiveType='',wdGpsFix=false,wdGpsLat=null,wdGpsLon=null,wdHighlightIdx=-1;
// Browser-side wardrive cache (survives firmware ring-buffer overwrites)
var _wdDB=null,_wdCacheReady=false,_wdAllData=[];
(function(){if(!window.indexedDB)return;var r=indexedDB.open('wdCache',1);
r.onupgradeneeded=function(e){e.target.result.createObjectStore('nets',{keyPath:'b'})};
r.onsuccess=function(){_wdDB=r.result;_wdCacheReady=true;_wdLoadAll()};r.onerror=function(){}})();
function _wdLoadAll(){if(!_wdDB)return;var t=_wdDB.transaction('nets','readonly').objectStore('nets').getAll();
t.onsuccess=function(){_wdAllData=t.result||[];wdData=_wdAllData;wdDraw();wdListRender()}}
function _wdCacheMerge(entries){if(!_wdDB||!entries.length)return;
var tx=_wdDB.transaction('nets','readwrite'),st=tx.objectStore('nets'),added=0;
entries.forEach(function(e){if(!e.b)return;
  var existing=_wdAllData.find(function(x){return x.b===e.b});
  if(!existing||(parseInt(e.r)>parseInt(existing.r))){st.put(e);added++}
});
if(added)tx.oncomplete=function(){_wdLoadAll()}}
function wdCacheClear(){if(!_wdDB)return;if(!confirm('¿Limpiar todos los datos cacheados del wardrive?'))return;var tx=_wdDB.transaction('nets','readwrite');
tx.objectStore('nets').clear();tx.oncomplete=function(){_wdAllData=[];wdData=[];wdDraw();wdListRender();toast('Cache limpiado')}}


if('serviceWorker' in navigator){navigator.serviceWorker.register('/sw-tiles.js').then(function(r){r.update()}).catch(function(){})}

function wdAuthColor(a){if(!a)return'#888';var u=String(a).toUpperCase();if(u.indexOf('OPEN')>=0)return'#ff4444';if(u.indexOf('WEP')>=0)return'#ff8800';if(u.indexOf('WPA3')>=0)return'#00ddff';if(u.indexOf('WPA2')>=0)return'#44ff44';if(u.indexOf('WPA')>=0)return'#ffdd00';return'#888'}

function wdPollGps(){fetch('/api/gps').then(function(r){return r.json()}).then(function(d){
  if(!d||!d.ok)return;
  wdGpsFix=!!(d.fix);wdGpsLat=parseFloat(d.lat)||null;wdGpsLon=parseFloat(d.lon)||null;
  var pill=document.getElementById('wdGpsPill'),dot=document.getElementById('wdGpsDot'),lbl=document.getElementById('wdGpsLbl');
  if(!pill)return;
  if(wdGpsFix){
    pill.className='wdGpsPill wdGpsFix';
    dot.style.cssText='width:8px;height:8px;border-radius:50%;background:var(--ok);box-shadow:0 0 6px var(--ok);flex-shrink:0';
    lbl.textContent='GPS Conectado'+(d.sats?' — '+d.sats+' satélites':'');
  }else{
    pill.className='wdGpsPill wdGpsNoFix';
    dot.style.cssText='width:8px;height:8px;border-radius:50%;background:var(--crit);box-shadow:0 0 6px var(--crit);flex-shrink:0';
    lbl.textContent='Sin GPS';
  }

  wdDraw();
}).catch(function(){})}

function wdPollData(){fetch('/api/wardrive/data').then(function(r){return r.json()}).then(function(d){
  wdIsActive=!!(d.active);
  var newData=d.entries||[];

  // Merge into browser cache (keeps ALL networks, even after firmware ring-buffer overwrites)
  _wdCacheMerge(newData);
  // wdData is set by _wdLoadAll callback, but update count immediately
  var count=Math.max(newData.length,_wdAllData.length);
  document.getElementById('wdcount').textContent=count+' redes capturadas';
  document.getElementById('wdListCount').textContent=count;
  document.getElementById('wdnodata').style.display=wdData.length?'none':'flex';
  wdDraw();wdListRender();

  wdSyncUI();
}).catch(function(){})}

function wdSyncUI(){
  var startRow=document.getElementById('wdStartRow'),stopRow=document.getElementById('wdStopRow');
  if(!startRow||!stopRow)return;
  if(wdIsActive){
    startRow.style.display='none';stopRow.style.display='block';
    document.getElementById('wdActiveType').textContent=(wdActiveType==='bt'?'BT':'WiFi')+' Wardrive activo';
  }else{
    startRow.style.display='flex';stopRow.style.display='none';

    if(wdAutoT){clearInterval(wdAutoT);wdAutoT=null}
  }
}

function wdStart(t){
  var dur=parseInt(document.getElementById('wdDur').value)||0;
  wdActiveType=t;
  fetch('/api/wardrive',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({type:t,duration:dur})}).then(function(r){return r.json()}).then(function(r){
    if(r&&r.ok){
      toast((t==='wifi'?'WiFi':'BT')+' Wardrive iniciado');
      wdIsActive=true;wdSyncUI();
      wdData=[];wdHighlightIdx=-1;

      if(wdAutoT)clearInterval(wdAutoT);
      wdAutoT=setInterval(function(){wdPollData();wdPollGps()},3000);
      wdPollData();wdPollGps();
    }else toast((r&&r.output)?r.output:'Error wardrive');
  }).catch(function(){toast('Error wardrive')})}

function wdStop(){

  if(wdAutoT){clearInterval(wdAutoT);wdAutoT=null}
  fetch('/api/stop',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({})}).then(function(r){return r.json()}).then(function(r){
    toast('Wardrive detenido');
    wdIsActive=false;
    wdSyncUI();
    wdPollData();
  }).catch(function(){

    toast('Wardrive detenido');
    wdIsActive=false;
    wdSyncUI();
  })}

function wdMapClear(){if(!confirm('¿Limpiar todos los datos del wardrive?'))return;
  fetch('/api/wardrive/clear',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({})}).then(function(r){return r.json()}).then(function(){
    wdData=[];wdHighlightIdx=-1;wdDraw();
    document.getElementById('wdcount').textContent='0 redes capturadas';
    document.getElementById('wdListCount').textContent='0';
    document.getElementById('wdnodata').style.display='flex';
    document.getElementById('wdlist').innerHTML='<div class="le" style="font-size:13px">Sin datos aún</div>';
    toast('Datos limpiados');
  }).catch(function(){toast('Error al limpiar')})}

function wdMapExport(){window.open('/api/wardrive/csv')}

// ── Tile Map Engine ──────────────────────────────────────────────────────────
var _tdb=null,_tReady=false,_tImgCache={},_tRedrawPending=false;
var _mCLat=25.67,_mCLon=-100.31,_mZoom=16,_mPanX=0,_mPanY=0;
(function(){if(!window.indexedDB)return;var r=indexedDB.open('wdTiles',1);
r.onupgradeneeded=function(e){e.target.result.createObjectStore('tiles',{keyPath:'k'})};
r.onsuccess=function(){_tdb=r.result;_tReady=true};r.onerror=function(){}})();

function _tGet(k,cb){if(!_tdb){cb(null);return}var t=_tdb.transaction('tiles','readonly').objectStore('tiles').get(k);t.onsuccess=function(){cb(t.result?t.result.b:null)};t.onerror=function(){cb(null)}}
function _tPut(k,b){if(!_tdb)return;var t=_tdb.transaction('tiles','readwrite').objectStore('tiles');t.put({k:k,b:b})}
function _tUrl(x,y,z){return'https://tile.openstreetmap.org/'+z+'/'+x+'/'+y+'.png'}
function _ll2t(la,lo,z){var n=Math.pow(2,z);return{x:Math.floor((lo+180)/360*n),y:Math.floor((1-Math.log(Math.tan(la*Math.PI/180)+1/Math.cos(la*Math.PI/180))/Math.PI)/2*n)}}
function _ll2px(la,lo){var n=Math.pow(2,_mZoom),tx=(lo+180)/360*n*256,ty=(1-Math.log(Math.tan(la*Math.PI/180)+1/Math.cos(la*Math.PI/180))/Math.PI)/2*n*256;var cx=(_mCLon+180)/360*n*256,cy=(1-Math.log(Math.tan(_mCLat*Math.PI/180)+1/Math.cos(_mCLat*Math.PI/180))/Math.PI)/2*n*256;var cv=document.getElementById('wdcanvas');return{x:tx-cx+cv.width/2+_mPanX,y:ty-cy+cv.height/2+_mPanY}}

function _loadTile(url,cb){
  if(_tImgCache[url]){cb(_tImgCache[url]);return}
  _tGet(url,function(blob){
    if(blob){var u=URL.createObjectURL(blob);var img=new Image();img.onload=function(){_tImgCache[url]=img;cb(img)};img.onerror=function(){cb(null)};img.src=u;return}
    // Always try fetch — phone may have mobile data even on badge AP WiFi
    var ctrl=new AbortController();var tid=setTimeout(function(){ctrl.abort()},4000);
    fetch(url,{mode:'cors',signal:ctrl.signal}).then(function(r){clearTimeout(tid);return r.ok?r.blob():null}).then(function(b){
      if(!b){cb(null);return}_tPut(url,b);var u=URL.createObjectURL(b);var img=new Image();img.onload=function(){_tImgCache[url]=img;cb(img)};img.onerror=function(){cb(null)};img.src=u;
    }).catch(function(){clearTimeout(tid);cb(null)})
  })
}

function wdDraw(){
  var cv=document.getElementById('wdcanvas');if(!cv)return;
  if(!document.getElementById('p-map').classList.contains('on'))return;
  var w=cv.parentElement.clientWidth,h=cv.parentElement.clientHeight||300;
  if(cv.width!==w)cv.width=w;if(cv.height!==h)cv.height=h;
  var ctx=cv.getContext('2d');
  ctx.fillStyle='#1a1a1a';ctx.fillRect(0,0,w,h);

  // Check if any entries have real coordinates
  var hasCoords=false;
  if(wdData&&wdData.length){
    for(var i=0;i<wdData.length;i++){
      var la=parseFloat(wdData[i].la),lo=parseFloat(wdData[i].lo);
      if(la&&lo&&Math.abs(la)>0.001&&Math.abs(lo)>0.001){hasCoords=true;break}
    }
  }

  // No data at all
  if(!wdData.length&&!wdGpsFix){
    var nd=document.getElementById('wdnodata');if(nd)nd.style.display='flex';
    return;
  }
  var nd2=document.getElementById('wdnodata');if(nd2)nd2.style.display='none';

  // No GPS coords: show summary on canvas
  if(!hasCoords&&!wdGpsFix){
    ctx.fillStyle='#888';ctx.font='bold 14px system-ui,sans-serif';ctx.textAlign='center';
    ctx.fillText(wdData.length+' redes capturadas',w/2,h/2-20);
    ctx.fillStyle='#555';ctx.font='12px system-ui,sans-serif';
    ctx.fillText('Sin coordenadas GPS',w/2,h/2+5);
    ctx.fillText('Activa GPS al aire libre para ver el mapa',w/2,h/2+25);
    // Mini channel histogram
    var chCount={};wdData.forEach(function(e){var c=e.ch||0;chCount[c]=(chCount[c]||0)+1});
    var chs=Object.keys(chCount).sort(function(a,b){return a-b});
    if(chs.length){
      var maxC=Math.max.apply(null,chs.map(function(c){return chCount[c]}));
      var bw=Math.min(30,Math.floor((w-40)/chs.length)-4);
      var startX=(w-chs.length*(bw+4))/2;
      ctx.fillStyle='#444';ctx.font='9px system-ui,sans-serif';ctx.textAlign='center';
      ctx.fillText('Canales',w/2,h/2+50);
      chs.forEach(function(c,i){
        var bh=Math.max(3,Math.round(chCount[c]/maxC*40));
        var x=startX+i*(bw+4);var y=h/2+90-bh;
        ctx.fillStyle='rgba(52,211,153,0.6)';ctx.fillRect(x,y,bw,bh);
        ctx.fillStyle='#888';ctx.font='8px system-ui,sans-serif';ctx.fillText(c,x+bw/2,h/2+100);
      });
    }
    ctx.textAlign='left';
    return;
  }

  // Auto-center on GPS if available
  if(wdGpsFix&&wdGpsLat&&wdGpsLon&&isFinite(wdGpsLat)&&isFinite(wdGpsLon)){
    if(!cv._userPanned){_mCLat=wdGpsLat;_mCLon=wdGpsLon}
  }

  // Draw tiles
  var n=Math.pow(2,_mZoom);
  var cpx=(_mCLon+180)/360*n*256,cpy=(1-Math.log(Math.tan(_mCLat*Math.PI/180)+1/Math.cos(_mCLat*Math.PI/180))/Math.PI)/2*n*256;
  var ox=w/2-cpx+_mPanX,oy=h/2-cpy+_mPanY;
  var t0x=Math.floor((cpx-w/2-_mPanX)/256),t0y=Math.floor((cpy-h/2-_mPanY)/256);
  var t1x=Math.ceil((cpx+w/2-_mPanX)/256),t1y=Math.ceil((cpy+h/2-_mPanY)/256);

  for(var tx=t0x;tx<=t1x;tx++){for(var ty=t0y;ty<=t1y;ty++){
    if(ty<0||ty>=n)continue;var ttx=((tx%n)+n)%n;
    var url=_tUrl(ttx,ty,_mZoom);
    var sx=tx*256+ox,sy=ty*256+oy;
    if(_tImgCache[url]){ctx.drawImage(_tImgCache[url],sx,sy,256,256)}
    else{
      // Draw styled placeholder tile instead of plain gray
      ctx.fillStyle='#1e1e1c';ctx.fillRect(sx,sy,256,256);
      ctx.strokeStyle='#2a2a28';ctx.strokeRect(sx,sy,256,256);
      // Draw grid lines inside tile
      ctx.strokeStyle='rgba(255,255,255,0.03)';ctx.lineWidth=0.5;
      for(var gi=64;gi<256;gi+=64){ctx.beginPath();ctx.moveTo(sx+gi,sy);ctx.lineTo(sx+gi,sy+256);ctx.stroke();ctx.beginPath();ctx.moveTo(sx,sy+gi);ctx.lineTo(sx+256,sy+gi);ctx.stroke()}
      // Show tile coordinates for debugging
      ctx.fillStyle='rgba(255,255,255,0.08)';ctx.font='9px system-ui,sans-serif';ctx.textAlign='center';
      ctx.fillText(ttx+'/'+ty,sx+128,sy+128);
      ctx.textAlign='left';
      _loadTile(url,function(){if(!_tRedrawPending){_tRedrawPending=true;setTimeout(function(){_tRedrawPending=false;wdDraw()},100)}})
    }
  }}

  // Wardrive dots (small, RSSI colored)
  if(wdData&&wdData.length){
    wdData.forEach(function(e,i){
      var la=parseFloat(e.la),lo=parseFloat(e.lo);
      if(!la&&!lo)return;if(!isFinite(la)||!isFinite(lo))return;if(Math.abs(la)<0.001&&Math.abs(lo)<0.001)return;
      var p=_ll2px(la,lo);if(p.x<-20||p.x>w+20||p.y<-20||p.y>h+20)return;
      var rssi=parseInt(e.r)||-100;
      var r=Math.min(255,Math.max(0,Math.round(255*(Math.min(-30,rssi)+100)/70)));
      var g=Math.min(255,Math.max(0,Math.round(255*(1-(Math.min(-30,rssi)+100)/70))));
      var isHi=(i===wdHighlightIdx);
      ctx.beginPath();ctx.arc(p.x,p.y,isHi?6:3,0,6.283);
      ctx.fillStyle='rgba('+g+','+r+',0,0.85)';ctx.fill();
      if(isHi){ctx.strokeStyle='#fff';ctx.lineWidth=2;ctx.stroke()}
    });
  }

  // GPS dot (pulsing blue)
  if(wdGpsFix&&wdGpsLat&&wdGpsLon&&isFinite(wdGpsLat)&&isFinite(wdGpsLon)){
    var gp=_ll2px(wdGpsLat,wdGpsLon);
    var pulse=4+Math.sin(Date.now()/300)*2;
    ctx.beginPath();ctx.arc(gp.x,gp.y,pulse+4,0,6.283);ctx.fillStyle='rgba(10,207,254,0.2)';ctx.fill();
    ctx.beginPath();ctx.arc(gp.x,gp.y,6,0,6.283);ctx.fillStyle='#0acffe';ctx.fill();
    ctx.strokeStyle='#fff';ctx.lineWidth=2;ctx.stroke();
  }

  // Zoom indicator
  ctx.fillStyle='rgba(255,255,255,0.6)';ctx.font='11px system-ui,sans-serif';
  ctx.fillText('z'+_mZoom,8,h-8);

  // Offline tiles hint
  var anyLoaded=false;for(var k in _tImgCache){anyLoaded=true;break}
  if(!anyLoaded&&!navigator.onLine){
    ctx.fillStyle='rgba(0,0,0,0.6)';ctx.fillRect(w/2-130,16,260,40);ctx.strokeStyle='rgba(255,255,255,0.1)';ctx.strokeRect(w/2-130,16,260,40);
    ctx.fillStyle='rgba(255,255,255,0.7)';ctx.font='11px system-ui,sans-serif';ctx.textAlign='center';
    ctx.fillText('Sin tiles — conecta a internet y pulsa',w/2,32);
    ctx.fillText('"Cachear Tiles" para ver el mapa de calle',w/2,47);
    ctx.textAlign='left';
  }
  var nd=document.getElementById('wdnodata');if(nd)nd.style.display=(wdData.length||wdGpsFix)?'none':'flex';
}

// Touch handlers for map
(function(){
  var cv,drag=false,px=0,py=0,ldist=0,lzoom=16,didDrag=false,tapX=0,tapY=0;
  function init(){
    cv=document.getElementById('wdcanvas');if(!cv)return;
    cv.addEventListener('touchstart',function(e){
      e.preventDefault();didDrag=false;
      if(e.touches.length===2){var dx=e.touches[0].clientX-e.touches[1].clientX,dy=e.touches[0].clientY-e.touches[1].clientY;ldist=Math.sqrt(dx*dx+dy*dy);lzoom=_mZoom}
      else if(e.touches.length===1){drag=true;px=e.touches[0].clientX;py=e.touches[0].clientY;tapX=px;tapY=py}
    },{passive:false});
    cv.addEventListener('touchmove',function(e){
      e.preventDefault();
      if(e.touches.length===2&&ldist>0){didDrag=true;var dx=e.touches[0].clientX-e.touches[1].clientX,dy=e.touches[0].clientY-e.touches[1].clientY;var d=Math.sqrt(dx*dx+dy*dy);var nz=Math.round(lzoom+Math.log2(d/ldist)*1.5);nz=Math.max(14,Math.min(18,nz));if(nz!==_mZoom){_mZoom=nz;_mPanX=0;_mPanY=0;wdDraw()}}
      else if(e.touches.length===1&&drag){var dx2=e.touches[0].clientX-px,dy2=e.touches[0].clientY-py;if(Math.abs(dx2)>3||Math.abs(dy2)>3)didDrag=true;_mPanX+=dx2;_mPanY+=dy2;px=e.touches[0].clientX;py=e.touches[0].clientY;cv._userPanned=true;wdDraw()}
    },{passive:false});
    cv.addEventListener('touchend',function(e){
      if(!didDrag&&drag){wdTapSelect(tapX,tapY)}
      drag=false;ldist=0;didDrag=false;
    },{passive:true});
    cv.addEventListener('wheel',function(e){e.preventDefault();var nz=_mZoom+(e.deltaY>0?-1:1);_mZoom=Math.max(14,Math.min(18,nz));_mPanX=0;_mPanY=0;wdDraw()},{passive:false});
    // Desktop click
    cv.addEventListener('click',function(e){var r=cv.getBoundingClientRect();wdTapSelect(e.clientX,e.clientY)});
  }
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init);else setTimeout(init,100);
})();

function wdTapSelect(cx,cy){
  var cv=document.getElementById('wdcanvas');if(!cv)return;
  var rect=cv.getBoundingClientRect();
  var mx=cx-rect.left,my=cy-rect.top;
  var best=-1,bestDist=900;
  wdData.forEach(function(e,i){
    var la=parseFloat(e.la),lo=parseFloat(e.lo);
    if(!la&&!lo)return;if(Math.abs(la)<0.001)return;
    var p=_ll2px(la,lo);
    var dx=p.x-mx,dy=p.y-my,d=dx*dx+dy*dy;
    if(d<bestDist){bestDist=d;best=i}
  });
  if(best>=0&&bestDist<400){// within ~20px
    wdHighlightIdx=best;wdDraw();wdListHighlight(best);
    var e=wdData[best];
    wdShowPopup(e,_ll2px(parseFloat(e.la),parseFloat(e.lo)));
  }else{
    wdHighlightIdx=-1;wdHidePopup();wdDraw();
  }
}

function wdShowPopup(e,pos){
  var pop=document.getElementById('wdPopup');
  if(!pop){pop=document.createElement('div');pop.id='wdPopup';
    pop.style.cssText='position:absolute;background:rgba(13,13,11,0.95);border:1px solid rgba(255,255,255,0.15);border-radius:10px;padding:8px 12px;font-size:11px;color:#ccc;pointer-events:none;z-index:10;max-width:200px;line-height:1.4;backdrop-filter:blur(8px)';
    document.getElementById('wdmap').appendChild(pop)}
  var rssi=parseInt(e.r)||-100;
  var strength=rssi>=-50?'Excelente':rssi>=-65?'Buena':rssi>=-75?'Regular':'Débil';
  pop.innerHTML='<div style="font-weight:700;color:#fff;font-size:12px;margin-bottom:4px">'+esc(e.s||'(oculta)')+'</div>'
    +'<div>Señal: '+esc(e.r)+' dBm ('+esc(strength)+')</div>'
    +'<div>Canal: '+esc(e.ch)+'</div>'
    +'<div>Auth: '+esc(e.a||'Open')+'</div>'
    +'<div style="color:#666;margin-top:3px">'+esc(e.b)+'</div>';
  var mapEl=document.getElementById('wdmap');
  var left=Math.max(4,Math.min(pos.x+10,mapEl.clientWidth-210));
  var top=Math.max(4,Math.min(pos.y>mapEl.clientHeight/2?pos.y-80:pos.y+15,mapEl.clientHeight-90));
  pop.style.left=left+'px';pop.style.top=top+'px';pop.style.display='block';
}
function wdHidePopup(){var p=document.getElementById('wdPopup');if(p)p.style.display='none'}

function wdCenter(){
  if(wdGpsFix&&wdGpsLat&&wdGpsLon){_mCLat=wdGpsLat;_mCLon=wdGpsLon;_mPanX=0;_mPanY=0;var cv=document.getElementById('wdcanvas');if(cv)cv._userPanned=false;wdDraw();toast('Centrado en GPS');return}
  var v=wdData.filter(function(e){return e.la&&e.lo&&isFinite(parseFloat(e.la))&&isFinite(parseFloat(e.lo))&&Math.abs(parseFloat(e.la))>0.001});
  if(v.length){var sla=0,slo=0;v.forEach(function(e){sla+=parseFloat(e.la);slo+=parseFloat(e.lo)});_mCLat=sla/v.length;_mCLon=slo/v.length;_mPanX=0;_mPanY=0;wdDraw();toast('Centrado en redes')}
}

function wdPreCache(){
  if(!_tReady){toast('Cache no disponible');return}
  if(!navigator.onLine){toast('Necesitas internet para cachear tiles');return}
  var btn=document.getElementById('wdCacheBtn');if(btn)btn.textContent='Cacheando...';
  var z=_mZoom,tiles=[];
  for(var dz=z-1;dz<=z+1;dz++){if(dz<14||dz>18)continue;
    var n=Math.pow(2,dz),delta=0.015;
    var nw=_ll2t(_mCLat+delta,_mCLon-delta,dz),se=_ll2t(_mCLat-delta,_mCLon+delta,dz);
    for(var x=nw.x;x<=se.x;x++)for(var y=nw.y;y<=se.y;y++)tiles.push({x:x,y:y,z:dz})
  }
  var done=0,total=tiles.length;
  function next(){if(!tiles.length){if(btn)btn.textContent='Cache ('+done+' tiles)';toast(done+' tiles cacheados');return}
    var t=tiles.shift();var url=_tUrl(t.x,t.y,t.z);
    _loadTile(url,function(){done++;if(btn)btn.textContent=done+'/'+total;setTimeout(next,80)})
  }
  next();next(); // 2 concurrent
}

function wdListHighlight(idx){
  document.querySelectorAll('#wdlist .wdrow').forEach(function(r,i){
    if(i===idx)r.classList.add('wd-active-row');else r.classList.remove('wd-active-row');
  });

  var rows=document.querySelectorAll('#wdlist .wdrow');
  if(rows[idx])rows[idx].scrollIntoView({block:'nearest',behavior:'smooth'})}

function wdListRender(){
  var el=document.getElementById('wdlist');
  if(!wdData.length){el.innerHTML='<div class="le" style="font-size:13px">Sin datos aún</div>';return}
  var TH='padding:8px 6px;font-size:10px;color:var(--fg3);text-transform:uppercase;letter-spacing:.6px;background:var(--bg3);border-bottom:1px solid var(--bd)';
var h='<table style="width:100%;border-collapse:collapse"><thead><tr><th style="'+TH+';text-align:left;padding:8px 12px">SSID</th><th style="'+TH+';text-align:center">CH</th><th style="'+TH+';text-align:center">dBm</th><th style="'+TH+'">Tipo</th></tr></thead><tbody>';
  wdData.forEach(function(e,i){
    var col=wdAuthColor(e.a),isHi=(i===wdHighlightIdx);
    h+='<tr class="wdrow'+(isHi?' wd-active-row':'')+'" style="cursor:pointer" onclick="wdRowClick('+i+')">';
    h+='<td style="padding:8px 12px;font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:140px;border-top:1px solid var(--bd)"><span style="display:inline-flex;align-items:center;gap:5px"><span style="width:7px;height:7px;border-radius:50%;background:'+col+';flex-shrink:0"></span>'+(e.s?esc(e.s):'<span style="color:var(--fg3)">(oculta)</span>')+'</span></td>';
    h+='<td style="padding:8px 6px;text-align:center;font-size:12px;color:var(--accent);border-top:1px solid var(--bd)">'+e.ch+'</td>';
    h+='<td style="padding:8px 6px;text-align:center;font-size:12px;font-variant-numeric:tabular-nums;color:'+(e.r>-65?'var(--ok)':e.r>-80?'var(--warn)':'var(--crit)')+';border-top:1px solid var(--bd)">'+e.r+'</td>';
    var shortAuth=(e.a||'').replace(/^\[|\]$/g,'').replace(/_PSK$/i,'').replace(/_ENTERPRISE$/i,'-ENT').replace('WPA2_WPA3','WPA2/3').replace('WPA2 Personal','WPA2').replace('WPA3 Personal','WPA3').replace('WPA_WPA2','WPA2');
    h+='<td style="padding:8px 6px;font-size:10px;font-weight:700;color:'+col+';border-top:1px solid var(--bd)">'+esc(shortAuth)+'</td>';
    h+='</tr>';
  });
  h+='</tbody></table>';
  el.innerHTML=h;

  if(wdHighlightIdx>=0)wdListHighlight(wdHighlightIdx);
}

function wdRowClick(i){
  wdHighlightIdx=i;wdDraw();wdListHighlight(i);
  var e=wdData[i];if(e)toast((e.s||'(oculta)')+' | '+e.b+' | CH'+e.ch+' | '+e.r+'dBm')}


var COMMAND_CATALOG=[{"title":"Sistema","items":[{"cmd":"help","syntax":"help","desc":"Ayuda del firmware"},{"cmd":"stopscan","syntax":"stopscan","desc":"Detener la operaci…"},{"cmd":"info","syntax":"info","desc":"Versión y hardware…"},{"cmd":"spiffs","syntax":"spiffs [ls/read <file>/rm <file>/format]","desc":"Consultar archivos…"},{"cmd":"led","syntax":"led -s <hex color>/-p <rainbow>","desc":"Configurar LED si …"},{"cmd":"ls","syntax":"ls <directory>","desc":"Listar directorio …"},{"cmd":"channel","syntax":"channel [-s <channel>]","desc":"Consultar o cambia…"},{"cmd":"clearlist","syntax":"clearlist -a/-c/-s","desc":"Vaciar listas de A…"},{"cmd":"settings","syntax":"settings [-s <setting> enable/disable>…","desc":"Consultar o cambia…"},{"cmd":"reboot","syntax":"reboot","desc":"Reiniciar el badge"},{"cmd":"update","syntax":"update -s/-w","desc":"Actualización por …"}]},{"title":"WiFi   escaneo y monitores","items":[{"cmd":"sigmon","syntax":"sigmon","desc":"Monitor de intensi…"},{"cmd":"wardrive","syntax":"wardrive [-s]","desc":"Registrar redes co…"},{"cmd":"scanap","syntax":"scanap","desc":"Escanear puntos de…"},{"cmd":"sniffraw","syntax":"sniffraw","desc":"Capturar tramas Wi…"},{"cmd":"scan","syntax":"scan","desc":"Alias de escaneo A…"},{"cmd":"scansta","syntax":"scansta","desc":"Escanear estacione…"},{"cmd":"sniffbeacon","syntax":"sniffbeacon","desc":"Escuchar beacons"},{"cmd":"sniffprobe","syntax":"sniffprobe","desc":"Escuchar solicitud…"},{"cmd":"sniffdeauth","syntax":"sniffdeauth","desc":"Monitor pasivo de …"},{"cmd":"sniffpwn","syntax":"sniffpwn","desc":"Escuchar Pwnagotchi"},{"cmd":"sniffesp","syntax":"sniffesp","desc":"Escuchar dispositi…"},{"cmd":"sniffpmkid","syntax":"sniffpmkid [-c <channel>][-d][-l]","desc":"Captura PMKID/EAPO…"}]},{"title":"WiFi   listas y selección","items":[{"cmd":"list","syntax":"list -s","desc":"Mostrar APs, estac…"},{"cmd":"select","syntax":"select -a/-s/-c <index (comma separate…","desc":"Seleccionar entrad…"},{"cmd":"save","syntax":"save -a/-s","desc":"Guardar listas"},{"cmd":"load","syntax":"load -a/-s","desc":"Cargar listas"},{"cmd":"ssid","syntax":"ssid -a [-g <count>/-n <name>]","desc":"Administrar lista …"}]},{"title":"WiFi   operaciones","items":[{"cmd":"evilportal","syntax":"evilportal [-c start [-w html.html]/se…","desc":"Administrar el por…"},{"cmd":"attack","syntax":"attack -t <beacon [-l/-r/-a]/deauth [-…","desc":"Operaciones WiFi d…"}]},{"title":"Bluetooth","items":[{"cmd":"sniffbt","syntax":"sniffbt [-t] <airtag/flipper>","desc":"Escaneo Bluetooth"},{"cmd":"spoofat","syntax":"spoofat -t <index>","desc":"Emulación de AirTag"},{"cmd":"blespam","syntax":"blespam -t <apple/google/samsung/windo…","desc":"Publicidad BLE; so…"},{"cmd":"btwardrive","syntax":"btwardrive [-c]","desc":"Registrar Bluetoot…"},{"cmd":"sniffskim","syntax":"sniffskim","desc":"Buscar identificad…"}]},{"title":"GPS","items":[{"cmd":"gpsdata","syntax":"gpsdata","desc":"Transmitir datos GPS"},{"cmd":"gps","syntax":"gps [-g] <fix/sat/lon/lat/alt/date/acc…","desc":"Consultar fix, sat…"},{"cmd":"nmea","syntax":"nmea","desc":"Transmitir NMEA"},{"cmd":"gpspoi","syntax":"gpspoi [-s/-m/-e]","desc":"Marcar punto de in…"}]},{"title":"NFC","items":[{"cmd":"nfc","syntax":"nfc [scan/read] [-u <url>] [-t <text>]…","desc":"Leer o escribir el…"}]}];
function pickCommand(cmd){var i=document.getElementById('tc');i.value=cmd;i.focus()}
function renderCommandGuide(){var h='';COMMAND_CATALOG.forEach(function(g){h+='<details class="command-category"><summary>'+esc(g.title)+' <span>'+g.items.length+'</span></summary>';g.items.forEach(function(e){h+='<button type="button" class="command-choice" onclick="pickCommand(\''+e.cmd+'\')"><code>'+esc(e.cmd)+'</code><span>'+esc(e.desc)+'</span><small>'+esc(e.syntax)+'</small></button>'});h+='</details>'});document.getElementById('command-categories').innerHTML=h}

function tL(m,s){var e=document.getElementById('term'),l=document.createElement('div');
if(s)l.style.cssText=s;l.textContent=m;e.appendChild(l);
while(e.children.length>500)e.removeChild(e.firstChild);
e.scrollTop=e.scrollHeight}
var _cmdHist=[],_cmdIdx=-1;
function sCmd(){var i=document.getElementById('tc'),c=i.value.trim();if(!c)return;
_cmdHist.push(c);if(_cmdHist.length>50)_cmdHist.shift();_cmdIdx=_cmdHist.length;
var body={cmd:c};
if(/^reboot$/i.test(c.trim())){if(!confirm('Reiniciar el badge?'))return;body={cmd:'reboot',confirm:'CONFIRM_REBOOT'};}
i.value='';tL('> '+c,'color:var(--info)');
ap('/api/cmd',body).then(function(r){
if(r&&r.output)tL(r.output,'');
if(r&&!r.ok&&r.code==='not_whitelisted')tL('[no permitido por API]','color:var(--warn)');
}).catch(function(){tL('[sin resp]','color:var(--crit)');});}
function clrTerm(){document.getElementById('term').innerHTML=''}
function exportLogs(){var e=document.getElementById('term');if(!e||!e.textContent.trim()){toast('Sin logs');return}var b=new Blob([e.textContent],{type:'text/plain'});var a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='badge-logs-'+new Date().toISOString().slice(0,19).replace(/[:T]/g,'-')+'.txt';a.click();URL.revokeObjectURL(a.href);toast('Logs exportados')}
var tPollBusy=false;
function tPoll(){
var termActive=document.getElementById('p-term').classList.contains('on');
var jobActive=document.getElementById('jobbar').style.display==='flex';
var needsPoll=termActive||jobActive||snActive||deauthOwnsSniffer;
if(!needsPoll||tPollBusy||document.visibilityState==='hidden')return;
tPollBusy=true;
api('/api/poll').then(function(d){tPollBusy=false;if(!d||!Array.isArray(d.lines))return;
var now=performance.now();d.lines.forEach(function(l){
tL(l,'');if(snActive==='deauth')deauthIngest(l,now);handshakeIngest(l);snifferIngest(l);
});fMonDeauth(now);renderHandshakes();renderSniffer()}).catch(function(){tPollBusy=false;})}

function setTheme(t){document.documentElement.setAttribute('data-theme',t);
var thd=document.getElementById('thd');if(thd)thd.className='thb'+(t==='dark'?' on':'');
var thl=document.getElementById('thl');if(thl)thl.className='thb'+(t==='light'?' on':'');
var mc=document.querySelector('meta[name=theme-color]');if(mc)mc.content='#0d0d0b';
try{localStorage.setItem('theme',t)}catch(e){}}
function fSettings(){
if(LS)document.getElementById('bgi').innerHTML='<div class="kv"><span class="kl">Versión</span><span class="kvv">'+esc(LS.fw||'-')+'</span></div><div class="kv"><span class="kl">Placa</span><span class="kvv">'+esc(LS.board||'-')+'</span></div>';

api('/api/settings').then(function(d){
var el=document.getElementById('devsets-list');
if(!el)return;
var list=(d&&d.Settings)||[];
if(!list.length){el.innerHTML='<div class="le" style="font-size:13px">Sin ajustes disponibles</div>';return}
var h='';list.forEach(function(s){
if(s.type==='bool'||s.type==='toggle'){
h+='<div class="devtog"><span class="devtog-lbl">'+esc(s.name)+'</span><label class="devswitch" aria-label="'+esc(s.name)+'">';
h+='<input type="checkbox"'+(s.value?'checked':'')+' onchange="devToggle(\'' +s.name.replace(/'/g,'')+'\'  ,this.checked)">';
h+='<span class="track"></span><span class="thumb"></span></label></div>';
}else if(s.range){
var sn=s.name.replace(/'/g,'');
h+='<div class="devtog" style="flex-wrap:wrap"><span class="devtog-lbl">'+esc(s.name)+'</span>';
h+='<div style="display:flex;align-items:center;gap:8px"><input type="range" min="'+s.range.min+'" max="'+s.range.max+'" value="'+s.value+'" style="flex:1;accent-color:var(--accent)" oninput="this.nextElementSibling.textContent=this.value" onchange="devSet(\''+sn+'\',+this.value)">';
h+='<span style="min-width:24px;text-align:center;font-variant-numeric:tabular-nums;color:var(--accent);font-weight:700">'+s.value+'</span></div></div>';
}
});
if(!h)h='<div class="le" style="font-size:13px">Sin ajustes disponibles</div>';
el.innerHTML=h;
}).catch(function(){var el=document.getElementById('devsets-list');if(el)el.innerHTML='<div class="le" style="font-size:13px">Error cargando ajustes</div>';});}
function devToggle(key,on){ap('/api/settings',{key:key,on:!!on}).then(function(r){if(r&&r.ok)toast(key+': '+(on?'activado':'desactivado'));else toast('Error al cambiar '+key);})}
function devSet(key,val){ap('/api/settings',{key:key,value:val}).then(function(r){if(r&&r.ok)toast(key+': '+val);else toast('Error al cambiar '+key);})}
function fmtB(n){n=+n||0;if(n>=1048576)return(n/1048576).toFixed(1)+' MB';if(n>=1024)return(n/1024).toFixed(1)+' KB';return n+' B'}
function fSpiffs(){api('/api/spiffs').then(function(d){
var inf=document.getElementById('spinf');
if(!d){inf.textContent='Sin datos';return}
var pct=d.total?Math.min(100,Math.round(d.used/d.total*100)):0;
inf.innerHTML='<div class="fr" style="justify-content:space-between"><span class="kl">Usado</span><span class="kvv">'+fmtB(d.used)+' / '+fmtB(d.total)+' ('+pct+'%)</span></div>';
document.getElementById('spbar').style.width=pct+'%';
var h='<div class="kv" style="padding:6px 0"><span class="kl">Libre</span><span class="kvv" style="color:var(--ok)">'+fmtB(d.free!=null?d.free:(d.total-d.used))+'</span></div>';
(d.files||[]).forEach(function(f){h+='<div class="kv" style="padding:6px 0"><span class="kl" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:65%">'+esc(f.name!=null?f.name:f.n)+'</span><span class="kvv">'+fmtB(f.size!=null?f.size:f.s)+'</span></div>'});
document.getElementById('spfiles').innerHTML=h})}
function upOta(){var fi=document.getElementById('otaf');
if(!fi.files||!fi.files.length){toast('Selecciona un archivo .bin');return}
var f=fi.files[0],msg=document.getElementById('otamsg'),b=document.getElementById('otab');
if(!confirm('¿Subir firmware "'+f.name+'" ('+Math.round(f.size/1024)+' KB)? No desconectar durante la actualización.'))return;
b.disabled=true;msg.style.display='none';
document.getElementById('otapw').style.display='block';
document.getElementById('otapb').style.width='0%';document.getElementById('otapc').textContent='0%';
var fd=new FormData();fd.append('firmware',f);
var x=new XMLHttpRequest();
x.upload.onprogress=function(e){if(e.lengthComputable){var p=Math.round(e.loaded/e.total*100);document.getElementById('otapb').style.width=p+'%';document.getElementById('otapc').textContent=p+'%'}};
x.onload=function(){b.disabled=false;msg.style.display='block';
var ok=false;try{var rj=JSON.parse(x.responseText);ok=!!(rj&&rj.ok)}catch(e){ok=(x.status>=200&&x.status<300&&x.responseText.indexOf('OK')>=0)}
if(ok){msg.style.color='var(--ok)';msg.textContent='Actualización completa. Reiniciando...';toast('Firmware actualizado')}
else{msg.style.color='var(--crit)';msg.textContent='Error en la actualización';toast('Error OTA')}};
x.onerror=function(){b.disabled=false;msg.style.display='block';msg.style.color='var(--crit)';msg.textContent='Error de conexión';toast('Error OTA')};
x.open('POST',B+'/api/ota?confirm=CONFIRM_OTA');x.send(fd)}
function fSsids(){api('/api/ssids').then(function(d){var e=document.getElementById('sl');
if(!d||!d.ssids||!d.ssids.length){e.innerHTML='<div class="le" style="padding:12px">Lista vacía</div>';return}
var h='';d.ssids.forEach(function(s){
h+='<div class="li" style="padding:9px 4px"><div class="nfo"><div class="ss">'+esc(s.name)+'</div></div><button class="b bd bs" style="width:auto;min-height:32px;padding:0 12px;font-size:12px" onclick="ssidRm('+s.i+')">X</button></div>'});
e.innerHTML=h})}
function ssidAdd(){var v=document.getElementById('sadd').value.trim();
if(!v){toast('Escribe un nombre');return}
ap('/api/ssids',{action:'add',name:v}).then(function(){document.getElementById('sadd').value='';fSsids()})}
function ssidRm(i){ap('/api/ssids',{action:'remove',index:i}).then(fSsids)}
function ssidGen(){var n=parseInt(document.getElementById('sgen').value)||10;
ap('/api/ssids',{action:'generate',count:n}).then(function(){toast(n+' SSIDs generados');fSsids()})}
function ssidImp(){var t=document.getElementById('sblk').value.trim();
if(!t){toast('Pega la lista');return}
ap('/api/ssids',{action:'import',list:t}).then(function(){toast('Lista importada');document.getElementById('sblk').value='';fSsids()})}
function ssidClr(){if(!confirm('Borrar toda la lista SSID?'))return;
ap('/api/ssids',{action:'clear'}).then(fSsids)}
function sCh(){ap('/api/cmd',{cmd:'channel -s '+document.getElementById('sch').value}).then(function(r){if(r&&r.ok)toast('Canal cambiado a '+document.getElementById('sch').value);else toast('Error: '+(r&&r.output||'no pudo cambiar canal'));})}
function doReboot(){if(!confirm('Reiniciar el badge? Se perderá la conexión y tardará ~10s.'))return;
ap('/api/cmd',{cmd:'reboot',confirm:'CONFIRM_REBOOT'}).then(function(r){
if(r&&r.ok)toast('Reiniciando');
else toast('Error al reiniciar: '+(r&&r.output||''));})}

var deauthEvents=[],deauthRows=[],deauthTail='',deauthLast=null,deauthChannel=null;
function deauthIngest(text,now){
var input=deauthTail+String(text),re=/RSSI:\s*(-?\d{1,3})\s+Ch:\s*(\d{1,3})\s+(?:BSSID:\s*)?((?:[\da-f]{2}:){5}[\da-f]{2})\s*->\s*((?:[\da-f]{2}:){5}[\da-f]{2})(?![\da-f:])/gi,m,end=0;
var cm,cr=/\[CH:\s*(\d{1,2})\]/g;while((cm=cr.exec(input)))if(+cm[1]>=1&&+cm[1]<=13)deauthChannel=+cm[1];
while((m=re.exec(input))){
end=re.lastIndex;var rssi=+m[1],channel=+m[2];
if(rssi>0||rssi<-127||channel<1||channel>233)continue;
var attacker=m[3].toUpperCase(),victim=m[4].toUpperCase(),row=deauthRows.find(function(e){return e.attacker===attacker});
if(!row){
if(deauthRows.length===50){var oldest=0;for(var i=1;i<deauthRows.length;i++)if(deauthRows[i].lastSeen<deauthRows[oldest].lastSeen)oldest=i;deauthRows.splice(oldest,1)}
row={attacker:attacker,count:0};deauthRows.push(row)}
row.victim=victim;row.channel=channel;row.rssi=rssi;row.count++;row.lastSeen=now;
deauthEvents.push(now);deauthLast=now;
}

deauthTail=input.slice(end).slice(-160);
}
function deauthSnapshot(now){
deauthEvents=deauthEvents.filter(function(t){return now-t<30000});
return {count:deauthEvents.length,level:deauthEvents.length>=5?'danger':deauthEvents.length?'warning':'safe',rows:deauthRows.slice().sort(function(a,b){return b.count-a.count||b.lastSeen-a.lastSeen||a.attacker.localeCompare(b.attacker)})};
}

var monT={deauth:null,probe:null,signal:null},monOn={deauth:false,probe:false,signal:false},monPending=false;
function monToggle(t){
if(monPending)return;
if(monOn[t]){monStopOne(t);return}
if(t==='deauth'){
if(monOn.probe||monOn.signal){toast('Detén los otros monitores antes de escuchar deauths');return}
monPending=true;snPending=true;
ap('/api/sniffer',{type:'deauth',duration:0}).then(function(r){
monPending=false;snPending=false;
if(!r||!r.ok){toast('No se pudo iniciar; verifica si el badge está ocupado');return}
monOn.deauth=true;deauthOwnsSniffer=true;deauthTail='';deauthChannel=null;
document.getElementById('mb-deauth').classList.add('on');setSnifferActive('deauth');renderSniffer();toast('Detector Deauth activo')});return;
}
if(snActive){toast('Detén el sniffer antes de iniciar otro monitor');return}
var b={type:t,action:'start'};
if(t==='signal'){var s=document.getElementById('msigap');
if(!aps.length){toast('Escanea primero para elegir un AP');return}
b.bssid=s.value}
ap('/api/monitor',b).then(function(r){
if(r&&r.ok){monOn[t]=true;document.getElementById('mb-'+t).classList.add('on');document.getElementById('mw-'+t).style.display='block';

if(t==='probe'){fMonProbe();monT.probe=setInterval(fMonProbe,2000)}
if(t==='signal'){fMonSig();monT.signal=setInterval(fMonSig,500)}
toast('Monitor '+t+' activo')}
else toast('Error al iniciar monitor')})}
function monStopOne(t,skip){
if(t==='deauth'){if(deauthOwnsSniffer)stopSniffer();return}
monOn[t]=false;
document.getElementById('mb-'+t).classList.remove('on');
document.getElementById('mw-'+t).style.display='none';
if(monT[t]){clearInterval(monT[t]);monT[t]=null}
if(!skip)ap('/api/monitor',{type:t,action:'stop'})}
function monLeave(){if(monOn.deauth&&deauthOwnsSniffer)monStopOne('deauth');
var any=false;['probe','signal'].forEach(function(t){if(monOn[t]){monStopOne(t,true);any=true}});
if(any)ap('/api/monitor',{type:'all',action:'stop'})}
function monAgo(e){if(e.ago!=null)return e.ago+'s';
var ts=e.ts||e.time||0;if(!ts)return'-';if(ts<1e12)ts*=1000;
var s=Math.max(0,Math.round((Date.now()-ts)/1000));
return s<2?'ahora':s<60?s+'s':Math.floor(s/60)+'m '+s%60+'s'}
function deauthAgo(at,now){var seconds=Math.max(0,Math.floor((now-at)/1000));return seconds<60?'hace '+seconds+'s':seconds<3600?'hace '+Math.floor(seconds/60)+'m':'hace '+Math.floor(seconds/3600)+'h'}
function signalSegments(rssi){if(rssi==null||isNaN(rssi))return '<span class="dm-signal">- dBm</span>';
var n=rssi>=-50?5:rssi>=-60?4:rssi>=-70?3:rssi>=-80?2:1,h='';
for(var i=0;i<5;i++)h+='<i'+(i>=n?' class="off"':'')+' style="height:'+(5+i*2)+'px"></i>';
return '<span class="dm-signal"><span class="dm-segments" aria-hidden="true">'+h+'</span><span>'+rssi+' dBm</span></span>'}
function fMonDeauth(now){if(typeof now!=='number')now=performance.now();if(document.visibilityState==='hidden')return;var s=deauthSnapshot(now);
document.getElementById('mdalert').className='m-state '+s.level;
var title={safe:'Sin ataques detectados',warning:'Actividad sospechosa',danger:'ATAQUE ACTIVO'}[s.level],status=document.getElementById('mdstatus');
if(status.textContent!==title)status.textContent=title;
document.getElementById('mdcount').textContent=s.count+' deauths en los últimos 30s';
document.getElementById('mdlast').textContent='Último evento: '+(deauthLast==null?'sin eventos':deauthAgo(deauthLast,now));
document.getElementById('mdcapture').textContent=snActive==='deauth'?'Escuchando en vivo   '+(deauthChannel==null?'canal pendiente':'CH '+deauthChannel)+'   hopping 1–13 / 200ms':'Monitor detenido   sin observación en vivo';
document.getElementById('mdrows').textContent=s.rows.length+' / 50';
var h='';s.rows.forEach(function(e){h+='<tr><td data-label="Atacante" class="mac">'+e.attacker+'</td><td data-label="Víctima" class="mac">'+e.victim+'</td><td data-label="Canal">'+e.channel+'</td><td data-label="RSSI">'+signalSegments(e.rssi)+'</td><td data-label="Conteo" class="dm-count">'+e.count+'</td><td data-label="Último visto">'+deauthAgo(e.lastSeen,now)+'</td></tr>'});
document.getElementById('mdb').innerHTML=h||'<tr><td colspan="6" class="le">'+(snActive==='deauth'?'Escuchando deauths...':'Sin eventos en esta sesión')+'</td></tr>';
}
function fMonProbe(){api('/api/monitor/probe').then(function(d){
var tb=document.getElementById('mpb');
if(!d||!d.probes){tb.innerHTML='<tr><td colspan="4" style="text-align:center;color:var(--fg3)">Sin datos</td></tr>';return}
var h='';d.probes.forEach(function(e){
h+='<tr><td>'+esc(e.mac||'-')+'</td><td>'+esc(e.ssid||'(broadcast)')+'</td><td>'+(e.rssi!=null?e.rssi:'-')+'</td><td>'+monAgo(e)+'</td></tr>'});
tb.innerHTML=h||'<tr><td colspan="4" style="text-align:center;color:var(--fg3)">Escuchando probes...</td></tr>'})}
function monSigList(){var s=document.getElementById('msigap'),h='';
aps.forEach(function(a){h+='<option value="'+esc(a.bssid)+'">'+esc(a.ssid||'(oculta)')+' ('+a.rssi+' dBm)</option>'});
s.innerHTML=h||'<option value="">Escanea primero</option>'}
function monSigSel(){if(!monOn.signal)return;
ap('/api/monitor',{type:'signal',action:'start',bssid:document.getElementById('msigap').value})}
function fMonSig(){api('/api/monitor/signal').then(function(d){
var db=document.getElementById('sigdb'),f=document.getElementById('sigfill');
if(!d||d.rssi==null){db.textContent='-- dBm';db.style.color='var(--fg3)';f.style.width='0%';return}
var r=d.rssi,col=r>-50?'var(--ok)':r>-70?'var(--warn)':'var(--crit)';
var pct=Math.max(2,Math.min(100,Math.round((r+100)*1.67)));
db.textContent=r+' dBm';db.style.color=col;db.style.textShadow='0 0 14px '+col;
f.style.width=pct+'%'})}

try{if(localStorage.getItem('theme')==='light')setTheme('light');else setTheme('dark')}catch(e){setTheme('dark')}
rAtks();rSnp();rBkp();renderCommandGuide();fMonDeauth();renderHandshakes();renderSniffer();
setInterval(fMonDeauth,1000);

document.addEventListener('visibilitychange',function(){if(document.visibilityState==='visible'){clearInterval(pid);pid=setInterval(poll,2000);poll();}});
document.addEventListener('keydown',function(e){if(e.key==='Escape'){var mor=document.getElementById('morsheet');if(mor&&mor.style.display==='flex'){closeMor();return}var emod=document.getElementById('emod');if(emod&&emod.style.display==='flex'){emod.style.display='none';return}}});
pid=setInterval(poll,2000);poll();
tpid=setInterval(tPoll,1500);

document.getElementById('jbstop').dataset.alwaysEnabled='1';
document.getElementById('bscan').dataset.alwaysEnabled='1';
