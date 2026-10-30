'use strict';

const token = new URLSearchParams(location.hash.slice(1)).get('token') || '';
history.replaceState(null, '', location.pathname);
const $ = (id) => document.getElementById(id);
let importedTargets = [];
let lastResultKey = '';
let lastLogSignature = '';
let currentState = null;
let graphData = {nodes:[], edges:[]};

const colors = {
  domain:'#4ce7f3', subdomain:'#5d91ff', ip:'#ad91ff', tcp_service:'#f6b85f',
  http_service:'#51e2ae', tls_certificate:'#51e2ae', dns_record:'#7db8e8',
  url:'#d5e6ff', route:'#fa78ba', form:'#ff8f75', javascript:'#b79aff',
  api_candidate:'#f6b85f', parameter:'#ffc56e', technology_hint:'#8ba9c9',
  exposed_resource:'#ff7181', robots:'#8296b0', sitemap:'#8296b0', robots_path:'#fa78ba'
};

async function api(path, options={}) {
  const headers = Object.assign({'X-Mirage-Token':token}, options.headers || {});
  const response = await fetch(path, Object.assign({},options,{headers}));
  const type = response.headers.get('content-type') || '';
  const data = type.includes('json') ? await response.json() : await response.text();
  if (!response.ok) throw new Error(data.error || data || `HTTP ${response.status}`);
  return data;
}

class Graph3D {
  constructor(glCanvas, overlayCanvas, interactive=true, onSelect=null) {
    this.canvas=glCanvas; this.overlay=overlayCanvas; this.interactive=interactive; this.onSelect=onSelect;
    this.nodes=[]; this.edges=[]; this.yaw=-.52; this.pitch=.22; this.zoom=1; this.selected=-1; this.drag=null;
    this.gl=glCanvas.getContext('webgl',{antialias:true,alpha:true}) || glCanvas.getContext('experimental-webgl');
    this.ctx=overlayCanvas.getContext('2d');
    if (this.gl) this._initGL();
    if (interactive) this._bind();
    new ResizeObserver(()=>this.draw()).observe(glCanvas);
    this._animate();
  }
  _animate(){if(document.hidden){requestAnimationFrame(()=>this._animate());return;}this.draw();requestAnimationFrame(()=>this._animate());}
  _shader(type, source) {
    const gl=this.gl, shader=gl.createShader(type); gl.shaderSource(shader,source); gl.compileShader(shader);
    if (!gl.getShaderParameter(shader,gl.COMPILE_STATUS)) throw new Error(gl.getShaderInfoLog(shader));
    return shader;
  }
  _initGL() {
    const gl=this.gl;
    const vs=this._shader(gl.VERTEX_SHADER,`attribute vec3 aPosition; attribute vec4 aColor; attribute float aSize; varying vec4 vColor; void main(){gl_Position=vec4(aPosition,1.0);gl_PointSize=aSize;vColor=aColor;}`);
    const fs=this._shader(gl.FRAGMENT_SHADER,`precision mediump float; varying vec4 vColor; void main(){vec2 p=gl_PointCoord-vec2(.5);float d=length(p);if(d>.48)discard;float edge=smoothstep(.5,.34,d);gl_FragColor=vec4(vColor.rgb,vColor.a*edge);}`);
    this.program=gl.createProgram();gl.attachShader(this.program,vs);gl.attachShader(this.program,fs);gl.linkProgram(this.program);
    if(!gl.getProgramParameter(this.program,gl.LINK_STATUS))throw new Error(gl.getProgramInfoLog(this.program));
    this.buffers={position:gl.createBuffer(),color:gl.createBuffer(),size:gl.createBuffer(),lines:gl.createBuffer()};
    this.locations={position:gl.getAttribLocation(this.program,'aPosition'),color:gl.getAttribLocation(this.program,'aColor'),size:gl.getAttribLocation(this.program,'aSize')};
    gl.enable(gl.BLEND);gl.blendFunc(gl.SRC_ALPHA,gl.ONE_MINUS_SRC_ALPHA);gl.enable(gl.DEPTH_TEST);gl.depthFunc(gl.LEQUAL);
  }
  setData(nodes,edges){this.nodes=nodes||[];this.edges=edges||[];this.selected=-1;this.draw();}
  _rotate(pos){
    let [x,y,z]=pos;const cy=Math.cos(this.yaw),sy=Math.sin(this.yaw);[x,z]=[x*cy-z*sy,x*sy+z*cy];
    const cp=Math.cos(this.pitch),sp=Math.sin(this.pitch);[y,z]=[y*cp-z*sp,y*sp+z*cp];
    const perspective=1/(1.0+Math.max(-1.5,z+3.4)*.085);
    return [x*.30*this.zoom*perspective,y*.43*this.zoom*perspective,z*.035];
  }
  _screen(pos){const p=this._rotate(pos),w=this.canvas.clientWidth,h=this.canvas.clientHeight;return [(p[0]*.5+.5)*w,(.5-p[1]*.5)*h,p[2]];}
  _hex(hex){const h=hex.replace('#','');return [parseInt(h.slice(0,2),16)/255,parseInt(h.slice(2,4),16)/255,parseInt(h.slice(4,6),16)/255,1];}
  draw(){
    const gl=this.gl,ctx=this.ctx,w=this.canvas.clientWidth,h=this.canvas.clientHeight;if(!w||!h)return;
    const dpr=Math.min(window.devicePixelRatio||1,2);this.canvas.width=Math.floor(w*dpr);this.canvas.height=Math.floor(h*dpr);this.overlay.width=Math.floor(w*dpr);this.overlay.height=Math.floor(h*dpr);
    if(gl){
      gl.viewport(0,0,this.canvas.width,this.canvas.height);gl.clearColor(.025,.055,.095,0);gl.clear(gl.COLOR_BUFFER_BIT|gl.DEPTH_BUFFER_BIT);gl.useProgram(this.program);
      const points=[],pointColors=[],sizes=[],screen=[];
      for(const node of this.nodes){const p=this._rotate(node.pos||[0,0,0]);points.push(...p);pointColors.push(...this._hex(node.color||colors[node.kind]||'#9db5d0'));sizes.push(node.root?15:node.kind==='domain'?13:9);screen.push(this._screen(node.pos||[0,0,0]));}
      const edgePositions=[];for(const [a,b] of this.edges){if(!this.nodes[a]||!this.nodes[b])continue;edgePositions.push(...this._rotate(this.nodes[a].pos),...this._rotate(this.nodes[b].pos));}
      this._buffer(this.buffers.lines,edgePositions,3,this.locations.position);gl.disableVertexAttribArray(this.locations.color);gl.vertexAttrib4f(this.locations.color,.12,.34,.48,.48);gl.disableVertexAttribArray(this.locations.size);gl.vertexAttrib1f(this.locations.size,1);gl.drawArrays(gl.LINES,0,edgePositions.length/3);
      this._buffer(this.buffers.position,points,3,this.locations.position);this._buffer(this.buffers.color,pointColors,4,this.locations.color);this._buffer(this.buffers.size,sizes,1,this.locations.size);gl.drawArrays(gl.POINTS,0,sizes.length);
      this.screenPoints=screen;
    } else this.screenPoints=this.nodes.map(n=>this._screen(n.pos||[0,0,0]));
    ctx.setTransform(dpr,0,0,dpr,0,0);ctx.clearRect(0,0,w,h);const pulse=(performance.now()-this.startedAt)/1900;
    // Perspective orbit guides.
    ctx.save();ctx.translate(w/2,h/2);ctx.strokeStyle='rgba(72,145,178,.13)';ctx.lineWidth=1;
    for(const r of [58,116,174,232]){ctx.beginPath();ctx.ellipse(0,0,r,r*.32,0,0,Math.PI*2);ctx.stroke();}ctx.restore();
    // Link glow and readable root/selected labels.
    for(const [a,b] of this.edges){const p=this.screenPoints[a],q=this.screenPoints[b];if(!p||!q)continue;ctx.beginPath();ctx.moveTo(p[0],p[1]);ctx.lineTo(q[0],q[1]);ctx.strokeStyle='rgba(66,174,210,.20)';ctx.lineWidth=1.15;ctx.shadowColor='#36c5e8';ctx.shadowBlur=5;ctx.stroke();ctx.shadowBlur=0;const t=(pulse*.55+(a*.137+b*.071))%1;const px=p[0]+(q[0]-p[0])*t,py=p[1]+(q[1]-p[1])*t;ctx.beginPath();ctx.arc(px,py,1.8,0,Math.PI*2);ctx.fillStyle='rgba(126,231,255,.82)';ctx.shadowColor='#5bdfff';ctx.shadowBlur=9;ctx.fill();ctx.shadowBlur=0;}
    if(!gl){for(const [a,b] of this.edges){const p=this.screenPoints[a],q=this.screenPoints[b];if(!p||!q)continue;ctx.beginPath();ctx.moveTo(p[0],p[1]);ctx.lineTo(q[0],q[1]);ctx.strokeStyle='#31536f';ctx.stroke();}this.nodes.forEach((n,i)=>{const p=this.screenPoints[i];ctx.beginPath();ctx.arc(p[0],p[1],n.root?7:4,0,Math.PI*2);ctx.fillStyle=n.color||'#9db5d0';ctx.fill();});}
    this.nodes.forEach((n,i)=>{const p=this.screenPoints[i];if(!p)return;const color=n.color||colors[n.kind]||'#69dff2';const radius=(n.root?10:n.kind==='domain'?8:5)+(Math.sin(pulse*2.3+i*.71)+1)*.9;ctx.beginPath();ctx.arc(p[0],p[1],radius+5,0,Math.PI*2);ctx.fillStyle=color+'22';ctx.shadowColor=color;ctx.shadowBlur=14;ctx.fill();ctx.shadowBlur=0;ctx.beginPath();ctx.arc(p[0],p[1],n.root?5.2:n.kind==='domain'?4.1:2.8,0,Math.PI*2);ctx.fillStyle=color;ctx.shadowColor=color;ctx.shadowBlur=11;ctx.fill();ctx.shadowBlur=0;if(!n.root&&i!==this.selected)return;ctx.font='600 10px ui-monospace,monospace';ctx.fillStyle=i===this.selected?'#ffffff':'#c2d8ed';ctx.shadowColor=n.color||'#4ce7f3';ctx.shadowBlur=10;ctx.fillText((n.label||n.value||'').slice(0,34),p[0]+10,p[1]-7);ctx.shadowBlur=0;});
    if(this.selected>=0&&this.screenPoints[this.selected]){const p=this.screenPoints[this.selected];ctx.beginPath();ctx.arc(p[0],p[1],17+Math.sin(pulse*3)*2,0,Math.PI*2);ctx.strokeStyle='rgba(223,248,255,.8)';ctx.lineWidth=1;ctx.setLineDash([3,4]);ctx.stroke();ctx.setLineDash([]);}if(!this.nodes.length){ctx.fillStyle='#7188a4';ctx.font='700 10px ui-monospace,monospace';ctx.textAlign='center';ctx.fillText('AWAITING DISCOVERY DATA',w/2,h/2);ctx.textAlign='left';}
  }
  _buffer(buffer,data,size,location){const gl=this.gl;gl.bindBuffer(gl.ARRAY_BUFFER,buffer);gl.bufferData(gl.ARRAY_BUFFER,new Float32Array(data),gl.DYNAMIC_DRAW);gl.enableVertexAttribArray(location);gl.vertexAttribPointer(location,size,gl.FLOAT,false,0,0);}
  _bind(){
    this.canvas.addEventListener('pointerdown',e=>{this.drag={x:e.clientX,y:e.clientY,yaw:this.yaw,pitch:this.pitch};this.canvas.setPointerCapture(e.pointerId);});
    this.canvas.addEventListener('pointermove',e=>{if(!this.drag)return;this.yaw=this.drag.yaw+(e.clientX-this.drag.x)*.008;this.pitch=Math.max(-1.05,Math.min(1.05,this.drag.pitch+(e.clientY-this.drag.y)*.006));this.draw();});
    this.canvas.addEventListener('pointerup',e=>{if(!this.drag)return;const moved=Math.abs(e.clientX-this.drag.x)+Math.abs(e.clientY-this.drag.y);this.drag=null;if(moved<5)this._pick(e);});
    this.canvas.addEventListener('wheel',e=>{e.preventDefault();this.zoom=Math.max(.55,Math.min(2.1,this.zoom*(e.deltaY<0?1.1:.9)));this.draw();},{passive:false});
  }
  _pick(e){let best=-1,dist=1e9;const r=this.canvas.getBoundingClientRect();const x=e.clientX-r.left,y=e.clientY-r.top;this.screenPoints.forEach((p,i)=>{const d=(p[0]-x)**2+(p[1]-y)**2;if(d<dist){dist=d;best=i;}});if(best>=0&&dist<28**2){this.selected=best;this.draw();if(this.onSelect)this.onSelect(this.nodes[best]);}}
  reset(){this.yaw=-.52;this.pitch=.22;this.zoom=1;this.draw();}
}

const miniGraph=new Graph3D($('miniGl'),$('miniOverlay'),false);
const mainGraph=new Graph3D($('mainGl'),$('mainOverlay'),true,inspectNode);

function inspectNode(node){
  $('inspectorEmpty').hidden=true;$('inspectorContent').hidden=false;
  $('objectKind').textContent=node.kind.replaceAll('_',' ');
  $('objectValue').textContent=node.value;
  $('objectSource').textContent=node.source||'—';$('objectStatus').textContent=node.status||'observed';
  $('objectDetails').textContent=JSON.stringify(node.details||{},null,2);
}

function showView(name){
  document.querySelectorAll('.view').forEach(v=>v.classList.toggle('active',v.id===`view-${name}`));
  document.querySelectorAll('.nav-item').forEach(v=>v.classList.toggle('active',v.dataset.view===name));
  const titles={overview:['Mission control','Map the exposed surface. Understand the application. Investigate the evidence.'],topology:['3D attack-surface map','Spatial relationship intelligence · Drag to rotate · Wheel to zoom · Select nodes to inspect'],assets:['Asset inventory','Every discovered host, service, route, parameter and application resource'],findings:['Security findings','Evidence-backed observations · Potential findings require independent verification'],activity:['Live activity','Chronological scan telemetry from the discovery engine']};
  $('pageTitle').textContent=titles[name][0];$('pageSub').textContent=titles[name][1];
  if(name==='topology')requestAnimationFrame(()=>mainGraph.draw());
}
document.querySelectorAll('.nav-item').forEach(b=>b.addEventListener('click',()=>showView(b.dataset.view)));
document.querySelectorAll('[data-goto]').forEach(b=>b.addEventListener('click',()=>showView(b.dataset.goto)));
$('closeDetail').addEventListener('click',()=> $('detailDialog').close());
$('detailDialog').addEventListener('click',e=>{if(e.target===$('detailDialog'))$('detailDialog').close();});
$('resetMap').addEventListener('click',()=>mainGraph.reset());
$('targetInput').addEventListener('input',()=>{if(importedTargets.length){importedTargets=[];$('importStatus').textContent='Imported target batch cleared · using the edited single target.';}});
$('scanProfile').addEventListener('change',()=>applyProfile($('scanProfile').value));
function applyProfile(name){const profiles={balanced:{pages:500,workers:24,depth:5,timeout:5,delay:.12,ports:'',desc:'Balanced coverage across DNS, services and web application discovery.'},deep:{pages:1800,workers:18,depth:9,timeout:8,delay:.18,ports:'80,443,8000-8100,8443,8888',desc:'Deeper crawl with a larger page budget, greater depth and additional common web ports.'},infra:{pages:80,workers:28,depth:1,timeout:4,delay:.08,ports:'21,22,25,53,80,110,143,443,445,587,993,995,1433,3306,3389,5432,5900,6379,8000,8080,8443,8888',desc:'Prioritizes host, TCP service and web-service exposure over deep crawling.'},fast:{pages:120,workers:16,depth:2,timeout:3,delay:.25,ports:'80,443,8080,8443',desc:'A restrained quick snapshot for initial inventory and change checks.'}};const p=profiles[name];if(!p)return;for(const [k,v] of Object.entries({pages:p.pages,workers:p.workers,depth:p.depth,timeout:p.timeout,delay:p.delay,ports:p.ports}))$(k).value=v;$('profileDescription').textContent=p.desc;}
$('targetFile').addEventListener('change',async e=>{const file=e.target.files[0];if(!file)return;try{const rows=(await file.text()).split(/\r?\n/).map(x=>x.trim()).filter(x=>x&&!x.startsWith('#')&&!x.startsWith(';'));if(!rows.length)throw new Error('No targets found in that file.');importedTargets=rows;$('targetInput').value=rows[0];$('importStatus').textContent=`${rows.length} targets loaded from ${file.name} · first target shown in the input`; }catch(err){$('importStatus').textContent=err.message;}e.target.value='';});

$('startScan').addEventListener('click',async()=>{
  const targets=importedTargets.length?importedTargets:[$('targetInput').value.trim()].filter(Boolean);
  if(!targets.length){$('stageText').textContent='Enter a target or import a target list.';return;}
  const config={pages:$('pages').value,workers:$('workers').value,depth:$('depth').value,timeout:$('timeout').value,delay:$('delay').value,ports:$('ports').value.trim()||null,cve_intel:$('cveIntel').checked};
  $('startScan').disabled=true;
  try{await api('/api/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({targets,config})});$('importStatus').textContent=`Discovery queued for ${targets.length} target(s).`;}
  catch(err){$('stageText').textContent=err.message;$('startScan').disabled=false;}
});

async function downloadReport(format){
  try{const response=await fetch(`/api/export?format=${format}`,{headers:{'X-Mirage-Token':token}});if(!response.ok){const e=await response.json();throw new Error(e.error||'Export failed');}const blob=await response.blob();const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download=`mirage-report.${format}`;a.click();URL.revokeObjectURL(url);}
  catch(err){$('stageText').textContent=err.message;}
}
$('exportJson').addEventListener('click',()=>downloadReport('json'));$('exportHtml').addEventListener('click',()=>downloadReport('html'));
$('clearLogs').addEventListener('click',()=>{$('fullLogs').innerHTML='<div class="feed-empty">View cleared · New events will appear here.</div>';$('miniLogs').innerHTML='<div class="feed-empty">Waiting for discovery events…</div>';lastLogSignature='';});
$('assetSearch').addEventListener('input',renderAssets);$('findingSearch').addEventListener('input',renderFindings);

function renderAssets(){const q=$('assetSearch').value.toLowerCase();const rows=(window.mirageAssets||[]).filter(a=>`${a.kind} ${a.value} ${a.source} ${a.status}`.toLowerCase().includes(q));$('assetCount').textContent=rows.length;$('assetRows').innerHTML=rows.length?rows.map((a,i)=>`<tr class="asset-row" data-asset-index="${i}" tabindex="0"><td>${esc(a.kind)}</td><td class="asset-value">${esc(a.value)}</td><td>${esc(a.source)}</td><td>${esc(a.status)}</td></tr>`).join(''):'<tr><td colspan="4" class="table-empty">No matching assets.</td></tr>';document.querySelectorAll('[data-asset-index]').forEach(row=>row.addEventListener('click',()=>showDetail('ASSET',rows[Number(row.dataset.assetIndex)])));}
function renderFindings(){const q=$('findingSearch').value.toLowerCase();const rows=(window.mirageFindings||[]).filter(f=>`${f.severity} ${f.title} ${f.asset} ${f.status}`.toLowerCase().includes(q));$('findingCount').textContent=rows.length;$('findingRows').innerHTML=rows.length?rows.map((f,i)=>`<tr class="finding-row" data-finding-index="${i}" tabindex="0"><td><span class="severity ${esc(f.severity)}">${esc(f.severity)}</span></td><td>${esc(f.title)}</td><td class="asset-value">${esc(f.asset)}</td><td>${esc(f.confidence)}</td><td>${esc(f.status)}</td></tr>`).join(''):'<tr><td colspan="5" class="table-empty">No matching findings.</td></tr>';document.querySelectorAll('[data-finding-index]').forEach(row=>row.addEventListener('click',()=>showDetail('SECURITY FINDING',rows[Number(row.dataset.findingIndex)])));}
function showDetail(kind,obj){if(!obj)return;$('detailKind').textContent=kind;$('detailTitle').textContent=obj.title||obj.value||obj.asset||'Selected object';if(kind==='SECURITY FINDING'){$('detailBody').innerHTML=`<div class="detail-grid"><b>Severity</b><span>${esc(obj.severity)}</span><b>Confidence</b><span>${esc(obj.confidence)}</span><b>Affected asset</b><span>${esc(obj.asset)}</span><b>Status</b><span>${esc(obj.status)}</span><b>Discovered</b><span>${esc(obj.discovered_at)}</span></div><p>${esc(obj.description)}</p><h3>Evidence</h3><pre>${esc(JSON.stringify(obj.evidence||{},null,2))}</pre><h3>Recommended remediation</h3><p>${esc(obj.recommendation||'Review manually.')}</p>`;}else{$('detailBody').innerHTML=`<div class="detail-grid"><b>Type</b><span>${esc(obj.kind)}</span><b>Value</b><span>${esc(obj.value)}</span><b>Source</b><span>${esc(obj.source)}</span><b>Status</b><span>${esc(obj.status)}</span><b>Discovered</b><span>${esc(obj.discovered_at)}</span></div><h3>Observed metadata</h3><pre>${esc(JSON.stringify(obj.details||{},null,2))}</pre>`;}$('detailDialog').showModal();}
function esc(value){return String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function renderLogs(logs){const signature=logs.map(x=>x.time+x.level+x.message).join('|');if(signature===lastLogSignature)return;lastLogSignature=signature;const item=x=>`<div class="feed-item"><span class="feed-time">${esc(x.time)}</span><span class="feed-level ${esc(x.level)}">${esc(x.level)}</span><span class="feed-message">${esc(x.message)}</span></div>`;$('miniLogs').innerHTML=logs.length?logs.slice(-12).map(item).join(''):'<div class="feed-empty">Waiting for discovery events…</div>';$('fullLogs').innerHTML=logs.length?logs.map(x=>`<div class="terminal-line"><span class="feed-time">${esc(x.time)}</span><span class="feed-level ${esc(x.level)}">${esc(x.level)}</span><span class="feed-message">${esc(x.message)}</span></div>`).join(''):'<div class="feed-empty">No activity yet.</div>';$('fullLogs').scrollTop=$('fullLogs').scrollHeight;}
function formatElapsed(seconds){seconds=Math.max(0,Math.floor(seconds));return `${String(Math.floor(seconds/60)).padStart(2,'0')}:${String(seconds%60).padStart(2,'0')}`;}
function updateState(s){currentState=s;const running=s.running;const status=s.status||'READY';$('runStatus').textContent=running?'SCAN IN PROGRESS':status==='COMPLETE'?'SCAN COMPLETE':status==='FAILED'?'SCAN FAILED':'SYSTEM READY';$('runChip').classList.toggle('running',running);$('runChip').classList.toggle('failed',status==='FAILED');$('sideState').textContent=running?'ACTIVE':status==='COMPLETE'?'COMPLETE':status==='FAILED'?'ERROR':'IDLE';$('sideDot').style.background=running?'var(--cyan)':status==='FAILED'?'var(--red)':'var(--green)';$('scanIndicator').textContent=running?'RUNNING':status;$('scanIndicator').classList.toggle('running',running);$('stageText').textContent=s.stage||'Standing by';$('phaseLabel').textContent=running?'DISCOVERY ENGINE ACTIVE':status==='COMPLETE'?'DISCOVERY COMPLETE':'DISCOVERY ENGINE READY';$('startScan').disabled=running;$('startScan').innerHTML=running?'<span class="play">◌</span> Discovery running':'<span class="play">▶</span> Initiate discovery';$('progressFill').classList.toggle('running',running);$('progressFill').style.width=running?'35%':status==='COMPLETE'?'100%':'0%';const now=Date.now()/1000;const elapsed=s.started?(s.finished||now)-s.started:0;$('elapsed').textContent=formatElapsed(elapsed);$('scanElapsed').textContent=`ELAPSED ${formatElapsed(elapsed)}`;
  const c=s.counts||{};$('metricAssets').textContent=c.assets||0;$('metricHosts').textContent=c.hosts??((c.subdomains||0));$('metricServices').textContent=(c.http_services||0)+(c.tcp_services||0);$('metricFindings').textContent=c.findings||0;
  renderLogs(s.logs||[]);
  if(!running&&status==='COMPLETE'&&s.finished&&String(s.finished)!==lastResultKey){lastResultKey=String(s.finished);loadResult();}
}
async function loadResult(){try{const data=await api('/api/result');graphData=data;miniGraph.setData(data.nodes,data.edges);mainGraph.setData(data.nodes,data.edges);$('miniEmpty').style.display=data.nodes.length?'none':'flex';$('mainEmpty').style.display=data.nodes.length?'none':'flex';$('graphCounts').textContent=`${data.nodes.length} NODES · ${data.edges.length} RELATIONSHIPS`;$('assetRows').innerHTML='';window.mirageAssets=data.assets||[];window.mirageFindings=data.findings||[];renderAssets();renderFindings();}catch(err){$('stageText').textContent=err.message;}}
async function poll(){try{const s=await api('/api/state');updateState(s);}catch(err){$('stageText').textContent=`Desktop service connection lost · ${err.message}`;}setTimeout(poll,650);}

poll();
