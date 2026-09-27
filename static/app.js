let latest = null;
const $ = id => document.getElementById(id);
const sample = `requests==2.31.0\nnumpy==1.26.4\npandas\nrequesrs==2.31.0\nflask`;
$('sampleBtn').onclick = () => { $('requirements').value = sample; $('status').textContent = 'Sample loaded — ready to scan.'; };
$('fileInput').onchange = e => { const f=e.target.files[0]; if(!f)return; const r=new FileReader(); r.onload=()=>{$('requirements').value=r.result;$('status').textContent=`Loaded ${f.name}.`}; r.readAsText(f); };
$('scanBtn').onclick = async () => {
  const req=$('requirements').value.trim(); if(!req){$('status').textContent='Add dependencies first.';return;}
  $('scanBtn').disabled=true; $('scanBtn').textContent='Scanning…'; $('status').textContent='Checking package intelligence feeds…';
  try{const r=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({requirements:req})}); const d=await r.json(); if(!r.ok)throw new Error(d.error); latest=d; render(d); $('status').textContent=`Scan complete — ${d.summary.total} packages analyzed.`; document.getElementById('results').scrollIntoView({behavior:'smooth'});}catch(e){$('status').textContent='Scan failed: '+e.message;}finally{$('scanBtn').disabled=false;$('scanBtn').textContent='Run full scan';}
};
function render(d){$('total').textContent=d.summary.total;$('danger').textContent=d.summary.Critical+d.summary.High;$('safe').textContent=d.summary.Low; $('empty').classList.add('hidden');$('tableWrap').classList.remove('hidden');$('tbody').innerHTML=d.results.map(x=>{let vuln=x.vulnerabilities.length?`<div class="vuln">${x.vulnerabilities.length} finding(s)</div>`:'None';let typo=x.typosquatting?`⚠ ${x.typosquatting}`:'None';let p=x.pypi.exists===true?'✓ Found':x.pypi.exists===false?'✕ Missing':'? Error';return `<tr><td><b>${esc(x.package)}</b></td><td>${esc(x.version)}</td><td>${typo}</td><td>${p}</td><td>${vuln}</td><td><span class="pill ${x.risk.toLowerCase()}">${x.risk}</span></td><td>${x.score}/100</td></tr>`}).join('');}
function esc(s){return String(s).replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));}
$('exportBtn').onclick=()=>{if(!latest){alert('Run a scan first.');return;}const blob=new Blob([JSON.stringify(latest,null,2)],{type:'application/json'});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='supplyshadow-scan-report.json';a.click();URL.revokeObjectURL(a.href);};
