const fs=require('fs');
let d={};
try{d=JSON.parse(fs.readFileSync('reports/trivy-backend.json','utf8'))}catch(e){}
const res=d.Results||[];
let html='<!DOCTYPE html><html><head><title>Backend Image - Trivy Report</title>';
html+='<style>body{font-family:Arial,sans-serif;margin:20px;background:#fff}h1{font-size:22px}h2{font-size:18px;margin-top:30px;color:#333}table{width:100%;border-collapse:collapse;margin-top:10px}th{background:#ddd;padding:10px;text-align:left;border:1px solid #ccc}td{padding:8px 10px;border:1px solid #ccc}.CRITICAL{background:#ff1744;color:white;font-weight:bold;text-align:center}.HIGH{background:#ff5252;color:white;font-weight:bold;text-align:center}.MEDIUM{background:#ffd600;font-weight:bold;text-align:center}.LOW{background:#76ff03;font-weight:bold;text-align:center}.UNKNOWN{background:#bdbdbd;text-align:center}a{color:#1565c0}.footer{margin-top:30px;color:#666;font-size:12px;text-align:center}p.nomisconfig{color:#4caf50;font-weight:bold}</style></head><body>';
html+='<h1>backend-image (alpine) - Trivy Report - '+new Date().toISOString()+'</h1>';
for(const r of res){
    const target=r.Target||'unknown';
    const typ=r.Type||'';
    const vulns=r.Vulnerabilities||[];
    if(vulns.length===0){continue}
    const section=typ.includes('node')? 'node-pkg' : target.includes('alpine')? 'alpine' : target;
    html+='<h2>'+section+'</h2>';
    if(r.Misconfigurations&&r.Misconfigurations.length===0){html+='<p class="nomisconfig">No Misconfigurations found</p>'}
    html+='<table><tr><th>Package</th><th>Vulnerability ID</th><th>Severity</th><th>Installed Version</th><th>Fixed Version</th><th>Links</th></tr>';
    for(const v of vulns){
        const sev=v.Severity||'UNKNOWN';
        const links=[];
        if(v.PrimaryURL){links.push('<a href="'+v.PrimaryURL+'" target="_blank">'+v.PrimaryURL+'</a>')}
        if(v.References){for(const ref of v.References.slice(0,3)){links.push('<a href="'+ref+'" target="_blank">'+ref+'</a>')}}
        if(v.References&&v.References.length>3){links.push('<a href="#">Toggle more links</a>')}
        html+='<tr><td>'+v.PkgName+'</td><td>'+v.VulnerabilityID+'</td><td class="'+sev+'">'+sev+'</td><td>'+(v.InstalledVersion||'')+'</td><td>'+(v.FixedVersion||'')+'</td><td>'+links.join('<br>')+'</td></tr>';
    }
    html+='</table>';
}
html+='<div class="footer">PFE DevSecOps - Wael Khadraoui - 2026</div></body></html>';
fs.writeFileSync('reports/trivy-backend.html',html);
console.log('Trivy HTML report generated');
