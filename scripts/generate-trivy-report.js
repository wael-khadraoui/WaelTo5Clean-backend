const fs=require('fs');
let d={};
try{d=JSON.parse(fs.readFileSync('reports/trivy-backend.json','utf8'))}catch(e){}
const res=d.Results||[];
let sections='';
let total=0;
for(const r of res){
    const vulns=r.Vulnerabilities||[];
    if(vulns.length===0)continue;
    const typ=r.Type||r.Target||'unknown';
    sections+='<h2>'+typ+'</h2><table><tr><th>Package</th><th>Vulnerability ID</th><th>Severity</th><th>Installed</th><th>Fixed</th><th>Links</th></tr>';
    for(const v of vulns){
        total++;
        const sev=v.Severity||'UNKNOWN';
        const link=v.PrimaryURL?'<a href="'+v.PrimaryURL+'" target="_blank">Details</a>':'';
        sections+='<tr><td>'+v.PkgName+'</td><td>'+v.VulnerabilityID+'</td><td class="'+sev+'">'+sev+'</td><td>'+(v.InstalledVersion||'')+'</td><td>'+(v.FixedVersion||'')+'</td><td>'+link+'</td></tr>';
    }
    sections+='</table>';
}
const html='<!DOCTYPE html><html><head><title>Trivy Report</title><style>body{font-family:Arial;margin:20px}h1{color:#0d47a1}h2{color:#1565c0;margin-top:30px}table{width:100%;border-collapse:collapse;margin-top:10px}th{background:#ddd;padding:10px;text-align:left;border:1px solid #ccc}td{padding:8px 10px;border:1px solid #ccc}.CRITICAL{background:#ff1744;color:white;font-weight:bold;text-align:center}.HIGH{background:#ff5252;color:white;font-weight:bold;text-align:center}.MEDIUM{background:#ffd600;font-weight:bold;text-align:center}.LOW{background:#76ff03;font-weight:bold;text-align:center}a{color:#1565c0}.info{background:#f5f5f5;padding:15px;border-radius:8px;margin:15px 0}</style></head><body><h1>Trivy Scan Report - Backend</h1><div class="info"><p><b>Image:</b> wael558/waelto5clean-backend</p><p><b>Total Vulnerabilities:</b> '+total+'</p><p><b>Date:</b> '+new Date().toISOString()+'</p></div>'+sections+'</body></html>';
fs.writeFileSync('reports/trivy-report.html',html);
console.log('OK: '+total+' vulns');
