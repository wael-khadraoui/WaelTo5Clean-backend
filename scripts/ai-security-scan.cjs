const fs = require('fs');
const path = require('path');
const https = require('https');

const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || '';
const issues = [];

// Pattern detection (rapide)
function scanPatterns(filePath, content) {
    const lines = content.split('\n');
    lines.forEach((line, idx) => {
        const lineNum = idx + 1;
        if (line.match(/(password|secret|token|api_key)\s*=\s*['"][^'"]+['"]/i) && !line.includes('process.env')) {
            issues.push({file: filePath, line: lineNum, severity: 'CRITICAL', type: 'Hardcoded Secret', code: line.trim()});
        }
        if (line.includes('eval(')) {
            issues.push({file: filePath, line: lineNum, severity: 'CRITICAL', type: 'Code Injection', code: line.trim()});
        }
        if (line.includes('jwt.sign') && !line.includes('expiresIn')) {
            issues.push({file: filePath, line: lineNum, severity: 'HIGH', type: 'JWT no expiration', code: line.trim()});
        }
        if (line.includes("origin: '*'") || line.includes('origin: "*"')) {
            issues.push({file: filePath, line: lineNum, severity: 'HIGH', type: 'CORS wildcard', code: line.trim()});
        }
        if (line.includes('req.body') && !line.includes('validate') && !line.includes('check')) {
            issues.push({file: filePath, line: lineNum, severity: 'MEDIUM', type: 'No Input Validation', code: line.trim()});
        }
        if (line.includes('console.log') && !filePath.includes('test')) {
            issues.push({file: filePath, line: lineNum, severity: 'LOW', type: 'Information Leak', code: line.trim()});
        }
    });
}

// Real AI Analysis avec Claude API
async function analyzeWithClaude(codeSnippet, issueType) {
    return new Promise((resolve) => {
        if (!ANTHROPIC_API_KEY) {
            resolve(null);
            return;
        }
        
        const data = JSON.stringify({
            model: "claude-haiku-4-5-20251001",
            max_tokens: 500,
            messages: [{
                role: "user",
                content: `You are a security expert. Analyze this code for security issues.
Type: ${issueType}
Code: ${codeSnippet}

Respond in JSON format:
{
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "explanation": "brief explanation",
  "fix": "secure code fix",
  "owasp": "OWASP category"
}`
            }]
        });
        
        const options = {
            hostname: 'api.anthropic.com',
            path: '/v1/messages',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-api-key': ANTHROPIC_API_KEY,
                'anthropic-version': '2023-06-01',
                'Content-Length': data.length
            }
        };
        
        const req = https.request(options, (res) => {
            let body = '';
            res.on('data', chunk => body += chunk);
            res.on('end', () => {
                try {
                    const response = JSON.parse(body);
                    if (response.content && response.content[0]) {
                        const text = response.content[0].text;
                        const jsonMatch = text.match(/\{[\s\S]*\}/);
                        if (jsonMatch) {
                            resolve(JSON.parse(jsonMatch[0]));
                            return;
                        }
                    }
                    resolve(null);
                } catch(e) { resolve(null); }
            });
        });
        req.on('error', () => resolve(null));
        req.write(data);
        req.end();
    });
}

function walkDir(dir) {
    if (!fs.existsSync(dir)) return;
    fs.readdirSync(dir).forEach(f => {
        const full = path.join(dir, f);
        if (fs.statSync(full).isDirectory()) walkDir(full);
        else if (f.endsWith('.js') || f.endsWith('.mjs')) {
            const content = fs.readFileSync(full, 'utf8');
            scanPatterns(full, content);
        }
    });
}

(async () => {
    console.log('Starting AI Security Scan...');
    walkDir('src');
    walkDir('middleware');
    
    console.log(`Pattern scan found ${issues.length} issues`);
    
    // AI Enhancement - analyser les top 5 issues critiques avec Claude
    const criticalIssues = issues.filter(i => i.severity === 'CRITICAL' || i.severity === 'HIGH').slice(0, 5);
    let aiEnhanced = 0;
    
    if (ANTHROPIC_API_KEY && criticalIssues.length > 0) {
        console.log(`Analyzing top ${criticalIssues.length} critical issues with Claude AI...`);
        for (const issue of criticalIssues) {
            const analysis = await analyzeWithClaude(issue.code, issue.type);
            if (analysis) {
                issue.aiAnalysis = analysis;
                aiEnhanced++;
            }
        }
        console.log(`Enhanced ${aiEnhanced} issues with Claude AI`);
    } else {
        console.log('No ANTHROPIC_API_KEY - using pattern detection only');
    }
    
    const critical = issues.filter(i => i.severity === 'CRITICAL').length;
    const high = issues.filter(i => i.severity === 'HIGH').length;
    const medium = issues.filter(i => i.severity === 'MEDIUM').length;
    const low = issues.filter(i => i.severity === 'LOW').length;
    
    let issueRows = '';
    issues.forEach(i => {
        const aiBadge = i.aiAnalysis ? '<span style="background:#7c4dff20;color:#7c4dff;padding:2px 8px;border-radius:4px;font-size:10px;margin-left:5px">AI ANALYZED</span>' : '';
        const fix = i.aiAnalysis ? i.aiAnalysis.fix : 'See documentation';
        const explanation = i.aiAnalysis ? i.aiAnalysis.explanation : '';
        issueRows += `<tr><td>${i.file}:${i.line}</td><td>${i.type}${aiBadge}</td><td class="${i.severity}">${i.severity}</td><td>${explanation}<br><pre style="font-size:11px;background:#f5f5f5;padding:5px;border-radius:4px;margin-top:5px">${fix}</pre></td></tr>`;
    });
    
    const html = `<!DOCTYPE html><html><head><title>AI Security Scanner Report</title><style>body{font-family:Arial;margin:20px;background:#f5f5f5}h1{color:#1a237e}h2{color:#0d47a1;border-bottom:2px solid #42a5f5;padding-bottom:8px}.summary{display:flex;gap:15px;margin:20px 0}.stat{padding:20px;border-radius:8px;text-align:center;flex:1;color:white}.stat .num{font-size:32px;font-weight:bold}table{width:100%;border-collapse:collapse;background:white;margin-top:10px}th{background:#1a237e;color:white;padding:12px;text-align:left}td{padding:10px 12px;border-bottom:1px solid #e0e0e0;vertical-align:top}.CRITICAL{background:#ff1744;color:white;font-weight:bold;text-align:center}.HIGH{background:#ff5252;color:white;font-weight:bold;text-align:center}.MEDIUM{background:#ffd600;font-weight:bold;text-align:center}.LOW{background:#76ff03;font-weight:bold;text-align:center}.ai-badge{background:linear-gradient(135deg,#7c4dff,#311b92);color:white;padding:8px 20px;border-radius:20px;font-size:14px;display:inline-block;margin-bottom:15px}.stats-info{background:white;padding:15px;border-radius:8px;margin:10px 0;border-left:4px solid #7c4dff}</style></head><body><span class="ai-badge">⚡ Powered by Claude AI (Anthropic)</span><h1>AI Security Scanner Report</h1><div class="stats-info"><strong>Scan Type:</strong> Hybrid (Pattern Detection + Claude AI Analysis)<br><strong>AI Enhanced Issues:</strong> ${aiEnhanced} / ${criticalIssues.length} critical issues<br><strong>Model:</strong> claude-haiku-4-5</div><div class="summary"><div class="stat" style="background:#ff1744"><div class="num">${critical}</div><div>CRITICAL</div></div><div class="stat" style="background:#ff5252"><div class="num">${high}</div><div>HIGH</div></div><div class="stat" style="background:#ff9800"><div class="num">${medium}</div><div>MEDIUM</div></div><div class="stat" style="background:#4caf50"><div class="num">${low}</div><div>LOW</div></div></div><h2>Security Issues</h2><table><tr><th>Location</th><th>Type</th><th>Severity</th><th>AI Analysis & Fix</th></tr>${issueRows}</table><div style="text-align:center;margin-top:30px;color:#666;font-size:13px">AI Security Scanner with Claude AI - Wael Khadraoui - 2026</div></body></html>`;
    
    fs.mkdirSync('reports', {recursive: true});
    fs.writeFileSync('reports/ai-security-report.html', html);
    console.log(`AI Security Scan Complete: ${issues.length} issues (${critical} CRITICAL, ${high} HIGH, ${medium} MEDIUM, ${low} LOW)`);
    console.log(`AI Enhanced: ${aiEnhanced} issues analyzed by Claude`);
})();
