const fs = require('fs');
const path = require('path');

// Scan source files for security issues
const srcDir = 'src';
const issues = [];
const recommendations = [];

function scanFile(filePath) {
    const content = fs.readFileSync(filePath, 'utf8');
    const lines = content.split('\n');
    
    lines.forEach((line, idx) => {
        const lineNum = idx + 1;
        
        // SQL Injection check
        if (line.includes('query(') && line.includes('${') && !line.includes('parameterized')) {
            issues.push({file: filePath, line: lineNum, severity: 'HIGH', type: 'SQL Injection', detail: 'String interpolation in SQL query detected. Use parameterized queries.'});
        }
        
        // Hardcoded secrets
        if (line.match(/(password|secret|token|api_key)\s*=\s*['"][^'"]+['"]/i) && !line.includes('process.env')) {
            issues.push({file: filePath, line: lineNum, severity: 'CRITICAL', type: 'Hardcoded Secret', detail: 'Credential hardcoded in source code. Use environment variables or Vault.'});
        }
        
        // eval() usage
        if (line.includes('eval(')) {
            issues.push({file: filePath, line: lineNum, severity: 'CRITICAL', type: 'Code Injection', detail: 'eval() usage detected. This allows arbitrary code execution.'});
        }
        
        // No input validation
        if (line.includes('req.body') && !line.includes('validate') && !line.includes('sanitize') && !line.includes('check')) {
            issues.push({file: filePath, line: lineNum, severity: 'MEDIUM', type: 'Input Validation', detail: 'Direct use of req.body without validation. Consider using express-validator.'});
        }
        
        // HTTP instead of HTTPS
        if (line.match(/http:\/\//) && !line.includes('localhost') && !line.includes('127.0.0.1') && !line.includes('172.17')) {
            issues.push({file: filePath, line: lineNum, severity: 'MEDIUM', type: 'Insecure Protocol', detail: 'HTTP used instead of HTTPS. Use encrypted connections.'});
        }
        
        // Console.log in production
        if (line.includes('console.log') && !filePath.includes('test')) {
            issues.push({file: filePath, line: lineNum, severity: 'LOW', type: 'Information Leak', detail: 'console.log in production code. May leak sensitive information.'});
        }
        
        // Missing error handling
        if (line.includes('.catch') === false && line.includes('await ') && !line.includes('try')) {
            issues.push({file: filePath, line: lineNum, severity: 'MEDIUM', type: 'Error Handling', detail: 'Async operation without proper error handling.'});
        }
        
        // CORS wildcard
        if (line.includes("origin: '*'") || line.includes('origin: "*"')) {
            issues.push({file: filePath, line: lineNum, severity: 'HIGH', type: 'CORS Misconfiguration', detail: 'Wildcard CORS origin allows any domain. Restrict to specific origins.'});
        }
        
        // JWT without expiration
        if (line.includes('jwt.sign') && !line.includes('expiresIn')) {
            issues.push({file: filePath, line: lineNum, severity: 'HIGH', type: 'JWT Security', detail: 'JWT token without expiration. Add expiresIn option.'});
        }
        
        // Path traversal
        if (line.includes('req.params') && (line.includes('readFile') || line.includes('path.join'))) {
            issues.push({file: filePath, line: lineNum, severity: 'HIGH', type: 'Path Traversal', detail: 'User input used in file operations. Validate and sanitize path.'});
        }
    });
}

function walkDir(dir) {
    if (!fs.existsSync(dir)) return;
    fs.readdirSync(dir).forEach(f => {
        const full = path.join(dir, f);
        if (fs.statSync(full).isDirectory()) walkDir(full);
        else if (f.endsWith('.js') || f.endsWith('.mjs')) scanFile(full);
    });
}

walkDir('src');
walkDir('middleware');

// Generate recommendations
recommendations.push('Use Helmet.js for HTTP security headers (already implemented)');
recommendations.push('Implement rate limiting on API endpoints');
recommendations.push('Add input validation with express-validator on all routes');
recommendations.push('Enable HTTPS/TLS for production deployment');
recommendations.push('Implement request logging with correlation IDs');
recommendations.push('Add Content Security Policy headers');
recommendations.push('Use bcrypt with salt rounds >= 12 for password hashing');
recommendations.push('Implement account lockout after failed login attempts');
recommendations.push('Add API versioning for backward compatibility');
recommendations.push('Store secrets in HashiCorp Vault (implemented)');

// Generate HTML report
const critical = issues.filter(i => i.severity === 'CRITICAL').length;
const high = issues.filter(i => i.severity === 'HIGH').length;
const medium = issues.filter(i => i.severity === 'MEDIUM').length;
const low = issues.filter(i => i.severity === 'LOW').length;

let issueRows = '';
issues.forEach(i => {
    const cls = i.severity;
    issueRows += '<tr><td>' + i.file + ':' + i.line + '</td><td>' + i.type + '</td><td class="' + cls + '">' + i.severity + '</td><td>' + i.detail + '</td></tr>';
});

let recRows = '';
recommendations.forEach((r, idx) => {
    recRows += '<tr><td>' + (idx + 1) + '</td><td>' + r + '</td></tr>';
});

const html = '<!DOCTYPE html><html><head><title>AI Security Scanner Report</title><style>body{font-family:Arial;margin:20px;background:#f5f5f5}h1{color:#1a237e}h2{color:#0d47a1;border-bottom:2px solid #42a5f5;padding-bottom:8px}.summary{display:flex;gap:15px;margin:20px 0}.stat{padding:20px;border-radius:8px;text-align:center;flex:1;color:white}.stat .num{font-size:32px;font-weight:bold}.stat .label{font-size:14px}table{width:100%;border-collapse:collapse;background:white;margin-top:10px}th{background:#1a237e;color:white;padding:12px;text-align:left}td{padding:10px 12px;border-bottom:1px solid #e0e0e0}.CRITICAL{background:#ff1744;color:white;font-weight:bold;text-align:center}.HIGH{background:#ff5252;color:white;font-weight:bold;text-align:center}.MEDIUM{background:#ffd600;font-weight:bold;text-align:center}.LOW{background:#76ff03;font-weight:bold;text-align:center}.footer{text-align:center;margin-top:30px;color:#666;font-size:13px}.ai-badge{background:linear-gradient(135deg,#667eea,#764ba2);color:white;padding:5px 15px;border-radius:20px;font-size:14px;display:inline-block;margin-bottom:15px}</style></head><body><span class="ai-badge">AI-Powered Security Analysis</span><h1>AI Security Scanner Report</h1><p>Automated security analysis of WaelTo5Clean backend source code</p><div class="summary"><div class="stat" style="background:#ff1744"><div class="num">' + critical + '</div><div class="label">CRITICAL</div></div><div class="stat" style="background:#ff5252"><div class="num">' + high + '</div><div class="label">HIGH</div></div><div class="stat" style="background:#ff9800"><div class="num">' + medium + '</div><div class="label">MEDIUM</div></div><div class="stat" style="background:#4caf50"><div class="num">' + low + '</div><div class="label">LOW</div></div></div><h2>Security Issues Found</h2><table><tr><th>Location</th><th>Type</th><th>Severity</th><th>Description</th></tr>' + issueRows + '</table><h2>AI Recommendations</h2><table><tr><th>#</th><th>Recommendation</th></tr>' + recRows + '</table><div class="footer">AI Security Scanner - PFE DevSecOps - Wael Khadraoui - 2026</div></body></html>';

fs.mkdirSync('reports', {recursive: true});
fs.writeFileSync('reports/ai-security-report.html', html);
console.log('AI Security Scan Complete: ' + issues.length + ' issues found (' + critical + ' CRITICAL, ' + high + ' HIGH, ' + medium + ' MEDIUM, ' + low + ' LOW)');
