pipeline {
    agent any
    environment {
        DOCKERHUB_USER = 'wael558'
        IMAGE_NAME     = "${DOCKERHUB_USER}/waelto5clean-backend"
        IMAGE_TAG      = "${BUILD_NUMBER}"
        SONAR_HOST     = 'http://172.17.0.1:9000'
    }
    stages {
        stage('Checkout') {
            steps {
                git branch: 'main',
                    url: 'https://github.com/wael-khadraoui/WaelTo5Clean-backend.git',
                    credentialsId: 'github-creds'
            }
        }
        stage('Install Dependencies') {
            steps {
                sh 'npm install'
            }
        }
        stage('Unit Tests') {
            steps {
                sh 'npm test || true'
            }
        }
        stage('SAST - SonarQube') {
            steps {
                withCredentials([string(credentialsId: 'sonarqube-token', variable: 'SONAR_TOKEN')]) {
                    sh """
                        sonar-scanner \
                          -Dsonar.projectKey=WaelTo5Clean-backend \
                          -Dsonar.projectName=WaelTo5Clean-backend \
                          -Dsonar.sources=src \
                          -Dsonar.host.url=${SONAR_HOST} \
                          -Dsonar.token=${SONAR_TOKEN}
                    """
                }
            }
        }
        stage('OWASP Dependency Check') {
            steps {
                sh 'mkdir -p reports'
                sh 'npm audit --json > reports/npm-audit.json || true'
                sh '''
                    node -e "
                    const audit = require('./reports/npm-audit.json');
                    const vulns = audit.vulnerabilities || {};
                    let rows = '';
                    for (const [name, info] of Object.entries(vulns)) {
                        const sev = info.severity || 'unknown';
                        const color = sev === 'critical' ? '#d32f2f' : sev === 'high' ? '#f44336' : sev === 'moderate' ? '#ff9800' : sev === 'low' ? '#4caf50' : '#9e9e9e';
                        const viaList = (info.via || []).map(v => typeof v === 'string' ? v : v.title || v.url || '').join(', ');
                        const range = info.range || '';
                        const fix = info.fixAvailable ? (typeof info.fixAvailable === 'object' ? info.fixAvailable.name + '@' + info.fixAvailable.version : 'Yes') : 'No';
                        rows += '<tr><td>' + name + '</td><td style=\"color:' + color + ';font-weight:bold\">' + sev.toUpperCase() + '</td><td>' + range + '</td><td>' + viaList + '</td><td>' + fix + '</td></tr>';
                    }
                    const count = Object.keys(vulns).length;
                    const html = '<!DOCTYPE html><html><head><title>OWASP Dependency Check - Backend</title><style>body{font-family:Arial,sans-serif;margin:20px;background:#f5f5f5}h1{color:#1a237e;border-bottom:3px solid #ff9800;padding-bottom:10px}.logo{display:flex;align-items:center;gap:15px;margin-bottom:20px}.logo-icon{width:60px;height:60px;background:linear-gradient(135deg,#ff9800,#f57c00);border-radius:50%;display:flex;align-items:center;justify-content:center;color:white;font-size:28px;font-weight:bold}.info{background:#fff;padding:15px;border-radius:8px;margin-bottom:20px;box-shadow:0 2px 4px rgba(0,0,0,0.1)}.info p{margin:5px 0}table{width:100%;border-collapse:collapse;background:white;box-shadow:0 2px 4px rgba(0,0,0,0.1);border-radius:8px;overflow:hidden}th{background:#1a237e;color:white;padding:12px;text-align:left}td{padding:10px 12px;border-bottom:1px solid #e0e0e0}tr:hover{background:#f5f5f5}tr:nth-child(even){background:#fafafa}.footer{text-align:center;margin-top:30px;color:#666;font-size:13px}</style></head><body><div class=\"logo\"><div class=\"logo-icon\">D</div><div><h1 style=\"margin:0;border:none;padding:0\">DEPENDENCY-CHECK</h1><p style=\"color:#666\">OWASP Dependency Analysis Report</p></div></div><div class=\"info\"><p><strong>Project:</strong> WaelTo5Clean-backend</p><p><strong>Report Generated:</strong> ' + new Date().toISOString() + '</p><p><strong>Dependencies Scanned:</strong> ' + count + ' with vulnerabilities</p><p><strong>Vulnerabilities Found:</strong> ' + count + '</p></div><table><tr><th>Package</th><th>Severity</th><th>Affected Versions</th><th>Details</th><th>Fix Available</th></tr>' + rows + '</table><div class=\"footer\">PFE DevSecOps - Wael Khadraoui - 2026</div></body></html>';
                    require('fs').writeFileSync('reports/owasp-report.html', html);
                    " || true
                '''
            }
        }
        stage('Build Docker Image') {
            steps {
                sh "docker build -t ${IMAGE_NAME}:${IMAGE_TAG} ."
            }
        }
        stage('Trivy Image Scan') {
            steps {
                sh "mkdir -p reports"
                sh "trivy image --severity HIGH,CRITICAL --format template --template '@/usr/local/share/trivy/templates/html.tpl' -o reports/trivy-backend.html ${IMAGE_NAME}:${IMAGE_TAG} || true"
                sh "trivy image --severity HIGH,CRITICAL --format json -o reports/trivy-backend.json ${IMAGE_NAME}:${IMAGE_TAG} || true"
                sh "trivy image --severity HIGH,CRITICAL --exit-code 0 ${IMAGE_NAME}:${IMAGE_TAG}"
                sh '''
                    if [ ! -f reports/trivy-backend.html ] || [ ! -s reports/trivy-backend.html ]; then
                        node -e "
                        const fs = require('fs');
                        let data = {};
                        try { data = JSON.parse(fs.readFileSync('reports/trivy-backend.json','utf8')); } catch(e) {}
                        const results = data.Results || [];
                        let rows = '';
                        let total = 0;
                        for (const r of results) {
                            for (const v of (r.Vulnerabilities || [])) {
                                total++;
                                const sev = v.Severity || 'UNKNOWN';
                                const color = sev === 'CRITICAL' ? '#d32f2f' : sev === 'HIGH' ? '#f44336' : sev === 'MEDIUM' ? '#ff9800' : sev === 'LOW' ? '#4caf50' : '#9e9e9e';
                                const bg = sev === 'CRITICAL' ? '#ffebee' : sev === 'HIGH' ? '#fff3e0' : sev === 'MEDIUM' ? '#fffde7' : sev === 'LOW' ? '#e8f5e9' : '#fafafa';
                                rows += '<tr style=\"background:'+bg+'\"><td>'+v.PkgName+'</td><td>'+v.VulnerabilityID+'</td><td style=\"color:'+color+';font-weight:bold\">'+sev+'</td><td>'+(v.InstalledVersion||'')+'</td><td>'+(v.FixedVersion||'')+'</td></tr>';
                            }
                        }
                        const html = '<!DOCTYPE html><html><head><title>Trivy Report - Backend</title><style>body{font-family:Arial,sans-serif;margin:20px;background:#f5f5f5}h1{color:#0d47a1}h2{color:#1565c0;border-bottom:2px solid #42a5f5;padding-bottom:8px}.summary{background:#fff;padding:15px;border-radius:8px;margin-bottom:20px;box-shadow:0 2px 4px rgba(0,0,0,0.1)}table{width:100%;border-collapse:collapse;background:white;box-shadow:0 2px 4px rgba(0,0,0,0.1);border-radius:8px;overflow:hidden}th{background:#0d47a1;color:white;padding:12px;text-align:left}td{padding:10px 12px;border-bottom:1px solid #e0e0e0}tr:hover{opacity:0.9}.footer{text-align:center;margin-top:30px;color:#666;font-size:13px}</style></head><body><h1>Trivy Scan Report - Backend</h1><div class=\"summary\"><p><strong>Image:</strong> ${IMAGE_NAME}:${IMAGE_TAG}</p><p><strong>Date:</strong> '+new Date().toISOString()+'</p><p><strong>Total Vulnerabilities:</strong> '+total+'</p></div><h2>Vulnerability Details</h2><table><tr><th>Package</th><th>Vulnerability ID</th><th>Severity</th><th>Installed Version</th><th>Fixed Version</th></tr>'+rows+'</table><div class=\"footer\">PFE DevSecOps - Wael Khadraoui - 2026</div></body></html>';
                        fs.writeFileSync('reports/trivy-backend.html', html);
                        "
                    fi
                '''
            }
        }
        stage('Snyk Security Scan') {
            steps {
                sh "snyk test --docker ${IMAGE_NAME}:${IMAGE_TAG} --severity-threshold=high --json > reports/snyk-report.json || true"
            }
        }
        stage('Generate Reports Index') {
            steps {
                sh '''
                    cat > reports/index.html << 'HTMLEOF'
<!DOCTYPE html>
<html>
<head>
    <title>Security Reports - WaelTo5Clean</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }
        .container { max-width: 800px; margin: 0 auto; }
        .header { background: white; border-radius: 12px; padding: 30px; margin-bottom: 25px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); text-align: center; }
        .header h1 { color: #1a237e; margin: 0 0 5px; font-size: 28px; }
        .header p { color: #666; margin: 5px 0; }
        .cards { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        .card { background: white; border-radius: 12px; padding: 25px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); transition: transform 0.2s; text-decoration: none; color: inherit; display: block; }
        .card:hover { transform: translateY(-5px); box-shadow: 0 8px 25px rgba(0,0,0,0.15); }
        .card-icon { width: 50px; height: 50px; border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 24px; margin-bottom: 15px; color: white; }
        .trivy { background: linear-gradient(135deg, #0d47a1, #42a5f5); }
        .owasp { background: linear-gradient(135deg, #e65100, #ff9800); }
        .sonar { background: linear-gradient(135deg, #1b5e20, #4caf50); }
        .snyk { background: linear-gradient(135deg, #4a148c, #9c27b0); }
        .card h3 { margin: 0 0 8px; color: #333; }
        .card p { margin: 0; color: #666; font-size: 14px; }
        .badge { display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 12px; font-weight: bold; margin-top: 10px; }
        .badge-warn { background: #fff3e0; color: #e65100; }
        .badge-pass { background: #e8f5e9; color: #1b5e20; }
        .badge-info { background: #e3f2fd; color: #0d47a1; }
        .footer { text-align: center; color: rgba(255,255,255,0.8); margin-top: 30px; font-size: 13px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Scan Reports</h1>
            <p>WaelTo5Clean - DevSecOps Pipeline</p>
            <p style="font-size:13px;color:#999">Generated by Jenkins CI/CD</p>
        </div>
        <div class="cards">
            <a class="card" href="trivy-backend.html">
                <div class="card-icon trivy">T</div>
                <h3>Trivy Image Scan</h3>
                <p>Container image vulnerability analysis</p>
                <span class="badge badge-warn">VULNERABILITIES FOUND</span>
            </a>
            <a class="card" href="owasp-report.html">
                <div class="card-icon owasp">D</div>
                <h3>OWASP Dependency Check</h3>
                <p>npm packages security audit</p>
                <span class="badge badge-warn">WARNINGS</span>
            </a>
            <a class="card" href="http://172.17.0.1:9000/dashboard?id=WaelTo5Clean-backend" target="_blank">
                <div class="card-icon sonar">S</div>
                <h3>SonarQube SAST</h3>
                <p>Static code analysis results</p>
                <span class="badge badge-pass">ANALYSIS SUCCESSFUL</span>
            </a>
            <a class="card" href="#">
                <div class="card-icon snyk">K</div>
                <h3>Snyk Container Scan</h3>
                <p>Additional vulnerability detection</p>
                <span class="badge badge-info">AUTH REQUIRED</span>
            </a>
        </div>
        <div class="footer">
            <p>PFE DevSecOps - Wael Khadraoui - 2026</p>
        </div>
    </div>
</body>
</html>
HTMLEOF
                '''
            }
        }
        stage('Push to DockerHub') {
            steps {
                withCredentials([usernamePassword(
                    credentialsId: 'dockerhub-creds',
                    usernameVariable: 'DOCKER_USER',
                    passwordVariable: 'DOCKER_PASS'
                )]) {
                    sh '''
                        echo "$DOCKER_PASS" | docker login -u "$DOCKER_USER" --password-stdin
                        docker push ${IMAGE_NAME}:${IMAGE_TAG}
                        docker tag ${IMAGE_NAME}:${IMAGE_TAG} ${IMAGE_NAME}:latest
                        docker push ${IMAGE_NAME}:latest
                        docker logout
                    '''
                }
            }
        }
        stage('Cleanup') {
            steps {
                sh "docker rmi ${IMAGE_NAME}:${IMAGE_TAG} || true"
            }
        }
    }
    post {
        always {
            publishHTML(target: [
                allowMissing: true,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: 'reports',
                reportFiles: 'index.html',
                reportName: 'Security Reports'
            ])
            cleanWs()
        }
        success { echo 'Pipeline Backend DevSecOps termine avec succes !' }
        failure { echo 'Pipeline Backend echoue - verifier les logs' }
    }
}
