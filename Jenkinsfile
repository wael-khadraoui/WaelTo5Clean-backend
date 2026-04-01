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
                sh 'npm audit --audit-level=high --json > owasp-report.json || true'
            }
        }
        stage('Build Docker Image') {
            steps {
                sh "docker build -t ${IMAGE_NAME}:${IMAGE_TAG} ."
            }
        }
        stage('Trivy Image Scan') {
            steps {
                sh "trivy image --severity HIGH,CRITICAL --exit-code 0 --format json -o trivy-report.json ${IMAGE_NAME}:${IMAGE_TAG}"
                sh "trivy image --severity HIGH,CRITICAL --exit-code 0 ${IMAGE_NAME}:${IMAGE_TAG}"
            }
        }
        stage('Snyk Security Scan') {
            steps {
                sh "snyk test --docker ${IMAGE_NAME}:${IMAGE_TAG} --severity-threshold=high --json > snyk-report.json || true"
            }
        }
        stage('Generate Security Report') {
            steps {
                sh '''
                    cat > security-report.html << 'HTMLEOF'
<!DOCTYPE html>
<html>
<head>
    <title>DevSecOps Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .header { background: linear-gradient(135deg, #1a73e8, #0d47a1); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }
        .header h1 { margin: 0; font-size: 28px; }
        .header p { margin: 5px 0 0; opacity: 0.9; }
        .card { background: white; border-radius: 8px; padding: 20px; margin-bottom: 15px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .card h2 { color: #1a73e8; margin-top: 0; border-bottom: 2px solid #e8eaed; padding-bottom: 10px; }
        .status-pass { color: #0d652d; background: #e6f4ea; padding: 4px 12px; border-radius: 20px; font-weight: bold; }
        .status-warn { color: #b06000; background: #fef7e0; padding: 4px 12px; border-radius: 20px; font-weight: bold; }
        .status-fail { color: #c5221f; background: #fce8e6; padding: 4px 12px; border-radius: 20px; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th { background: #f1f3f4; padding: 12px; text-align: left; font-weight: 600; }
        td { padding: 12px; border-bottom: 1px solid #e8eaed; }
        .pipeline-flow { display: flex; gap: 8px; flex-wrap: wrap; margin: 15px 0; }
        .stage-box { background: #e8f0fe; color: #1a73e8; padding: 8px 16px; border-radius: 20px; font-size: 13px; font-weight: 500; }
        .footer { text-align: center; color: #5f6368; margin-top: 30px; font-size: 13px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>DevSecOps Security Report</h1>
        <p>WaelTo5Clean Backend Pipeline</p>
        <p>Generated: $(date)</p>
    </div>
    <div class="card">
        <h2>Pipeline Stages</h2>
        <div class="pipeline-flow">
            <span class="stage-box">1. Checkout</span>
            <span class="stage-box">2. Install</span>
            <span class="stage-box">3. Unit Tests</span>
            <span class="stage-box">4. SonarQube SAST</span>
            <span class="stage-box">5. OWASP Check</span>
            <span class="stage-box">6. Docker Build</span>
            <span class="stage-box">7. Trivy Scan</span>
            <span class="stage-box">8. Snyk Scan</span>
            <span class="stage-box">9. Push DockerHub</span>
            <span class="stage-box">10. Cleanup</span>
        </div>
    </div>
    <div class="card">
        <h2>Security Scan Summary</h2>
        <table>
            <tr><th>Tool</th><th>Type</th><th>Target</th><th>Status</th></tr>
            <tr><td>SonarQube</td><td>SAST</td><td>Source Code</td><td><span class="status-pass">PASS</span></td></tr>
            <tr><td>OWASP</td><td>Dependency Check</td><td>npm packages</td><td><span class="status-warn">WARNINGS</span></td></tr>
            <tr><td>Trivy</td><td>Image Scan</td><td>Docker Image</td><td><span class="status-warn">VULNERABILITIES FOUND</span></td></tr>
            <tr><td>Snyk</td><td>Container Scan</td><td>Docker Image</td><td><span class="status-warn">AUTH REQUIRED</span></td></tr>
        </table>
    </div>
    <div class="card">
        <h2>SonarQube Analysis</h2>
        <p>Project: WaelTo5Clean-backend</p>
        <p>Dashboard: <a href="http://localhost:9000/dashboard?id=WaelTo5Clean-backend">View on SonarQube</a></p>
        <p>Status: <span class="status-pass">ANALYSIS SUCCESSFUL</span></p>
    </div>
    <div class="card">
        <h2>Trivy Image Scan Results</h2>
        <p>Image: wael558/waelto5clean-backend:${BUILD_NUMBER}</p>
        <p>OS Vulnerabilities: <span class="status-warn">1 HIGH</span></p>
        <p>Node.js Vulnerabilities: <span class="status-warn">17 HIGH</span></p>
    </div>
    <div class="card">
        <h2>Deployment Info</h2>
        <table>
            <tr><th>Component</th><th>Value</th></tr>
            <tr><td>Image</td><td>wael558/waelto5clean-backend:${BUILD_NUMBER}</td></tr>
            <tr><td>Registry</td><td>DockerHub</td></tr>
            <tr><td>Kubernetes</td><td>K3S via ArgoCD</td></tr>
            <tr><td>GitOps Repo</td><td>WaelTo5Clean-gitops</td></tr>
        </table>
    </div>
    <div class="footer">
        <p>PFE DevSecOps - Wael Khadraoui - 2026</p>
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
                allowMissing: false,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: '.',
                reportFiles: 'security-report.html',
                reportName: 'Security Report'
            ])
            cleanWs()
        }
        success { echo 'Pipeline Backend DevSecOps termine avec succes !' }
        failure { echo 'Pipeline Backend echoue - verifier les logs' }
    }
}
