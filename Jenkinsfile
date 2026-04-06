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
                git branch: 'main', url: 'https://github.com/wael-khadraoui/WaelTo5Clean-backend.git', credentialsId: 'github-creds'
            }
        }
        stage('SAST - SonarQube') {
            steps {
                withCredentials([string(credentialsId: 'sonarqube-token', variable: 'SONAR_TOKEN')]) {
                    sh """sonar-scanner -Dsonar.projectKey=WaelTo5Clean-backend -Dsonar.projectName=WaelTo5Clean-backend -Dsonar.sources=src -Dsonar.host.url=${SONAR_HOST} -Dsonar.token=${SONAR_TOKEN}"""
                }
            }
        }
        stage('OWASP Dependency Check') {
            steps {
                sh 'mkdir -p reports'
                sh 'npm audit --json > reports/npm-audit.json || true'
                sh 'node scripts/generate-owasp-report.js || true'
            }
        }
        stage('Build Docker Image') {
            steps { sh "docker build -t ${IMAGE_NAME}:${IMAGE_TAG} ." }
        }
        stage('Trivy Image Scan') {
            steps {
                sh "trivy image --severity HIGH,CRITICAL --format json -o reports/trivy-backend.json ${IMAGE_NAME}:${IMAGE_TAG} || true"
                sh 'node scripts/generate-trivy-report.js || true'
                sh "trivy image --severity HIGH,CRITICAL --exit-code 0 ${IMAGE_NAME}:${IMAGE_TAG}"
            }
        }
        stage('Snyk Security Scan') {
            steps { sh "snyk test --docker ${IMAGE_NAME}:${IMAGE_TAG} --severity-threshold=high || true" }
        }
        stage('Generate Reports Index') {
            steps { sh 'cp scripts/index.html reports/index.html' }
        }
        stage('Push to DockerHub') {
            steps {
                withCredentials([usernamePassword(credentialsId: 'dockerhub-creds', usernameVariable: 'DOCKER_USER', passwordVariable: 'DOCKER_PASS')]) {
                    sh 'echo "$DOCKER_PASS" | docker login -u "$DOCKER_USER" --password-stdin'
                    sh "docker push ${IMAGE_NAME}:${IMAGE_TAG}"
                    sh "docker tag ${IMAGE_NAME}:${IMAGE_TAG} ${IMAGE_NAME}:latest"
                    sh "docker push ${IMAGE_NAME}:latest"
                    sh 'docker logout'
                }
            }
        }
        stage('Cleanup') {
            steps { sh "docker rmi ${IMAGE_NAME}:${IMAGE_TAG} || true" }
        }
    }
    post {
        always {
            publishHTML(target: [allowMissing: true, alwaysLinkToLastBuild: true, keepAll: true, reportDir: 'reports', reportFiles: 'index.html', reportName: 'Security Reports'])
            cleanWs()
        }
        success { echo 'Pipeline Backend DevSecOps termine avec succes !' }
        failure { echo 'Pipeline Backend echoue - verifier les logs' }
    }
}
