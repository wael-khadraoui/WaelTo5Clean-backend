pipeline {
    agent any
    environment {
        DOCKERHUB_USER = 'wael558'
        IMAGE_NAME     = "${DOCKERHUB_USER}/waelto5clean-backend"
        IMAGE_TAG      = "${BUILD_NUMBER}"
    }
    stages {
        stage('Vault - Fetch All Secrets') {
            steps {
                withVault(configuration: [vaultUrl: 'http://172.17.0.1:31200', vaultCredentialId: 'vault-token', engineVersion: 2], vaultSecrets: [
                    [path: 'secret/waelto5clean/sonarqube', secretValues: [
                        [envVar: 'SONAR_URL', vaultKey: 'url'],
                        [envVar: 'SONAR_TOKEN', vaultKey: 'token']
                    ]],
                    [path: 'secret/waelto5clean/dockerhub', secretValues: [
                        [envVar: 'DOCKER_USER', vaultKey: 'username'],
                        [envVar: 'DOCKER_PASS', vaultKey: 'token']
                    ]],
                    [path: 'secret/waelto5clean/github', secretValues: [
                        [envVar: 'GIT_USER', vaultKey: 'username'],
                        [envVar: 'GIT_TOKEN', vaultKey: 'token']
                    ]]
                ]) {
                    sh 'echo "All secrets fetched from Vault successfully"'
                    sh 'echo "SonarQube URL: $SONAR_URL"'
                    sh 'echo "DockerHub User: $DOCKER_USER"'
                    sh 'echo "GitHub User: $GIT_USER"'
                }
            }
        }
        stage('Checkout') {
            steps { git branch: 'main', url: 'https://github.com/wael-khadraoui/WaelTo5Clean-backend.git', credentialsId: 'github-creds' }
        }
        stage('SAST - SonarQube via Vault') {
            steps {
                withVault(configuration: [vaultUrl: 'http://172.17.0.1:31200', vaultCredentialId: 'vault-token', engineVersion: 2], vaultSecrets: [[path: 'secret/waelto5clean/sonarqube', secretValues: [[envVar: 'SONAR_URL', vaultKey: 'url'], [envVar: 'SONAR_TOKEN', vaultKey: 'token']]]]) {
                    sh 'sonar-scanner -Dsonar.projectKey=WaelTo5Clean-backend -Dsonar.projectName=WaelTo5Clean-backend -Dsonar.sources=src -Dsonar.host.url=$SONAR_URL -Dsonar.token=$SONAR_TOKEN'
                }
            }
        }
        stage('OWASP Dependency Check') {
            steps {
                sh 'mkdir -p reports'
                sh 'npm audit --json > reports/npm-audit.json || true'
            }
        }
        stage('Build Docker Image') {
            steps { sh "docker build -t ${IMAGE_NAME}:${IMAGE_TAG} ." }
        }
        stage('Trivy Image Scan') {
            steps {
                sh "trivy image --severity HIGH,CRITICAL --format json -o reports/trivy-backend.json ${IMAGE_NAME}:${IMAGE_TAG} || true"
                sh "trivy image --severity HIGH,CRITICAL --exit-code 0 ${IMAGE_NAME}:${IMAGE_TAG}"
            }
        }
        stage('Snyk Security Scan') {
            steps { sh "snyk test --docker ${IMAGE_NAME}:${IMAGE_TAG} --severity-threshold=high || true" }
        }
        stage('Push to DockerHub via Vault') {
            steps {
                withVault(configuration: [vaultUrl: 'http://172.17.0.1:31200', vaultCredentialId: 'vault-token', engineVersion: 2], vaultSecrets: [[path: 'secret/waelto5clean/dockerhub', secretValues: [[envVar: 'DOCKER_USER', vaultKey: 'username'], [envVar: 'DOCKER_PASS', vaultKey: 'token']]]]) {
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
        always { cleanWs() }
        success { echo 'Pipeline DevSecOps avec Vault - TOUS les secrets centralises !' }
        failure { echo 'Pipeline echoue - verifier les logs' }
    }
}
