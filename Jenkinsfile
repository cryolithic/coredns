pipeline {
  agent { label 'mfw' }

  stages {
    stage('Build') {
      agent { label 'mfw' }
      steps {
        sh "hostname"
        sh "docker pull golang:1.12"
        sh "docker pull golang:1.12"
        sh "docker-compose -f docker-compose.build.yml -p coredns_build run build"
      }

      post {
        success { 
          archiveArtifacts artifacts: "coredns", fingerprint: true
        }
      }
    }

    stage('Test') {
      agent { label 'mfw' }
      steps {
	sh "true" // FIXME
      }

      post {
	changed {
	  script {
	    // set result before pipeline ends, so emailer sees it
	    currentBuild.result = currentBuild.currentResult
          }
          emailext(to:'nfgw-engineering@untangle.com', subject:"${env.JOB_NAME} #${env.BUILD_NUMBER}: ${currentBuild.result}", body:"${env.BUILD_URL}")
          slackSend(channel:"#engineering", message:"${env.JOB_NAME} #${env.BUILD_NUMBER}: ${currentBuild.result} at ${env.BUILD_URL}")
	}
      }
    }
  }
}
