// Declarative Jenkins pipeline for the same suite. Not exercised by this repo's own CI.
pipeline {
  agent any
  triggers { cron('H 13 * * *') }
  stages {
    stage('fhircheck') {
      steps {
        script {
          if (isUnix()) { sh 'bash run.sh --perf-n 20' } else { powershell './run.ps1 -PerfN 20' }
        }
      }
    }
  }
  post { always { archiveArtifacts artifacts: 'results/**', allowEmptyArchive: true } }
}
