// vim: et:ts=4:sw=4:ft=groovy
node('docker'){
    catchError {
        def imageName = 'simonswine/kube-lego'
        def imageTags = ['latest']


        stage 'Checkout source code'
        checkout scm
        //git credentialsId: 'fe845ec0-c0f3-4125-823c-b2064751fbea', url: 'git@github.com:/simonswine/kube-lego.git'

        stage 'Test kube-lego'
        sh "make docker_test"
        step([$class: 'JUnitResultArchiver', testResults: '_test/test*.xml'])

        stage 'Build kube-lego'
        sh "make docker_build"

        stage 'Build docker image'
        sh "docker build -t ${imageName}:${imageTags[0]} ."

        stage 'Push docker image'
        withCredentials([[$class: 'FileBinding', credentialsId: '31a54b99-cab6-4a1a-9bd7-4de5e85ca0e6', variable: 'DOCKER_CONFIG']]) {
            try {
                sh 'mkdir -p .dockercfg'
                sh 'ln -s \$DOCKER_CONFIG .dockercfg/config.json'
                sh "docker --config=.dockercfg push ${imageName}:${imageTags[0]}"
            } finally {
                sh 'rm -rf .dockercfg'
            }
        }
    }
    step([$class: 'Mailer', recipients: 'christian@jetstack.io', notifyEveryUnstableBuild: true])
}
