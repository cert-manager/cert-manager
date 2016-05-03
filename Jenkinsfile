// vim: et:ts=4:sw=4:ft=groovy
def jenkinsSlack(type){
    def jobInfo = "\n » ${env.JOB_NAME} ${env.BUILD_NUMBER} (<${env.BUILD_URL}|job>) (<${env.BUILD_URL}/console|console>)"
    if (type == 'start'){
        slackSend color: 'blue', message: "build started${jobInfo}"
    }
    if (type == 'finish'){
        def buildColor = currentBuild.result == null? "good": "warning"
        def buildStatus = currentBuild.result == null? "SUCCESS": currentBuild.result
        slackSend color: buildColor, message: "build finished - ${buildStatus}${jobInfo}"
    }
}

def gitTags(commit) {
    sh("git tag --contains ${commit} > GIT_TAGS")
    def gitTags = readFile('GIT_TAGS').trim()
    sh('rm -f GIT_TAGS')
    if (gitTags == '') {
        return []
    }
    return gitTags.tokenize('\n')
}

def gitCommit() {
    sh('git rev-parse HEAD > GIT_COMMIT')
    def gitCommit = readFile('GIT_COMMIT').trim()
    sh('rm -f GIT_COMMIT')
    return gitCommit
}

def gitMasterBranchCommit() {
    sh('git rev-parse origin/master > GIT_MASTER_COMMIT')
    def gitCommit = readFile('GIT_MASTER_COMMIT').trim()
    sh('rm -f GIT_MASTER_COMMIT')
    return gitCommit
}

def onMasterBranch(){
    return gitCommit() == gitMasterBranchCommit()
}

def imageTags(){
    def gitTags = gitTags(gitCommit())
    if (gitTags == []) {
        return ["canary"]
    } else {
        return gitTags + ["latest"]
    }
}

node('docker'){
    catchError {
        def imageName = 'simonswine/kube-lego'
        def imageTag = 'jenkins-build'

        jenkinsSlack('start')

        stage 'Checkout source code'
        checkout scm

        stage 'Test kube-lego'
        //sh "make docker_test"
        //step([$class: 'JUnitResultArchiver', testResults: '_test/test*.xml'])

        stage 'Build kube-lego'
        sh "make docker_build"

        stage 'Build docker image'
        sh "docker build -t ${imageName}:${imageTag} ."

        if (onMasterBranch()) {
            stage 'Push docker image'


            withCredentials([[$class: 'FileBinding', credentialsId: '31a54b99-cab6-4a1a-9bd7-4de5e85ca0e6', variable: 'DOCKER_CONFIG_FILE']]) {
                try {
                    // prepare docker auth
                    sh 'mkdir -p _temp_dockercfg'
                    sh 'ln -sf \$DOCKER_CONFIG_FILE _temp_dockercfg/config.json'

                    // get tags to push
                    def imageTags = imageTags()
                    echo "tags to push '${imageTags}'"

                    def desc = []
                    for (i = 0; i < imageTags.size(); i++) {
                        def repoNameTag = "${imageName}:${imageTags[i]}"
                        echo "Push and tag ${repoNameTag}"
                        sh "docker tag ${imageName}:${imageTag} ${repoNameTag}"
                        sh "docker --config=_temp_dockercfg push ${repoNameTag}"
                        desc << "${repoNameTag}"
                    }

                    currentBuild.description = desc.join("\n") + "\ngit_commit=${gitCommit().take(8)}"
                } finally {
                    sh 'rm -rf _temp_dockercfg'
                }
            }
        }
    }
    jenkinsSlack('finish')
    step([$class: 'Mailer', recipients: 'christian@jetstack.io', notifyEveryUnstableBuild: true])
}
