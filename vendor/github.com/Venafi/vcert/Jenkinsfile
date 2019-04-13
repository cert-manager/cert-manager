#!/usr/bin/env groovy
node("jnode-vcert") {

    String goPath = "/go/src/github.com/Venafi/vcert"

    stage('Checkout') {
        checkout scm
    }

    stage("Build") {
        docker.image("golang:1.9").inside("-v ${pwd()}:${goPath} -u root") {
            sh "cd ${goPath} && make build"
        }
    }

    stage("Run Tests") {
        parallel(
            test: {
                docker.image("golang:1.9").inside("-v ${pwd()}:${goPath} -u root") {
                    sh "cd ${goPath} && go get ./... && make test"
                }
            },
            e2eTPP: {
                docker.image("golang:1.9").inside("-v ${pwd()}:${goPath} -u root") {
                    sh "cd ${goPath} && go get ./... && make tpp_test"
                }
            },
            e2eCloud: {
                docker.image("golang:1.9").inside("-v ${pwd()}:${goPath} -u root") {
                    sh "cd ${goPath} && go get ./... && make cloud_test"
                }
            },
            testCLI: {
                sh "make cucumber"
            }
        )
    }

    stage("Deploy") {
        archiveArtifacts artifacts: 'bin/**/*', fingerprint: true
    }

    stage("Publish") {
        cifsPublisher paramPublish: null, masterNodeName:'', alwaysPublishFromMaster: false,
        continueOnError: false,
        failOnError: false,
        publishers: [[
            configName: 'buildsDev',
            transfers: [[
                cleanRemote: true, excludes: '*/obj/,/node_modules/,/_src/,/_config/,/_sassdocs/',
                flatten: false, makeEmptyDirs: false, noDefaultExcludes: false, patternSeparator: '[, ]+',
                remoteDirectory: env.JOB_NAME, remoteDirectorySDF: false,
                removePrefix: 'bin',
                sourceFiles: 'bin/'
            ]], usePromotionTimestamp: false, useWorkspaceInPromotion: false, verbose: true
        ]]
    }
}
