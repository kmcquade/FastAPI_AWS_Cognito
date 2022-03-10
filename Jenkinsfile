pipeline {
    agent any

    environment {
        BRANCH_NAME = "${GIT_BRANCH}"
        BUILD_NUMBER = "${BUILD_NUMBER}"
        DEFAULT_TAG = "${BRANCH_NAME}_${BUILD_NUMBER}"
    }

    stages {
        stage('Tag build') {
            steps {
                echo "Tagging ${DEFAULT_TAG}"
                sh '''
                git config user.email jenkins@bar.local
                git config --replace-all user.name 'Jenkins'
                git tag -a ${BRANCH_NAME}_${BUILD_NUMBER} -m 'Jenkins build ${BUILD_NUMBER} on branch ${BRANCH_NAME}'
                '''

                sshagent(["Bitbucket"]) {
                    echo "Pushing tags"
                    sh "git push origin ${DEFAULT_TAG}"
                }
                sh '''
                sed -i "s/_LOCAL_/${BUILD_NUMBER}/g" AWSLoginHandler/version.py
                python3 setup.py sdist
                mv dist/*.tar.gz /var/pypi/OAuth
                '''
            }
            post {
                failure {
                    sh "exit 1"
                }
            }
        }

//         stage('Check unit tests') { // No current unit tests :)
//             steps {
//                 sh 'docker run --rm --entrypoint cat ${DOCKER_TAG_THIS} results.xml > results.xml'
//                 junit "results.xml"
//             }
//         }

        stage('Build and push python package') {
            when {
                allOf {
                    branch "master"
                    expression{currentBuild.currentResult == 'SUCCESS'}
                }
            }
            steps {
                sh '''
                sed -i "s/_LOCAL_/${BUILD_NUMBER}/g" AWSLoginHandler/version.py
                python3 setup.py sdist
                mv dist/*.tar.gz /var/pypi/AWSLoginHandler
                '''
            }
        }
    }
}