pipeline {
    agent {
        docker {
            image 'registry.access.redhat.com/ubi8/ubi:latest' // Use a Red Hat Universal Base Image
            args '-v /var/run/docker.sock:/var/run/docker.sock' // Optional: Mount Docker socket if needed
        }
    }

    environment {
        RPM_BUILD_ROOT = "/build/rpmbuild" // Define RPM build root within the container
        SPEC_FILE = "Nokia-VM-HealthMonitoring.spec" // Name of the spec file
    }

    stages {
        stage('Preparation') {
            steps {
                script {
                    // Create necessary directories for RPM build
                    sh 'mkdir -p ${RPM_BUILD_ROOT}/BUILD ${RPM_BUILD_ROOT}/RPMS ${RPM_BUILD_ROOT}/SOURCES ${RPM_BUILD_ROOT}/SPECS ${RPM_BUILD_ROOT}/SRPMS'
                }
            }
        }

        stage('Package Source') {
            steps {
                script {
                    // Create a tarball of the source code for the RPM
                    sh "tar -czf ${RPM_BUILD_ROOT}/SOURCES/${SPEC_FILE}.tar.gz -C Nokia-VM-HealthMonitoring ."
                }
            }
        }

        stage('Build RPM') {
            steps {
                script {
                    // Copy the spec file to the SPECS directory
                    sh "cp Nokia-VM-HealthMonitoring/${SPEC_FILE} ${RPM_BUILD_ROOT}/SPECS/"

                    // Install rpm-build in the Red Hat container
                    sh "yum install -y rpm-build"

                    // Build the RPM package using rpmbuild
                    sh """
                    rpmbuild -ba ${RPM_BUILD_ROOT}/SPECS/${SPEC_FILE} --define '_topdir ${RPM_BUILD_ROOT}'
                    """
                }
            }
        }

        stage('Archive RPM') {
            steps {
                script {
                    // Archive the generated RPM files
                    archiveArtifacts artifacts: "${RPM_BUILD_ROOT}/RPMS/*/*.rpm", fingerprint: true
                }
            }
        }
    }

    post {
        success {
            echo 'RPM built successfully!'
        }
        failure {
            echo 'RPM build failed.'
        }
    }
}
