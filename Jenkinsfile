// Load the common Pipeline utilities library
// Library code is at https://stash.simplivt.local/projects/OBI/repos/jenkins-pipeline-utils-library/browse
@Library('jenkins-pipeline-utils')
// This is a special syntax, not a mistake! The '_' is an anchor for the
// @Library annotation. Groovy requires that this annotation is applied
// on an import statement or similar and the '_' is a special no-op.
_ // <-- LEAVE THIS LINE IN PLACE!

// Load this build branch properties
def props = readTrustedProperties('branch.properties')

// Setup environment for this build
def gitBranch = computeGitBranch(props)
def buildType = computeBuildType(props)
def linuxSlaveLabel = props['linuxSlaveLabel'] ?: 'linux_x64'
def windowsSlaveLabel = props['windowsSlaveLabel'] ?: 'windows_x64'
def cloverEnabled = Boolean.parseBoolean(props['cloverEnabled'] ?: 'false')
def dockerImage = props['dockerImage']
def dockerArgs = props['dockerArgs']

// Using env to avoid propagating this through many layers of calls
env.artifactoryRepoKey = env.CUSTOM_REPO_KEY ?: props['artifactoryRepoKey'] ?: 'ext-release-local'
env.artifactoryServerId = env.ARTIFACTORY_SERVER_ID ?: 'artifactory-production-id'
env.skipTagging = env.SKIP_TAGGING ?: props['skipTagging'] ?: 'false'
env.skipBuildForTesting = env.SKIP_BUILD_FOR_TESTING ?: props['skipBuildForTesting'] ?: 'false'
env.stashPrefix = "stashed-" + env.BUILD_TAG.replace('%2f', '-').replace('%2F', '-')

customNode(linuxSlaveLabel, 'Linux') {

    def gradleSwitches = """
            -Pbuild.type=$buildType
    """
    // Add artifactory_password to support use cases where the operation in Gradle
    // uses the artifactory_user/artifactory_password tuple for authentication
    // outside of the typical Gradle artifactoryPublish context.
    withCredentials([string(credentialsId: 'API_KEY', variable: 'artifactory_password')]) {
        gradleSwitches += """
            -Partifactory_password=${artifactory_password}
        """
    }

    def mandatoryCiTasks = ':printVersion :writeSvtVersion :buildEnvironment :buildDashboard htmlDependencyReport build artifactoryPublish'

    try {
        // This helps preserve the Version-Align features which dictate the branch to build
        // via an external input instead of the branch of the default job selection.
        def branchSelector = env.GIT_SINGLE_BRANCH_SELECTOR ?: ''

        stage("Checkout sources for the Linux build") {
            checkoutGitScmWithOptions(scm, branchSelector)
            // This signals build in progress for the HEAD commit
            svtNotifyBitbucket()
        }

        def buildInfo = Artifactory.newBuildInfo()
        def rtGradle = configureGradleRuntime(gitBranch)

        // Shared GRADLE_USER_HOME to allow reusing cached artifacts
        def gradleUserHome = customGradleUserHome()

        // Use this outside the Docker container builds when merging the descriptors
        def linuxSwitches = """
            --gradle-user-home ${gradleUserHome}
            -Pbuild.platform=linux_x64
        """ + gradleSwitches

        def tagVersion = "Unknown"

        def linuxInfoRef = new Reference(buildInfo)
        def windowsInfoRef = new Reference(Artifactory.newBuildInfo())
        def jobsMap = [
            failFast:   false,
            linux:      makeLinuxStep(dockerArgs, dockerImage, gitBranch, rtGradle, linuxSwitches, mandatoryCiTasks, gradleUserHome, linuxInfoRef),
            windows:    makeWindowsStep(gitBranch, branchSelector, windowsSlaveLabel, gradleSwitches, mandatoryCiTasks, pwd(), windowsInfoRef)
        ]

        // Execute the builds now and wait for them
        parallel jobsMap

        // Read the version tag as created by the linux build
        tagVersion = readSvtVersion()
        echo "Built version: $tagVersion"

        if (!isPullRequest()) {
            stage("Publish All build Artifacts and Ivy Descriptors") {
                // We need to make a parallel directory structure from buildDir
                // matching the linux structure but using the Windows layout.
                // This will make it possible to correctly archive each parallel
                // build result as a separate entity viewable in the results page.
                dir('windowsIvy/lin') {
                    unstash "${stashPrefix}-ivyDescriptors"
                }
                linuxSwitches += '''
                    -PivyDescriptorRoot=windowsIvy
                '''

                // Unstash the build artifacts stashed by the stashDeployableArtifacts
                // step in the Windows build leg which will make the following process
                // have them to make it possible to deploy atomically from Linux
                unstash "${stashPrefix}-artifacts"

                // Run Gradle but do not collect new build info for it, just run the quick mergeIvyDescriptors task
                buildLinuxWithDocker(dockerArgs, dockerImage, gitBranch, rtGradle, linuxSwitches, 'mergeIvyDescriptors', gradleUserHome, new Reference(Artifactory.newBuildInfo()))

                buildInfo = linuxInfoRef.get()
                recomputeIvyDescriptorHashes(buildInfo)
                // Merge the buildInfo from the two builds
                buildInfo.append(windowsInfoRef.get())

                rtGradle.deployer.deployArtifacts buildInfo

                def artifactoryServer = Artifactory.server artifactoryServerId
                artifactoryServer.publishBuildInfo buildInfo
            }

            stage("Tag Git repository for new version") {
                if (skipTagging.toBoolean()) {
                    echo "skipTagging is set so we are not performing this step"
                } else {
                    postBuildTagging(scm, tagVersion, [ 'omni3p' ])
                }
            }
        }

        if (currentBuild.result == null) {
            currentBuild.result = 'SUCCESS'
        }

        stage("Create build summary") {
            // Report the actual branch that was built
            postBuildSummary(tagVersion, (branchSelector == '') ? gitBranch : branchSelector)
        }
    } catch (err) {
        echo "Aborting because of $err"
        currentBuild.result = 'FAILURE'
        throw err
    } finally {
        svtNotifyBitbucket()
    }
}

// prepare and return a callable closure
def makeLinuxStep(dockerArgs, dockerImage, gitBranch, rtGradle, gradleSwitches, gradleTasks, gradleUserHome, buildInfoRef) {
    return {
        stage('Building Linux') {
            try {
                buildLinuxWithDocker(dockerArgs, dockerImage, gitBranch, rtGradle, gradleSwitches, gradleTasks, gradleUserHome, buildInfoRef)
            } catch (err) {
                echo "Aborting because of $err"
                currentBuild.result = 'FAILURE'
                throw err
            }
        }
    }
}

def buildLinuxWithDocker(dockerArgs, dockerImage, gitBranch, rtGradle, gradleSwitches, gradleTasks, gradleUserHome, buildInfoRef) {
    if (isPullRequest()) {
        gradleSwitches += """
            -PdockerRepositoryPrefix=${jenkins_pr_dockerRepositoryPrefix}
            -PdebianRepo=staging-debian-local
            -PdebianDist=svt-trusty
            -PdebianComp=omnistack
        """
    }
    maybeUseDocker(dockerImage, dockerArgs, gradleUserHome) {
        // Linux builds just run Gradle in this node
        buildInfoRef.set(runGradlew(gitBranch, rtGradle, gradleSwitches, gradleTasks, buildInfoRef.get(), '/lin'))
    }
}

// prepare and return a callable closure
def makeWindowsStep(gitBranch, branchSelector, slaveLabel, gradleSwitches, gradleTasks, linuxWks, buildInfoRef) {
    return {
        customNode(slaveLabel, 'Windows') {
            stage('Building Windows') {
                try {
                    // Checkout the same sources in the new node
                    checkoutGitScmWithOptions(scm, branchSelector)

                    def rtGradle = configureGradleRuntime(gitBranch)

                    // Shared GRADLE_USER_HOME to allow reusing cached artifacts
                    def gradleUserHome = customGradleUserHome()

                    gradleSwitches = """
                        --gradle-user-home ${gradleUserHome}
                        -Pbuild.platform=windows_x64
                        -PdisableModuleDependenciesLock=true
                    """ + gradleSwitches

                    buildInfoRef.set(runGradlew(gitBranch, rtGradle, gradleSwitches, gradleTasks, buildInfoRef.get(), '/win'))
                    if (!isPullRequest()) {
                        dir('buildDir/win') {
                            // Stash the Ivy descriptors to merge with Linux build
                            stash includes: '**/publications/**/ivy.xml', name: "${stashPrefix}-ivyDescriptors"
                        }

                        stashDeployableArtifacts(buildInfoRef.get(), linuxWks, "${stashPrefix}-artifacts")
                    }
                } catch (err) {
                    echo "Aborting because of $err"
                    currentBuild.result = 'FAILURE'
                    throw err
                }
            }
        }
    }
}
