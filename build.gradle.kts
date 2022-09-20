plugins {
    kotlin("multiplatform") version "1.7.20-RC"
}

group = "com.deptagency"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

kotlin {
    val hostOs = System.getProperty("os.name")
    val isMingwX64 = hostOs.startsWith("Windows")
    val nativeTarget = when {
        hostOs == "Mac OS X" -> macosX64("native")
        hostOs == "Linux" -> linuxX64("native")
        isMingwX64 -> mingwX64("native")
        else -> throw GradleException("Host OS is not supported in Kotlin/Native.")
    }

    nativeTarget.apply {
        compilations.getByName("main") {
            cinterops {
                val sockets by creating
            }
        }

        binaries {
            executable {
                entryPoint = "main"
            }
        }
    }

    sourceSets {
        all {
            languageSettings.apply {
                optIn("kotlin.Experimental")
                optIn("kotlinx.cli.ExperimentalCli")
            }
        }

        commonMain {
            dependencies {
                implementation("org.jetbrains.kotlinx:kotlinx-cli:0.3.5")
//                implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.6.4")
            }
        }

        val nativeMain by getting {
//            sourceSets["macosMain"].dependsOn(this)
            dependsOn(sourceSets["commonMain"])
        }
        val nativeTest by getting
    }
}
