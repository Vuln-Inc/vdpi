import java.io.File

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("org.jetbrains.kotlin.plugin.serialization")
}

fun readWorkspaceVersion(): String {
    val override = providers.gradleProperty("vdpiVersionName").orNull?.trim()
    val stripped = override?.trimStart { it == 'v' || it == 'V' }
    if (!stripped.isNullOrEmpty()) return stripped
    val cargoToml = rootProject.projectDir.parentFile?.resolve("Cargo.toml")
    if (cargoToml != null && cargoToml.isFile) {
        val match = Regex("""(?m)^version\s*=\s*"([^"]+)"""").find(cargoToml.readText())
        if (match != null) return match.groupValues[1]
    }
    return "0.6.1"
}

fun computeVersionCode(semver: String): Int {
    val parts = semver.substringBefore('-').split('.').mapNotNull { it.toIntOrNull() }
    val major = parts.getOrElse(0) { 0 }
    val minor = parts.getOrElse(1) { 0 }
    val patch = parts.getOrElse(2) { 0 }
    return (major * 10000 + minor * 100 + patch).coerceAtLeast(1)
}

val resolvedVersionName = readWorkspaceVersion()
val resolvedVersionCode = computeVersionCode(resolvedVersionName)

val releaseKeystorePath = System.getenv("VDPI_KEYSTORE_PATH")?.takeIf { it.isNotBlank() }
val releaseKeystorePassword = System.getenv("VDPI_KEYSTORE_PASSWORD")?.takeIf { it.isNotBlank() }
val releaseKeyAlias = System.getenv("VDPI_KEY_ALIAS")?.takeIf { it.isNotBlank() }
val releaseKeyPassword = System.getenv("VDPI_KEY_PASSWORD")?.takeIf { it.isNotBlank() }
val hasReleaseSigning = releaseKeystorePath != null &&
    File(releaseKeystorePath).isFile &&
    releaseKeystorePassword != null &&
    releaseKeyAlias != null &&
    releaseKeyPassword != null

android {
    namespace = "com.vulninc.vdpi"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.vulninc.vdpi"
        minSdk = 26
        targetSdk = 35
        versionCode = resolvedVersionCode
        versionName = resolvedVersionName

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }
    }

    signingConfigs {
        if (hasReleaseSigning) {
            create("release") {
                storeFile = File(releaseKeystorePath!!)
                storePassword = releaseKeystorePassword
                keyAlias = releaseKeyAlias
                keyPassword = releaseKeyPassword
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            signingConfig = if (hasReleaseSigning) {
                signingConfigs.getByName("release")
            } else {
                signingConfigs.getByName("debug")
            }
        }
        debug {
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
        jniLibs {
            useLegacyPackaging = false
        }
    }
}

val verifyNativeLibs by tasks.registering {
    val jniDir = file("src/main/jniLibs")
    val requiredAbis = listOf("arm64-v8a", "armeabi-v7a", "x86_64")
    doLast {
        val missing = requiredAbis.filter { abi ->
            !jniDir.resolve("$abi/libvdpi_android.so").isFile
        }
        if (missing.isNotEmpty()) {
            throw GradleException(
                "Missing native Rust JNI libraries for ABIs: ${missing.joinToString(", ")}. " +
                    "Run ./android/scripts/build-native.sh first."
            )
        }
    }
}

tasks.matching { it.name.startsWith("merge") && it.name.endsWith("JniLibFolders") }.configureEach {
    dependsOn(verifyNativeLibs)
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2025.02.00")
    implementation(composeBom)

    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.activity:activity-compose:1.10.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")

    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.animation:animation")
    implementation("androidx.compose.material3:material3")

    implementation("androidx.datastore:datastore-preferences:1.1.2")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.1")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.8.0")

    testImplementation("junit:junit:4.13.2")
    debugImplementation("androidx.compose.ui:ui-tooling")
}
