plugins {
    kotlin("jvm") version "2.4.20"
    kotlin("plugin.serialization") version "2.4.20"
    application
}

group = "com.elevenid.marty"
version = "1.0.0"

repositories {
    mavenCentral()
    // Multipaz's JVM key-attestation implementation is published by Android.
    // Keep this additional repository scoped to that group and its annotations.
    google {
        mavenContent {
            includeGroup("com.android.keyattestation")
            includeGroup("androidx.annotation")
        }
    }
    maven { url = uri("https://repo.danubetech.com/repository/maven-public/") }
    maven { url = uri("https://jitpack.io") }
}

dependencyLocking {
    lockAllConfigurations()
}

dependencies {
    // EUDI Wallet Kit — OID4VCI (wallet role)
    implementation("eu.europa.ec.eudi:eudi-lib-jvm-openid4vci-kt:0.16.0")
    // EUDI Wallet Kit — OID4VP (wallet role)
    implementation("eu.europa.ec.eudi:eudi-lib-jvm-openid4vp-kt:0.17.0")
    // EUDI SD-JWT (for decoding issued credentials)
    implementation("eu.europa.ec.eudi:eudi-lib-jvm-sdjwt-kt:0.21.0")
    implementation("org.multipaz:multipaz-jvm:0.102.0")

    // Ktor server — exposes HTTP API for test orchestration
    implementation("io.ktor:ktor-server-core:3.6.0")
    implementation("io.ktor:ktor-server-netty:3.6.0")
    implementation("io.ktor:ktor-server-content-negotiation:3.6.0")
    implementation("io.ktor:ktor-serialization-kotlinx-json:3.6.0")
    implementation("io.ktor:ktor-server-status-pages:3.6.0")

    // Ktor client — used by EUDI libs for HTTP
    implementation("io.ktor:ktor-client-java:3.6.0")
    implementation("io.ktor:ktor-client-content-negotiation:3.6.0")
    implementation("io.ktor:ktor-client-logging:3.6.0")

    // Nimbus JOSE+JWT (transitive, but explicit for crypto operations)
    implementation("com.nimbusds:nimbus-jose-jwt:10.9")
    // Bouncy Castle for X509 certificate support
    implementation("org.bouncycastle:bcpkix-jdk18on:1.83")

    // Kotlinx serialization
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.11.0")

    // SLF4J logging
    implementation("ch.qos.logback:logback-classic:1.5.15")

    testImplementation(kotlin("test"))
}

application {
    mainClass.set("com.elevenid.marty.wallet.MainKt")
}

kotlin {
    jvmToolchain(21)
}

tasks.jar {
    manifest {
        attributes["Main-Class"] = "com.elevenid.marty.wallet.MainKt"
    }
}

// Fat JAR for Docker
tasks.register<Jar>("fatJar") {
    group = "build"
    archiveClassifier.set("all")
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    manifest {
        attributes["Main-Class"] = "com.elevenid.marty.wallet.MainKt"
    }
    dependsOn(tasks.named("classes"))
    from(sourceSets.main.get().output)
    dependsOn(configurations.runtimeClasspath)
    from({
        configurations.runtimeClasspath.get().filter { it.name.endsWith("jar") }.map { zipTree(it) }
    })
}
