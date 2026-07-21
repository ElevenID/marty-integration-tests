plugins {
    kotlin("jvm") version "2.0.21"
    kotlin("plugin.serialization") version "2.0.21"
    application
}

group = "com.elevenid.marty"
version = "1.0.0"

repositories {
    mavenCentral()
    maven { url = uri("https://repo.danubetech.com/repository/maven-public/") }
    maven { url = uri("https://jitpack.io") }
}

dependencyLocking {
    lockAllConfigurations()
}

dependencies {
    // EUDI Wallet Kit — OID4VCI (wallet role)
    implementation("eu.europa.ec.eudi:eudi-lib-jvm-openid4vci-kt:0.9.1")
    // EUDI Wallet Kit — OID4VP (wallet role)
    implementation("eu.europa.ec.eudi:eudi-lib-jvm-openid4vp-kt:0.12.3")
    // EUDI SD-JWT (for decoding issued credentials)
    implementation("eu.europa.ec.eudi:eudi-lib-jvm-sdjwt-kt:0.18.0")

    // Ktor server — exposes HTTP API for test orchestration
    implementation("io.ktor:ktor-server-core:3.0.3")
    implementation("io.ktor:ktor-server-netty:3.0.3")
    implementation("io.ktor:ktor-server-content-negotiation:3.0.3")
    implementation("io.ktor:ktor-serialization-kotlinx-json:3.0.3")
    implementation("io.ktor:ktor-server-status-pages:3.0.3")

    // Ktor client — used by EUDI libs for HTTP
    implementation("io.ktor:ktor-client-java:3.0.3")
    implementation("io.ktor:ktor-client-content-negotiation:3.0.3")
    implementation("io.ktor:ktor-client-logging:3.0.3")

    // Nimbus JOSE+JWT (transitive, but explicit for crypto operations)
    implementation("com.nimbusds:nimbus-jose-jwt:10.0.2")
    // Bouncy Castle for X509 certificate support
    implementation("org.bouncycastle:bcpkix-jdk18on:1.79")

    // Kotlinx serialization
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")

    // SLF4J logging
    implementation("ch.qos.logback:logback-classic:1.5.15")
}

application {
    mainClass.set("com.elevenid.marty.wallet.MainKt")
}

kotlin {
    jvmToolchain(17)
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
