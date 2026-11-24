// Resolve Netty patch releases on the *Gradle build plugin* classpath only.
// Android Gradle Plugin 8.13.2 pulls Netty 4.1.110.Final through grpc-netty,
// which has several high/critical published security advisories.
// Do not globally force app runtime dependencies or override AGP's plugin version.
// The BOM-equivalent constraints keep the 11 observed Netty modules aligned.
buildscript {
  repositories {
    google()
    mavenCentral()
    gradlePluginPortal()
  }
  dependencies {
    constraints {
      // Build tools only: resolve known-vulnerable AGP 8.13.2 transitives.
      // Keep the BC Java modules in sync for provider/ASN.1 compatibility.
      classpath("org.bouncycastle:bcprov-jdk18on:1.86")
      classpath("org.bouncycastle:bcpkix-jdk18on:1.86")
      classpath("org.bouncycastle:bcutil-jdk18on:1.86")
      classpath("org.bitbucket.b_c:jose4j:0.9.6")
      classpath("org.jdom:jdom2:2.0.6.1")
      classpath("org.apache.commons:commons-compress:1.26.0")
      classpath("com.google.guava:guava:33.7.2-jre")
      classpath("io.netty:netty-buffer:4.1.137.Final")
      classpath("io.netty:netty-codec:4.1.137.Final")
      classpath("io.netty:netty-codec-http:4.1.137.Final")
      classpath("io.netty:netty-codec-http2:4.1.137.Final")
      classpath("io.netty:netty-codec-socks:4.1.137.Final")
      classpath("io.netty:netty-common:4.1.137.Final")
      classpath("io.netty:netty-handler:4.1.137.Final")
      classpath("io.netty:netty-handler-proxy:4.1.137.Final")
      classpath("io.netty:netty-resolver:4.1.137.Final")
      classpath("io.netty:netty-transport:4.1.137.Final")
      classpath("io.netty:netty-transport-native-unix-common:4.1.137.Final")
    }
  }
}

plugins {
  id("com.android.application") version "8.13.2" apply false
  id("org.jetbrains.kotlin.android") version "2.2.21" apply false
}
