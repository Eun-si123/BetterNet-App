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
  id("com.android.application") version "9.4.0" apply false
}
