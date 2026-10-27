plugins {
  id("com.android.application")
  id("org.jetbrains.kotlin.android")
}
android {
  namespace = "io.betternet.next"
  compileSdk = 36
  defaultConfig {
    applicationId = "io.betternet.next"
    minSdk = 26
    targetSdk = 36
    versionCode = 1
    versionName = "0.1.0-dev"
  }
  compileOptions {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
  }
  kotlinOptions { jvmTarget = "17" }
}
dependencies { testImplementation("junit:junit:4.13.2") }
