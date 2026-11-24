// AGP 9.4 no longer brings Netty into the tested Gradle dependency graph.
// Do not reintroduce unrelated direct buildscript constraints just to mask
// old plugin transitive versions in GitHub's dependency graph.
plugins {
  id("com.android.application") version "9.5.1" apply false
}
