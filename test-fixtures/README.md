# Raeva Test Fixtures

This directory contains real-world Maven pom.xml files from popular open source projects,
organized by the features they test.

## Directory Structure

```
test-fixtures/
├── simple-single-module/    # Simple single-module projects
├── multi-module/            # Multi-module projects with parent POMs
├── dependency-types/        # Projects with various dependency scopes
├── bom-usage/               # Projects using Bill of Materials (BOMs)
├── profile-based/           # Projects with profile-based dependencies
├── spring-ecosystem/        # Spring Framework, Spring Security, Spring Data projects
├── apache-projects/         # Apache Maven, HttpClient, Commons projects
├── popular-libs/            # Slf4j, Logback, Hibernate, JUnit5, Mockito
└── complex-deps/            # Projects with complex dependency graphs (Hadoop, Spark, etc.)
```

---

## 1. Simple Single-Module Projects

These are standalone projects without parent POMs (or with simple parents), good for testing basic parsing.

### commons-lang3-pom.xml
- **Source**: Apache Commons Lang
- **Features tested**:
  - Parent POM inheritance (`org.apache.commons:commons-parent`)
  - Test-scoped dependencies (JUnit Jupiter, EasyMock)
  - Property-based version management (`${commons.text.version}`, `${commons.jmh.version}`)
  - Multiple profiles (java8, java9+, benchmark, java-25-up)
  - SCM, CI, and issue management configuration

### commons-io-pom.xml
- **Source**: Apache Commons IO
- **Features tested**:
  - Parent POM inheritance
  - Module name configuration (`org.apache.commons.io`)
  - Test-scoped dependencies (JUnit Jupiter, Mockito, ByteBuddy, JiMFS)
  - Distribution management configuration

### commons-collections-pom.xml
- **Source**: Apache Commons Collections
- **Features tested**:
  - Full Apache Commons POM structure
  - Build plugins configuration
  - Test dependencies with exclusions

### javapoet-pom.xml
- **Source**: Square JavaPoet
- **Features tested**:
  - Simple standalone project structure
  - Minimal dependencies

### jsoup-pom.xml
- **Source**: jsoup HTML Parser
- **Features tested**:
  - Standalone project (no parent)
  - Multi-release JAR configuration
  - Animal Sniffer plugin for API compatibility checking
  - Multiple compiler executions (Java 8, 9, 11 versions)
  - Profile-based build configuration

### lombok-pom.xml
- **Source**: Project Lombok (from Maven Central)
- **Features tested**:
  - Published POM format (from Maven Central)
  - Minimal dependencies declaration

### assertj-core-pom.xml
- **Source**: AssertJ Core
- **Features tested**:
  - Parent reference to internal parent
  - Module configuration
  - Test dependencies

---

## 2. Multi-Module Projects

These test parent-child POM relationships and module aggregation.

### guava-parent-pom.xml + guava-module-pom.xml
- **Source**: Google Guava
- **Features tested**:
  - Parent POM with modules declaration (`guava`, `guava-bom`, `guava-gwt`, `guava-testlib`, `guava-tests`)
  - Non-standard source directories (`src`, `test` instead of `src/main/java`, `src/test/java`)
  - `dependencyManagement` section
  - Extensive property definitions
  - Build toolchain configuration
  - Module POM inheriting from parent

### gson-parent-pom.xml + gson-module-pom.xml
- **Source**: Google Gson
- **Features tested**:
  - Multi-module structure (7 modules: gson, test-jpms, test-graal-native-image, test-shrinker, extras, metrics, proto)
  - Reproducible builds configuration (`project.build.outputTimestamp`)
  - Custom properties for module-specific behavior
  - Error Prone integration
  - Module POM with parent reference using `<version>` tag

---

## 3. Dependency Types

These test various dependency scope configurations.

### jackson-databind-pom.xml
- **Source**: Jackson Databind
- **Features tested**:
  - Parent POM reference (`jackson-base`)
  - Multiple dependency scopes (compile, test, provided)
  - BOM import usage
  - OSGi bundle configuration

### maven-shade-plugin-pom.xml
- **Source**: Apache Maven Shade Plugin
- **Features tested**:
  - Maven plugin packaging (`maven-plugin`)
  - `provided` scope dependencies (Maven API, plugin annotations)
  - Plugin dependencies (ASM, Plexus)
  - `test` scope dependencies
  - Prerequisites declaration

### maven-compiler-plugin-pom.xml
- **Source**: Apache Maven Compiler Plugin
- **Features tested**:
  - Maven plugin structure
  - Provided scope for Maven APIs
  - Test dependencies

### maven-resources-plugin-pom.xml
- **Source**: Apache Maven Resources Plugin
- **Features tested**:
  - Maven plugin structure
  - Filtering and resource processing

### maven-war-plugin-pom.xml
- **Source**: Apache Maven WAR Plugin
- **Features tested**:
  - WAR packaging plugin
  - Plugin dependencies

---

## 4. BOM Usage (Bill of Materials)

These test `dependencyManagement` sections and BOM patterns.

### spring-boot-dependencies-pom.xml
- **Source**: Spring Boot Dependencies BOM (version 3.3.0 from Maven Central)
- **Features tested**:
  - Extensive `dependencyManagement` section covering the Spring Boot stack
  - Version properties for all major Java libraries
  - Plugin version management
  - No actual dependencies (pure BOM)
  - Real-world industry standard BOM

### jackson-bom-pom.xml
- **Source**: Jackson BOM
- **Features tested**:
  - BOM with parent POM (`jackson-parent`)
  - Module declaration (`base`)
  - Property-based version management for Jackson ecosystem
  - Grouped dependencies (Core, Data Formats, Data Types, JAX-RS, Jakarta RS, Jackson Jr, Modules)
  - Reproducible builds timestamp

### junit-bom-pom.xml
- **Source**: JUnit BOM (version 5.10.2 from Maven Central)
- **Features tested**:
  - Testing framework BOM
  - Manages JUnit Jupiter, JUnit Platform, JUnit Vintage versions

### guava-bom-pom.xml
- **Source**: Google Guava BOM
- **Features tested**:
  - Simple BOM structure
  - Parent reference
  - Manages guava, guava-testlib, listenablefuture, failureaccess artifacts

### assertj-bom-pom.xml
- **Source**: AssertJ BOM
- **Features tested**:
  - Testing library BOM
  - Manages AssertJ Core and other AssertJ modules

---

## 5. Profile-Based Dependencies

These test profile activation and profile-specific dependencies.

### netty-parent-pom.xml
- **Source**: Netty (version 4.2.x)
- **Features tested**:
  - Many Maven profiles covering platform-specific and JDK-specific configurations
  - Profile activation by file existence (`graal` profile checks for `${java.home}/bin/native-image`)
  - Profile activation by JDK version
  - Profile-specific properties
  - Profile-specific plugin configurations
  - Parent POM inheritance (`oss-parent`)
  - Large multi-module project configuration

### log4j2-parent-pom.xml
- **Source**: Apache Log4j 2
- **Features tested**:
  - Multi-module logging framework
  - Profile-based build configuration
  - Complex plugin configurations

### maven-surefire-pom.xml
- **Source**: Apache Maven Surefire
- **Features tested**:
  - Multi-module test runner
  - Integration test configurations
  - Profile-based testing options

---

## 6. Spring Ecosystem Projects

Real-world Spring Framework projects for testing Spring-specific POM patterns.

### spring-boot-starter-pom.xml
- **Source**: Spring Boot Starter (version 3.3.0 from Maven Central)
- **Features tested**:
  - Starter POM pattern with parent reference
  - Published dependency format
  - Spring Boot parent inheritance

### spring-core-pom.xml
- **Source**: Spring Core (version 6.1.8 from Maven Central)
- **Features tested**:
  - Core Spring Framework module
  - Published POM from Maven Central

### spring-data-commons-pom.xml
- **Source**: Spring Data Commons (GitHub)
- **Features tested**:
  - Spring Data parent inheritance (`spring-data-parent`)
  - Many optional dependencies
  - Kotlin and Scala support
  - Reactive dependencies (Reactor, RxJava, Mutiny)
  - QueryDSL integration
  - Profile-based resource filtering

### spring-data-jpa-pom.xml
- **Source**: Spring Data JPA (GitHub)
- **Features tested**:
  - Spring Data module structure
  - JPA-specific dependencies

### spring-security-core-pom.xml
- **Source**: Spring Security Core (version 6.3.0 from Maven Central)
- **Features tested**:
  - Spring Security module structure
  - Security-specific dependencies

---

## 7. Apache Projects

Further Apache projects, including Maven itself and the HttpComponents client.

### commons-codec-pom.xml
- **Source**: Apache Commons Codec (GitHub)
- **Features tested**:
  - Apache Commons parent inheritance
  - Encoding/decoding library structure

### commons-text-pom.xml
- **Source**: Apache Commons Text (GitHub)
- **Features tested**:
  - Text processing library
  - Commons parent structure

### httpclient5-pom.xml
- **Source**: Apache HttpComponents Client 5 (GitHub)
- **Features tested**:
  - Multi-module HTTP client project
  - `dependencyManagement` with BOM imports (JUnit BOM, OpenTelemetry BOM)
  - Property-based version management (20+ version properties)
  - Extensive plugin configuration (checkstyle, japicmp, rat)
  - Profile for slow tests

### maven-pom.xml
- **Source**: Apache Maven (GitHub, version 4.1.x)
- **Features tested**:
  - Maven itself as a multi-module project
  - 4 modules (api, impl, compat, apache-maven)
  - Extensive property definitions (30+ version properties)
  - Complex build configuration
  - Reproducible builds timestamp

### maven-model-pom.xml
- **Source**: Apache Maven Impl module (GitHub)
- **Features tested**:
  - Maven internal module structure
  - Module POM with parent reference

---

## 8. Popular Libraries

Industry-standard Java libraries for testing common dependency patterns.

### hibernate-core-pom.xml
- **Source**: Hibernate ORM Core (version 6.5.0.Final from Maven Central)
- **Features tested**:
  - Published Hibernate POM format
  - ORM library dependencies

### junit-jupiter-pom.xml
- **Source**: JUnit Jupiter (version 5.10.2 from Maven Central)
- **Features tested**:
  - Testing framework module
  - JUnit platform dependencies

### logback-pom.xml
- **Source**: Logback (GitHub)
- **Features tested**:
  - Multi-module logging framework (13 modules)
  - `dependencyManagement` section
  - Profile for artifact signing
  - Distribution management configuration

### mockito-core-pom.xml
- **Source**: Mockito Core (version 5.12.0 from Maven Central)
- **Features tested**:
  - Mocking framework dependencies
  - Published POM format

### okhttp-pom.xml
- **Source**: OkHttp (version 4.12.0 from Maven Central)
- **Features tested**:
  - HTTP client library
  - Square parent inheritance

### retrofit-pom.xml
- **Source**: Retrofit (version 2.11.0 from Maven Central)
- **Features tested**:
  - REST client library
  - Square ecosystem dependencies

### slf4j-pom.xml
- **Source**: SLF4J (GitHub)
- **Features tested**:
  - Multi-module logging API (14 modules)
  - BOM pattern with modules
  - `dependencyManagement` section with `${project.version}`
  - Javadoc grouping configuration
  - Profile for artifact signing

---

## 9. Complex Dependency Graphs

Big data and enterprise projects with complex dependency structures.

### camel-core-pom.xml
- **Source**: Apache Camel Core (GitHub)
- **Features tested**:
  - Integration framework module
  - Complex dependency structure

### dropwizard-core-pom.xml
- **Source**: Dropwizard Core (GitHub, version 4.0.x)
- **Features tested**:
  - Microservices framework module
  - Parent reference to dropwizard-parent
  - Various web framework dependencies

### flink-core-pom.xml
- **Source**: Apache Flink Core (GitHub)
- **Features tested**:
  - Stream processing framework module
  - Complex build configuration

### hadoop-common-pom.xml
- **Source**: Apache Hadoop Common (GitHub)
- **Features tested**:
  - Many direct dependencies
  - Complex parent POM hierarchy (`hadoop-project-dist`)
  - Multiple dependency scopes (compile, test, provided, runtime)
  - Dependencies with exclusions
  - Test-jar dependencies (`<type>test-jar</type>`)
  - Several Maven profiles (native, native-win, parallel-tests, releasedocs, shelltest, aarch64, x86_64)
  - Profile activation by OS family and architecture
  - Native code compilation (C/C++ with CMake)
  - Protobuf code generation
  - Windows and Unix platform support

### quarkus-bom-pom.xml
- **Source**: Quarkus BOM (version 3.11.0 from Maven Central)
- **Features tested**:
  - Large BOM with extensive managed dependencies
  - Non-JAR dependency types (`<type>json</type>`, `<type>properties</type>`)
  - Classifier usage
  - Many dependency exclusions
  - Cloud-native framework ecosystem

### spark-core-pom.xml
- **Source**: Apache Spark Core (GitHub)
- **Features tested**:
  - Big data processing framework module
  - Complex dependency graph

### vertx-core-pom.xml
- **Source**: Eclipse Vert.x Core (GitHub)
- **Features tested**:
  - Reactive toolkit core module
  - Event-driven framework dependencies

---

## Usage

These fixtures can be used to test:

1. **POM Parsing**: Verify correct parsing of XML structure
2. **Dependency Resolution**: Test transitive dependency resolution
3. **Property Interpolation**: Test `${property}` resolution
4. **Parent POM Handling**: Test inheritance and effective POM calculation
5. **BOM Import**: Test `<scope>import</scope>` handling
6. **Profile Activation**: Test profile-based dependency modifications
7. **Scope Handling**: Test compile, test, provided, runtime, system scopes
8. **Multi-Module**: Test reactor builds and module relationships

## Sources

All files downloaded from:
- GitHub raw files (apache/*, google/*, square/*, jhy/*, assertj/*, spring-projects/*, eclipse-vertx/*, qos-ch/*, dropwizard/*)
- Maven Central Repository (for published POMs)

## Summary

Categories included:

- simple-single-module
- multi-module
- dependency-types
- bom-usage
- profile-based
- spring-ecosystem
- apache-projects
- popular-libs
- complex-deps
