# Verified against real projects

Raeva is checked against real open-source Maven projects. The single-module
offline matrix verifies three things from a cold cache:

1. `rv sync` reads the project's `pom.xml` and writes `rv.lock`.
2. rv's locked set is compared against Maven's own resolution
   (`mvn dependency:list`). *Exact* means the two sets are identical,
   coordinate for coordinate.
3. Every locked artifact is deleted from a scratch `~/.m2` so rv is the sole
   provider, then `rv export-m2` and `mvn -o dependency:resolve` must succeed.
   (Build plugins are seeded separately, since they are out of scope; see
   [Scope](offline-builds.md#scope).)

| Project | Dependencies | Parity | Offline `mvn -o` |
| --- | ---: | --- | --- |
| commons-lang | 22 | exact | pass |
| commons-collections | 31 | exact | pass |
| gson | 12 | exact | pass |
| guava | 5 | exact | pass |
| junit4 | 2 | exact | pass |
| jackson-databind 2.18.2 | 28 | exact | pass |
| spring-petclinic | 171 | exact | pass |

The reactor corpus is 48 open-source Maven projects. Each was synced with
empty caches (shared by the few projects run in the same batch) on Linux
x86_64 and compared module by module with `mvn dependency:list` from Maven
3.9.16 on JDK 21. A module *matches* when both tools list the same external
`group:artifact:classifier:version` set; scopes, types, and graph edges are not
compared, and reactor modules are left out. *Compared* counts the modules for
which both tools produced a list.

- 46 of 48 projects lock, and all 1,309 compared modules match.
- apache/struts needs a repository that only a transitive POM declares. Raeva
  does not trust transitive repositories by default; the error lists the
  repositories Maven would search and the `rv.toml` entries that admit them.
- flyway/flyway declares a GitHub Packages repository that requires
  credentials; without them the sync fails with a 401, as Maven's does.
- httpcomponents-client, zookeeper, and feign lock, but the Maven baseline
  failed to build, so they have no comparison.

<details>
<summary>All 48 projects</summary>

| Project | Modules | Compared | Parity |
| --- | ---: | ---: | --- |
| alibaba/arthas | 25 | 25 | match |
| alibaba/fastjson2 | 17 | 17 | match |
| alibaba/nacos | 62 | 62 | match |
| alibaba/Sentinel | 94 | 59 | match |
| apache/commons-compress | 1 | 1 | match |
| apache/commons-io | 1 | 1 | match |
| apache/commons-lang | 1 | 1 | match |
| apache/commons-text | 1 | 1 | match |
| apache/dubbo | 116 | 116 | match |
| apache/httpcomponents-client | 9 | - | no Maven baseline |
| apache/maven-resolver | 31 | 28 | match |
| apache/opennlp | 23 | 23 | match |
| apache/rocketmq | 20 | 12 | match |
| apache/shiro | 55 | 54 | match |
| apache/skywalking | 109 | 21 | match |
| apache/struts | - | - | fails, see above |
| apache/tika | 125 | 111 | match |
| apache/zookeeper | 14 | - | no Maven baseline |
| apolloconfig/apollo | 14 | 14 | match |
| assertj/assertj | 15 | 9 | match |
| checkstyle/checkstyle | 1 | 1 | match |
| dromara/hutool | 23 | 23 | match |
| dropwizard/metrics | 44 | 44 | match |
| eclipse-vertx/vert.x | 4 | 4 | match |
| FasterXML/jackson-core | 1 | 1 | match |
| FasterXML/jackson-databind | 1 | 1 | match |
| flyway/flyway | - | - | fails, see above |
| google/guava | 6 | 5 | match |
| iluwatar/java-design-patterns | 211 | 211 | match |
| jenkinsci/jenkins | 9 | 9 | match |
| jhipster/jhipster-sample-app | 1 | 1 | match |
| jhy/jsoup | 1 | 1 | match |
| langchain4j/langchain4j | 119 | 119 | match |
| liquibase/liquibase | 9 | 9 | match |
| macrozheng/mall | 8 | 8 | match |
| mybatis/mybatis-3 | 1 | 1 | match |
| netty/netty | 62 | 34 | match |
| OpenFeign/feign | 55 | - | no Maven baseline |
| openzipkin/zipkin | 18 | 17 | match |
| pmd/pmd | 44 | 44 | match |
| spring-cloud/spring-cloud-gateway | 15 | 15 | match |
| spring-projects/spring-ai | 169 | 169 | match |
| spring-projects/spring-data-commons | 1 | 1 | match |
| spring-projects/spring-data-jpa | 4 | 4 | match |
| spring-projects/spring-petclinic | 1 | 1 | match |
| swagger-api/swagger-core | 21 | 20 | match |
| xuxueli/xxl-job | 7 | 7 | match |
| zxing/zxing | 4 | 4 | match |

</details>

Each checkout is the project's default branch as of October 2026, except
jackson-databind in the single-module matrix, which is pinned to release 2.18.2.

## Speed

With a warm cache, `rv sync --offline` finishes in tens to a few hundred
milliseconds on these projects, and `mvn -o dependency:list` takes about a
second. Times are for the whole command, including process startup:

| Project | Deps | `rv sync --offline` | `mvn -o dependency:list` | Speedup |
| --- | ---: | ---: | ---: | ---: |
| junit4 | 2 | 0.03 s | 0.76 s | ~26x |
| guava | 5 | 0.05 s | 0.94 s | ~20x |
| gson | 12 | 0.07 s | 0.78 s | ~11x |
| commons-lang | 22 | 0.11 s | 0.81 s | ~8x |
| commons-collections | 31 | 0.10 s | 0.79 s | ~8x |
| jackson-databind 2.18.2 | 28 | 0.10 s | 1.04 s | ~10x |
| spring-petclinic | 171 | 0.27 s | 0.99 s | ~4x |

Both read from a warm cache, so no network time is included. Median of five
runs on one machine.
