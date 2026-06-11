# rv-maven-model

A Rust implementation of the Apache Maven Project Object Model (POM).

## Features

*   **Parsing**: Deserializes `pom.xml` files using `quick-xml` and `serde`.
*   **Effective POM**: Computes the effective model by:
    *   Handling parent inheritance (recursive merging).
    *   Resolving property placeholders (`${project.version}`).
    *   Managing `dependencyManagement` imports (BOMs).
*   **Profiles**: Basic support for profile activation (JDK version, OS family, properties).

## Usage

```rust
use rv_maven_model::Pom;

let pom_content = std::fs::read_to_string("pom.xml")?;
let pom = Pom::parse(&pom_content)?;

println!("Project: {}:{}", pom.group_id, pom.artifact_id);
```
