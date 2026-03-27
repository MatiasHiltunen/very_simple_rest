use crate::error::{Error, Result};
use clap::ValueEnum;
use colored::Colorize;
use dialoguer::{Select, theme::ColorfulTheme};
use std::fs::{File, create_dir_all};
use std::io::{IsTerminal, Write};
use std::path::Path;

const DEFAULT_DB_URL: &str = "sqlite:var/data/app.db?mode=rwc";
const DEFAULT_BIND_ADDR: &str = "127.0.0.1:8080";

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum StarterKind {
    Commented,
    Minimal,
}

impl StarterKind {
    fn label(self) -> &'static str {
        match self {
            Self::Commented => "Commented starter (Recommended)",
            Self::Minimal => "Minimal CRUD starter",
        }
    }

    fn description(self) -> &'static str {
        match self {
            Self::Commented => {
                "A starter `api.eon` with commented examples of current VSR features."
            }
            Self::Minimal => "A lean `api.eon` with one resource and the smallest runnable shape.",
        }
    }
}

pub fn create_project(
    name: &str,
    description: String,
    author: String,
    license: &str,
    output_dir: String,
    repository: Option<String>,
    starter: Option<StarterKind>,
) -> Result<()> {
    let project_dir = Path::new(&output_dir).join(name);
    if project_dir.exists() {
        return Err(Error::Config(format!(
            "Directory already exists: {}",
            project_dir.display()
        )));
    }

    create_dir_all(&project_dir)?;
    create_dir_all(project_dir.join("migrations"))?;
    create_dir_all(project_dir.join("var/data"))?;
    println!(
        "{} {}",
        "Created project directory:".green(),
        project_dir.display()
    );

    let starter = resolve_starter_kind(starter)?;
    let module_name = sanitize_module_name(name);

    write_file(
        &project_dir.join("api.eon"),
        &match starter {
            StarterKind::Commented => {
                commented_service_template(module_name.as_str(), name, description.as_str())
            }
            StarterKind::Minimal => minimal_service_template(module_name.as_str()),
        },
    )?;
    write_file(&project_dir.join(".env.example"), &env_example())?;
    write_file(
        &project_dir.join("README.md"),
        &readme_template(
            name,
            description.as_str(),
            author.as_str(),
            license,
            repository,
        ),
    )?;
    write_file(&project_dir.join(".gitignore"), gitignore_template())?;
    write_file(&project_dir.join("var/data/.gitkeep"), "")?;

    println!(
        "\n{} {}",
        "Project created successfully at:".green().bold(),
        project_dir.display()
    );
    println!("\nStarter kind: {}", starter.label());
    println!("\nTo get started:");
    println!("  cd {}", name);
    println!("  cp .env.example .env");
    println!("  vsr migrate generate --input api.eon --output migrations/0001_init.sql");
    println!("  vsr serve api.eon");

    Ok(())
}

fn resolve_starter_kind(starter: Option<StarterKind>) -> Result<StarterKind> {
    if let Some(starter) = starter {
        return Ok(starter);
    }

    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Ok(StarterKind::Commented);
    }

    let options = [StarterKind::Commented, StarterKind::Minimal];
    let labels = options
        .iter()
        .map(|starter| format!("{} - {}", starter.label(), starter.description()))
        .collect::<Vec<_>>();

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Choose a VSR starter")
        .default(0)
        .items(&labels)
        .interact()
        .map_err(|error| Error::Config(format!("Failed to read init selection: {error}")))?;

    Ok(options[selection])
}

fn sanitize_module_name(name: &str) -> String {
    let mut module = String::new();
    let mut last_was_separator = false;

    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            if last_was_separator && !module.is_empty() {
                module.push('_');
            }
            last_was_separator = false;
            module.push(ch.to_ascii_lowercase());
        } else {
            last_was_separator = true;
        }
    }

    if module.is_empty() {
        "app".to_owned()
    } else if module
        .chars()
        .next()
        .map(|ch| ch.is_ascii_digit())
        .unwrap_or(false)
    {
        format!("app_{module}")
    } else {
        module
    }
}

fn write_file(path: &Path, content: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }
    let mut file = File::create(path)?;
    file.write_all(content.as_bytes())?;
    println!("{} {}", "Created:".green(), path.display());
    Ok(())
}

fn env_example() -> String {
    format!(
        r#"# Copy this file to `.env` and adjust values for your environment.
DATABASE_URL={DEFAULT_DB_URL}
TURSO_ENCRYPTION_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
BIND_ADDR={DEFAULT_BIND_ADDR}

# Only required when you enable built-in auth or auth-managed routes.
JWT_SECRET=change-me-in-development
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=change-me
"#
    )
}

fn gitignore_template() -> &'static str {
    r#".env
target/
.vsr-build/
*.bundle/
var/data/*.db
var/data/*.sqlite
var/data/*.sqlite3
"#
}

fn readme_template(
    project_name: &str,
    description: &str,
    author: &str,
    license: &str,
    repository: Option<String>,
) -> String {
    let repository_line = repository
        .map(|value| format!("- Repository: {value}\n"))
        .unwrap_or_default();

    format!(
        r#"# {project_name}

{description}

## Project

- Author: {author}
- License: {license}
{repository_line}
## Files

- `api.eon`: VSR service contract
- `.env.example`: local environment template
- `migrations/`: generated SQL migrations

## First Run

```bash
cp .env.example .env
vsr migrate generate --input api.eon --output migrations/0001_init.sql
vsr serve api.eon
```

## Next Steps

- Edit `api.eon` to match your resources and policies
- Run `vsr docs --output docs/eon-reference.md` for a local reference snapshot
- Use `vsr build api.eon --release` when you want a standalone binary
"#
    )
}

fn minimal_service_template(module_name: &str) -> String {
    format!(
        r#"module: "{module_name}"

resources: [
    {{
        name: "Post"
        api_name: "posts"
        fields: [
            {{ name: "id", type: I64, id: true }}
            {{ name: "title", type: String }}
            {{ name: "body", type: String, nullable: true }}
            {{ name: "created_at", type: DateTime, generated: CreatedAt }}
            {{ name: "updated_at", type: DateTime, generated: UpdatedAt }}
        ]
    }}
]
"#
    )
}

fn commented_service_template(module_name: &str, project_name: &str, description: &str) -> String {
    format!(
        r#"// {project_name}
// {description}
//
// This starter is intentionally comment-heavy so `vsr init` gives you a current
// `.eon` contract to edit directly instead of copying a fragile example app.
//
// Common commands:
//   vsr serve api.eon
//   vsr migrate generate --input api.eon --output migrations/0001_init.sql
//   vsr build api.eon --release
//   vsr docs --output docs/eon-reference.md

module: "{module_name}"

// Service-level defaults. These are optional.
database: {{
    // The native `vsr serve` path defaults well for local SQLite development.
    // For local encrypted SQLite compatibility, keep `database.engine = TursoLocal`.
    engine: TursoLocal {{
        path: "var/data/app.db"
    }}
}}

// Optional runtime knobs:
// logging: {{
//     level: "info"
// }}
// runtime: {{
//     gzip: true
//     brotli: true
// }}
// tls: {{
//     cert_file: "certs/dev.pem"
//     key_file: "certs/dev-key.pem"
// }}
// static_mounts: [
//     {{
//         mount_path: "/"
//         source_dir: "public"
//         mode: "Spa"
//         fallback_file: "index.html"
//     }}
// ]
// security: {{
//     cors: {{
//         origins: ["http://localhost:3000"]
//     }}
//     // Uncomment when you want built-in auth and account flows.
//     // auth: {{
//     //     ui_pages: {{
//     //         login_path: "/login"
//     //         register_path: "/register"
//     //     }}
//     // }}
// }}

// Optional reusable pieces:
// enums: {{
//     PostStatus: ["draft", "review", "published"]
// }}
// mixins: {{
//     Timestamps: {{
//         fields: {{
//             created_at: {{ type: DateTime, generated: CreatedAt }}
//             updated_at: {{ type: DateTime, generated: UpdatedAt }}
//         }}
//     }}
// }}

resources: [
    {{
        name: "Post"
        table: "post"
        api_name: "posts"

        // Resource-level access rules.
        roles: {{
            update: "editor"
            delete: "editor"
        }}

        // Optional list tuning.
        list: {{
            default_limit: 20
            max_limit: 100
        }}

        // Optional API shape controls.
        // api: {{
        //     default_context: "view"
        //     fields: {{
        //         title: {{ from: "title_text" }}
        //         permalink: {{ template: "/posts/{{slug}}" }}
        //     }}
        //     contexts: {{
        //         view: ["id", "title", "slug", "status", "created_at", "permalink"]
        //         edit: ["id", "title", "slug", "status", "body", "meta", "created_at", "updated_at"]
        //     }}
        // }}

        // Optional declarative actions.
        // actions: [
        //     {{
        //         name: "publish"
        //         behavior: {{
        //             kind: "UpdateFields"
        //             set: {{
        //                 status: "published"
        //             }}
        //         }}
        //     }}
        //     {{
        //         name: "rename"
        //         behavior: {{
        //             kind: "UpdateFields"
        //             set: {{
        //                 title: {{ input: "newTitle" }}
        //                 slug: {{ input: "newSlug" }}
        //             }}
        //         }}
        //     }}
        //     {{
        //         name: "purge"
        //         behavior: {{
        //             kind: "DeleteResource"
        //         }}
        //     }}
        // ]

        fields: [
            {{ name: "id", type: I64, id: true }}

            // Scalars, validation, uniqueness, and transforms.
            {{ name: "title", type: String, validate: {{ min_length: 3, max_length: 120 }} }}
            {{ name: "slug", type: String, unique: true, transforms: [Slugify] }}
            {{ name: "status", type: String, transforms: [Trim, Lowercase] }}

            // Typed object, list, and JSON support.
            {{
                name: "body"
                type: Object
                fields: {{
                    raw: {{ type: String, transforms: [CollapseWhitespace] }}
                    rendered: String
                }}
            }}
            {{ name: "tags", type: List, items: String, nullable: true }}
            {{ name: "meta", type: JsonObject, nullable: true }}

            // Generated timestamps.
            {{ name: "created_at", type: DateTime, generated: CreatedAt }}
            {{ name: "updated_at", type: DateTime, generated: UpdatedAt }}

            // Example relation:
            // {{ name: "author_id", type: I64, relation: {{ references: "user.id" }} }}
        ]

        indexes: [
            {{ fields: ["status", "created_at"] }}
        ]
    }}

    // Add more resources as needed. Many-to-many uses an explicit join resource today.
    // {{
    //     name: "Tag"
    //     api_name: "tags"
    //     fields: [
    //         {{ name: "id", type: I64, id: true }}
    //         {{ name: "name", type: String, unique: true }}
    //     ]
    // }}
    // {{
    //     name: "PostTag"
    //     table: "post_tag"
    //     fields: [
    //         {{ name: "post_id", type: I64, relation: {{ references: "post.id" }} }}
    //         {{ name: "tag_id", type: I64, relation: {{ references: "tag.id" }} }}
    //     ]
    // }}
]
"#
    )
}

#[cfg(test)]
mod tests {
    use super::{
        StarterKind, commented_service_template, create_project, env_example, sanitize_module_name,
    };
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should advance")
            .as_nanos();
        std::env::temp_dir().join(format!("vsr_init_{prefix}_{nanos}"))
    }

    #[test]
    fn sanitize_module_name_normalizes_project_names() {
        assert_eq!(sanitize_module_name("My API"), "my_api");
        assert_eq!(sanitize_module_name("123 project"), "app_123_project");
        assert_eq!(sanitize_module_name("___"), "app");
    }

    #[test]
    fn create_project_writes_local_comment_config_starter() {
        let root = temp_root("commented");
        fs::create_dir_all(&root).expect("temp root should exist");

        create_project(
            "demo-app",
            "Example API".to_owned(),
            "Tester".to_owned(),
            "MIT",
            root.display().to_string(),
            None,
            Some(StarterKind::Commented),
        )
        .expect("project should generate");

        let project_root = root.join("demo-app");
        let api_eon =
            fs::read_to_string(project_root.join("api.eon")).expect("api.eon should be readable");
        let readme =
            fs::read_to_string(project_root.join("README.md")).expect("README should be readable");

        assert!(api_eon.contains(r#"module: "demo_app""#));
        assert!(api_eon.contains(r#"kind: "DeleteResource""#));
        assert!(api_eon.contains("// Optional declarative actions."));
        assert!(readme.contains("vsr serve api.eon"));
        assert!(project_root.join(".env.example").exists());
        assert!(project_root.join(".gitignore").exists());
        assert!(project_root.join("migrations").is_dir());
        assert!(project_root.join("var/data").is_dir());

        fs::remove_dir_all(root).expect("temp root should clean up");
    }

    #[test]
    fn commented_template_is_comment_rich() {
        let template = commented_service_template("sample_app", "Sample", "Sample API");
        assert!(template.contains("// Service-level defaults."));
        assert!(template.contains("// Optional declarative actions."));
        assert!(template.contains("// Typed object, list, and JSON support."));
    }

    #[test]
    fn env_example_uses_dotenv_comments() {
        let template = env_example();
        assert!(template.starts_with("# Copy this file"));
        assert!(template.contains("DATABASE_URL=sqlite:var/data/app.db?mode=rwc"));
        assert!(!template.contains("// Only required"));
    }
}
