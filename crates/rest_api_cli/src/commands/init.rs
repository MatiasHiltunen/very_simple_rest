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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum ProjectFormat {
    #[default]
    Eon,
    Ts,
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
    format: ProjectFormat,
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

    match format {
        ProjectFormat::Eon => {
            write_file(
                &project_dir.join("api.eon"),
                &match starter {
                    StarterKind::Commented => {
                        commented_service_template(module_name.as_str(), name, description.as_str())
                    }
                    StarterKind::Minimal => minimal_service_template(module_name.as_str()),
                },
            )?;
        }
        ProjectFormat::Ts => {
            write_file(
                &project_dir.join("vsr.config.ts"),
                &match starter {
                    StarterKind::Commented => commented_typescript_service_template(
                        module_name.as_str(),
                        name,
                        description.as_str(),
                    ),
                    StarterKind::Minimal => minimal_typescript_service_template(module_name.as_str()),
                },
            )?;
        }
    }
    write_file(&project_dir.join(".env.example"), &env_example())?;
    write_file(
        &project_dir.join("README.md"),
        &readme_template(
            name,
            description.as_str(),
            author.as_str(),
            license,
            repository,
            format,
        ),
    )?;
    write_file(&project_dir.join(".gitignore"), &gitignore_template(format))?;
    write_file(&project_dir.join("var/data/.gitkeep"), "")?;

    println!(
        "\n{} {}",
        "Project created successfully at:".green().bold(),
        project_dir.display()
    );
    println!("\nStarter kind: {}", starter.label());
    println!("\nTo get started:");
    println!("  cd {}", name);
    if format == ProjectFormat::Ts {
        println!("  npm install --save-dev @matiashiltunen/vsr typescript");
        println!("  cp .env.example .env");
        println!("  npx vsr migrate generate --output migrations/0001_init.sql");
        println!("  npx vsr serve");
    } else {
        println!("  cp .env.example .env");
        println!("  vsr migrate generate --input api.eon --output migrations/0001_init.sql");
        println!("  vsr serve api.eon");
    }

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

fn gitignore_template(format: ProjectFormat) -> String {
    let mut output = String::from(
        r#".env
target/
.vsr-build/
*.bundle/
var/data/*.db
var/data/*.sqlite
var/data/*.sqlite3
"#,
    );

    if format == ProjectFormat::Ts {
        output.push_str("node_modules/\n");
        output.push_str("api.eon\n");
    }

    output
}

fn readme_template(
    project_name: &str,
    description: &str,
    author: &str,
    license: &str,
    repository: Option<String>,
    format: ProjectFormat,
) -> String {
    let repository_line = repository
        .map(|value| format!("- Repository: {value}\n"))
        .unwrap_or_default();

    let (files_section, first_run, next_steps) = match format {
        ProjectFormat::Eon => (
            r#"- `api.eon`: VSR service contract
- `.env.example`: local environment template
- `migrations/`: generated SQL migrations"#,
            r#"cp .env.example .env
vsr migrate generate --input api.eon --output migrations/0001_init.sql
vsr serve api.eon"#,
            r#"- Edit `api.eon` to match your resources and policies
- Run `vsr docs --output docs/eon-reference.md` for a local reference snapshot
- Use `vsr build api.eon --release` when you want a standalone binary"#,
        ),
        ProjectFormat::Ts => (
            r#"- `vsr.config.ts`: typed VSR schema source
- `api.eon`: managed generated artifact written by the npm wrapper
- `.env.example`: local environment template
- `migrations/`: generated SQL migrations"#,
            r#"npm install --save-dev @matiashiltunen/vsr typescript
cp .env.example .env
npx vsr migrate generate --output migrations/0001_init.sql
npx vsr serve"#,
            r#"- Edit `vsr.config.ts`; do not hand-edit the generated `api.eon`
- Use `npx vsr check --strict` to validate the generated schema surface
- Use `npx vsr build --release` when you want a standalone binary"#,
        ),
    };

    format!(
        r#"# {project_name}

{description}

## Project

- Author: {author}
- License: {license}
{repository_line}
## Files

{files_section}

## First Run

```bash
{first_run}
```

## Next Steps

{next_steps}
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
            {{ name: "created_at", type: DateTime }}
            {{ name: "updated_at", type: DateTime }}
        ]
    }}
]
"#
    )
}

fn minimal_typescript_service_template(module_name: &str) -> String {
    format!(
        r#"import {{ defineService }} from "@matiashiltunen/vsr";

export default defineService({{
    module: "{module_name}",
    resources: {{
        Post: {{
            name: "Post",
            api_name: "posts",
            fields: {{
                id: {{ type: "I64", id: true }},
                title: {{ type: "String" }},
                body: {{ type: "String", nullable: true }},
                created_at: {{ type: "DateTime" }},
                updated_at: {{ type: "DateTime" }}
            }}
        }}
    }}
}});
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
    engine: {{
        kind: TursoLocal
        path: "var/data/app.db"
        encryption_key: {{ env_or_file: "TURSO_ENCRYPTION_KEY" }}
    }}
}}

// Optional runtime knobs:
// logging: {{
//     filter_env: "RUST_LOG"
//     default_filter: "info"
//     timestamp: Millis
// }}
// runtime: {{
//     compression: {{
//         enabled: true
//         static_precompressed: false
//     }}
// }}
// tls: {{
//     cert_path: "certs/dev-cert.pem"
//     key_path: "certs/dev-key.pem"
// }}
// static: {{
//     mounts: [
//         {{
//             mount: "/"
//             dir: "public"
//             mode: Spa
//             index_file: "index.html"
//             fallback_file: "index.html"
//             cache: NoStore
//         }}
//     ]
// }}
// security: {{
//     cors: {{
//         origins: ["http://localhost:3000"]
//     }}
//     // Uncomment when you want built-in auth and account flows.
//     // auth: {{
//     //     issuer: "example_api"
//     //     audience: "example_clients"
//     //     access_token_ttl_seconds: 3600
//     //     session_cookie: {{
//     //         secure: false
//     //     }}
//     // }}
// }}

// Optional reusable pieces:
enums: {{
    PostStatus: ["draft", "review", "published"]
}}
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
            {{ name: "title", type: String, garde: {{ length: {{ min: 3, max: 120, mode: Chars }} }} }}
            {{ name: "slug", type: String, unique: true, transforms: [Slugify] }}
            {{ name: "status", type: PostStatus }}

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

            // Generated timestamps are inferred automatically from these field names.
            {{ name: "created_at", type: DateTime }}
            {{ name: "updated_at", type: DateTime }}

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

fn commented_typescript_service_template(
    module_name: &str,
    project_name: &str,
    description: &str,
) -> String {
    format!(
        r#"import {{ defineService }} from "@matiashiltunen/vsr";

// {project_name}
// {description}
//
// This starter is intentionally comment-heavy so `vsr init --format ts` gives
// you a typed config to edit directly while VSR keeps generating canonical
// `api.eon` in the background.
//
// Common commands:
//   npx vsr serve
//   npx vsr migrate generate --output migrations/0001_init.sql
//   npx vsr build --release
//   npx vsr check --strict

export default defineService({{
    module: "{module_name}",

    // Service-level defaults. These are optional.
    database: {{
        engine: {{
            kind: "TursoLocal",
            path: "var/data/app.db",
            encryption_key: {{ env_or_file: "TURSO_ENCRYPTION_KEY" }}
        }}
    }},

    // Optional runtime knobs:
    // logging: {{
    //     filter_env: "RUST_LOG",
    //     default_filter: "info",
    //     timestamp: "Millis"
    // }},
    // runtime: {{
    //     compression: {{
    //         enabled: true,
    //         static_precompressed: false
    //     }}
    // }},
    // tls: {{
    //     cert_path: "certs/dev-cert.pem",
    //     key_path: "certs/dev-key.pem"
    // }},
    // static: {{
    //     mounts: [
    //         {{
    //             mount: "/",
    //             dir: "public",
    //             mode: "Spa",
    //             index_file: "index.html",
    //             fallback_file: "index.html",
    //             cache: "NoStore"
    //         }}
    //     ]
    // }},
    // security: {{
    //     cors: {{
    //         origins: ["http://localhost:3000"]
    //     }},
    //     auth: {{
    //         issuer: "example_api",
    //         audience: "example_clients",
    //         access_token_ttl_seconds: 3600,
    //         session_cookie: {{
    //             secure: false
    //         }}
    //     }}
    // }},

    // Optional reusable pieces:
    enums: {{
        PostStatus: ["draft", "review", "published"]
    }},
    // mixins: {{
    //     Timestamps: {{
    //         fields: {{
    //             created_at: {{ type: "DateTime", generated: "CreatedAt" }},
    //             updated_at: {{ type: "DateTime", generated: "UpdatedAt" }}
    //         }}
    //     }}
    // }},

    resources: {{
        Post: {{
            name: "Post",
            table: "post",
            api_name: "posts",

            // Resource-level access rules.
            roles: {{
                update: "editor",
                delete: "editor"
            }},

            // Optional list tuning.
            list: {{
                default_limit: 20,
                max_limit: 100
            }},

            // Optional API shape controls.
            // api: {{
            //     default_context: "view",
            //     fields: {{
            //         title: {{ from: "title_text" }},
            //         permalink: {{ template: "/posts/{{slug}}" }}
            //     }},
            //     contexts: {{
            //         view: ["id", "title", "slug", "status", "created_at", "permalink"],
            //         edit: ["id", "title", "slug", "status", "body", "meta", "created_at", "updated_at"]
            //     }}
            // }},

            // Optional declarative actions.
            // actions: [
            //     {{
            //         name: "publish",
            //         behavior: {{
            //             kind: "UpdateFields",
            //             set: {{
            //                 status: "published"
            //             }}
            //         }}
            //     }},
            //     {{
            //         name: "purge",
            //         behavior: {{
            //             kind: "DeleteResource"
            //         }}
            //     }}
            // ],

            fields: {{
                id: {{ type: "I64", id: true }},

                // Scalars, validation, uniqueness, and transforms.
                title: {{ type: "String", validate: {{ min_length: 3, max_length: 120 }} }},
                slug: {{ type: "String", unique: true, transforms: ["Slugify"] }},
                status: {{ type: "PostStatus" }},

                // Typed object, list, and JSON support.
                body: {{
                    type: "Object",
                    fields: {{
                        raw: {{ type: "String", transforms: ["CollapseWhitespace"] }},
                        rendered: "String"
                    }}
                }},
                tags: {{ type: "List", items: "String", nullable: true }},
                meta: {{ type: "JsonObject", nullable: true }},

                // Generated timestamps are inferred automatically from these field names.
                created_at: {{ type: "DateTime" }},
                updated_at: {{ type: "DateTime" }}

                // Example relation:
                // author_id: {{ type: "I64", relation: {{ references: "user.id" }} }}
            }},

            indexes: [
                {{ fields: ["status", "created_at"] }}
            ]
        }}

        // Add more resources as needed. Many-to-many uses an explicit join resource today.
        // Tag: {{
        //     name: "Tag",
        //     api_name: "tags",
        //     fields: {{
        //         id: {{ type: "I64", id: true }},
        //         name: {{ type: "String", unique: true }}
        //     }}
        // }},
        // PostTag: {{
        //     name: "PostTag",
        //     table: "post_tag",
        //     fields: {{
        //         post_id: {{ type: "I64", relation: {{ references: "post.id" }} }},
        //         tag_id: {{ type: "I64", relation: {{ references: "tag.id" }} }}
        //     }}
        // }}
    }}
}});
"#
    )
}

#[cfg(test)]
mod tests {
    use super::{
        ProjectFormat, StarterKind, commented_service_template,
        commented_typescript_service_template, create_project, env_example, sanitize_module_name,
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
            ProjectFormat::Eon,
        )
        .expect("project should generate");

        let project_root = root.join("demo-app");
        let api_eon =
            fs::read_to_string(project_root.join("api.eon")).expect("api.eon should be readable");
        let readme =
            fs::read_to_string(project_root.join("README.md")).expect("README should be readable");
        assert!(api_eon.contains(r#"module: "demo_app""#));
        assert!(api_eon.contains(r#"kind: "DeleteResource""#));
        assert!(api_eon.contains(r#"kind: TursoLocal"#));
        assert!(api_eon.contains(r#"encryption_key: { env_or_file: "TURSO_ENCRYPTION_KEY" }"#));
        assert!(api_eon.contains(r#"garde: { length: { min: 3, max: 120, mode: Chars } }"#));
        assert!(!api_eon.contains("validate:"));
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
    fn create_project_writes_typescript_starter() {
        let root = temp_root("typescript");
        fs::create_dir_all(&root).expect("temp root should exist");

        create_project(
            "demo-app",
            "Example API".to_owned(),
            "Tester".to_owned(),
            "MIT",
            root.display().to_string(),
            None,
            Some(StarterKind::Minimal),
            ProjectFormat::Ts,
        )
        .expect("project should generate");

        let project_root = root.join("demo-app");
        let config = fs::read_to_string(project_root.join("vsr.config.ts"))
            .expect("vsr.config.ts should be readable");
        let readme =
            fs::read_to_string(project_root.join("README.md")).expect("README should be readable");
        let gitignore = fs::read_to_string(project_root.join(".gitignore"))
            .expect(".gitignore should be readable");

        assert!(config.contains("defineService"));
        assert!(config.contains("module: \"demo_app\""));
        assert!(readme.contains("npx vsr serve"));
        assert!(readme.contains("do not hand-edit the generated `api.eon`"));
        assert!(gitignore.contains("api.eon"));
        assert!(gitignore.contains("node_modules/"));
        assert!(project_root.join("migrations").is_dir());
        assert!(project_root.join("var/data").is_dir());

        fs::remove_dir_all(root).expect("temp root should clean up");
    }

    #[test]
    fn commented_typescript_template_is_comment_rich() {
        let template =
            commented_typescript_service_template("sample_app", "Sample", "Sample API");
        assert!(template.contains("// Optional declarative actions."));
        assert!(template.contains("export default defineService"));
        assert!(template.contains("typed config"));
    }

    #[test]
    fn env_example_uses_dotenv_comments() {
        let template = env_example();
        assert!(template.starts_with("# Copy this file"));
        assert!(template.contains("DATABASE_URL=sqlite:var/data/app.db?mode=rwc"));
        assert!(!template.contains("// Only required"));
    }
}
