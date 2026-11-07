//! Turns an image-based `devcontainer.json` into a template.

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value, json};

/// Keys that need a container build, which Spawnbox does not do.
const REFUSED: [&str; 5] = [
    "build",
    "dockerFile",
    "dockerfile",
    "dockerComposeFile",
    "features",
];
/// Lifecycle commands that become setup steps, in the order they run.
const SETUP: [&str; 3] = [
    "onCreateCommand",
    "updateContentCommand",
    "postCreateCommand",
];
/// Keys that are used, or have no meaning here.
const KNOWN: [&str; 6] = [
    "name",
    "image",
    "containerEnv",
    "remoteEnv",
    "$schema",
    "customizations",
];

/// The template for a devcontainer file's text. `name` defaults to the
/// file's `name`, made a valid template name. Returns the template and
/// the keys it ignored.
pub fn to_template(text: &str, name: Option<&str>) -> Result<(Value, Vec<String>)> {
    let parsed: Value =
        serde_json::from_str(&strip_jsonc(text)).context("devcontainer.json is not valid JSON")?;
    let file = parsed
        .as_object()
        .context("devcontainer.json must be an object")?;
    for key in REFUSED {
        let used = match file.get(key) {
            Some(Value::Object(map)) => !map.is_empty(),
            Some(Value::Null) | None => false,
            Some(_) => true,
        };
        if used {
            bail!("{key:?} is not supported: Spawnbox uses a prebuilt \"image\" only");
        }
    }
    let image = file
        .get("image")
        .and_then(Value::as_str)
        .context("devcontainer.json needs \"image\"")?;
    let name = match name {
        Some(name) => name.to_owned(),
        None => file
            .get("name")
            .and_then(Value::as_str)
            .map(template_name)
            .filter(|n| !n.is_empty())
            .context("give the template a name with --name")?,
    };

    let mut env = Map::new();
    for key in ["containerEnv", "remoteEnv"] {
        for (var, value) in file
            .get(key)
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
        {
            let value = value
                .as_str()
                .with_context(|| format!("{key}.{var} must be a string"))?;
            if value.contains("${") {
                bail!("{key}.{var} uses a ${{...}} variable, which is not supported");
            }
            env.insert(var.clone(), Value::from(value));
        }
    }

    let mut setup = Vec::new();
    for key in SETUP {
        if let Some(command) = file.get(key) {
            setup.extend(steps(key, command)?);
        }
    }

    let ignored = file
        .keys()
        .filter(|k| !KNOWN.contains(&k.as_str()) && !SETUP.contains(&k.as_str()))
        .cloned()
        .collect();
    let template = json!({
        "name": name,
        "base": image,
        "env": env,
        "setup": setup,
    });
    Ok((template, ignored))
}

/// A lifecycle command's steps: a string is a shell command, an array is
/// a program and its arguments, and an object holds named commands.
fn steps(key: &str, command: &Value) -> Result<Vec<String>> {
    match command {
        Value::String(cmd) => Ok(vec![cmd.clone()]),
        Value::Array(argv) => {
            let words = argv
                .iter()
                .map(|w| w.as_str().map(quote))
                .collect::<Option<Vec<_>>>()
                .with_context(|| format!("{key} must hold strings"))?;
            Ok(vec![words.join(" ")])
        }
        Value::Object(named) => {
            let mut all = Vec::new();
            for (name, command) in named {
                all.extend(steps(&format!("{key}.{name}"), command)?);
            }
            Ok(all)
        }
        _ => bail!("{key} must be a string, an array or an object"),
    }
}

fn quote(word: &str) -> String {
    let plain = !word.is_empty()
        && word
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_./=:@+,".contains(&b));
    if plain {
        word.to_owned()
    } else {
        format!("'{}'", word.replace('\'', "'\\''"))
    }
}

/// Lowercase, with runs of other characters made one `-`.
fn template_name(name: &str) -> String {
    let mut out = String::new();
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if !out.is_empty() && !out.ends_with('-') {
            out.push('-');
        }
    }
    let out = out.trim_end_matches('-');
    out.trim_start_matches(|c: char| c.is_ascii_digit())
        .chars()
        .take(63)
        .collect::<String>()
        .trim_end_matches('-')
        .to_owned()
}

/// JSON with comments and trailing commas, as devcontainer files allow,
/// made plain JSON.
fn strip_jsonc(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                out.push(c);
                while let Some(c) = chars.next() {
                    out.push(c);
                    match c {
                        '\\' => out.extend(chars.next()),
                        '"' => break,
                        _ => {}
                    }
                }
            }
            '/' if chars.peek() == Some(&'/') => {
                for c in chars.by_ref() {
                    if c == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                let mut last = ' ';
                for c in chars.by_ref() {
                    if last == '*' && c == '/' {
                        break;
                    }
                    last = c;
                }
                out.push(' ');
            }
            '}' | ']' => {
                let kept = out.trim_end().len();
                if out[..kept].ends_with(',') {
                    out.truncate(kept - 1);
                }
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_an_image_based_devcontainer() {
        let text = r#"{
            // A Node project.
            "name": "My Web App",
            "image": "mcr.microsoft.com/devcontainers/javascript-node:22", /* pinned */
            "containerEnv": { "NODE_ENV": "development", },
            "remoteEnv": { "URL": "http://x//y" },
            "onCreateCommand": "npm ci",
            "postCreateCommand": { "a": ["echo", "it's done"], "b": "make" },
            "forwardPorts": [3000],
        }"#;
        let (template, ignored) = to_template(text, None).unwrap();
        assert_eq!(
            template,
            json!({
                "name": "my-web-app",
                "base": "mcr.microsoft.com/devcontainers/javascript-node:22",
                "env": { "NODE_ENV": "development", "URL": "http://x//y" },
                "setup": ["npm ci", "echo 'it'\\''s done'", "make"],
            })
        );
        assert_eq!(ignored, vec!["forwardPorts".to_owned()]);
    }

    #[test]
    fn refuses_what_needs_a_container_build() {
        for text in [
            r#"{"name":"a","build":{"dockerfile":"Dockerfile"}}"#,
            r#"{"name":"a","image":"x","features":{"ghcr.io/f/node:1":{}}}"#,
            r#"{"name":"a","dockerComposeFile":"c.yml"}"#,
            r#"{"name":"a"}"#,
            r#"{"name":"a","image":"x","remoteEnv":{"P":"${containerEnv:PATH}"}}"#,
        ] {
            assert!(to_template(text, None).is_err(), "{text}");
        }
        let (template, _) = to_template(r#"{"image":"x","features":{}}"#, Some("t")).unwrap();
        assert_eq!(template["name"], "t");
    }
}
