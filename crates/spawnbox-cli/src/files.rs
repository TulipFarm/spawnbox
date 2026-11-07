//! `spawnbox cp`: copy files and directories in and out of a sandbox.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use futures_util::StreamExt;
use reqwest::Method;
use serde_json::Value;
use tokio::io::AsyncWriteExt;

use crate::api::{Api, seg};

#[derive(Debug, PartialEq, Eq)]
pub enum Place {
    Local(PathBuf),
    /// `-`: stdin or stdout.
    Std,
    Remote {
        id: String,
        path: String,
    },
}

/// `ID:PATH` is in a sandbox, like `scp`. A colon after a slash, or a
/// one-letter prefix (a Windows drive), stays local.
pub fn place(text: &str) -> Place {
    if text == "-" {
        return Place::Std;
    }
    match text.split_once(':') {
        Some((id, path)) if id.len() > 1 && !id.contains('/') && !id.contains('\\') => {
            Place::Remote {
                id: id.to_owned(),
                path: if path.is_empty() {
                    "/workspace".into()
                } else {
                    path.to_owned()
                },
            }
        }
        _ => Place::Local(PathBuf::from(text)),
    }
}

pub async fn copy(api: &Api, from: &Place, to: &Place, user: Option<&str>) -> Result<()> {
    let copier = Copier { api, user };
    match (from, to) {
        (Place::Local(local), Place::Remote { id, path }) => copier.upload(local, id, path).await,
        (Place::Std, Place::Remote { id, path }) => {
            let body = reqwest::Body::wrap_stream(tokio_stream_stdin());
            copier.put(id, path, body).await
        }
        (Place::Remote { id, path }, Place::Local(local)) => copier.download(id, path, local).await,
        (Place::Remote { id, path }, Place::Std) => copier.cat(id, path).await,
        _ => bail!("one side must be a sandbox path, as ID:PATH"),
    }
}

struct Copier<'a> {
    api: &'a Api,
    user: Option<&'a str>,
}

impl Copier<'_> {
    fn files(&self, method: Method, id: &str, path: &str) -> reqwest::RequestBuilder {
        let mut query = vec![("path", path)];
        if let Some(user) = self.user {
            query.push(("user", user));
        }
        self.api
            .request(method, &format!("/sandboxes/{}/files", seg(id)))
            .query(&query)
    }

    async fn put(&self, id: &str, path: &str, body: reqwest::Body) -> Result<()> {
        self.api
            .send(self.files(Method::PUT, id, path).body(body))
            .await?;
        Ok(())
    }

    /// A file goes to `path` (or into it, if `path` ends with `/`). A
    /// directory's contents go into `path`.
    async fn upload(&self, local: &Path, id: &str, path: &str) -> Result<()> {
        let meta = tokio::fs::metadata(local)
            .await
            .with_context(|| format!("read {}", local.display()))?;
        if meta.is_file() {
            let target = if path.ends_with('/') {
                format!("{path}{}", file_name(local)?)
            } else {
                path.to_owned()
            };
            return self.upload_file(local, id, &target).await;
        }
        let mut count = 0usize;
        let mut dirs = vec![(local.to_path_buf(), path.trim_end_matches('/').to_owned())];
        while let Some((dir, remote)) = dirs.pop() {
            let mut entries = Vec::new();
            let mut reader = tokio::fs::read_dir(&dir)
                .await
                .with_context(|| format!("read {}", dir.display()))?;
            while let Some(entry) = reader.next_entry().await? {
                entries.push(entry);
            }
            entries.sort_by_key(tokio::fs::DirEntry::file_name);
            for entry in entries {
                let kind = entry.file_type().await?;
                let name = entry.file_name().to_string_lossy().into_owned();
                let target = format!("{remote}/{name}");
                if kind.is_dir() {
                    dirs.push((entry.path(), target));
                } else if kind.is_file() {
                    self.upload_file(&entry.path(), id, &target).await?;
                    count += 1;
                } else {
                    eprintln!("skipped {} (not a regular file)", entry.path().display());
                }
            }
        }
        eprintln!("copied {count} files");
        Ok(())
    }

    async fn upload_file(&self, local: &Path, id: &str, path: &str) -> Result<()> {
        let file = tokio::fs::File::open(local)
            .await
            .with_context(|| format!("open {}", local.display()))?;
        self.put(id, path, reqwest::Body::from(file))
            .await
            .with_context(|| format!("upload {} to {path}", local.display()))
    }

    /// A file goes to `local` (or into it, if it is a directory). A
    /// directory goes to `local` (or into it, if it exists), like `cp -r`.
    async fn download(&self, id: &str, path: &str, local: &Path) -> Result<()> {
        let response = self.api.send(self.files(Method::GET, id, path)).await?;
        let into = tokio::fs::metadata(local).await.is_ok_and(|m| m.is_dir());
        let target = if into {
            local.join(remote_name(path))
        } else {
            local.to_path_buf()
        };
        if !is_listing(&response) {
            return write_body(response, &target).await;
        }
        let mut count = 0usize;
        let mut dirs = vec![(
            path.trim_end_matches('/').to_owned(),
            target,
            Some(response),
        )];
        while let Some((remote, local, response)) = dirs.pop() {
            let response = match response {
                Some(response) => response,
                None => self.api.send(self.files(Method::GET, id, &remote)).await?,
            };
            let list: Value = response.json().await?;
            tokio::fs::create_dir_all(&local)
                .await
                .with_context(|| format!("create {}", local.display()))?;
            if list["truncated"] == true {
                eprintln!("warning: {remote} has more entries than the server lists");
            }
            for entry in list["entries"].as_array().into_iter().flatten() {
                let name = entry["name"].as_str().unwrap_or_default();
                let name = remote_name(name);
                if name.is_empty() || name == "." || name == ".." {
                    continue;
                }
                let child = format!("{remote}/{name}");
                match entry["kind"].as_str() {
                    Some("dir") => dirs.push((child, local.join(name), None)),
                    Some("file") => {
                        let response = self.api.send(self.files(Method::GET, id, &child)).await?;
                        write_body(response, &local.join(name)).await?;
                        count += 1;
                    }
                    _ => eprintln!("skipped {child} (not a regular file)"),
                }
            }
        }
        eprintln!("copied {count} files");
        Ok(())
    }

    async fn cat(&self, id: &str, path: &str) -> Result<()> {
        let response = self.api.send(self.files(Method::GET, id, path)).await?;
        if is_listing(&response) {
            bail!("{path} is a directory");
        }
        let mut stdout = tokio::io::stdout();
        let mut body = response.bytes_stream();
        while let Some(chunk) = body.next().await {
            stdout.write_all(&chunk?).await?;
        }
        stdout.flush().await?;
        Ok(())
    }
}

fn is_listing(response: &reqwest::Response) -> bool {
    response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/json"))
}

async fn write_body(response: reqwest::Response, target: &Path) -> Result<()> {
    let mut file = tokio::fs::File::create(target)
        .await
        .with_context(|| format!("create {}", target.display()))?;
    let mut body = response.bytes_stream();
    while let Some(chunk) = body.next().await {
        file.write_all(&chunk.context("download broke")?).await?;
    }
    file.flush().await?;
    Ok(())
}

fn file_name(path: &Path) -> Result<String> {
    Ok(path
        .file_name()
        .context("the source has no file name")?
        .to_string_lossy()
        .into_owned())
}

fn remote_name(path: &str) -> &str {
    path.trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or(path)
}

fn tokio_stream_stdin() -> impl futures_util::Stream<Item = std::io::Result<Vec<u8>>> {
    use tokio::io::AsyncReadExt;
    futures_util::stream::unfold(tokio::io::stdin(), |mut stdin| async move {
        let mut buf = vec![0u8; 64 * 1024];
        match stdin.read(&mut buf).await {
            Ok(0) => None,
            Ok(n) => {
                buf.truncate(n);
                Some((Ok(buf), stdin))
            }
            Err(error) => Some((Err(error), stdin)),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tells_sandbox_paths_from_local_paths() {
        let remote = |id: &str, path: &str| Place::Remote {
            id: id.into(),
            path: path.into(),
        };
        assert_eq!(place("sbx_1:/tmp/a"), remote("sbx_1", "/tmp/a"));
        assert_eq!(place("sbx_1:src"), remote("sbx_1", "src"));
        assert_eq!(place("sbx_1:"), remote("sbx_1", "/workspace"));
        assert_eq!(place("-"), Place::Std);
        assert_eq!(place("./a:b"), Place::Local("./a:b".into()));
        assert_eq!(place("C:\\x"), Place::Local("C:\\x".into()));
        assert_eq!(place("notes.txt"), Place::Local("notes.txt".into()));
    }

    #[test]
    fn names_remote_paths() {
        assert_eq!(remote_name("/workspace/src/"), "src");
        assert_eq!(remote_name("a.txt"), "a.txt");
    }
}
