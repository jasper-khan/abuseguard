// File activation for panel-owned Caddy sites. The caller retains control of
// Caddy validation, reload/restart, and the decision to commit or roll back.
use std::fs::{self, DirBuilder, File, Metadata};
use std::io::{self, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

const PENDING: &str = ".site-transaction";
const RECORD: &str = "operation";
const SNAPSHOT: &str = "snapshot";
const REFERENCE: &str = "reference";
const MAX_CANDIDATE: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Change {
    Add,
    Remove,
}

impl Change {
    fn label(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Remove => "remove",
        }
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(ErrorKind::InvalidInput, message)
}

fn conflict(message: &str) -> io::Error {
    io::Error::new(ErrorKind::AlreadyExists, message)
}

fn site_path(sites: &Path, name: &str) -> io::Result<PathBuf> {
    if name.is_empty()
        || name.starts_with('.')
        || name == "_placeholder"
        || name.len() > 249
        || name.chars().any(|c| c.is_control() || matches!(c, '/' | '\\' | ':'))
    {
        return Err(invalid("invalid Caddy site file name"));
    }
    if !fs::symlink_metadata(sites)?.is_dir() {
        return Err(invalid("Caddy sites path is not a directory"));
    }
    Ok(sites.join(format!("{name}.caddy")))
}

fn make_private_directory(path: &Path) -> io::Result<()> {
    let mut dir = DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        dir.mode(0o700);
    }
    dir.create(path)
}

fn optional_metadata(path: &Path) -> io::Result<Option<Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(meta) => Ok(Some(meta)),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

fn same_file(existing: &Path, metadata: &Metadata, staged: &Path) -> io::Result<bool> {
    let staged_meta = fs::symlink_metadata(staged)?;
    if !metadata.is_file() || !staged_meta.is_file() {
        return Ok(false);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let _ = existing;
        Ok(metadata.dev() == staged_meta.dev() && metadata.ino() == staged_meta.ino())
    }
    #[cfg(not(unix))]
    {
        // The installed panel only runs on Linux. Retain a conservative
        // file-content comparison for native development/test builds.
        Ok(fs::read(existing)? == fs::read(staged)?)
    }
}

fn clean_pending(pending: &Path) {
    if let Err(err) = fs::remove_dir_all(pending) {
        crate::util::logf(&format!(
            "config-transaction: file operation completed but could not clean {}: {err}",
            pending.display()
        ));
    }
}

fn begin(sites: &Path, name: &str, change: Change, contents: &[u8]) -> io::Result<()> {
    let site = site_path(sites, name)?;
    let pending = sites.join(PENDING);
    make_private_directory(&pending).map_err(|err| {
        if err.kind() == ErrorKind::AlreadyExists {
            conflict("a Caddy site transaction is already pending; inspect .site-transaction before retrying")
        } else {
            err
        }
    })?;
    let stage = || {
        fs::write(pending.join(RECORD), format!("{}\n{name}\n", change.label()))?;
        let snapshot = pending.join(SNAPSHOT);
        match change {
            Change::Add => {
                // The published file and snapshot share an inode. Keep a
                // separate reference to detect in-place edits before rollback.
                fs::write(pending.join(REFERENCE), contents)?;
                let mut candidate = File::create(&snapshot)?;
                candidate.write_all(contents)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    candidate.set_permissions(fs::Permissions::from_mode(0o644))?;
                }
                candidate.sync_all()?;
                drop(candidate);
                // Atomic and does not overwrite an existing site.
                fs::hard_link(snapshot, site)
            }
            Change::Remove => {
                if !fs::symlink_metadata(&site)?.is_file() {
                    return Err(invalid("Caddy site is not a regular file"));
                }
                // Same filesystem: retain original inode, metadata and bytes.
                fs::rename(site, snapshot)
            }
        }
    };
    if let Err(err) = stage() {
        clean_pending(&pending);
        return Err(err);
    }
    Ok(())
}

fn finish(sites: &Path, name: &str, rollback: bool) -> io::Result<()> {
    let site = site_path(sites, name)?;
    let pending = sites.join(PENDING);
    if !fs::symlink_metadata(&pending)?.is_dir() {
        return Err(invalid("Caddy transaction state is not a directory"));
    }
    let record = fs::read_to_string(pending.join(RECORD))?;
    let change = [Change::Add, Change::Remove]
        .into_iter()
        .find(|change| record == format!("{}\n{name}\n", change.label()))
        .ok_or_else(|| invalid("pending transaction does not match the requested Caddy site"))?;
    let snapshot = pending.join(SNAPSHOT);
    let meta = optional_metadata(&site)?;
    let mut same = match &meta {
        Some(meta) => same_file(&site, meta, &snapshot)?,
        None => false,
    };
    if same && change == Change::Add {
        let reference = fs::read(pending.join(REFERENCE))?;
        let live = File::open(&site)?;
        let mut bytes = Vec::new();
        live.take((reference.len() + 1) as u64).read_to_end(&mut bytes)?;
        same = bytes == reference;
    }
    match (change, rollback) {
        (Change::Add, true) => {
            if same {
                fs::remove_file(&site)?;
            } else if meta.is_some() {
                return Err(conflict("Caddy site changed since activation; keeping transaction files"));
            }
        }
        (Change::Remove, true) => {
            if !same {
                // No-clobber recovery. A newly created file is preserved.
                fs::hard_link(&snapshot, &site)?;
            }
        }
        (Change::Add, false) if !same => {
            return Err(conflict("activated Caddy site changed; keeping transaction files"));
        }
        (Change::Remove, false) if meta.is_some() => {
            return Err(conflict("removed Caddy site was recreated; keeping transaction files"));
        }
        _ => {}
    }
    clean_pending(&pending);
    Ok(())
}

fn read_candidate(input: impl Read) -> io::Result<Vec<u8>> {
    let mut contents = Vec::new();
    input.take((MAX_CANDIDATE + 1) as u64).read_to_end(&mut contents)?;
    if contents.is_empty() || contents.len() > MAX_CANDIDATE {
        return Err(invalid("Caddy candidate is empty or exceeds 64 KiB"));
    }
    Ok(contents)
}

pub fn run(args: &[String]) {
    let [operation, dir, name] = args else {
        eprintln!("usage: caddy-abuseguard config-transaction add|remove|commit|rollback SITES_DIR SITE");
        std::process::exit(2);
    };
    let sites = Path::new(dir);
    let result = match operation.as_str() {
        "add" => read_candidate(io::stdin().lock())
            .and_then(|contents| begin(sites, name, Change::Add, &contents)),
        "remove" => begin(sites, name, Change::Remove, &[]),
        "commit" => finish(sites, name, false),
        "rollback" => finish(sites, name, true),
        _ => {
            eprintln!("usage: caddy-abuseguard config-transaction add|remove|commit|rollback SITES_DIR SITE");
            std::process::exit(2);
        }
    };
    if let Err(err) = result {
        crate::util::fatalf(&format!("config-transaction {operation}: {err}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;

    #[test]
    fn add_can_commit_or_roll_back_without_overwriting_existing_site() {
        let dir = TempDir::new("site-add");
        let sites = dir.path();
        let site = dir.join("example.com.caddy");
        begin(sites, "example.com", Change::Add, b"candidate").unwrap();
        assert_eq!(fs::read(&site).unwrap(), b"candidate");
        assert!(begin(sites, "other.example", Change::Add, b"other").is_err());
        assert!(finish(sites, "other.example", true).is_err());
        finish(sites, "example.com", true).unwrap();
        assert!(!site.exists());
        assert!(!dir.join(PENDING).exists());

        begin(sites, "example.com", Change::Add, b"candidate").unwrap();
        finish(sites, "example.com", false).unwrap();
        assert!(begin(sites, "example.com", Change::Add, b"replacement").is_err());
        assert_eq!(fs::read(&site).unwrap(), b"candidate");
        assert!(!dir.join(PENDING).exists());
    }

    #[test]
    fn remove_rollback_restores_old_site_and_commit_discards_snapshot() {
        let dir = TempDir::new("site-remove");
        let sites = dir.path();
        let site = dir.join("example.com.caddy");
        fs::write(&site, b"old site").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&site, fs::Permissions::from_mode(0o640)).unwrap();
        }
        begin(sites, "example.com", Change::Remove, &[]).unwrap();
        assert!(!site.exists());
        finish(sites, "example.com", true).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&site).unwrap().permissions().mode() & 0o777, 0o640);
        }
        assert_eq!(fs::read(&site).unwrap(), b"old site");

        begin(sites, "example.com", Change::Remove, &[]).unwrap();
        finish(sites, "example.com", false).unwrap();
        assert!(!site.exists());
        assert!(!dir.join(PENDING).exists());
    }

    #[test]
    fn rollback_does_not_overwrite_or_delete_a_replacement() {
        let dir = TempDir::new("site-conflict");
        let sites = dir.path();
        let site = dir.join("example.com.caddy");
        begin(sites, "example.com", Change::Add, b"candidate").unwrap();
        fs::remove_file(&site).unwrap();
        fs::write(&site, b"replacement").unwrap();
        assert!(finish(sites, "example.com", true).is_err());
        assert_eq!(fs::read(&site).unwrap(), b"replacement");
        fs::remove_file(&site).unwrap();
        finish(sites, "example.com", true).unwrap();

        fs::write(&site, b"old site").unwrap();
        begin(sites, "example.com", Change::Remove, &[]).unwrap();
        fs::write(&site, b"replacement").unwrap();
        assert!(finish(sites, "example.com", true).is_err());
        assert_eq!(fs::read(&site).unwrap(), b"replacement");
        assert_eq!(fs::read(dir.join(PENDING).join(SNAPSHOT)).unwrap(), b"old site");
    }

    #[test]
    fn rollback_does_not_remove_an_in_place_edit() {
        let dir = TempDir::new("site-edit");
        let sites = dir.path();
        let site = dir.join("example.com.caddy");
        begin(sites, "example.com", Change::Add, b"candidate").unwrap();
        fs::write(&site, b"changed").unwrap();

        assert!(finish(sites, "example.com", true).is_err());
        assert_eq!(fs::read(&site).unwrap(), b"changed");
        assert!(dir.join(PENDING).is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_sites_directory() {
        let dir = TempDir::new("site-dir");
        let original = dir.join("original");
        let link = dir.join("linked");
        fs::create_dir(&original).unwrap();
        std::os::unix::fs::symlink(&original, &link).unwrap();

        assert!(begin(&link, "example.com", Change::Add, b"candidate").is_err());
        assert!(fs::read_dir(&original).unwrap().next().is_none());
    }

    #[test]
    fn unsafe_names_and_invalid_candidate_size_are_rejected_without_writes() {
        let dir = TempDir::new("site-names");
        for name in ["", ".", "../example", "dir/example", "_placeholder", "example\ncom"] {
            assert!(begin(dir.path(), name, Change::Add, b"candidate").is_err());
        }
        assert!(read_candidate(&[][..]).is_err());
        assert!(read_candidate(io::repeat(b'a').take((MAX_CANDIDATE + 1) as u64)).is_err());
        assert!(fs::read_dir(dir.path()).unwrap().next().is_none());
    }
}
