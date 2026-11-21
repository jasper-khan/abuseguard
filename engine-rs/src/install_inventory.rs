// Read-only uninstall inventory. Only a complete, root-trusted record can
// authorize a thorough uninstall. Nothing parsed here is executed as shell.
use std::collections::BTreeMap;
use std::path::Path;

const MANIFEST_FIELDS: [&str; 8] = [
    "caddy_bin_preexisting",
    "caddy_service_preexisting",
    "caddy_user_preexisting",
    "abuseguard_user_preexisting",
    "caddyfile_preexisting",
    "caddy_etc_preexisting",
    "log_dir_preexisting",
    "caddy_lib_preexisting",
];

const PACKAGE_FIELDS: [&str; 5] = [
    "nginx_preexisting",
    "nginx_core_preexisting",
    "nginx_common_preexisting",
    "certbot_preexisting",
    "certbot_dns_cloudflare_preexisting",
];

fn records(text: &str) -> Option<BTreeMap<&str, &str>> {
    let mut fields = BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line.split_once('=')?;
        if key.is_empty() || value.is_empty() || fields.insert(key, value).is_some() {
            return None;
        }
    }
    Some(fields)
}

fn bit(value: &str) -> Option<&'static str> {
    match value {
        "0" => Some("0"),
        "1" => Some("1"),
        _ => None,
    }
}

fn proxy(value: &str) -> Option<&'static str> {
    match value {
        "caddy" => Some("caddy"),
        "nginx" => Some("nginx"),
        _ => None,
    }
}

fn manifest(text: &str) -> Option<(&'static str, [&'static str; 8])> {
    let fields = records(text)?;
    if fields.get("version") != Some(&"1") || fields.len() != MANIFEST_FIELDS.len() + 2 {
        return None;
    }
    let mode = proxy(fields.get("web_server")?)?;
    let mut flags = ["1"; MANIFEST_FIELDS.len()];
    for (flag, key) in flags.iter_mut().zip(MANIFEST_FIELDS) {
        *flag = bit(fields.get(key)?)?;
    }
    Some((mode, flags))
}

fn packages(text: &str) -> Option<[&'static str; 5]> {
    let fields = records(text)?;
    if fields.get("version") != Some(&"1") {
        return None;
    }
    for (&key, &value) in &fields {
        if key == "version" {
            continue;
        }
        if (!PACKAGE_FIELDS.contains(&key) && key != "nginx_any_preexisting")
            || (value != "unknown" && bit(value).is_none())
        {
            return None;
        }
    }
    Some(PACKAGE_FIELDS.map(|key| fields.get(key).and_then(|value| bit(value)).unwrap_or("unknown")))
}

fn inventory(mode: Option<&str>, manifest_text: Option<&str>, packages_text: Option<&str>) -> String {
    let mode = mode
        .and_then(|text| proxy(text.trim_end_matches('\n')))
        .unwrap_or("unknown");
    let manifest_flags = manifest_text
        .and_then(manifest)
        .filter(|(manifest_mode, _)| *manifest_mode == mode)
        .map(|(_, flags)| flags);
    let package_flags = if manifest_flags.is_some() && mode == "nginx" {
        packages_text.and_then(packages).unwrap_or(["unknown"; PACKAGE_FIELDS.len()])
    } else {
        ["unknown"; PACKAGE_FIELDS.len()]
    };

    let status = if manifest_flags.is_some() { "verified" } else { "unknown" };
    let mut row = vec!["v1", mode, status];
    row.extend(manifest_flags.unwrap_or(["1"; MANIFEST_FIELDS.len()]));
    row.extend(package_flags);
    row.join("|")
}

#[cfg(target_os = "linux")]
fn read_trusted(path: &Path, owner: u32) -> Option<String> {
    use rustix::fs::{open, openat, Mode, OFlags};
    use std::fs::File;
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;

    const MAX_SIZE: u64 = 4096;
    let lock_flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
    let parent = File::from(open(path.parent()?, lock_flags | OFlags::DIRECTORY, Mode::empty()).ok()?);
    let dir = parent.metadata().ok()?;
    if dir.uid() != owner || dir.mode() & 0o022 != 0 {
        return None;
    }
    let file = File::from(openat(&parent, path.file_name()?, lock_flags, Mode::empty()).ok()?);
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.uid() != owner || meta.mode() & 0o022 != 0 || meta.len() > MAX_SIZE {
        return None;
    }
    let mut data = String::new();
    file.take(MAX_SIZE + 1).read_to_string(&mut data).ok()?;
    (data.len() as u64 <= MAX_SIZE).then_some(data)
}

#[cfg(not(target_os = "linux"))]
fn read_trusted(_path: &Path, _owner: u32) -> Option<String> {
    None
}

pub fn run(args: &[String]) {
    // Fixed positional schema, no live state reads besides explicit paths.
    let [verb, mode, manifest, packages] = args else {
        eprintln!("usage: caddy-abuseguard install-inventory inspect MODE_FILE MANIFEST PACKAGE_RECORD");
        std::process::exit(2);
    };
    if verb != "inspect" {
        eprintln!("install-inventory: unknown operation");
        std::process::exit(2);
    }
    let mode = read_trusted(Path::new(mode), 0);
    let manifest = read_trusted(Path::new(manifest), 0);
    let packages = read_trusted(Path::new(packages), 0);
    println!(
        "{}",
        inventory(mode.as_deref(), manifest.as_deref(), packages.as_deref())
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(mode: &str) -> String {
        let mut content = format!("version=1\nweb_server={mode}\n");
        for key in MANIFEST_FIELDS {
            content.push_str(&format!("{key}=0\n"));
        }
        content
    }

    #[test]
    fn trusted_manifest_and_packages_only_authorize_exact_known_fields() {
        let manifest = sample("nginx");
        let packages = "version=1\nnginx_preexisting=0\nnginx_common_preexisting=1\nnginx_any_preexisting=unknown\n";
        assert_eq!(
            inventory(Some("nginx\n"), Some(&manifest), Some(packages)),
            "v1|nginx|verified|0|0|0|0|0|0|0|0|0|unknown|1|unknown|unknown"
        );
        let malformed_packages = format!("{packages}nginx_preexisting=0\n");
        assert!(inventory(Some("nginx"), Some(&manifest), Some(&malformed_packages))
            .ends_with("|unknown|unknown|unknown|unknown|unknown"));
    }

    #[test]
    fn absent_unknown_incomplete_duplicate_or_mismatched_inventory_is_conservative() {
        let manifest = sample("caddy");
        let incomplete = manifest.trim_end_matches("caddy_lib_preexisting=0\n");
        let duplicate = format!("{manifest}caddy_lib_preexisting=0\n");
        let unsupported = manifest.replacen("version=1", "version=2", 1);
        let invalid = manifest.replace("caddy_lib_preexisting=0", "caddy_lib_preexisting=0=extra");
        for record in [None, Some(incomplete), Some(&duplicate), Some(&unsupported), Some(&invalid)] {
            assert!(inventory(Some("caddy"), record, None)
                .starts_with("v1|caddy|unknown|1|1|1|1|1|1|1|1|"));
        }
        assert!(inventory(Some("nginx"), Some(&manifest), None).starts_with("v1|nginx|unknown|"));
        assert!(inventory(None, Some(&manifest), None).starts_with("v1|unknown|unknown|"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ownership_read_rejects_symlink_unsafe_modes_and_wrong_owner() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let tmp = crate::testutil::TempDir::new("install-inventory");
        let dir = tmp.path().join("config");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o750)).unwrap();
        let path = dir.join("record");
        std::fs::write(&path, "nginx\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let owner = rustix::process::getuid().as_raw();
        assert_eq!(read_trusted(&path, owner).as_deref(), Some("nginx\n"));
        assert!(read_trusted(&path, owner ^ 1).is_none());

        let link = dir.join("link");
        symlink(&path, &link).unwrap();
        assert!(read_trusted(&link, owner).is_none());
        let dir_link = tmp.path().join("dir-link");
        symlink(&dir, &dir_link).unwrap();
        assert!(read_trusted(&dir_link.join("record"), owner).is_none());

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o664)).unwrap();
        assert!(read_trusted(&path, owner).is_none());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(read_trusted(&path, owner).is_none());
    }
}
