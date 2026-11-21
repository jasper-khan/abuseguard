// Inspection and candidate generation only. The panel still owns sshd's
// native checks, session/firewall ordering, reload, and rollback.
use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

const FILE_LIMIT: u64 = 256 * 1024;
const INPUT_LIMIT: u64 = 2 * 1024 * 1024;
const MAX_DROPINS: usize = 128;

type Result<T> = std::result::Result<T, String>;

#[derive(Clone, Copy, PartialEq)]
enum Auth {
    Password,
    PublicKey,
    KeyboardInteractive,
}

impl Auth {
    fn parse(key: &str) -> Option<Self> {
        if key.eq_ignore_ascii_case("PasswordAuthentication") {
            Some(Self::Password)
        } else if key.eq_ignore_ascii_case("PubkeyAuthentication") {
            Some(Self::PublicKey)
        } else if key.eq_ignore_ascii_case("KbdInteractiveAuthentication") {
            Some(Self::KeyboardInteractive)
        } else {
            None
        }
    }

    fn managed(key: &str) -> Result<Self> {
        match Self::parse(key) {
            Some(auth @ (Self::Password | Self::PublicKey)) => Ok(auth),
            _ => Err("不支持的 SSH 认证指令".into()),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Password => "PasswordAuthentication",
            Self::PublicKey => "PubkeyAuthentication",
            Self::KeyboardInteractive => "KbdInteractiveAuthentication",
        }
    }
}

#[derive(Debug)]
struct Source {
    path: PathBuf,
    contents: String,
}

fn directive(line: &str) -> Option<(&str, &str)> {
    let line = line.trim_start_matches([' ', '\t', '\r']);
    if line.is_empty() || line.starts_with('#') || line == "\n" {
        return None;
    }
    let key_end = line
        .find(|c: char| c.is_ascii_whitespace() || c == '=')
        .unwrap_or(line.len());
    let key = &line[..key_end];
    let arg = line[key_end..].trim_start_matches([' ', '\t']);
    let arg = arg.strip_prefix('=').unwrap_or(arg);
    Some((key, arg.trim_start_matches([' ', '\t'])))
}

// Interpret only single uncomplicated values needed here. Other syntax is
// not guessed: native sshd is authoritative and custom Includes are refused.
fn single_arg(arg: &str) -> Option<&str> {
    let value = if let Some(quoted) = arg.strip_prefix('"') {
        let (value, rest) = quoted.split_once('"')?;
        if !rest.trim().is_empty() && !rest.trim_start().starts_with('#') {
            return None;
        }
        value
    } else {
        let end = arg
            .find(|c: char| c.is_ascii_whitespace() || c == '#')
            .unwrap_or(arg.len());
        let rest = arg[end..].trim_start();
        if !rest.is_empty() && !rest.starts_with('#') {
            return None;
        }
        &arg[..end]
    };
    if value.is_empty() || value.contains(['"', '\'', '\\']) {
        None
    } else {
        Some(value)
    }
}

fn parse_port(value: &str) -> Result<u16> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err("无效的 SSH 端口".into());
    }
    match value.parse() {
        Ok(port) if port > 0 => Ok(port),
        _ => Err("无效的 SSH 端口".into()),
    }
}

fn port_lines(source: &Source) -> Result<Vec<(usize, u16)>> {
    let mut ports = Vec::new();
    let mut conditional = false;
    for (i, (key, arg)) in source.contents.lines().enumerate().filter_map(|(i, line)| {
        directive(line).map(|parsed| (i, parsed))
    }) {
        if key.eq_ignore_ascii_case("Match") {
            conditional = true;
        }
        if !key.eq_ignore_ascii_case("Port") {
            continue;
        }
        let value = single_arg(arg).and_then(|v| parse_port(v).ok());
        let Some(port) = value.filter(|_| !conditional) else {
            return Err(format!("{}:{} 的 Port 指令无法安全处理", source.path.display(), i + 1));
        };
        ports.push((i, port));
    }
    Ok(ports)
}

fn effective_ports(text: &str) -> Result<String> {
    let mut ports = BTreeSet::new();
    for (key, arg) in text.lines().filter_map(directive) {
        if key.eq_ignore_ascii_case("port") {
            ports.insert(parse_port(single_arg(arg).unwrap_or(""))?);
        }
    }
    if ports.is_empty() {
        return Err("sshd 未返回有效端口".into());
    }
    Ok(ports.into_iter().map(|p| format!("{p}\n")).collect())
}

fn effective_auth(text: &str, auth: Auth) -> &'static str {
    let mut matches = text
        .lines()
        .filter_map(directive)
        .filter(|(key, _)| Auth::parse(key) == Some(auth));
    match (matches.next().and_then(|(_, arg)| single_arg(arg)), matches.next()) {
        (Some("yes" | "on"), None) => "on",
        (Some("no" | "off"), None) => "off",
        _ => "unknown",
    }
}

fn read_limited(reader: impl Read, limit: u64) -> Result<String> {
    let mut bytes = Vec::new();
    reader.take(limit + 1).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    if bytes.len() as u64 > limit {
        return Err("SSH 配置超过大小上限".into());
    }
    if bytes.contains(&0) {
        return Err("SSH 配置包含空字节".into());
    }
    String::from_utf8(bytes).map_err(|_| "SSH 配置不是 UTF-8".into())
}

fn open_regular(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    {
        use rustix::fs::OFlags;
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags((OFlags::NOFOLLOW | OFlags::NONBLOCK).bits() as i32);
    }
    if !std::fs::symlink_metadata(path)?.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not a regular file"));
    }
    let f = options.open(path)?;
    if !f.metadata()?.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not a regular file"));
    }
    Ok(f)
}

fn read_source(path: &Path, missing_ok: bool) -> Result<Source> {
    let path_text = path.to_str().ok_or("SSH 配置路径不是 UTF-8")?;
    if path_text.contains(':') || path_text.chars().any(char::is_control) {
        return Err("SSH 配置路径包含不支持的字符".into());
    }
    let contents = match open_regular(path) {
        Ok(f) => read_limited(f, FILE_LIMIT),
        Err(e) if missing_ok && e.kind() == io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(e.to_string()),
    }.map_err(|e| format!("{}：{e}", path.display()))?;
    Ok(Source { path: path.to_owned(), contents })
}

struct Inventory {
    main: Source,
    dropins: Vec<Source>,
    include_line: Option<usize>,
}

fn inventory(main: &Path, dir: &Path) -> Result<Inventory> {
    let main = read_source(main, false)?;
    let glob = dir.join("*.conf");
    let glob = glob.to_str().ok_or("SSH drop-in 路径不是 UTF-8")?;
    let mut include_line = None;
    let mut conditional = false;
    for (i, (key, arg)) in main.contents.lines().enumerate().filter_map(|(i, line)| {
        directive(line).map(|parsed| (i, parsed))
    }) {
        if key.eq_ignore_ascii_case("Match") {
            conditional = true;
        }
        if !key.eq_ignore_ascii_case("Include") {
            continue;
        }
        let known = match single_arg(arg) {
            Some(v) if v == glob => true,
            Some("sshd_config.d/*.conf") if dir == Path::new("/etc/ssh/sshd_config.d") => true,
            _ => false,
        };
        if !known || conditional || include_line.is_some() {
            return Err(format!("{}:{} 含无法安全推断顺序的 Include；请手动管理", main.path.display(), i + 1));
        }
        include_line = Some(i);
    }
    let mut paths = Vec::new();
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{}：{e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("{}：{e}", dir.display()))?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("conf")
            || entry.file_name().as_encoded_bytes().starts_with(b".")
        {
            continue;
        }
        if paths.len() >= MAX_DROPINS {
            return Err("SSH drop-in 文件过多，无法安全检查".into());
        }
        paths.push(path);
    }
    paths.sort();
    let mut dropins = Vec::new();
    for path in paths {
        let source = read_source(&path, false)?;
        if source.contents.lines().filter_map(directive).any(|(key, _)| key.eq_ignore_ascii_case("Include")) {
            return Err(format!("{} 含嵌套 Include；请手动管理", path.display()));
        }
        dropins.push(source);
    }
    Ok(Inventory { main, dropins, include_line })
}

impl Inventory {
    fn sources(&self) -> impl Iterator<Item = &Source> {
        std::iter::once(&self.main).chain(&self.dropins)
    }

    fn port_sites(&self, target: Option<u16>) -> Result<Vec<(&Path, usize, u16)>> {
        let mut sites = Vec::new();
        for source in self.sources() {
            for (i, port) in port_lines(source)? {
                if target.is_none() || target == Some(port) {
                    sites.push((source.path.as_path(), i + 1, port));
                }
            }
        }
        Ok(sites)
    }

    fn auth_conflicts(&self, managed: &Path, auth: Auth) -> Vec<String> {
        let Some(include) = self.include_line else {
            return vec![format!("{} 缺少受支持的全局 Include，面板配置不会生效", self.main.path.display())];
        };
        let mut conflicts = Vec::new();
        for source in self.sources() {
            let mut conditional = false;
            for (i, (key, _)) in source.contents.lines().enumerate().filter_map(|(i, line)| {
                directive(line).map(|parsed| (i, parsed))
            }) {
                if key.eq_ignore_ascii_case("Match") {
                    conditional = true;
                }
                if Auth::parse(key) != Some(auth) {
                    continue;
                }
                let reason = if conditional {
                    "Match 块内，会覆盖面板配置"
                } else if source.path == self.main.path && i < include {
                    "在 Include 之前，先于面板生效"
                } else if source.path != self.main.path && source.path.as_path() < managed {
                    "drop-in 排序在面板之前"
                } else {
                    continue;
                };
                conflicts.push(format!("{}:{}: {}（{reason}）", source.path.display(), i + 1, auth.name()));
            }
        }
        conflicts
    }
}

fn append_line(out: &mut String, line: &str) {
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(line);
    out.push('\n');
}

fn port_candidate(config: &Inventory, managed: &Source, current: u16, new: u16) -> Result<String> {
    if current == new {
        return Err("新旧 SSH 端口相同".into());
    }
    if managed.contents.lines().filter_map(directive).any(|(key, _)| {
        key.eq_ignore_ascii_case("Match") || key.eq_ignore_ascii_case("Include")
    }) {
        return Err("面板 Port 文件含 Match 或 Include，无法安全编辑".into());
    }
    let sites = config.port_sites(None)?;
    let keep_current = match sites.as_slice() {
        [] => true,
        [(path, _, port)] if *port == current => *path == managed.path.as_path(),
        _ => return Err("SSH Port 声明已变化，无法安全添加端口".into()),
    };
    let mut candidate = without_port(managed, None)?;
    if keep_current {
        append_line(&mut candidate, &format!("Port {current}"));
    }
    append_line(&mut candidate, &format!("Port {new}"));
    Ok(candidate)
}

// Filter whole lines, preserving all other text byte-for-byte including CRLF.
fn without_port(source: &Source, port: Option<u16>) -> Result<String> {
    let indexes: BTreeSet<usize> = port_lines(source)?
        .into_iter()
        .filter_map(|(i, p)| (port.is_none() || port == Some(p)).then_some(i))
        .collect();
    if port.is_some() && indexes.is_empty() {
        return Err("未找到要移除的 SSH Port 声明".into());
    }
    Ok(source.contents.split_inclusive('\n').enumerate()
        .filter_map(|(i, line)| (!indexes.contains(&i)).then_some(line))
        .collect())
}

fn auth_candidate(source: &Source, pw: &str, pk: &str) -> Result<String> {
    if !matches!(pw, "yes" | "no" | "") || !matches!(pk, "yes" | "no" | "") {
        return Err("认证开关必须是 yes/no 或留空".into());
    }
    if pw != "yes" && pk != "yes" {
        return Err("无法确认仍保留密码或公钥认证".into());
    }
    let mut out = String::new();
    for line in source.contents.split_inclusive('\n') {
        if let Some((key, _)) = directive(line) {
            if key.eq_ignore_ascii_case("Include") || key.eq_ignore_ascii_case("Match") {
                return Err("面板认证文件含 Match 或 Include，无法安全编辑".into());
            }
            if matches!(Auth::parse(key), Some(Auth::Password | Auth::PublicKey)) {
                continue;
            }
        }
        out.push_str(line);
    }
    for (auth, value) in [(Auth::Password, pw), (Auth::PublicKey, pk)] {
        if !value.is_empty() {
            append_line(&mut out, &format!("{} {value}", auth.name()));
        }
    }
    Ok(out)
}

fn usage() -> &'static str {
    "usage: caddy-abuseguard ssh-admin effective-ports | effective-auth <key> | port-sites <main> <dir> [port] | auth-conflicts <main> <dir> <managed> <key> | render-port-add <main> <dir> <managed> <old> <new> | render-port-remove <file> <port> | render-auth <file> <password> <pubkey>"
}

fn command(args: &[&str], input: impl Read) -> Result<String> {
    match args {
        ["effective-ports"] => effective_ports(&read_limited(input, INPUT_LIMIT)?),
        ["effective-auth", key] => {
            let auth = Auth::parse(key).ok_or("不支持的 SSH 认证指令")?;
            Ok(format!("{}\n", effective_auth(&read_limited(input, INPUT_LIMIT)?, auth)))
        }
        ["port-sites", main, dir] | ["port-sites", main, dir, _] => {
            let target = args.get(3).map(|val| parse_port(val)).transpose()?;
            let config = inventory(Path::new(main), Path::new(dir))?;
            Ok(config.port_sites(target)?.into_iter()
                .map(|(path, line, port)| format!("{}:{line}:Port {port}\n", path.display()))
                .collect())
        }
        ["auth-conflicts", main, dir, managed, key] => {
            let config = inventory(Path::new(main), Path::new(dir))?;
            Ok(config.auth_conflicts(Path::new(managed), Auth::managed(key)?)
                .into_iter().map(|s| format!("{s}\n")).collect())
        }
        ["render-port-add", main, dir, managed, old, new] => {
            let config = inventory(Path::new(main), Path::new(dir))?;
            let managed = read_source(Path::new(managed), true)?;
            port_candidate(&config, &managed, parse_port(old)?, parse_port(new)?)
        }
        ["render-port-remove", file, port] => {
            without_port(&read_source(Path::new(file), false)?, Some(parse_port(port)?))
        }
        ["render-auth", file, password, pubkey] => {
            auth_candidate(&read_source(Path::new(file), true)?, password, pubkey)
        }
        _ => Err(usage().into()),
    }
}

pub fn run(args: &[String]) {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match command(&args, io::stdin().lock()) {
        Ok(body) => {
            if let Err(e) = io::stdout().lock().write_all(body.as_bytes()) {
                crate::util::fatalf(&format!("ssh-admin: {e}"));
            }
        }
        Err(e) => {
            crate::util::logf(&format!("ssh-admin: {e}"));
            std::process::exit(if e == usage() { 2 } else { 1 });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;
    use std::io::Cursor;

    fn fixture() -> (TempDir, PathBuf, PathBuf, PathBuf) {
        let tmp = TempDir::new("ssh-admin");
        let main = tmp.join("sshd_config");
        let dir = tmp.join("sshd_config.d");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(&main, format!("Include {}/*.conf\n", dir.display())).unwrap();
        let managed = dir.join("99-abuseguard-port.conf");
        (tmp, main, dir, managed)
    }

    #[test]
    fn validates_native_effective_output() {
        assert_eq!(effective_ports("port 2222\nport 22\nport 22\n").unwrap(), "22\n2222\n");
        assert!(effective_ports("port 22\nport 65536\n").is_err());
        assert!(effective_ports("listenaddress 0.0.0.0:22\n").is_err());
        assert_eq!(effective_auth("passwordauthentication no\n", Auth::Password), "off");
        assert_eq!(effective_auth("pubkeyauthentication yes\n", Auth::PublicKey), "on");
        assert_eq!(effective_auth("pubkeyauthentication no\npubkeyauthentication yes\n", Auth::PublicKey), "unknown");
        assert_eq!(effective_auth("pubkeyauthentication\n", Auth::PublicKey), "unknown");
        assert!(command(&["effective-ports"], Cursor::new(b"port 22\x00")).is_err());
    }

    #[test]
    fn plans_port_transitions_and_preserves_unrelated_config() {
        let (_tmp, main, dir, managed) = fixture();
        let src = read_source(&managed, true).unwrap();
        assert_eq!(port_candidate(&inventory(&main, &dir).unwrap(), &src, 22, 2222).unwrap(),
            "Port 22\nPort 2222\n");
        std::fs::write(&main, format!("Include {}/*.conf\n  pOrT = 022 # text\n", dir.display())).unwrap();
        assert_eq!(port_candidate(&inventory(&main, &dir).unwrap(), &src, 22, 2222).unwrap(),
            "Port 2222\n");
        assert!(port_candidate(&inventory(&main, &dir).unwrap(), &src, 23, 2222).is_err());
        let port_source = read_source(&main, false).unwrap();
        let removed = without_port(&port_source, Some(22)).unwrap();
        assert_eq!(removed, format!("Include {}/*.conf\n", dir.display()));
        assert!(std::fs::read_to_string(&main).unwrap().contains("pOrT"));
        assert!(!managed.exists());

        let other = Source {
            path: PathBuf::from("test-file"),
            contents: "# keep\r\nPort=2222\r\n# no final newline".into(),
        };
        assert_eq!(without_port(&other, Some(2222)).unwrap(), "# keep\r\n# no final newline");
        assert!(without_port(&other, Some(22)).is_err());
    }

    #[test]
    fn refuses_ambiguous_auth_order_and_keeps_supported_order() {
        let (_tmp, main, dir, _) = fixture();
        let managed = dir.join("00-abuseguard-auth.conf");
        let foreign = dir.join("50-cloud-init.conf");
        std::fs::write(&foreign, "PasswordAuthentication yes\n").unwrap();
        std::fs::write(&main, format!("iNcLuDe=\"{}/*.conf\" # normal\nPasswordAuthentication yes\n", dir.display())).unwrap();
        assert!(inventory(&main, &dir).unwrap().auth_conflicts(&managed, Auth::Password).is_empty());
        std::fs::write(&foreign, "Match User fixture\n  passwordauthentication = no\n").unwrap();
        assert!(inventory(&main, &dir).unwrap().auth_conflicts(&managed, Auth::Password)[0].contains("Match"));
        std::fs::write(dir.join("00-aaa.conf"), "PasswordAuthentication yes\n").unwrap();
        let conflicts = inventory(&main, &dir).unwrap().auth_conflicts(&managed, Auth::Password);
        assert!(conflicts.iter().any(|c| c.contains("00-aaa.conf")));
        std::fs::write(&main, format!("PasswordAuthentication no\nInclude {}/*.conf\n", dir.display())).unwrap();
        let conflicts = inventory(&main, &dir).unwrap().auth_conflicts(&managed, Auth::Password);
        assert!(conflicts[0].contains("Include 之前"));
        std::fs::write(&foreign, "Include fixture.conf\n").unwrap();
        assert!(inventory(&main, &dir).is_err());
        std::fs::write(&main, "Include /other/*.conf\n").unwrap();
        assert!(inventory(&main, &dir).is_err());
    }

    #[test]
    fn renders_auth_without_dropping_nonmanaged_directives() {
        let source = Source {
            path: PathBuf::from("test-file"),
            contents: "passwordauthentication = yes\r\n# retain\r\nOtherValue yes".into(),
        };
        assert_eq!(
            auth_candidate(&source, "no", "yes").unwrap(),
            "# retain\r\nOtherValue yes\nPasswordAuthentication no\nPubkeyAuthentication yes\n"
        );
        assert!(auth_candidate(&source, "no", "no").is_err());
        assert!(auth_candidate(&source, "off", "on").is_err());
        let matched = Source { contents: "Match User fixture\n".into(), ..source };
        assert!(auth_candidate(&matched, "no", "yes").is_err());
    }
}
