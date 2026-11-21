//! Migrate the project's legacy Caddyfile sites to a private candidate tree.
//! Caddy, not this scanner, validates the assembled configuration.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

const MAX_CADDYFILE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Token<'a> {
    Bare(&'a str),
    Literal,
}

#[derive(Default)]
struct LexState<'a> {
    quote: Option<char>,
    heredoc: Option<&'a str>,
    continuation: bool,
}

struct Line<'a> {
    raw: &'a str,
    tokens: Vec<Token<'a>>,
    continued: bool,
    continues: bool,
}

impl<'a> LexState<'a> {
    fn line(&mut self, raw: &'a str, first: bool) -> Line<'a> {
        let mut code = raw.trim_end_matches(['\n', '\r']);
        if first {
            code = code.strip_prefix('\u{feff}').unwrap_or(code);
        }
        let mut tokens = Vec::new();
        let mut continued = std::mem::take(&mut self.continuation) || self.quote.is_some();
        if let Some(marker) = self.heredoc {
            continued = true;
            // Inside a heredoc only the terminator is structural. Anything
            // on its closing line is still part of the originating directive.
            if let Some(rest) = code.trim_start().strip_prefix(marker) {
                if rest.is_empty() || rest.starts_with(char::is_whitespace) {
                    self.heredoc = None;
                    code = rest;
                } else {
                    return Line { raw, tokens, continued, continues: false };
                }
            } else {
                return Line { raw, tokens, continued, continues: false };
            }
        }

        let mut bare_start = None;
        let mut chars = code.char_indices().peekable();
        while let Some((position, c)) = chars.next() {
            if let Some(quote) = self.quote {
                if quote == '"' && c == '\\' && chars.peek().is_some() {
                    // The following rune cannot terminate a double-quoted token.
                    chars.next();
                } else if c == quote {
                    self.quote = None;
                }
                continue;
            }
            if c.is_whitespace() {
                if let Some(start) = bare_start.take() {
                    tokens.push(Token::Bare(&code[start..position]));
                }
            } else if bare_start.is_none() {
                match c {
                    '#' => break, // comments begin only at a token boundary
                    '"' | '`' => {
                        self.quote = Some(c);
                        tokens.push(Token::Literal);
                    }
                    _ => bare_start = Some(position),
                }
            }
        }
        if let Some(start) = bare_start {
            let last = &code[start..];
            if last == "\\" && code[..start].ends_with([' ', '\t']) {
                self.continuation = true;
            } else if let Some(marker) = last.strip_prefix("<<").filter(|marker| {
                !marker.is_empty()
                    && marker.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
            }) {
                if raw.ends_with('\n') {
                    self.heredoc = Some(marker);
                }
                tokens.push(Token::Literal);
            } else {
                tokens.push(Token::Bare(last));
            }
        }
        Line { raw, tokens, continued, continues: self.continuation }
    }
}

#[derive(PartialEq, Eq)]
enum Directive {
    Other,
    ReverseProxy,
    ImportProtection,
    SiteMarker,
    Probe,
    ProbeMarker,
    ProtectionLog,
}

impl Line<'_> {
    fn directive(&self) -> Directive {
        use Token::Bare;
        if self.continued {
            return Directive::Other;
        }
        if matches!(self.tokens.first(), Some(Bare("reverse_proxy"))) {
            return Directive::ReverseProxy;
        }
        if self.continues {
            return Directive::Other;
        }
        match self.tokens.as_slice() {
            [Bare("import"), Bare("abuseguard" | "caddy_abuseguard_log")] => {
                Directive::ImportProtection
            }
            [Bare("log_append"), Bare("caddy_abuseguard_site"), Bare("protected")] => {
                Directive::SiteMarker
            }
            [Bare("@caddy_abuseguard_probe"), Bare("path"), ..] => Directive::Probe,
            [Bare("log_append"), Bare("@caddy_abuseguard_probe"), Bare("caddy_abuseguard_probe"), Bare("web-probe")] => {
                Directive::ProbeMarker
            }
            [Bare("log"), Bare("caddy_abuseguard"), Bare("{"), ..] => Directive::ProtectionLog,
            _ => Directive::Other,
        }
    }

    fn is_legacy_comment(&self) -> bool {
        if self.continued {
            return false;
        }
        self.raw.trim().strip_prefix('#').is_some_and(|comment| {
            matches!(
                comment.trim(),
                "These fixed markers let Fail2Ban classify protected traffic without"
                    | "retaining the site's host name or the requested path in the access log."
                    | "retaining the site’s host name or the requested path in the access log."
            )
        })
    }
}

fn is_domain(value: &str) -> bool {
    value.len() <= 253
        && value.contains('.')
        && value.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

fn keep_protected_block(value: &str) -> bool {
    if let Some(name) = value.strip_prefix('(').and_then(|s| s.strip_suffix(')')) {
        return !name.is_empty() && !name.contains(['(', ')']);
    }
    value.strip_prefix("http://127.0.0.1").is_some_and(|tail| {
        tail.is_empty()
            || tail.strip_prefix(':').is_some_and(|port| {
                !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit())
            })
    })
}

fn append_line(output: &mut String, line: &str) {
    output.push_str(line);
    if !line.ends_with('\n') {
        output.push('\n');
    }
}

fn depth_after(tokens: &[Token<'_>], mut depth: usize) -> Result<usize, &'static str> {
    for (index, token) in tokens.iter().enumerate() {
        match token {
            Token::Bare("{") => depth += 1,
            Token::Bare("}") => {
                depth = depth.checked_sub(1).ok_or("unexpected closing brace")?;
                if depth == 0 && index + 1 != tokens.len() {
                    return Err("content after closing brace on the same line");
                }
            }
            _ => {}
        }
    }
    Ok(depth)
}

#[derive(Debug, PartialEq, Eq)]
struct Site {
    domain: String,
    contents: String,
}

#[derive(Default, Debug, PartialEq, Eq)]
struct Plan {
    main: String,
    sites: Vec<Site>,
}

fn render_block(
    lines: &[Line<'_>],
    simple_address: Option<&str>,
    occupied: &mut HashSet<String>,
    plan: &mut Plan,
) -> Result<(), String> {
    let protected = lines.iter().any(|line| {
        matches!(
            line.directive(),
            Directive::ImportProtection | Directive::SiteMarker | Directive::ProtectionLog
        )
    });
    let domain = simple_address.filter(|address| is_domain(address));
    let proxy = lines.iter().any(|line| line.directive() == Directive::ReverseProxy);
    if (!protected && !(proxy && domain.is_some()))
        || simple_address.is_some_and(keep_protected_block)
    {
        for line in lines {
            append_line(&mut plan.main, line.raw);
        }
        return Ok(());
    }

    let Some(domain) = domain else {
        let raw = lines[0].raw;
        let header = raw.split_once('#').map_or(raw, |(text, _)| text).trim();
        return Err(format!("cannot migrate protected non-single-domain block: {header}"));
    };
    let domain = domain.to_ascii_lowercase();
    let filename = format!("{domain}.caddy");
    if !occupied.insert(filename.clone()) {
        return Err(format!("cannot migrate protected site; target already exists: {filename}"));
    }

    let mut contents = String::new();
    append_line(&mut contents, lines[0].raw);
    contents.push_str("\timport abuseguard\n");
    let mut log_depth = 0;
    for line in &lines[1..] {
        if log_depth > 0 {
            log_depth = depth_after(&line.tokens, log_depth)
                .map_err(|e| format!("cannot migrate legacy protection log: {e}"))?;
            continue;
        }
        match line.directive() {
            Directive::ImportProtection
            | Directive::SiteMarker
            | Directive::Probe
            | Directive::ProbeMarker => {}
            Directive::ProtectionLog => {
                log_depth = depth_after(&line.tokens[2..], 0)
                    .map_err(|e| format!("cannot migrate legacy protection log: {e}"))?;
            }
            _ if line.is_legacy_comment() => {}
            _ => append_line(&mut contents, line.raw),
        }
    }
    if log_depth != 0 {
        return Err("cannot migrate legacy protection log: unclosed log block".into());
    }
    plan.sites.push(Site { domain, contents });
    Ok(())
}

fn plan_migration(input: &str, mut occupied: HashSet<String>) -> Result<Plan, String> {
    use Token::Bare;
    let mut plan = Plan::default();
    let mut state = LexState::default();
    let mut block = Vec::new();
    let mut depth = 0;
    let mut simple_address = None;
    let mut pending_addresses = false;
    for (index, raw) in input.split_inclusive('\n').enumerate() {
        let line = state.line(raw, index == 0);
        let has_brace = line.tokens.iter().any(|token| matches!(token, Bare("{" | "}")));
        if depth == 0 && !has_brace {
            if let Some(last) = line.tokens.last() {
                pending_addresses = matches!(last, Bare(token) if token.ends_with(','))
                    || state.continuation;
            }
            append_line(&mut plan.main, raw);
            continue;
        }
        if depth == 0 {
            simple_address = match line.tokens.as_slice() {
                [Bare(address), Bare("{")] if !pending_addresses && !line.continued => Some(*address),
                _ => None,
            };
            pending_addresses = false;
        }
        depth = depth_after(&line.tokens, depth)
            .map_err(|message| format!("cannot migrate malformed Caddyfile: {message} on line {}", index + 1))?;
        block.push(line);
        if depth == 0 {
            render_block(&block, simple_address, &mut occupied, &mut plan)?;
            block.clear();
        }
    }

    if state.quote.is_some() || state.heredoc.is_some() {
        return Err("cannot migrate malformed Caddyfile: unterminated quoted value or heredoc".into());
    }
    if depth != 0 {
        return Err("cannot migrate malformed Caddyfile: unclosed top-level block".into());
    }
    Ok(plan)
}

fn occupied_sites(dir: &Path) -> io::Result<HashSet<String>> {
    let mut names = HashSet::new();
    match fs::read_dir(dir) {
        Ok(entries) => {
            for entry in entries {
                // Even dangling symlinks and non-file entries reserve their names.
                if let Some(name) = entry?.file_name().to_str() {
                    let canonical = name.to_ascii_lowercase();
                    if canonical.ends_with(".caddy") {
                        names.insert(canonical);
                    }
                }
            }
        }
        Err(e) if matches!(e.kind(), io::ErrorKind::NotFound | io::ErrorKind::NotADirectory) => {}
        Err(e) => return Err(e),
    }
    Ok(names)
}

fn read_input(path: &Path) -> Result<String, String> {
    let missing = |e| format!("missing Caddyfile: {} ({e})", path.display());
    if !fs::metadata(path).map_err(missing)?.is_file() {
        return Err(format!("missing Caddyfile: {}", path.display()));
    }
    let file = File::open(path).map_err(missing)?;
    let mut input = String::new();
    file.take(MAX_CADDYFILE_BYTES + 1)
        .read_to_string(&mut input)
        .map_err(|e| format!("cannot read Caddyfile {}: {e}", path.display()))?;
    if input.len() as u64 > MAX_CADDYFILE_BYTES {
        return Err(format!("Caddyfile exceeds {MAX_CADDYFILE_BYTES} bytes: {}", path.display()));
    }
    Ok(input)
}

fn write_outputs(input: &Path, main: &str, sites: &Path, plan: &Plan) -> Result<(), String> {
    let main_path = Path::new(main);
    let canonical_input = fs::canonicalize(input).map_err(|e| e.to_string())?;
    if fs::canonicalize(main_path).is_ok_and(|path| path == canonical_input) {
        return Err("destination Caddyfile is the input Caddyfile".into());
    }
    let main_name = main_path.file_name().ok_or("missing destination Caddyfile name")?;
    let occupied = occupied_sites(sites).map_err(|e| format!("cannot read {}: {e}", sites.display()))?;
    for site in &plan.sites {
        let name = format!("{}.caddy", site.domain);
        if occupied.contains(&name) {
            return Err(format!("cannot migrate protected site; target already exists: {name}"));
        }
    }
    fs::create_dir_all(sites).map_err(|e| format!("cannot create {}: {e}", sites.display()))?;
    let canonical_sites = fs::canonicalize(sites).map_err(|e| e.to_string())?;
    let main_parent = main_path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let canonical_main_parent = fs::canonicalize(main_parent)
        .map_err(|e| format!("cannot access {}: {e}", main_parent.display()))?;
    let canonical_main = canonical_main_parent.join(main_name);
    let canonical_main = canonical_main.to_str().ok_or("destination Caddyfile path must be UTF-8")?;
    let mut created = Vec::new();
    let result = (|| {
        for site in &plan.sites {
            let name = format!("{}.caddy", site.domain);
            if canonical_main_parent == canonical_sites && main_path.file_name().is_some_and(|n| n == name.as_str()) {
                return Err("destination Caddyfile conflicts with a generated site".into());
            }
            let path = sites.join(name);
            let mut file = OpenOptions::new().write(true).create_new(true).open(&path)
                .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
            created.push(path);
            file.write_all(site.contents.as_bytes())
                .map_err(|e| format!("cannot write generated site {}: {e}", site.domain))?;
        }
        crate::util::write_file_atomic(canonical_main, plan.main.as_bytes(), 0o644)
            .map_err(|e| format!("cannot write {main}: {e}"))
    })();
    if result.is_err() {
        for path in created {
            let _ = fs::remove_file(path);
        }
    }
    result
}

fn report_failure(message: &str, status: i32) -> ! {
    eprintln!("{message}");
    std::process::exit(status);
}

pub fn run(args: &[String]) {
    let (input, existing_sites, output_paths) = match args {
        [flag, input, existing_sites] if flag == "--plan" => (input, existing_sites, None),
        [input, output_main, output_sites, existing_sites] if input != "--plan" => {
            (input, existing_sites, Some((output_main, output_sites)))
        }
        _ => report_failure(
            "usage: migrate-caddy-sites INPUT OUTPUT_MAIN OUTPUT_SITES EXISTING_SITES | migrate-caddy-sites --plan INPUT EXISTING_SITES",
            2,
        ),
    };
    let input_path = Path::new(input);
    let input = read_input(input_path).unwrap_or_else(|e| report_failure(&e, 2));
    let existing = occupied_sites(Path::new(existing_sites))
        .unwrap_or_else(|e| report_failure(&format!("cannot read {existing_sites}: {e}"), 2));
    let plan = plan_migration(&input, existing).unwrap_or_else(|e| report_failure(&e, 3));
    if let Some((output_main, output_sites)) = output_paths {
        write_outputs(input_path, output_main, Path::new(output_sites), &plan)
            .unwrap_or_else(|e| report_failure(&e, 2));
    }
    let mut output = io::stdout().lock();
    for site in plan.sites {
        if writeln!(output, "{}", site.domain).is_err() {
            report_failure("cannot write migrated site names", 2);
        }
    }
    if output.flush().is_err() {
        report_failure("cannot write migrated site names", 2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrates_legacy_log_once_and_keeps_nested_routes() {
        let input = "(shared) {\n\timport abuseguard\n}\nEXAMPLE.test {\n\timport abuseguard\n\tlog caddy_abuseguard {\n\t\toutput file /tmp/test {\n\t\t\tmode 0640\n\t\t}\n\t}\n\thandle /sub/* {\n\t\treverse_proxy localhost:3000\n\t}\n}\n";
        let plan = plan_migration(input, HashSet::new()).unwrap();
        assert_eq!(plan.main, "(shared) {\n\timport abuseguard\n}\n");
        assert_eq!(plan.sites.len(), 1);
        assert_eq!(plan.sites[0].domain, "example.test");
        assert_eq!(plan.sites[0].contents, "EXAMPLE.test {\n\timport abuseguard\n\thandle /sub/* {\n\t\treverse_proxy localhost:3000\n\t}\n}\n");
    }

    #[test]
    fn ambiguous_or_duplicate_destinations_fail_during_planning() {
        let duplicate = "Example.test {\n reverse_proxy localhost:3000\n}\nexample.test {\n import abuseguard\n}\n";
        assert!(plan_migration(duplicate, HashSet::new()).unwrap_err().contains("target already exists: example.test.caddy"));
        let multiline = "example.test,\nother.test {\n import abuseguard\n}\n";
        assert!(plan_migration(multiline, HashSet::new()).unwrap_err().contains("non-single-domain"));
        let unprotected = "example.test,\nother.test {\n reverse_proxy localhost:3000\n}\n";
        let plan = plan_migration(unprotected, HashSet::new()).unwrap();
        assert!(plan.sites.is_empty());
        assert_eq!(plan.main, unprotected);
    }

    #[test]
    fn ignores_braces_and_directive_like_text_inside_literals() {
        let input = r#"example.test {
    # this comment has a }
    respond "a { followed by # and a multiline
    import abuseguard
    }"
    respond `raw {
        }
    `
    respond <<END
    }
    import abuseguard
    END
    header X-Test {http.request.uri.path}
    reverse_proxy 127.0.0.1:3000
}
"#;
        let plan = plan_migration(input, HashSet::new()).unwrap();
        assert!(plan.main.is_empty());
        assert_eq!(plan.sites[0].contents, input.replacen("example.test {\n", "example.test {\n\timport abuseguard\n", 1));
    }

    #[test]
    fn recognizes_a_reverse_proxy_with_continued_arguments() {
        let input = "one.test {\n reverse_proxy \\\n localhost:3000\n}\n";
        let plan = plan_migration(input, HashSet::new()).unwrap();
        assert_eq!(plan.sites[0].domain, "one.test");
        assert!(plan.sites[0].contents.contains("reverse_proxy \\\n localhost:3000"));
    }

    #[test]
    fn rejects_unclosed_or_unmatched_structure() {
        for input in ["\n}\n", "one.test {\n import abuseguard\n", "one.test {\n respond \"unclosed\n}\n", "one.test {\n respond <<EOF\n}\n"] {
            assert!(plan_migration(input, HashSet::new()).is_err(), "{input}");
        }
    }
}
