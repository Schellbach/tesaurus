//! Call-site lock for the dumb public assembler. Not a type-system TCB seal.

use std::fs;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("tesaurus-agent is a workspace member")
        .to_path_buf()
}

fn walk_rs(path: &Path, out: &mut Vec<PathBuf>) {
    if path.is_dir() {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name == "target" {
            return;
        }
        for entry in fs::read_dir(path).expect("read dir") {
            walk_rs(&entry.expect("dir entry").path(), out);
        }
        return;
    }
    if path.extension().and_then(|e| e.to_str()) == Some("rs") {
        out.push(path.to_path_buf());
    }
}

fn ident_hits(ident: &str) -> Vec<(PathBuf, usize, String)> {
    let root = workspace_root();
    let mut files = Vec::new();
    walk_rs(&root.join("tesaurus-policy"), &mut files);
    walk_rs(&root.join("tesaurus-agent"), &mut files);
    let mut hits = Vec::new();
    for path in files {
        let text = fs::read_to_string(&path).expect("read rust");
        for (i, line) in text.lines().enumerate() {
            let mut rest = line;
            while let Some(pos) = rest.find(ident) {
                let after = &rest[pos + ident.len()..];
                let continues = after
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
                if continues {
                    rest = &rest[pos + ident.len()..];
                    continue;
                }
                hits.push((path.clone(), i + 1, line.to_string()));
                break;
            }
        }
    }
    hits
}

fn rel(path: &Path) -> String {
    path.strip_prefix(workspace_root())
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[test]
fn view_assembler_call_sites() {
    let ident = concat!("from_agent_", "tcb");
    let hits = ident_hits(ident);
    assert!(
        hits.iter()
            .any(|(p, _, _)| rel(p) == "tesaurus-policy/src/facts.rs"),
        "view assembler must be defined in tesaurus-policy/src/facts.rs"
    );
    assert!(
        hits.iter()
            .any(|(p, _, _)| rel(p) == "tesaurus-agent/src/chain.rs"),
        "view assembler must be called from tesaurus-agent/src/chain.rs"
    );
    for (path, line, text) in &hits {
        let r = rel(path);
        assert!(
            r == "tesaurus-policy/src/facts.rs" || r == "tesaurus-agent/src/chain.rs",
            "view assembler is a dumb public assembler; unexpected {r}:{line}: {text}"
        );
    }
}

#[test]
fn auth_assembler_call_sites() {
    let ident = concat!("from_agent_tcb_", "mac_unspecified");
    let hits = ident_hits(ident);
    assert!(
        hits.iter()
            .any(|(p, _, _)| rel(p) == "tesaurus-policy/src/facts.rs"),
        "auth assembler must be defined in tesaurus-policy/src/facts.rs"
    );
    assert!(
        hits.iter()
            .any(|(p, _, _)| rel(p) == "tesaurus-agent/src/auth.rs"),
        "auth assembler must be called from tesaurus-agent/src/auth.rs"
    );
    for (path, line, text) in &hits {
        let r = rel(path);
        assert!(
            r == "tesaurus-policy/src/facts.rs" || r == "tesaurus-agent/src/auth.rs",
            "auth assembler unexpected {r}:{line}: {text}"
        );
    }
}

#[test]
fn agent_test_harness_is_not_a_production_dependency() {
    let root = workspace_root();
    let mut bad = Vec::new();
    fn walk_toml(path: &Path, bad: &mut Vec<String>) {
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == "target" {
                return;
            }
            for entry in fs::read_dir(path).expect("read dir") {
                walk_toml(&entry.expect("dir entry").path(), bad);
            }
            return;
        }
        if path.file_name().and_then(|n| n.to_str()) != Some("Cargo.toml") {
            return;
        }
        let text = fs::read_to_string(path).expect("read toml");
        let mut section = String::new();
        for (i, line) in text.lines().enumerate() {
            let trimmed = line.trim();
            if let Some(inner) = trimmed.strip_prefix('[') {
                if let Some(name) = inner.strip_suffix(']') {
                    section = name.trim().to_string();
                    continue;
                }
            }
            if section == "dependencies" && line.contains("agent-test-harness") {
                bad.push(format!("{}:{}:{line}", path.display(), i + 1));
            }
        }
    }
    walk_toml(&root, &mut bad);
    assert!(
        bad.is_empty(),
        "agent-test-harness under [dependencies] bypasses AUTH:\n{}",
        bad.join("\n")
    );
}
