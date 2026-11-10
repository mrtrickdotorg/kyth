//! Port of `page_just.py`'s `just --list` / `just <recipe>` launch path.
//!
//! `page_just.py` used a Qt `Worker(["just","--list"])` and `popen(["just",name])`.
//! The Tauri shell keeps the same direct invocation, but its command runner
//! captures output in a background job so the Hub can show progress and the
//! result in-app instead of opening a terminal window.
//!
//! Two things the Qt version got wrong and this one does not:
//!
//! 1. Bare `just` resolves a justfile by walking up from the process working
//!    directory. The Hub's working directory is whatever the `.desktop`
//!    launcher gives it — `/` or `$HOME` — and neither has a justfile, so
//!    `just --list` returned "error: no justfile found" and every recipe
//!    launch was a no-op. Kyth's recipes live in ublue's justfile, which is
//!    exactly what `ujust` exists to point `just` at:
//!    `JUST_JUSTFILE=/usr/share/ublue-os/justfile /usr/bin/just "$@"`.
//!    Setting that variable also makes `just` treat the justfile's parent as
//!    the working directory, so this matches `ujust` exactly (verified
//!    against just 1.58, the version the image ships).
//! 2. Recipes use `sudo`, never `pkexec` (see `build_files/just/kyth/*.just`).
//!    The Hub supplies the graphical askpass helper when available, captures
//!    stdout/stderr, and reports the outcome through its in-app job status.

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use serde::Serialize;

/// The justfile `ujust` points `just` at — see the module docs. Kyth's
/// recipes are imported into it by `branding/31-ujust-recipes.sh`.
pub const UBLUE_JUSTFILE: &str = "/usr/share/ublue-os/justfile";

#[derive(Debug, Clone, Serialize)]
pub struct JustRecipe {
    pub name: String,
    /// Parameters as `just --list` prints them (`flavor="fedora"`), empty for
    /// a recipe that takes none. `run_hub_action` spawns the name with no arguments,
    /// so a non-empty `params` means running it from the Hub would silently
    /// use the defaults — the listing renders those rows as text, not buttons.
    pub params: String,
    pub comment: String,
}

/// Parse `just --list` stdout exactly like `page_just.py:_on_just_list_done`:
/// - drop empty lines and `Available recipes:` header
/// - split each remaining line into `name` + `comment` at first whitespace
/// - keep first 500 (the shipped justfile has ~200 recipes; the React
/// listing filters over the whole set and caps its own display at 30,
/// so cutting the backend list short just hides recipes from the filter)
fn parse_just_list(stdout: &str) -> Vec<JustRecipe> {
    let mut out = Vec::new();
    for raw in stdout.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with("Available recipes:") {
            continue;
        }
        // Every kyth recipe carries `[group('KythOS')]`, so real `just --list`
        // output puts a `[KythOS]` heading line above them. It parses as a
        // name with no parameters, which used to give it a button that spawns
        // `just [KythOS]` and fails. Headings are never runnable.
        if line.starts_with('[') && line.ends_with(']') {
            continue;
        }
        // When a recipe's signature is long, `just --list` prints its doc
        // comment on the line above instead of beside it. That line is not a
        // recipe — parsed as one it becomes a row named `#`, and ublue's
        // `distrobox-assemble`/`distrobox-new` produce two of them, so the
        // listing also got duplicate React keys.
        if line.starts_with('#') {
            continue;
        }
        // `just --list` indents with 4 spaces; after trim we have
        // `name [params]  # comment`. Split at first whitespace for the name
        // (like `ln.split(None,1)` in Python), then at the first `#` to keep
        // parameters out of the comment — page_just.py folded them together,
        // but the React listing needs them apart to decide button vs text.
        let mut parts = line.splitn(2, char::is_whitespace);
        let name = parts.next().unwrap_or("").trim().to_string();
        if name.is_empty() {
            continue;
        }
        let rest = parts.next().unwrap_or("").trim();
        let (params, comment) = match rest.split_once('#') {
            Some((before, after)) => (before.trim().to_string(), after.trim().to_string()),
            None => (rest.to_string(), String::new()),
        };
        out.push(JustRecipe {
            name,
            params,
            comment,
        });
        if out.len() >= 500 {
            break;
        }
    }
    out
}

/// Point `just` at ublue's justfile, exactly as the `ujust` wrapper does.
/// Split out from `configure` so a test can pin the behaviour against a
/// temporary path instead of the real `/usr` one, which is absent off-image.
fn justfile_env_for(justfile: &Path) -> Option<String> {
    justfile
        .is_file()
        .then(|| justfile.to_string_lossy().into_owned())
}

pub fn configure_command(cmd: &mut Command) {
    if let Some(justfile) = justfile_env_for(Path::new(UBLUE_JUSTFILE)) {
        cmd.env("JUST_JUSTFILE", justfile);
    }
}

/// A recipe name (or a fixed argument) is safe to hand to `just` when it is
/// a single bare token. Allowlist rather than a metacharacter blocklist: a
/// just recipe name is alphanumerics, `-` and `_` (Guardian also passes
/// dotted ids like `audio.restart`, which simply do not resolve). The
/// blocklist this replaces let `[KythOS]` through, because brackets are not
/// shell metacharacters — harmless to spawn, but it meant nothing upstream
/// had to be careful about what it handed us.
fn is_bare_token(token: &str) -> bool {
    !token.is_empty()
        && !token.starts_with('-')
        && token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// Build the argv for a captured, in-app launch. Recipe names and arguments
/// are validated as individual tokens before they reach `just`; there is no
/// shell or terminal wrapper in this path.
pub fn command_for(recipe: &str, args: &[&str]) -> Option<Vec<String>> {
    if !is_bare_token(recipe) || !args.iter().all(|arg| is_bare_token(arg)) {
        return None;
    }
    let mut argv = vec!["/usr/bin/just".to_string(), recipe.to_string()];
    argv.extend(args.iter().map(|arg| (*arg).to_string()));
    Some(argv)
}

/// Build a command for a fixed `just` assignment such as
/// `switch-kernel flavor=cachy`. Assignments are kept separate argv values;
/// callers must still choose the exact values rather than forwarding UI text.
pub fn command_for_fixed_assignments(recipe: &str, args: &[(&str, &str)]) -> Option<Vec<String>> {
    if !is_bare_token(recipe)
        || !args
            .iter()
            .all(|(key, value)| is_bare_token(key) && is_bare_token(value))
    {
        return None;
    }
    let mut argv = vec!["/usr/bin/just".to_string(), recipe.to_string()];
    argv.extend(args.iter().map(|(key, value)| format!("{key}={value}")));
    Some(argv)
}

/// Run `just --list` with the justfile `ujust` uses and parse.
///
/// Fallible, preserving the Qt fallback: a non-zero exit that still
/// produced a parseable listing returns that listing (`page_just.py`
/// only showed its "just --list failed" note when both the exit was
/// non-zero AND stdout was empty). A hard failure — the binary could not
/// run, or it failed with nothing parseable — is an `Err`, never an
/// empty vec: the old shape read in the Hub as "No just recipes found"
/// for a `just` that never ran.
pub fn just_list() -> Result<Vec<JustRecipe>, String> {
    let mut cmd = Command::new("/usr/bin/just");
    cmd.arg("--list");
    configure_command(&mut cmd);
    let out = super::process::run_bounded_command(cmd, Duration::from_secs(10))
        .map_err(|err| format!("could not run /usr/bin/just --list: {err}"))?;
    interpret_list_output(
        out.status.success(),
        out.status.code(),
        &String::from_utf8_lossy(&out.stdout),
        &String::from_utf8_lossy(&out.stderr),
    )
}

/// Pure verdict for one `just --list` outcome, split out so the contract
/// is unit-testable without running a real `just`: parseable stdout wins
/// even on a non-zero exit (the Qt fallback); a successful run with no
/// recipes is a legitimate empty `Ok`; a failed run with nothing
/// parseable is an `Err` carrying the exit and stderr — never parse
/// stderr as recipes, and never disguise the failure as an empty list.
fn interpret_list_output(
    success: bool,
    code: Option<i32>,
    stdout: &str,
    stderr: &str,
) -> Result<Vec<JustRecipe>, String> {
    let parsed = parse_just_list(stdout);
    if !parsed.is_empty() {
        return Ok(parsed);
    }
    if success {
        return Ok(Vec::new());
    }
    let stderr = stderr.trim();
    let how = match code {
        Some(code) => format!("just --list failed (exit {code})"),
        None => "just --list was stopped before it finished".to_string(),
    };
    Err(if stderr.is_empty() {
        how
    } else {
        format!("{how}: {stderr}")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic() {
        let out = "Available recipes:\n    build    # Build the full KythOS image.\n    lint     # Run checks\n    foo\n";
        let v = parse_just_list(out);
        assert_eq!(v.len(), 3);
        assert_eq!(v[0].name, "build");
        assert_eq!(v[0].params, "");
        assert_eq!(v[0].comment, "Build the full KythOS image.");
        assert_eq!(v[1].name, "lint");
        assert_eq!(v[1].comment, "Run checks");
        assert_eq!(v[2].name, "foo");
        assert_eq!(v[2].params, "");
        assert_eq!(v[2].comment, "");
    }

    #[test]
    fn parse_keeps_parameters_out_of_the_comment() {
        // `just switch-kernel` with no argument means `fedora`. The listing
        // has to surface that, or a row in the Hub becomes a one-click switch
        // off the CachyOS default under a label that only says the name.
        let out = "Available recipes:\n    switch-kernel flavor=\"fedora\"   # Switch the installed kernel.\n    gaming-mode  # Gaming profile\n";
        let v = parse_just_list(out);
        assert_eq!(v[0].name, "switch-kernel");
        assert_eq!(v[0].params, "flavor=\"fedora\"");
        assert_eq!(v[0].comment, "Switch the installed kernel.");
        assert_eq!(v[1].params, "");
        assert_eq!(v[1].comment, "Gaming profile");
    }

    #[test]
    fn parse_keeps_more_recipes_than_the_justfile_has() {
        // The shipped justfile lists ~200 recipes and the section filters
        // over the whole list, so a cap below that silently hides the tail.
        let mut out = String::from("Available recipes:\n");
        for i in 0..300 {
            out.push_str(&format!("    recipe-{i}  # comment\n"));
        }
        assert_eq!(parse_just_list(&out).len(), 300);
    }

    #[test]
    fn parse_empty() {
        assert!(parse_just_list("").is_empty());
        assert!(parse_just_list("Available recipes:\n").is_empty());
    }

    #[test]
    fn failed_list_run_is_an_error_not_an_empty_listing() {
        // `just` ran and failed with nothing parseable (e.g. no justfile):
        // the caller must hear about the failure, not see "no recipes".
        let err =
            interpret_list_output(false, Some(1), "", "error: no justfile found").unwrap_err();
        assert!(err.contains("exit 1"), "error carries the exit: {err}");
        assert!(
            err.contains("no justfile found"),
            "error carries stderr: {err}"
        );
        // A killed run (no exit code) is an error too.
        assert!(interpret_list_output(false, None, "", "").is_err());
    }

    #[test]
    fn successful_empty_list_run_is_an_empty_ok() {
        // The command succeeded and the justfile simply has no recipes:
        // a legitimate empty result, distinct from the failure above.
        let v = interpret_list_output(true, Some(0), "Available recipes:\n", "")
            .expect("successful empty listing is Ok");
        assert!(v.is_empty());
    }

    #[test]
    fn failed_run_with_parseable_stdout_keeps_the_qt_fallback() {
        // Non-zero exit but a real listing on stdout: the listing wins,
        // exactly like page_just.py behaved.
        let out = "Available recipes:\n    build    # Build the full KythOS image.\n";
        let v = interpret_list_output(false, Some(1), out, "warning: something")
            .expect("parseable stdout survives a non-zero exit");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].name, "build");
    }

    #[test]
    fn just_run_rejects_injection() {
        assert!(command_for("foo; rm -rf /", &[]).is_none());
        assert!(command_for("foo && bar", &[]).is_none());
        assert!(command_for("", &[]).is_none());
        assert!(command_for("foo bar", &[]).is_none());
        assert!(command_for("[KythOS]", &[]).is_none());
    }

    #[test]
    fn launch_rejects_arguments_that_are_not_bare_tokens() {
        // `args` is for fixed literals like `switch-channel stable`; a flag
        // or a second word would change what the recipe does.
        assert!(command_for("switch-channel", &["--dry-run"]).is_none());
        assert!(command_for("switch-channel", &["stable; reboot"]).is_none());
    }

    /// The justfile ublue's `ujust` wrapper exports:
    /// `JUST_JUSTFILE="/usr/share/ublue-os/justfile" /usr/bin/just "${@}"`.
    /// `branding/31-ujust-recipes.sh` appends kyth's import to that file, so
    /// this is where the recipes are. Without it, `just` walks up from the
    /// Hub's working directory, finds nothing, and every launch is a no-op.
    #[test]
    fn justfile_is_the_one_ujust_uses() {
        assert_eq!(UBLUE_JUSTFILE, "/usr/share/ublue-os/justfile");
    }

    #[test]
    fn justfile_env_is_set_only_when_the_justfile_is_installed() {
        let dir = std::env::temp_dir().join("kyth-just-env-test");
        let _ = std::fs::create_dir_all(&dir);
        let justfile = dir.join("justfile");
        std::fs::write(&justfile, "default:\n    @true\n").expect("write justfile");
        assert_eq!(
            justfile_env_for(&justfile).as_deref(),
            Some(justfile.to_string_lossy().as_ref())
        );
        assert_eq!(justfile_env_for(&dir.join("absent")), None);
        let _ = std::fs::remove_file(&justfile);
    }

    #[test]
    fn command_for_uses_just_directly_without_a_terminal_wrapper() {
        assert_eq!(
            command_for("switch-channel", &["stable"]),
            Some(
                vec!["/usr/bin/just", "switch-channel", "stable"]
                    .into_iter()
                    .map(String::from)
                    .collect()
            ),
        );
    }

    #[test]
    fn fixed_assignments_are_separate_and_validated() {
        assert_eq!(
            command_for_fixed_assignments("switch-kernel", &[("flavor", "cachy")]),
            Some(
                vec!["/usr/bin/just", "switch-kernel", "flavor=cachy"]
                    .into_iter()
                    .map(String::from)
                    .collect()
            ),
        );
        assert!(
            command_for_fixed_assignments("switch-kernel", &[("flavor", "cachy; reboot")])
                .is_none()
        );
        assert!(command_for_fixed_assignments("switch-kernel", &[("--flavor", "cachy")]).is_none());
    }

    /// Captured from a `just --list` (just 1.58) over ublue's justfile with
    /// kyth's import appended — i.e. what `ujust --list` prints on the image,
    /// not kyth's recipes alone. Upstream's long distrobox signatures push
    /// their doc comments onto their own line.
    #[test]
    fn parse_drops_doc_comments_printed_on_their_own_line() {
        let out = concat!(
            "Available recipes:\n",
            "    device-info                            # Gather device info to a pastebin\n",
            "    # Create a new custom distrobox\n",
            "    distrobox-new IMAGE=\"prompt\" NAME=\"prompt\" HOMEDIR=\"\" # [alias: distrobox]\n",
        );
        let v = parse_just_list(out);
        let names: Vec<&str> = v.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["device-info", "distrobox-new"]);
    }

    /// Captured from `just --justfile build_files/just/kyth.just --list`
    /// (just 1.58) — the heading is what `[group('KythOS')]` produces, and
    /// the two parameter forms are the ones the shipped recipes use.
    #[test]
    fn parse_real_list_output() {
        let out = concat!(
            "Available recipes:\n",
            "    [KythOS]\n",
            "    ai-dev-enter\n",
            "    gaming-audit mode=\"\"                   # Perf audit\n",
            "    retry-quarantined-update digest        # Usage: ujust retry-quarantined-update sha256:...\n",
            "    switch-kernel flavor=\"fedora\"          # ujust switch-kernel cachy\n",
        );
        let v = parse_just_list(out);
        let names: Vec<&str> = v.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "ai-dev-enter",
                "gaming-audit",
                "retry-quarantined-update",
                "switch-kernel"
            ]
        );
        assert_eq!(v[0].params, "");
        assert_eq!(v[1].params, "mode=\"\"");
        assert_eq!(v[2].params, "digest");
        assert_eq!(v[3].params, "flavor=\"fedora\"");
        assert_eq!(v[3].comment, "ujust switch-kernel cachy");
    }
}
