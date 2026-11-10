//! Port of `kyth_shared.system.controllers` — pure controller detection.
//! lsusb → vid/pid → PlayStation/Xbox/Nintendo + lsmod + /dev/input/by-id

use std::fs;

/// Run a detection probe and return its stdout, or explain the failure.
/// The old shape collapsed spawn errors, timeouts and non-zero exits into
/// an empty string, so a broken `lsusb` read as "no controllers plugged
/// in" — the failure-disguised-as-empty defect. Detection verdicts are
/// only meaningful when the probes actually ran, so probe failure is an
/// `Err` the caller surfaces instead of an empty result.
fn command_stdout_checked(cmd: &str, args: &[&str], timeout_secs: u64) -> Result<String, String> {
    let mut argv = vec![cmd.to_string()];
    argv.extend(args.iter().map(|arg| (*arg).to_string()));
    let output =
        crate::system::process::run_bounded(&argv, std::time::Duration::from_secs(timeout_secs))
            .map_err(|err| format!("could not run {cmd}: {err}"))?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).to_string());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let how = match output.status.code() {
        Some(code) => format!("{cmd} failed (exit {code})"),
        None => format!("{cmd} was stopped before it finished"),
    };
    if stderr.is_empty() {
        Err(how)
    } else {
        Err(format!("{how}: {stderr}"))
    }
}

/// Best-effort stdout for auxiliary probes whose output is informational
/// text rather than a detection verdict (the `dualsensectl` status blurb):
/// a failure there means "no blurb", never a wrong verdict.
fn command_stdout_best_effort(cmd: &str, args: &[&str], timeout_secs: u64) -> String {
    command_stdout_checked(cmd, args, timeout_secs).unwrap_or_default()
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ControllersDetect {
    pub usb_controllers: Vec<(String, String)>,
    pub input_nodes: Vec<String>,
    pub xone_dongle: bool,
    pub xone_loaded: bool,
    pub xpadneo_loaded: bool,
    pub hid_ps_loaded: bool,
    pub dualsense_found: bool,
    pub ds4_found: bool,
    pub switch_pro_found: bool,
    pub dualsensectl_out: String,
    pub secure_boot: bool,
    pub jstest_available: bool,
}

#[derive(Default)]
struct UsbControllerParse {
    controllers: Vec<(String, String)>,
    xone_dongle: bool,
    dualsense_found: bool,
    ds4_found: bool,
    switch_pro_found: bool,
}

fn parse_usb_controllers(usb_text: &str) -> UsbControllerParse {
    let mut parsed = UsbControllerParse::default();
    for line in usb_text.lines() {
        let Some(id) = line
            .split_once("ID ")
            .and_then(|(_, rest)| rest.split_whitespace().next())
        else {
            continue;
        };
        let Some((vid, pid)) = id.split_once(':') else {
            continue;
        };
        let vid = vid.to_ascii_lowercase();
        let pid = pid.to_ascii_lowercase();
        let description = line
            .split_once(id)
            .map(|(_, rest)| rest.trim())
            .unwrap_or_default();
        let label = match vid.as_str() {
            "045e" => "Xbox",
            "054c" => "PlayStation",
            "057e" => "Nintendo",
            "2dc8" => "8BitDo",
            "0f0d" => "HORI",
            "28de" => "Valve",
            "20d6" => "PowerA",
            "0e6f" => "PDP",
            _ => continue,
        };
        if vid == "045e" && matches!(pid.as_str(), "02e6" | "02fe") {
            parsed.xone_dongle = true;
            parsed
                .controllers
                .push(("Xbox Wireless USB Dongle".into(), "xbox_dongle".into()));
        } else if vid == "054c" && matches!(pid.as_str(), "0ce6" | "0df2") {
            parsed.dualsense_found = true;
            parsed
                .controllers
                .push(("PlayStation 5 DualSense".into(), "dualsense".into()));
        } else if vid == "054c" && matches!(pid.as_str(), "05c4" | "09cc" | "0ba0") {
            parsed.ds4_found = true;
            parsed
                .controllers
                .push(("PlayStation 4 DualShock 4".into(), "ds4".into()));
        } else if vid == "057e" && pid == "2009" {
            parsed.switch_pro_found = true;
            parsed
                .controllers
                .push(("Nintendo Switch Pro Controller".into(), "switch_pro".into()));
        } else {
            parsed.controllers.push((
                if description.is_empty() {
                    format!("{label} controller")
                } else {
                    description.into()
                },
                "generic".into(),
            ));
        }
    }
    parsed
}

/// Detect connected controllers and loaded controller drivers.
///
/// Fallible: when a primary probe (`lsusb` / `lsmod`) cannot run or exits
/// non-zero, the detection did not happen and the caller gets an `Err` —
/// never a struct whose empty fields impersonate "nothing connected".
/// Genuinely-absent things stay non-errors: a missing `/dev/input/by-id`
/// directory or efivars tree just yields empty/false fields, and the
/// `dualsensectl` status blurb is best-effort informational text.
pub fn detect_controllers() -> Result<ControllersDetect, String> {
    detect_controllers_with(&command_stdout_checked)
}

/// [`detect_controllers`] with the probe runner injected, so the contract
/// (failing probe → `Err`, successful empty probe → empty `Ok`) is
/// unit-testable without running real system commands.
fn detect_controllers_with(
    run: &dyn Fn(&str, &[&str], u64) -> Result<String, String>,
) -> Result<ControllersDetect, String> {
    let usb_text = run("lsusb", &[], 6)?;
    let lsmod_text = run("lsmod", &[], 4)?;
    let parsed = parse_usb_controllers(&usb_text);
    let input_nodes = fs::read_dir("/dev/input/by-id")
        .ok()
        .map(|rd| {
            let mut v: Vec<String> = rd
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().to_string())
                .filter(|n| {
                    let l = n.to_lowercase();
                    l.contains("joystick") || l.contains("gamepad") || l.contains("controller")
                })
                .collect();
            v.sort();
            v
        })
        .unwrap_or_default();

    let secure_boot = fs::read_dir("/sys/firmware/efi/efivars")
        .ok()
        .and_then(|rd| {
            for e in rd.filter_map(|e| e.ok()) {
                let name = e.file_name().to_string_lossy().to_string();
                if name.starts_with("SecureBoot-") {
                    if let Ok(data) = fs::read(e.path()) {
                        return Some(data.len() >= 5 && data[4] == 1);
                    }
                }
            }
            None
        })
        .unwrap_or(false);

    let modules = lsmod_text.to_lowercase().replace('-', "_");
    let dualsensectl_out = if parsed.dualsense_found && which("dualsensectl") {
        command_stdout_best_effort("dualsensectl", &["status", "0"], 3)
    } else {
        String::new()
    };
    Ok(ControllersDetect {
        usb_controllers: parsed.controllers,
        input_nodes,
        xone_dongle: parsed.xone_dongle,
        xone_loaded: modules.contains("xone_hid"),
        xpadneo_loaded: modules.contains("xpadneo"),
        hid_ps_loaded: modules.contains("hid_playstation"),
        dualsense_found: parsed.dualsense_found,
        ds4_found: parsed.ds4_found,
        switch_pro_found: parsed.switch_pro_found,
        dualsensectl_out,
        secure_boot,
        jstest_available: which("jstest-gtk"),
    })
}

fn which(command: &str) -> bool {
    std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).any(|dir| dir.join(command).is_file()))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_known_usb_controller_variants() {
        let parsed = parse_usb_controllers(concat!(
            "Bus 001 Device 002: ID 054c:0ce6 Sony DualSense\n",
            "Bus 001 Device 003: ID 054c:05c4 Sony DualShock\n",
            "Bus 001 Device 004: ID 057e:2009 Nintendo Pro\n",
            "Bus 001 Device 005: ID 1d6b:0002 ignored\n",
        ));
        assert!(parsed.dualsense_found);
        assert!(parsed.ds4_found);
        assert!(parsed.switch_pro_found);
        assert_eq!(parsed.controllers.len(), 3);
    }

    #[test]
    fn failing_lsusb_probe_is_an_error_not_an_empty_detection() {
        let run = |cmd: &str, _args: &[&str], _timeout: u64| -> Result<String, String> {
            Err(format!("{cmd} failed (exit 1): simulated failure"))
        };
        let err = detect_controllers_with(&run).unwrap_err();
        assert!(err.contains("lsusb"), "error names the failed probe: {err}");
    }

    #[test]
    fn failing_lsmod_probe_is_an_error_not_an_empty_detection() {
        let run = |cmd: &str, _args: &[&str], _timeout: u64| -> Result<String, String> {
            match cmd {
                "lsusb" => Ok(String::new()),
                other => Err(format!("{other} failed (exit 1): simulated failure")),
            }
        };
        let err = detect_controllers_with(&run).unwrap_err();
        assert!(err.contains("lsmod"), "error names the failed probe: {err}");
    }

    #[test]
    fn successful_empty_probes_are_an_empty_detection() {
        // The probes ran fine and found nothing: a legitimate "no
        // controllers" answer, distinct from a failed probe above.
        let run = |_cmd: &str, _args: &[&str], _timeout: u64| -> Result<String, String> {
            Ok(String::new())
        };
        let d = detect_controllers_with(&run).expect("empty probes still detect");
        assert!(d.usb_controllers.is_empty());
        assert!(!d.xone_loaded && !d.xpadneo_loaded && !d.hid_ps_loaded);
        assert!(!d.dualsense_found && !d.ds4_found && !d.switch_pro_found);
    }

    #[test]
    fn successful_probes_feed_the_detection() {
        let run = |cmd: &str, _args: &[&str], _timeout: u64| -> Result<String, String> {
            match cmd {
                "lsusb" => Ok("Bus 001 Device 002: ID 054c:0ce6 Sony DualSense\n".to_string()),
                "lsmod" => Ok("hid_playstation 40960 0\n".to_string()),
                _ => Ok(String::new()),
            }
        };
        let d = detect_controllers_with(&run).expect("fixture probes detect");
        assert!(d.dualsense_found);
        assert!(d.hid_ps_loaded);
        assert_eq!(d.usb_controllers.len(), 1);
    }
}
