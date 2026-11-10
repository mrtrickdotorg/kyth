//! Native read-only controller readiness report.
use kyth_shared::system::controllers::detect_controllers;
use kyth_shared::system::smoke_check::Report;
use std::path::Path;
fn main() {
    let mut r = Report::default();
    // A failed detection probe is a failed check, not a "none found"
    // warning: the readiness report must not reassure from a read that
    // never happened.
    let d = match detect_controllers() {
        Ok(detected) => detected,
        Err(error) => {
            r.failed(
                "Controller detection",
                format!("detection failed: {error}"),
                "Controller Readiness",
            );
            println!("Controller Check\n");
            for row in &r.results {
                println!(
                    "{:5} {:24} {}",
                    format!("{:?}", row.level).to_uppercase(),
                    row.name,
                    row.detail
                );
            }
            println!("\nResult: controller readiness has failures.");
            std::process::exit(r.exit_code_with_strict(true));
        }
    };
    if Path::new("/dev/input").is_dir() {
        r.passed(
            "Input subsystem",
            "/dev/input present",
            "Controller Readiness",
        );
    } else {
        r.failed(
            "Input subsystem",
            "/dev/input missing",
            "Controller Readiness",
        );
    }
    if let Some((name, _)) = d.usb_controllers.first() {
        r.passed("Controller detected", name, "Controller Readiness");
    } else {
        r.warned(
            "Controller detected",
            "none found; plug in or pair a controller and rerun",
            "Controller Readiness",
        );
    }
    if d.dualsense_found || d.ds4_found || d.switch_pro_found || d.xone_dongle {
        r.passed(
            "Bluetooth controller",
            "controller-like device detected",
            "Controller Readiness",
        );
    } else {
        r.warned(
            "Bluetooth controller",
            "no paired controller-like Bluetooth device found",
            "Controller Readiness",
        );
    }
    if d.xone_loaded || d.xpadneo_loaded || d.hid_ps_loaded {
        r.passed(
            "Controller kernel rules",
            "controller kernel module loaded",
            "Controller Readiness",
        );
    } else {
        r.warned(
            "Controller kernel rules",
            "known controller module not detected",
            "Controller Readiness",
        );
    }
    if Path::new("/dev/uinput").exists() {
        r.passed("uinput", "/dev/uinput present", "Controller Readiness");
    } else {
        r.warned(
            "uinput",
            "/dev/uinput missing; some remappers may not work",
            "Controller Readiness",
        );
    }
    println!("Controller Check\n");
    for row in &r.results {
        println!(
            "{:5} {:24} {}",
            format!("{:?}", row.level).to_uppercase(),
            row.name,
            row.detail
        );
    }
    println!(
        "\nResult: controller readiness {}.",
        if r.failures() > 0 {
            "has failures"
        } else if r.warnings() > 0 {
            "has warnings"
        } else {
            "is clean"
        }
    );
    std::process::exit(r.exit_code_with_strict(true));
}
