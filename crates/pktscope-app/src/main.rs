mod app;
mod cli;
mod widgets;

use std::process::ExitCode;

use app::PktScopeApp;
use cli::{parse_args, run_summary, usage};
use widgets::apply_theme;

fn main() -> ExitCode {
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(err) => {
            eprintln!("error: {err}\n\n{}", usage());
            return ExitCode::from(2);
        }
    };

    if args.show_help {
        println!("{}", usage());
        return ExitCode::SUCCESS;
    }

    if args.summary {
        return match run_summary(&args) {
            Ok(report) => {
                print!("{report}");
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("error: {err}");
                ExitCode::FAILURE
            }
        };
    }

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 820.0])
            .with_min_inner_size([900.0, 600.0]),
        ..Default::default()
    };

    let run_res = eframe::run_native(
        "pktscope — Network Packet Analyzer",
        native_options,
        Box::new(move |cc| {
            apply_theme(&cc.egui_ctx);
            Ok(Box::new(PktScopeApp::new_with_args(args)))
        }),
    );

    if let Err(err) = run_res {
        eprintln!("failed to launch GUI: {err}");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
