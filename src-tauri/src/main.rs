#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::process::Command;
use tauri::Manager;

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            // Spawn the Python backend sidecar on startup
            let resource_path = app.path_resolver()
                .resolve_resource("sidecar/mcp-scanner-backend.exe")
                .expect("failed to resolve sidecar binary");

            let mut cmd = Command::new(&resource_path);
            cmd.env("RUST_LOG", "info");

            #[cfg(debug_assertions)]
            {
                // In dev mode, backend is started separately by the developer
                println!("[tauri] Dev mode: start backend manually on port 3030");
            }

            #[cfg(not(debug_assertions))]
            {
                println!("[tauri] Spawning sidecar: {:?}", resource_path);
                let _child = cmd.spawn().expect("failed to spawn backend sidecar");
            }

            Ok(())
        })
        .on_window_event(|event| {
            if let tauri::WindowEvent::CloseRequested { .. } = event.event() {
                // Kill the sidecar process on window close
                #[cfg(not(debug_assertions))]
                {
                    // The sidecar is a child process and will be killed automatically
                    // when the parent (this Tauri app) exits
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
