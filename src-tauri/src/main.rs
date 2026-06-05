#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::process::Command;
use tauri::Manager;

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            #[cfg(debug_assertions)]
            {
                println!("[tauri] Dev mode: start backend manually on port 3030");
            }

            #[cfg(not(debug_assertions))]
            {
                let resource_path = app
                    .path()
                    .resource_dir()
                    .expect("failed to get resource dir")
                    .join("sidecar")
                    .join("mcp-scanner-backend-x86_64-pc-windows-msvc.exe");

                let resource_path = if resource_path.exists() {
                    resource_path
                } else {
                    app.path()
                        .resource_dir()
                        .expect("failed to get resource dir")
                        .join("sidecar")
                        .join("mcp-scanner-backend.exe")
                };

                if resource_path.exists() {
                    println!("[tauri] Spawning sidecar: {:?}", resource_path);
                    let _child = Command::new(&resource_path)
                        .env("RUST_LOG", "info")
                        .spawn()
                        .expect("failed to spawn backend sidecar");
                } else {
                    eprintln!("[tauri] WARNING: sidecar not found at {:?}", resource_path);
                }
            }

            Ok(())
        })
        .on_window_event(|_window, event| {
            if let tauri::WindowEvent::CloseRequested { .. } = event {
                // Sidecar is a child process, will be killed automatically
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
