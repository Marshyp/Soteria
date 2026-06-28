mod commands;

use commands::{analysis, database, hash, sandbox, settings, virustotal};

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![
            hash::hash_file,
            virustotal::lookup_hash,
            database::init_database,
            database::clear_database,
            database::list_runs,
            database::get_run,
            database::ingest_run,
            sandbox::prepare_and_launch_sandbox,
            analysis::compare_runs,
            settings::get_settings,
            settings::save_settings,
        ])
        .run(tauri::generate_context!())
        .expect("failed to run Sandbox Analyzer");
}
