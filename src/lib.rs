pub mod config;
pub mod errors;

use crate::config::AppConfig;

struct CertCheckResult {
    url: String,
    issuer: String,
    is_valid: bool,
    days_remaining: i32,
}

// async fn process_urls(urls: Vec<String>) -> Vec<CertCheckResult> {}

async fn run(app_config: AppConfig) -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}
