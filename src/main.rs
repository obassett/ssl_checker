use clap::Parser; // Needed to use CliArgs:parse
use ssl_checker::config::{AppConfig, CliArgs};
use ssl_checker::run;
use tracing_subscriber::{EnvFilter, fmt as tracing_fmt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli_args = CliArgs::parse();
    let app_config = AppConfig::build(cli_args)?;

    // Initialize tracing subscriber
    let env_filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(format!("ssl_checker={}", &app_config.log_level)))
        .unwrap_or_else(|_| EnvFilter::new("ssl_checker=info")); // Fallback to default if parsing fails

    tracing_fmt().with_env_filter(env_filter).init();

    tracing::info!("Logger initialized");
    tracing::debug!(config = ?app_config, "Effective configuration loaded");

    let results = run(app_config).await?;
    for result in results {
        if result.result.is_ok() {
            println!(
                "URL: {0:?} - Result: {1:?}",
                result.url,
                result.result.unwrap()
            );
        } else {
            println!(
                "URL: {0:?} - Error: {1:?}",
                result.url,
                result.result.err().unwrap()
            );
        }
    }

    Ok(())
}
