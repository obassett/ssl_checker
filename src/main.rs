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
    tracing::info!(
        urls = ?app_config.urls,
        error_days = app_config.error_days,
        warning_days = app_config.warning_days,
        log_level = %app_config.log_level,
        slack_webhook_url = ?app_config.slack_webhook_url,
        "Effective Configuration Loaded"
    );

    if let Some(check_frequency) = app_config.check_frequency {
        tracing::info!(
            "Running in Daemon mode - Check will be run every {} days.",
            check_frequency
        );
        let mut ticker = tokio::time::interval(tokio::time::Duration::from_secs(
            60 * 60 * 24 * check_frequency as u64,
        ));
        loop {
            ticker.tick().await;
            let results = run(&app_config).await;

            match results {
                Ok(results) => {
                    for result in results {
                        println!("{}", result)
                    }
                }
                Err(error) => {
                    tracing::error!(error, "Error running SSL Checks");
                    break;
                }
            }
        }
    } else {
        tracing::info!("Running in Non-Daemon mode");
        let results = run(&app_config).await?;

        for result in results {
            println!("{}", result)
        }
    }

    Ok(())
}
