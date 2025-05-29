use clap::Parser;
use serde::Deserialize;
use std::{fs, path::PathBuf};

// Default values for the application
const DEFAULT_ERROR_DAYS: u32 = 14;
const DEFAULT_WARNING_DAYS: u32 = 30;
const DEFAULT_LOG_LEVEL: &str = "info";
const DEFAULT_CONFIG_FILE: &str = "config.toml";

// --- Final application configuration structure ---
#[derive(Debug)]
pub struct AppConfig {
    urls: Vec<String>,
    error_days: u32,
    warning_days: u32,
    log_level: String,
    slack_webhook_url: Option<String>,
}

// --- Configuration structure for TOML file ---
#[derive(Deserialize, Debug, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct TomlConfig {
    urls: Option<Vec<String>>,
    error_days: Option<u32>,
    warning_days: Option<u32>,
    log_level: Option<String>,
    slack_webhook_url: Option<String>,
}

impl AppConfig {
    fn build(args: CliArgs) -> Result<Self, ConfigError> {
        let mut toml_config = TomlConfig::default();

        let effective_config_path: Option<PathBuf>;

        if let Some(cli_config_path) = &args.config_file {
            // Config file explicitly specified via CLI
            if !cli_config_path.exists() {
                return Err(ConfigError::FileNotFound(cli_config_path.clone()));
            }
            effective_config_path = Some(cli_config_path.clone());
        } else {
            // No config file specified via CLI, try default
            let default_path = PathBuf::from(DEFAULT_CONFIG_FILE);
            if default_path.exists() {
                effective_config_path = Some(default_path);
            } else {
                effective_config_path = None; // No explicit and no default found
            }
        }

        if let Some(path_to_load) = effective_config_path {
            let toml_content = fs::read_to_string(&path_to_load)
                .map_err(|e| ConfigError::FileReadError(path_to_load.clone(), e))?;
            toml_config = toml::from_str(&toml_content)
                .map_err(|e| ConfigError::TomlParseError(path_to_load.clone(), e))?;
        }
        // If effective_config_path was None, toml_config remains TomlConfig::default()

        let urls = args.urls.or(toml_config.urls).filter(|v| !v.is_empty());
        if urls.is_none() {
            return Err(ConfigError::MissingUrls);
        }

        Ok(AppConfig {
            urls: urls.unwrap(), // Safe due to the check above
            error_days: args
                .error_days
                .or(toml_config.error_days)
                .unwrap_or(DEFAULT_ERROR_DAYS),
            warning_days: args
                .warning_days
                .or(toml_config.warning_days)
                .unwrap_or(DEFAULT_WARNING_DAYS),
            log_level: args
                .log_level
                .or(toml_config.log_level)
                .unwrap_or_else(|| DEFAULT_LOG_LEVEL.to_string()),
            slack_webhook_url: args.slack_webhook_url.or(toml_config.slack_webhook_url),
        })
    }
}

// --- CLI arguments structure using clap ---
#[derive(Parser, Debug)]
#[clap(author, version, about = "SSL Certificate Checker Utility", long_about = None)]
struct CliArgs {
    /// List of URLs to check SSL certificates for (comma-separated or multiple flags)
    #[clap(short, long, value_delimiter = ',', num_args = 1..)]
    urls: Option<Vec<String>>,

    /// Days remaining on SSL certificate to trigger an error
    #[clap(short = 'e', long, value_name = "DAYS")]
    error_days: Option<u32>,

    /// Days remaining on SSL certificate to trigger a warning
    #[clap(short = 'w', long, value_name = "DAYS")]
    warning_days: Option<u32>,

    /// Logging level (e.g., error, warn, info, debug, trace)
    #[clap(short, long, value_name = "LEVEL")]
    log_level: Option<String>,

    /// Slack webhook URL for notifications
    #[clap(long, value_name = "URL")]
    slack_webhook_url: Option<String>,

    /// Path to a TOML configuration file
    #[clap(short, long, value_name = "FILE_PATH")]
    config_file: Option<PathBuf>,
}
