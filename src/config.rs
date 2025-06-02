use clap::Parser;
use serde::Deserialize;
use std::{fs, path::PathBuf};

use crate::errors::ConfigError;

// Default values for the application
const DEFAULT_ERROR_DAYS: i64 = 14;
const DEFAULT_WARNING_DAYS: i64 = 30;
const DEFAULT_LOG_LEVEL: &str = "info";

// --- Final application configuration structure ---
#[derive(Debug)]
pub struct AppConfig {
    pub urls: Vec<String>,
    pub error_days: i64,
    pub warning_days: i64,
    pub log_level: String,
    pub check_frequency: Option<u32>,
    pub slack_webhook_url: Option<String>,
}

// --- Configuration structure for TOML file ---
#[derive(Deserialize, Debug, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct TomlConfig {
    urls: Option<Vec<String>>,
    error_days: Option<i64>,
    warning_days: Option<i64>,
    log_level: Option<String>,
    check_frequency: Option<u32>,
    slack_webhook_url: Option<String>,
}

impl AppConfig {
    pub fn build(args: CliArgs) -> Result<Self, ConfigError> {
        let mut toml_config = TomlConfig::default();

        if let Some(path_to_load) = &args.config_file {
            if !path_to_load.exists() {
                return Err(ConfigError::FileNotFound(path_to_load.clone()));
            }
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
            check_frequency: args.check_frequency.or(toml_config.check_frequency),
            slack_webhook_url: args.slack_webhook_url.or(toml_config.slack_webhook_url),
        })
    }
}

// --- CLI arguments structure using clap ---
#[derive(Parser, Debug)]
#[clap(author, version, about = "SSL Certificate Checker Utility", long_about = None)]
pub struct CliArgs {
    /// List of URLs to check SSL certificates for (comma-separated or multiple flags)
    #[clap(short, long, value_delimiter = ',', num_args = 1..)]
    urls: Option<Vec<String>>,

    /// Days remaining on SSL certificate to trigger an error
    #[clap(short = 'e', long, value_name = "DAYS")]
    error_days: Option<i64>,

    /// Days remaining on SSL certificate to trigger a warning
    #[clap(short = 'w', long, value_name = "DAYS")]
    warning_days: Option<i64>,

    /// Logging level (e.g., error, warn, info, debug, trace)
    #[clap(short, long, value_name = "LEVEL")]
    log_level: Option<String>,

    /// Slack webhook URL for notifications
    #[clap(long, value_name = "URL")]
    slack_webhook_url: Option<String>,

    /// Frequency to check urls in days - activating this runing in daemon mode
    #[clap(long, value_name = "FREQUENCY")]
    check_frequency: Option<u32>,

    /// Path to a TOML configuration file
    #[clap(short, long, value_name = "FILE_PATH")]
    config_file: Option<PathBuf>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_temp_toml_config(content: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().expect("Failed to create temp file");
        writeln!(file, "{}", content).expect("Failed to write to temp file");
        file
    }

    fn basic_cli_args() -> CliArgs {
        CliArgs {
            urls: None,
            error_days: None,
            warning_days: None,
            log_level: None,
            slack_webhook_url: None,
            check_frequency: None,
            config_file: None,
        }
    }

    #[test]
    fn build_config_cli_only() {
        let args = CliArgs {
            urls: Some(vec!["https://cli.com".to_string()]),
            error_days: Some(5),
            warning_days: Some(10),
            log_level: Some("trace".to_string()),
            slack_webhook_url: Some("https://slack.cli.com".to_string()),
            check_frequency: None,
            config_file: None,
        };
        let config = AppConfig::build(args).unwrap();
        assert_eq!(config.urls, vec!["https://cli.com".to_string()]);
        assert_eq!(config.error_days, 5);
        assert_eq!(config.warning_days, 10);
        assert_eq!(config.log_level, "trace");
        assert_eq!(
            config.slack_webhook_url,
            Some("https://slack.cli.com".to_string())
        );
    }

    #[test]
    fn build_config_toml_only() {
        let toml_content = r#"
            urls = ["https://toml.com"]
            error_days = 3
            warning_days = 12
            log_level = "warn"
            slack_webhook_url = "https://slack.toml.com"
        "#;
        let temp_config_file = create_temp_toml_config(toml_content);
        let args = CliArgs {
            config_file: Some(temp_config_file.path().to_path_buf()),
            ..basic_cli_args()
        };

        let config = AppConfig::build(args).unwrap();
        assert_eq!(config.urls, vec!["https://toml.com".to_string()]);
        assert_eq!(config.error_days, 3);
        assert_eq!(config.warning_days, 12);
        assert_eq!(config.log_level, "warn");
        assert_eq!(
            config.slack_webhook_url,
            Some("https://slack.toml.com".to_string())
        );
    }

    #[test]
    fn build_config_cli_overrides_toml() {
        let toml_content = r#"
            urls = ["https://toml.com"]
            error_days = 3
            warning_days = 12
            log_level = "error"
        "#;
        let temp_config_file = create_temp_toml_config(toml_content);
        let args = CliArgs {
            urls: Some(vec!["https://cli.com".to_string()]),
            error_days: Some(5), // CLI overrides TOML's 3
            // warning_days will come from TOML
            log_level: Some("debug".to_string()), // CLI overrides TOML's error
            config_file: Some(temp_config_file.path().to_path_buf()),
            ..basic_cli_args()
        };

        let config = AppConfig::build(args).unwrap();
        assert_eq!(config.urls, vec!["https://cli.com".to_string()]);
        assert_eq!(config.error_days, 5);
        assert_eq!(config.warning_days, 12); // From TOML
        assert_eq!(config.log_level, "debug");
    }

    #[test]
    fn build_config_uses_defaults() {
        let args = CliArgs {
            urls: Some(vec!["https://default.com".to_string()]), // Only URL provided
            ..basic_cli_args()
        };
        let config = AppConfig::build(args).unwrap();
        assert_eq!(config.urls, vec!["https://default.com".to_string()]);
        assert_eq!(config.error_days, DEFAULT_ERROR_DAYS);
        assert_eq!(config.warning_days, DEFAULT_WARNING_DAYS);
        assert_eq!(config.log_level, DEFAULT_LOG_LEVEL);
        assert_eq!(config.slack_webhook_url, None);
    }

    #[test]
    fn build_config_error_missing_urls() {
        let args = basic_cli_args(); // No URLs anywhere
        let result = AppConfig::build(args);
        assert!(matches!(result, Err(ConfigError::MissingUrls)));
    }

    #[test]
    fn build_config_error_config_file_not_found_explicit() {
        let non_existent_path = PathBuf::from("non_existent_config.toml");
        let args = CliArgs {
            config_file: Some(non_existent_path.clone()),
            ..basic_cli_args() // No URLs, but FileNotFound should take precedence
        };
        let result = AppConfig::build(args);
        match result {
            Err(ConfigError::FileNotFound(path)) => assert_eq!(path, non_existent_path),
            _ => panic!("Expected FileNotFound error"),
        }
    }

    #[test]
    fn build_config_error_toml_parse_error() {
        let malformed_toml_content = "urls = [\"bad\" error_days = invalid";
        let temp_config_file = create_temp_toml_config(malformed_toml_content);
        let args = CliArgs {
            config_file: Some(temp_config_file.path().to_path_buf()),
            ..basic_cli_args()
        };
        let result = AppConfig::build(args);
        match result {
            Err(ConfigError::TomlParseError(path, _)) => assert_eq!(path, temp_config_file.path()),
            _ => panic!("Expected TomlParseError"),
        }
    }

    #[test]
    fn build_config_empty_url_list_from_toml_is_error() {
        let toml_content = r#"
            urls = []
        "#;
        let temp_config_file = create_temp_toml_config(toml_content);
        let args = CliArgs {
            config_file: Some(temp_config_file.path().to_path_buf()),
            ..basic_cli_args()
        };
        let result = AppConfig::build(args);
        assert!(matches!(result, Err(ConfigError::MissingUrls)));
    }
}
