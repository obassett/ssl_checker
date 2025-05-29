use clap::Parser;
use reqwest::tls::TlsInfo;
use serde::Deserialize;
use tracing_subscriber::{EnvFilter, fmt as tracing_fmt};
use x509_parser::{parse_x509_certificate, prelude::X509Certificate};
use SslCheckError::AppConfig;



/// Retrieves the SSL/TLS server certificates for a given URL.
///
/// # Arguments
/// * `client` - A reference to a `reqwest::Client`.
/// * `url_str` - The URL string to check.
///
/// # Returns
/// A `Result` containing a vector of `reqwest::tls::Certificate` on success,
/// or an `SslCheckError` on failure.
async fn get_ssl_certificate(
    client: &reqwest::Client,
    url_str: &str,
) -> Result<X509Certificate, SslCheckError> {
    let url = reqwest::Url::parse(url_str)
        .map_err(|e| SslCheckError::UrlParseError(url_str.to_string(), e))?;

    tracing::debug!(url = %url, "Attempting to retrieve SSL certificate");
    let response = client
        .head(url.clone())
        .send()
        .await
        .map_err(SslCheckError::NetworkError)?;

    // Access the DER encoded certificate from  TLS info
    if let Some(tls_info) = response.extensions().get::<TlsInfo>() {
        if let Some(cert_der) = tls_info.peer_certificate() {
            // let cert = parse_x509_certificate(cert_der);
            if let Ok(cert) = parse_x509_certificate(cert_der) {
                return Ok(cert));
            }
        } else {
            tracing::warn!("No Cert Detail Found");
        }
    } else {
        tracing::warn!("No TLS Info Found");
    }
    Err(SslCheckError::NoCertificatesFound(url_str.to_string()))
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli_args = CliArgs::parse();
    let app_config = AppConfig::build(cli_args)?;

    // Initialize tracing subscriber
    let env_filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(&app_config.log_level))
        .unwrap_or_else(|_| EnvFilter::new(DEFAULT_LOG_LEVEL)); // Fallback to default if parsing fails

    tracing_fmt().with_env_filter(env_filter).init();

    tracing::info!("Logger initialized");
    tracing::debug!(config = ?app_config, "Effective configuration loaded");

    // For more structured logging of the config, you could do:
    // tracing::info!(
    //     urls = ?app_config.urls,
    //     error_days = app_config.error_days,
    //     warning_days = app_config.warning_days,
    //     log_level = %app_config.log_level,
    //     slack_webhook_url = ?app_config.slack_webhook_url,
    //     "Effective Configuration Loaded"
    // );

    if let Some(webhook_url) = &app_config.slack_webhook_url {
        tracing::info!(slack_webhook_url = %webhook_url, "Slack notifications enabled.");
    } else {
        tracing::info!("Slack notifications disabled.");
    }

    tracing::info!("Starting SSL certificate checks...");

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(false) // Ensure we validate certs by default
        .use_rustls_tls() // Explicitly use rustls
        .tls_info(true)
        .build()?;

    // --- Main application logic starts here ---
    for url in &app_config.urls {
        match get_ssl_certificate(&client, url).await {
            Ok(cert) => {
                cert.into
                // You can now inspect the certificates in `certs`.
                // For example, to get the first certificate in DER format:
                // if let Some(first_cert) = certs.first() {
                //     let der_bytes = first_cert.to_der()?;
                //     tracing::debug!(%url, "First certificate DER length: {}", der_bytes.len());
                // }
            }
            Err(e) => {
                tracing::error!(%url, error = %e, "Failed to retrieve SSL certificate");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::{parallel, serial};
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
            config_file: None,
        }
    }

    #[test]
    #[parallel]
    fn build_config_cli_only() {
        let args = CliArgs {
            urls: Some(vec!["https://cli.com".to_string()]),
            error_days: Some(5),
            warning_days: Some(10),
            log_level: Some("trace".to_string()),
            slack_webhook_url: Some("https://slack.cli.com".to_string()),
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
    #[parallel]
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
    #[parallel]
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
    #[parallel]
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
    #[parallel]
    fn build_config_error_missing_urls() {
        let args = basic_cli_args(); // No URLs anywhere
        let result = AppConfig::build(args);
        assert!(matches!(result, Err(ConfigError::MissingUrls)));
    }

    #[test]
    #[parallel]
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
    #[serial]
    fn build_config_default_config_file_used_if_exists() {
        // Create a temporary config.toml in the current directory for this test
        let default_config_path = PathBuf::from(DEFAULT_CONFIG_FILE);
        let _ = fs::remove_file(&default_config_path); // Clean up if it exists from previous failed test

        let toml_content = r#"
            urls = ["https://default-file.com"]
            error_days = 2
        "#;
        fs::write(&default_config_path, toml_content).expect("Failed to write default config");

        let args = basic_cli_args(); // No explicit config file, no CLI URLs
        let config = AppConfig::build(args).unwrap();

        assert_eq!(config.urls, vec!["https://default-file.com".to_string()]);
        assert_eq!(config.error_days, 2);
        assert_eq!(config.warning_days, DEFAULT_WARNING_DAYS); // Default

        fs::remove_file(default_config_path).expect("Failed to clean up default config");
    }

    #[test]
    #[serial]
    fn build_config_default_config_file_not_found_no_error_if_urls_from_cli() {
        // All tests using the Default Conifug Path mus tbe run in serial
        let default_config_path = PathBuf::from(DEFAULT_CONFIG_FILE);
        let _ = fs::remove_file(&default_config_path); // Ensure it doesn't exist

        let args = CliArgs {
            urls: Some(vec!["https://cli-only.com".to_string()]),
            ..basic_cli_args() // No explicit config file
        };
        let config = AppConfig::build(args).unwrap(); // Should not error
        assert_eq!(config.urls, vec!["https://cli-only.com".to_string()]);
        assert_eq!(config.error_days, DEFAULT_ERROR_DAYS);
    }

    #[test]
    #[parallel]
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
    #[parallel]
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
