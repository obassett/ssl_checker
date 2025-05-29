pub mod config;
pub mod errors;

use crate::config::AppConfig;
use crate::errors::SslCheckError;

use futures;
use reqwest::tls::TlsInfo;
use tokio::task;
use x509_parser::prelude::{FromDer, X509Certificate};

#[derive(Debug)]
pub struct CertCheckResult {
    pub url: String,
    pub issuer: String,
    pub subject: String,
    pub is_valid: bool,
    pub days_remaining: i64,
}

impl CertCheckResult {
    pub fn new(
        url: String,
        issuer: String,
        subject: String,
        is_valid: bool,
        days_remaining: i64,
    ) -> Self {
        Self {
            url,
            issuer,
            subject,
            is_valid,
            days_remaining,
        }
    }

    // TODO: Extract the Issueer from the cert more cleanly, and extract the CN and SANs to make sure they match the hostname part of url
    pub fn from_x509_certificate(url: String, cert: X509Certificate) -> Self {
        let issuer = cert.issuer().to_string();
        let subject = cert.subject().to_string();
        let is_valid = cert.validity().is_valid();
        let time_to_expiry = cert.validity().time_to_expiration();

        let days_remaining = match time_to_expiry {
            Some(dur) => dur.whole_days(),
            None => 0_i64,
        };
        Self {
            url,
            issuer,
            subject,
            is_valid,
            days_remaining,
        }
    }
}

// async fn process_urls(urls: Vec<String>) -> Vec<CertCheckResult> {}

pub async fn run(
    app_config: AppConfig,
) -> Result<Vec<CertCheckResult>, Box<dyn std::error::Error>> {
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

    let handles: Vec<_> = app_config
        .urls
        .clone()
        .into_iter()
        .map(|url| {
            let client = client.clone();
            task::spawn(async move { get_ssl_certificate(&client, &url).await })
        })
        .collect();

    let check_results = futures::future::join_all(handles)
        .await
        .into_iter()
        .filter_map(|res| match res {
            Ok(cert_result) => match cert_result {
                Ok(cert) => Some(cert),
                Err(e) => {
                    tracing::error!(error = %e, "Failed to retrieve SSL certificate");
                    None
                }
            },
            Err(e) => {
                tracing::error!(error = %e, "Failed to properly process URL");
                None
            }
        })
        .collect();

    Ok(check_results)
}

// TODO: We need to also validate the certifcates and ensure they are good
async fn get_ssl_certificate<'a>(
    client: &reqwest::Client,
    url_str: &str,
) -> Result<CertCheckResult, SslCheckError> {
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
            if let Ok((_, cert)) = X509Certificate::from_der(cert_der) {
                let cert_result = CertCheckResult::from_x509_certificate(url_str.to_string(), cert);

                return Ok(cert_result);
            }
        } else {
            tracing::warn!("No Cert Detail Found");
        }
    } else {
        tracing::warn!("No TLS Info Found");
    }
    Err(SslCheckError::NoCertificatesFound(url_str.to_string()))
}
