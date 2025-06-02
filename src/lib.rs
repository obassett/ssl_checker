pub mod certs;
pub mod config;
pub mod errors;
pub mod formatter;
pub mod slack_webhook;

use crate::certs::{extract_issuer, extract_subject_common_name, is_self_signed, valid_name};
use crate::errors::SslCheckError;
use crate::slack_webhook::send_check_results;
use crate::{certs::extract_sans, config::AppConfig};

use futures;
use reqwest::tls::TlsInfo;
use tokio::task;
use url::Url;
use x509_parser::prelude::{FromDer, X509Certificate};

#[derive(Debug)]
pub struct SslCheck {
    pub url: String,
    pub result: Result<CertCheckResult, SslCheckError>,
}

#[derive(Debug, Clone)]
pub struct CertCheckResult {
    pub issuer: String,
    pub subject: String,
    pub sans: Option<Vec<String>>,
    pub is_valid: bool,
    pub days_remaining: i64,
    pub days_remaining_state: DaysRemainingState,
}

#[derive(Debug, Clone)]
pub enum DaysRemainingState {
    Ok,
    Warning,
    Error,
}

impl CertCheckResult {
    pub fn new(
        issuer: String,
        subject: String,
        is_valid: bool,
        days_remaining: i64,
        days_remaining_state: DaysRemainingState,
    ) -> Self {
        Self {
            issuer,
            subject,
            sans: None,
            is_valid,
            days_remaining,
            days_remaining_state,
        }
    }

    pub fn from_x509_certificate(
        certificate_url: Url,
        warning_days: i64,
        error_days: i64,
        cert: X509Certificate,
    ) -> Self {
        // Get Validity from cert decode - We are then going to mark it false
        // if we can't match the CN or SANS to the URL.
        let mut is_valid = cert.validity().is_valid();

        let issuer = extract_issuer(&cert);
        let sans = extract_sans(&cert);

        let subject = extract_subject_common_name(&cert);
        let time_to_expiry = cert.validity().time_to_expiration();

        let days_remaining = match time_to_expiry {
            Some(dur) => dur.whole_days(),
            None => 0_i64,
        };

        if is_self_signed(&cert) {
            is_valid = false;
        };

        // Validate URL is in subject or sans
        if let Some(name) = certificate_url.domain() {
            if !valid_name(&cert, name) {
                is_valid = false;
            }
        } else {
            tracing::error!(
                url = certificate_url.to_string(),
                "Unable to determine domamin from url"
            );
            is_valid = false;
        }
        let days_remaining_state: DaysRemainingState;

        if days_remaining < error_days {
            days_remaining_state = DaysRemainingState::Error;
        } else if days_remaining < warning_days {
            days_remaining_state = DaysRemainingState::Warning;
        } else {
            days_remaining_state = DaysRemainingState::Ok;
        };

        Self {
            issuer,
            subject,
            sans,
            is_valid,
            days_remaining,
            days_remaining_state,
        }
    }
}

pub async fn run(app_config: &AppConfig) -> Result<Vec<SslCheck>, Box<dyn std::error::Error>> {
    if let Some(webhook_url) = &app_config.slack_webhook_url {
        tracing::info!(slack_webhook_url = %webhook_url, "Slack notifications enabled.");
    } else {
        tracing::info!("Slack notifications disabled.");
    }

    tracing::info!("Starting SSL certificate checks...");

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true) // We want bad certs so we can report on them
        .use_rustls_tls() // Explicitly use rustls
        .tls_info(true) // Make sure we expose the tls cert
        .build()?;

    let warning_days = app_config.warning_days.clone();
    let error_days = app_config.error_days.clone();

    let handles: Vec<_> = app_config
        .urls
        .clone()
        .into_iter()
        .map(|url| {
            let client = client.clone();
            task::spawn(async move {
                get_ssl_certificate(&client, &url, warning_days, error_days).await
            })
        })
        .collect();

    let check_results = futures::future::join_all(handles)
        .await
        .into_iter()
        .filter_map(|res| match res {
            Ok(cert_result) => Some(cert_result),
            Err(e) => {
                tracing::error!(error = %e, "Failed to properly process URL");
                None
            }
        })
        .collect();

    // Send Slack Notifications
    if let Some(webhook_url) = &app_config.slack_webhook_url {
        tracing::info!("Sending Slack notifications...");
        send_check_results(&webhook_url, &check_results).await;
    }

    Ok(check_results)
}

async fn get_ssl_certificate<'a>(
    client: &reqwest::Client,
    url_str: &str,
    warning_days: i64,
    error_days: i64,
) -> SslCheck {
    let parse_result = reqwest::Url::parse(url_str);

    let parsed_url = match parse_result {
        Ok(url) => url,
        Err(e) => {
            return SslCheck {
                url: url_str.to_string(),
                result: Err(SslCheckError::UrlParseError(url_str.to_string(), e)),
            };
        }
    };

    tracing::debug!(url = url_str, "Attempting to retrieve SSL certificate");
    let response = client.head(parsed_url.clone()).send().await;

    if response.is_err() {
        tracing::error!(url = url_str, "Failed to retrieve SSL certificate");
        return SslCheck {
            url: url_str.to_string(),
            result: Err(SslCheckError::NetworkError(response.unwrap_err())),
        };
    };
    let response = response.unwrap();

    // Access the DER encoded certificate from  TLS info
    if let Some(tls_info) = response.extensions().get::<TlsInfo>() {
        if let Some(cert_der) = tls_info.peer_certificate() {
            if let Ok((_, cert)) = X509Certificate::from_der(cert_der) {
                let cert_result = CertCheckResult::from_x509_certificate(
                    parsed_url,
                    warning_days,
                    error_days,
                    cert,
                );

                return SslCheck {
                    url: url_str.to_string(),
                    result: Ok(cert_result),
                };
            } else {
                tracing::warn!("No Cert Detail Found");
            }
        } else {
            tracing::warn!("No TLS Info Found");
        }
    }
    SslCheck {
        url: url_str.to_string(),
        result: Err(SslCheckError::NoCertificatesFound(url_str.to_string())),
    }
}
