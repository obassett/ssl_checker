use std::net::Ipv4Addr;
use x509_parser::prelude::*;

pub fn is_self_signed(cert: &X509Certificate) -> bool {
    if cert.subject() == cert.issuer() {
        // Try to verify the signature with the certificate's own public key
        cert.verify_signature(None).is_ok()
    } else {
        false
    }
}

fn valid_name_wildcard(name: &str, wildcard: &str) -> bool {
    tracing::debug!(name, wildcard, "Checking if wildcard matches name");

    let wildcard_suffix = &wildcard[2..];
    if let Some(idx) = name.find('.') {
        let suffix = &name[idx + 1..];
        return suffix == wildcard_suffix && name[..idx].len() > 0;
    }
    false
}

pub fn valid_name(cert: &X509Certificate, name: &str) -> bool {
    tracing::info!(name, "Validating Certificate subject and sans against name");
    let subject = extract_subject_common_name(cert);
    tracing::debug!(name, subject, "Checking if subject matches name");
    if subject.contains(name) {
        return true;
    };

    let sans = extract_sans(cert);
    if let Some(sans) = sans {
        for san in &sans {
            if san.contains(name) {
                return true;
            }

            if san.starts_with("*.") {
                if valid_name_wildcard(name, san) {
                    return true;
                }
            }
        }
        tracing::debug!(name, sans = sans.join(","), "Checking if sans matches name");
    };
    tracing::warn!(name, "No Subject or Sans name match found");
    false
}

pub fn extract_subject_common_name(cert: &X509Certificate) -> String {
    let cert_subject: Vec<_> = cert
        .subject()
        .iter_common_name()
        .map(|name| match name.as_str() {
            Ok(name) => name.to_string(),
            Err(e) => {
                tracing::error!(error = e.to_string(), "Failed to parse issuer name");
                "".to_string()
            }
        })
        .collect();
    cert_subject.join(",")
}
pub fn extract_issuer(cert: &X509Certificate) -> String {
    let cert_issuer: Vec<_> = cert
        .issuer()
        .iter_organization()
        .map(|name| match name.as_str() {
            Ok(name) => name.to_string(),
            Err(e) => {
                tracing::error!(error = e.to_string(), "Failed to parse issuer name");
                "".to_string()
            }
        })
        .collect();
    cert_issuer.join(",")
}

pub fn extract_sans(cert: &X509Certificate) -> Option<Vec<String>> {
    // Unwrap Subject Altername Names
    let sans_extension = cert.subject_alternative_name();

    let sans: Option<Vec<String>>;

    if sans_extension.is_ok() {
        // Safe due to check above
        sans = match sans_extension.unwrap() {
            Some(sans) => Some(
                sans.value
                    .general_names
                    .iter()
                    .filter_map(|san| match san {
                        // Only Get DNSNames, URI and IpAddress for check
                        GeneralName::DNSName(dns_name) => Some(dns_name.to_string()),
                        GeneralName::URI(uri) => Some(uri.to_string()),
                        GeneralName::IPAddress(ip_address) => {
                            if ip_address.len() == 4 {
                                Some(
                                    Ipv4Addr::from([
                                        ip_address[0],
                                        ip_address[1],
                                        ip_address[2],
                                        ip_address[3],
                                    ])
                                    .to_string(),
                                )
                            } else {
                                None
                            }
                        }
                        _ => None,
                    })
                    .collect(),
            ),
            None => None,
        }
    } else {
        sans = None;
    };

    sans
}
