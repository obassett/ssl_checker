use std::{fmt, path::PathBuf};

// --- Configuration Error Type ---
#[derive(Debug)]
pub enum ConfigError {
    FileReadError(PathBuf, std::io::Error),
    TomlParseError(PathBuf, toml::de::Error),
    FileNotFound(PathBuf),
    MissingUrls,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::FileReadError(path, err) => {
                write!(f, "Failed to read config file {:?}: {}", path, err)
            }
            ConfigError::TomlParseError(path, err) => {
                write!(f, "Failed to parse TOML from {:?}: {}", path, err)
            }
            ConfigError::FileNotFound(path) => write!(
                f,
                "Configuration file {:?} not found. Ensure the path is correct and the file exists.",
                path
            ),
            ConfigError::MissingUrls => write!(
                f,
                "No URLs provided. Please specify URLs via the --urls flag or in the 'urls' field of the configuration file."
            ),
        }
    }
}

impl std::error::Error for ConfigError {}

// --- SSL Check Error Type ---
#[derive(Debug)]
pub enum SslCheckError {
    NetworkError(reqwest::Error),
    NoCertificatesFound(String),            // URL for context
    UrlParseError(String, url::ParseError), // Original URL string and error
}

impl fmt::Display for SslCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SslCheckError::NetworkError(err) => write!(f, "Network error: {}", err),
            SslCheckError::NoCertificatesFound(url) => {
                write!(f, "No SSL certificates found for URL: {}", url)
            }
            SslCheckError::UrlParseError(url, err) => {
                write!(f, "Failed to parse URL '{}': {}", url, err)
            }
        }
    }
}

impl std::error::Error for SslCheckError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SslCheckError::NetworkError(err) => Some(err),
            SslCheckError::UrlParseError(_, err) => Some(err),
            _ => None,
        }
    }
}
