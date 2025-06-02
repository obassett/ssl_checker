use ssl_checker::{config, run};

// Some Defaults
fn default_config_with_url(url: &str) -> config::AppConfig {
    config::AppConfig {
        urls: vec![url.to_string()],
        error_days: 15,
        warning_days: 30,
        log_level: "info".to_string(),
        check_frequency: None,
        slack_webhook_url: None,
    }
}

#[tokio::test]
async fn expired_cert() {
    // Arrange
    let app_config = default_config_with_url("https://expired.badssl.com/");

    //Act
    let result = run(&app_config).await;
    //Assert
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.len(), 1);
    let check = &result[0];
    assert!(check.result.is_ok());
    let check_result = check.result.as_ref().unwrap();
    assert_eq!(check_result.is_valid, false);
    assert_eq!(check_result.days_remaining, 0);
    assert_eq!(check.url, "https://expired.badssl.com/".to_string());
}

#[tokio::test]
async fn wrong_host() {
    // Arrange
    let app_config = default_config_with_url("https://wrong.host.badssl.com/");

    //Act

    let result = run(&app_config).await;
    //Assert
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.len(), 1);
    let check = &result[0];
    assert!(check.result.is_ok());
    let check_result = check.result.as_ref().unwrap();
    assert_eq!(check_result.is_valid, false);
    assert_eq!(check.url, "https://wrong.host.badssl.com/".to_string());
}

#[tokio::test]
async fn self_signed() {
    // Arrange
    let app_config = default_config_with_url("https://self-signed.badssl.com/");

    //Act

    let result = run(&app_config).await;
    //Assert
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.len(), 1);
    let check = &result[0];
    assert!(check.result.is_ok());
    let check_result = check.result.as_ref().unwrap();
    assert_eq!(check_result.is_valid, false);
    assert_eq!(check.url, "https://self-signed.badssl.com/".to_string());
}

// #[tokio::test]
// async fn untrusted_root() {
//     // Arrange
//     let app_config = default_config_with_url("https://untrusted-root.badssl.com/");

//     //Act

//     let result = run(&app_config).await;
//     // Assert
//     assert!(result.is_ok());
//     let result = result.unwrap();
//     assert_eq!(result.len(), 1);
//     let check = &result[0];
//     assert!(check.result.is_ok());
//     let check_result = check.result.as_ref().unwrap();
//     assert_eq!(check_result.is_valid, false);
//     assert_eq!(check.url, "https://untrusted-root.badssl.com/".to_string());
// }
