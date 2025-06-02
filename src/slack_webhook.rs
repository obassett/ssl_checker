use reqwest::{self, Client};
use serde_json::json;

use crate::SslCheck;

// Build Functions to fire off slack webhook for notifications
async fn send_slack_notification(
    endpoint: &str,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let payload = json!({
        "text": &message
    });

    let client = Client::new();
    let res = client.post(endpoint).json(&payload).send().await?;

    if res.status().is_success() {
        tracing::info!("Slack notification sent successfully");
    } else {
        tracing::error!("Failed to send Slack notification");
    }

    Ok(())
}

pub async fn send_check_results(slack_endpoint: &str, results: &[SslCheck]) {
    //get current date time
    let now = chrono::Utc::now();

    // Construct Message
    let mut message = format!(
        "SSL Checker Utility Report -  Date: {} (UTC)\n\n",
        now.format("%Y-%m-%d %H:%M:%S")
    );

    let result_lines = results
        .iter()
        .map(|result| format!("{result}"))
        .collect::<Vec<String>>()
        .join("\n");

    message.push_str(&result_lines);

    match send_slack_notification(slack_endpoint, &message).await {
        Ok(()) => {}
        Err(err) => {
            tracing::error!("Error sending Slack notification: {}", err);
        }
    };
}
