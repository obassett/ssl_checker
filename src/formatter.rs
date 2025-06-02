use crate::{CertCheckResult, DaysRemainingState, SslCheck};
use std::fmt::{Display, Formatter};

pub const PURPLE_TICK: char = '\u{2714}';
pub const GREEN_TICK: char = '\u{2705}';
pub const RED_CROSS: char = '\u{274C}';

pub const GREEN_CIRCLE: char = '\u{1F7E2}';
pub const YELLOW_CIRCLE: char = '\u{1F7E1}';
pub const RED_CIRCLE: char = '\u{1F534}';

impl Display for DaysRemainingState {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let output_char = match &self {
            DaysRemainingState::Ok => GREEN_CIRCLE,
            DaysRemainingState::Warning => YELLOW_CIRCLE,
            DaysRemainingState::Error => RED_CIRCLE,
        };

        write!(f, "{0}", output_char)
    }
}

impl Display for CertCheckResult {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // Add Emojis
        let check_state_emoji = match &self.is_valid {
            true => GREEN_TICK,
            false => RED_CROSS,
        };

        write!(
            f,
            "CertCheck - Issuer: {0} - is_valid: {1} - {2} {3} days remaining",
            self.issuer, check_state_emoji, self.days_remaining_state, self.days_remaining
        )
    }
}

impl Display for SslCheck {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let check_result = match &self.result {
            Ok(check) => format!("Completed:{0} Result: {1}", PURPLE_TICK, check),
            Err(err) => format!("Error:{0} Message: {1}", RED_CROSS, err),
        };

        write!(f, "URL: {0} {1}", self.url, check_result)
    }
}
