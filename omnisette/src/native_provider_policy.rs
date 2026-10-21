//! Keep existing accounts on their issuer; select native only for explicit new login.
pub const NATIVE_PROVIDER: &str = "openbubbles-native-20002286";
pub fn restore_native(provider: Option<&str>) -> Result<bool, &'static str> {
    match provider {
        None => Ok(false),
        Some(NATIVE_PROVIDER) => Ok(true),
        Some(_) => Err("Unsupported saved authentication provider"),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn old_accounts_keep_their_provider() { assert_eq!(restore_native(None), Ok(false)); }
    #[test] fn native_accounts_never_silently_switch_to_remote() { assert_eq!(restore_native(Some(NATIVE_PROVIDER)), Ok(true)); }
    #[test] fn unknown_provider_fails_closed() { assert!(restore_native(Some("future-provider")).is_err()); }
}
