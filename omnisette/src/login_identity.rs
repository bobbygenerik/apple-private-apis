use crate::LoginClientInfo;

#[cfg(all(not(target_os = "macos"), feature = "remote-anisette-v3"))]
fn compatible_context(original: &str) -> String {
    match original.rsplit_once("> <") {
        Some((_, app)) => format!("<PC> <Windows;6.2(0,0);9200> <{app}"),
        None => original.to_string(),
    }
}

/// Account authentication profile for the selected Anisette implementation.
/// Registration, APS activation and the provisioning identity stay separate.
pub fn account_login_info(info: LoginClientInfo) -> LoginClientInfo {
    #[cfg(all(not(target_os = "macos"), feature = "remote-anisette-v3"))]
    {
        // Compatibility profile documented in anisette-v3-server issue #61 and
        // reproduced with a nonexistent account: old iPhone profile => -80045;
        // this profile => normal incorrect-account response (-20970).
        let mut info = info;
        info.mme_client_info_akd = compatible_context(&info.mme_client_info_akd);
        info.mme_client_info = compatible_context(&info.mme_client_info);
        info
    }
    #[cfg(not(all(not(target_os = "macos"), feature = "remote-anisette-v3")))]
    {
        info
    }
}

/// Do not change the platform of an existing PET minted before this policy.
pub fn restored_account_login_info(info: LoginClientInfo, previous: Option<&str>) -> LoginClientInfo {
    if previous.is_some_and(|value| value.starts_with("<PC> <Windows;6.2(0,0);9200> <")) {
        account_login_info(info)
    } else {
        info
    }
}

/// Client description used for the PET service-token exchange.
pub fn account_delegate_info(info: &LoginClientInfo, delegate_context: &str) -> String {
    #[cfg(all(not(target_os = "macos"), feature = "remote-anisette-v3"))]
    if account_uses_remote_compatibility(info) {
        return compatible_context(delegate_context);
    }
    let _ = info;
    delegate_context.to_string()
}

/// Whether this account uses the remote-v3 compatibility authentication profile.
pub fn account_uses_remote_compatibility(_info: &LoginClientInfo) -> bool {
    cfg!(all(not(target_os = "macos"), feature = "remote-anisette-v3")) &&
        _info.mme_client_info_akd.starts_with("<PC> <Windows;6.2(0,0);9200> <")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn original() -> LoginClientInfo {
        LoginClientInfo {
            mme_client_info_akd: "<iPhone9,1> <iPhone OS;15.8.3;19H386> <com.apple.AuthKit/1 (com.apple.akd/1.0)>".into(),
            mme_client_info: "<iPhone9,1> <iPhone OS;15.8.3;19H386> <com.apple.AuthKit/1 (com.apple.MobileSMS/1262.500.151.1.2)>".into(),
            hardware_headers: [("X-Apple-I-SRL-NO".into(), "hardware-serial".into())].into(),
            push_token: Some("existing-token".into()),
            client_bundle_id: "com.apple.MobileSMS".into(),
            update_account_bundle_id: "existing-update-context".into(),
            ..Default::default()
        }
    }

    #[cfg(all(not(target_os = "macos"), feature = "remote-anisette-v3"))]
    #[test]
    fn remote_login_and_messages_use_the_same_compatible_platform() {
        let info = account_login_info(original());
        assert_eq!(info.mme_client_info_akd,
            "<PC> <Windows;6.2(0,0);9200> <com.apple.AuthKit/1 (com.apple.akd/1.0)>");
        assert_eq!(info.mme_client_info,
            "<PC> <Windows;6.2(0,0);9200> <com.apple.AuthKit/1 (com.apple.MobileSMS/1262.500.151.1.2)>");
        assert!(account_uses_remote_compatibility(&info));
        assert!(!account_uses_remote_compatibility(&original()));
    }

    #[cfg(all(not(target_os = "macos"), feature = "remote-anisette-v3"))]
    #[test]
    fn delegate_preserves_aoskit_application_instead_of_messages_authkit() {
        let info = account_login_info(original());
        let delegate = "<iPhone9,1> <iPhone OS;15.8.3;19H386> <com.apple.AOSKit/282 (com.apple.accountsd/113)>";
        assert_eq!(account_delegate_info(&info, delegate),
            "<PC> <Windows;6.2(0,0);9200> <com.apple.AOSKit/282 (com.apple.accountsd/113)>");
    }

    #[test]
    fn legacy_delegate_retains_original_platform_and_application() {
        let delegate = "<iPhone9,1> <iPhone OS;15.8.3;19H386> <com.apple.AOSKit/282 (com.apple.accountsd/113)>";
        assert_eq!(account_delegate_info(&original(), delegate), delegate);
    }

    #[test]
    fn unknown_delegate_context_is_preserved_without_panicking() {
        let info = account_login_info(original());
        assert_eq!(account_delegate_info(&info, "unknown"), "unknown");
    }

    #[test]
    fn account_policy_preserves_hardware_and_service_metadata() {
        let info = account_login_info(original());
        assert_eq!(info.hardware_headers["X-Apple-I-SRL-NO"], "hardware-serial");
        assert_eq!(info.push_token.as_deref(), Some("existing-token"));
        assert_eq!(info.client_bundle_id, "com.apple.MobileSMS");
        assert_eq!(info.update_account_bundle_id, "existing-update-context");
    }

    #[test]
    fn unknown_client_info_is_preserved_without_panicking() {
        let mut info = original();
        info.mme_client_info_akd = "unrecognized context".into();
        assert_eq!(account_login_info(info).mme_client_info_akd, "unrecognized context");
    }

    #[test]
    fn restoring_legacy_tokens_retains_their_original_platform() {
        let info = original();
        let expected = info.mme_client_info_akd.clone();
        assert_eq!(restored_account_login_info(info, None).mme_client_info_akd, expected);
    }

    #[cfg(all(not(target_os = "macos"), feature = "remote-anisette-v3"))]
    #[test]
    fn restoring_compatibility_tokens_keeps_login_and_delegate_consistent() {
        let authenticated = account_login_info(original());
        let info = restored_account_login_info(original(), Some(&authenticated.mme_client_info_akd));
        assert_eq!(info.mme_client_info_akd, authenticated.mme_client_info_akd);
        assert_eq!(info.mme_client_info, authenticated.mme_client_info);
    }

    #[cfg(not(all(not(target_os = "macos"), feature = "remote-anisette-v3")))]
    #[test]
    fn native_provider_profiles_are_preserved() {
        let info = original();
        let expected = info.mme_client_info_akd.clone();
        assert_eq!(account_login_info(info).mme_client_info_akd, expected);
        assert!(!account_uses_remote_compatibility(&original()));
    }
}
