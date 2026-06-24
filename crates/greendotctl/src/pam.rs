//! PAM authentication plus admin-group authorization for the web UI.
//!
//! The PAM conversation itself can only be exercised against a real PAM
//! stack (covered by the dev-VM smoke tests); the rate limiter and the
//! membership rule are pure and unit-tested here.

use greendot_proto::{ErrKind, Response, Secret, Username};
use std::sync::Mutex;
use std::time::Instant;

pub struct AuthConfig {
    pub pam_service: String,
    pub admin_group: String,
}

/// Token bucket: at most `capacity` attempts per `window_secs` window.
pub struct RateLimiter {
    capacity: f64,
    refill_per_sec: f64,
    tokens: f64,
    last: Instant,
}

impl RateLimiter {
    pub fn new(capacity: u32, window_secs: f64, now: Instant) -> Self {
        let capacity = f64::from(capacity);
        RateLimiter {
            capacity,
            refill_per_sec: capacity / window_secs,
            tokens: capacity,
            last: now,
        }
    }

    pub fn allow(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// The authorization rule: a user is admin if the admin group is their
/// primary group or lists them as a member.
fn is_member(
    username: &str,
    user_primary_gid: Option<u32>,
    group_gid: u32,
    group_members: &[String],
) -> bool {
    user_primary_gid == Some(group_gid) || group_members.iter().any(|m| m == username)
}

fn in_admin_group(username: &str, admin_group: &str) -> bool {
    let Ok(Some(group)) = nix::unistd::Group::from_name(admin_group) else {
        return false;
    };
    let primary_gid = nix::unistd::User::from_name(username)
        .ok()
        .flatten()
        .map(|u| u.gid.as_raw());
    is_member(username, primary_gid, group.gid.as_raw(), &group.mem)
}

pub fn authenticate(
    cfg: &AuthConfig,
    limiter: &Mutex<RateLimiter>,
    username: &Username,
    password: &Secret,
) -> Response {
    if !limiter.lock().unwrap().allow(Instant::now()) {
        return Response::err(
            ErrKind::Busy,
            "too many authentication attempts, try again later",
        );
    }
    if let Err(e) = pam_check(&cfg.pam_service, username.as_str(), &password.0) {
        tracing::warn!(user = %username, error = %e, "PAM authentication failed");
        return Response::err(ErrKind::AuthFailed, "invalid username or password");
    }
    if !in_admin_group(username.as_str(), &cfg.admin_group) {
        tracing::warn!(user = %username, group = %cfg.admin_group, "authenticated but not in admin group");
        return Response::err(
            ErrKind::NotInAdminGroup,
            format!("user is not a member of the {} group", cfg.admin_group),
        );
    }
    tracing::info!(user = %username, "login successful");
    Response::OkAuth {
        username: username.to_string(),
    }
}

fn pam_check(service: &str, username: &str, password: &str) -> Result<(), pam::PamError> {
    let mut auth = pam::Authenticator::with_password(service)?;
    auth.get_handler().set_credentials(username, password);
    auth.authenticate()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use std::time::Duration;

    #[test]
    fn rate_limiter_allows_burst_then_blocks_then_refills() {
        let t0 = Instant::now();
        let mut rl = RateLimiter::new(5, 30.0, t0);
        for i in 0..5 {
            assert!(rl.allow(t0), "attempt {i} within burst should pass");
        }
        assert!(!rl.allow(t0), "6th immediate attempt must be blocked");
        // After 6 seconds one token has refilled (5 tokens / 30 s).
        let t1 = t0 + Duration::from_secs(6);
        assert!(rl.allow(t1), "one attempt allowed after partial refill");
        assert!(!rl.allow(t1), "but only one");
        // A full window later the full burst is available again.
        let t2 = t1 + Duration::from_secs(30);
        for i in 0..5 {
            assert!(rl.allow(t2), "attempt {i} after full refill should pass");
        }
        assert!(!rl.allow(t2));
    }

    #[rstest]
    #[case::listed_member("alice", Some(100), 990, &["bob".into(), "alice".into()], true)]
    #[case::primary_group("alice", Some(990), 990, &[], true)]
    #[case::not_member("alice", Some(100), 990, &["bob".into()], false)]
    #[case::unknown_user("alice", None, 990, &[], false)]
    #[case::empty_group("alice", Some(100), 990, &[], false)]
    fn membership_rule(
        #[case] user: &str,
        #[case] primary_gid: Option<u32>,
        #[case] group_gid: u32,
        #[case] members: &[String],
        #[case] expected: bool,
    ) {
        assert_eq!(is_member(user, primary_gid, group_gid, members), expected);
    }
}
