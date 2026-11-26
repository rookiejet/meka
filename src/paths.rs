//! Where Meka keeps things: the configuration and data directories, the file each holds, and the
//! `~` expansion every path setting goes through. A leaf, so any layer may ask without reaching
//! into `config`.

use std::path::{Path, PathBuf};

/// A directory in a WSL distribution. The guest path is POSIX text, not a Windows `PathBuf`, so
/// comparison and resolution cannot accidentally follow Win32 path rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WslDirectory {
    distribution: String,
    guest_path: String,
}

impl WslDirectory {
    #[cfg(windows)]
    pub(crate) fn distribution(&self) -> &str {
        &self.distribution
    }

    #[cfg(windows)]
    pub(crate) fn guest_path(&self) -> &str {
        &self.guest_path
    }

    /// Recognize WSL aliases on Windows without consulting the UNC provider or starting a distro.
    /// An invalid path in either alias is an error, never a native path.
    pub(crate) fn from_run_directory(path: &Path) -> Result<Option<Self>, &'static str> {
        if !cfg!(windows) {
            return Ok(None);
        }
        Self::from_explorer_path(path)
    }

    fn from_explorer_path(path: &Path) -> Result<Option<Self>, &'static str> {
        // Recognize the ASCII namespace even if a later path component is not Unicode. A lossy
        // conversion is sufficient only for that test; it must never supply a guest path.
        let displayed = path.to_string_lossy();
        let separators = ['\\', '/'];
        let rest = displayed.trim_start_matches(separators);
        if displayed.len() - rest.len() < 2 {
            return Ok(None);
        }
        let mut components = rest.split(separators);
        let server = match components.next() {
            Some("?" | ".") => match components.next() {
                Some(namespace) if namespace.eq_ignore_ascii_case("unc") => components.next(),
                _ => None,
            },
            server => server,
        };
        if !server.is_some_and(|server| {
            server.eq_ignore_ascii_case("wsl.localhost") || server.eq_ignore_ascii_case("wsl$")
        }) {
            return Ok(None);
        }
        if path.to_str().is_none() || displayed.chars().any(char::is_control) {
            return Err("WSL paths must be Unicode and contain no control characters");
        }
        let distribution = components
            .next()
            .filter(|name| !matches!(*name, "" | "." | ".."))
            .ok_or("a WSL path must name a distribution")?;
        let components: Vec<_> = components.filter(|part| !part.is_empty()).collect();
        if components.is_empty() {
            return Err("a WSL path must name a directory below the distribution root");
        }
        if components.iter().any(|part| matches!(*part, "." | "..")) {
            return Err("WSL paths must not contain `.` or `..` components");
        }
        Ok(Some(Self {
            distribution: distribution.to_owned(),
            guest_path: format!("/{}", components.join("/")),
        }))
    }
}

impl std::fmt::Display for WslDirectory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            r"\\wsl.localhost\{}{}",
            self.distribution,
            self.guest_path.replace('/', "\\"),
        )
    }
}

/// Expand a leading `~` or `~/` in a user-supplied path to the home directory.
///
/// Returns `None` only when a tilde needs the home directory but it cannot be determined, which the
/// caller reports rather than silently treating `~` as a relative directory of that name.
///
/// Shared by the screen's `/cd` (and its path completer) and by `[skills] additional_directories`,
/// so a tilde means the same thing wherever a user types a path. Deliberately does *not* expand
/// `~user`: that needs a password-database lookup, and no config surface here has ever accepted the
/// form.
pub(crate) fn expand_user_path(target: &str) -> Option<PathBuf> {
    if target.is_empty() || target == "~" {
        dirs::home_dir()
    } else if let Some(rest) = target
        .strip_prefix('~')
        .and_then(|rest| rest.strip_prefix(std::path::is_separator))
    {
        // `is_separator`, not a literal `"~/"`. On Windows both `/` and `\` separate, and `~\` is
        // the spelling a user reaches for there because that is what PowerShell's own tilde
        // expansion produces. Matched on `~/` only, `~\projects` stays a literal relative
        // directory of that name.
        dirs::home_dir().map(|home| home.join(rest))
    } else {
        Some(PathBuf::from(target))
    }
}
/// Returns the Meka config directory (the directory that contains `config.toml` and `skills/`).
/// Honors the `MEKA_CONFIG_DIR` env var, used by tests for per-run isolation and by power users
/// who want a non-standard location, before falling back to the platform-native
/// `dirs::config_dir().join("meka")`. The env-var route is the only reliable way to isolate state
/// on macOS and Windows, where `dirs::config_dir()` doesn't honor `XDG_CONFIG_HOME`.
///
/// `None` for a relative override as well as for a platform with no config directory: the user
/// asked for another directory, and the platform's would be the real one, so a relative value
/// fails closed. [`refuse_relative_overrides`] says so at startup.
pub(crate) fn meka_config_dir() -> Option<PathBuf> {
    match override_of(std::env::var_os("MEKA_CONFIG_DIR")) {
        Override::Absolute(path) => Some(path),
        Override::Relative(_) => None,
        Override::Unset => dirs::config_dir().map(|directory| directory.join("meka")),
    }
}

/// What a directory override holds. An empty value reads as unset, as an empty `XDG_*` does: a
/// shell profile's `MEKA_CONFIG_DIR=` or a systemd unit that exports one blank asks for nothing.
enum Override {
    Unset,
    Absolute(PathBuf),
    Relative(PathBuf),
}

fn override_of(value: Option<std::ffi::OsString>) -> Override {
    match value {
        None => Override::Unset,
        Some(value) if value.is_empty() => Override::Unset,
        Some(value) => {
            let path = PathBuf::from(value);
            if path.is_absolute() {
                Override::Absolute(path)
            } else {
                Override::Relative(path)
            }
        }
    }
}

/// Refuse a relative `MEKA_CONFIG_DIR` or `MEKA_DATA_DIR`, before anything reads either directory.
///
/// Falling back to the platform directory would act on the real configuration and the real store,
/// credentials and all, when the user asked for another place; resolving it against the working
/// directory would give each launch directory its own store. Neither is what was meant.
pub(crate) fn refuse_relative_overrides() -> Result<(), String> {
    for (variable, value) in [
        ("MEKA_CONFIG_DIR", std::env::var_os("MEKA_CONFIG_DIR")),
        ("MEKA_DATA_DIR", std::env::var_os("MEKA_DATA_DIR")),
    ] {
        if let Override::Relative(path) = override_of(value) {
            return Err(format!(
                "`{variable}` must be an absolute path, not '{}'",
                path.display()
            ));
        }
    }
    Ok(())
}

/// The directory `meka.db` lives in: the `MEKA_DATA_DIR` override, else the platform data
/// directory's `meka` subdirectory. `None` when the platform names no data directory at all, and
/// for a relative override, for the reason [`meka_config_dir`] gives.
///
/// `dirs::data_dir()` honors `XDG_DATA_HOME` on Linux, returns `~/Library/Application Support` on
/// macOS, and `%APPDATA%` on Windows. No silent fallback: writing the session store to a
/// wrong-for-the-platform path is worse than asking the user to set `MEKA_DATA_DIR`.
pub(crate) fn meka_data_dir() -> Option<PathBuf> {
    match override_of(std::env::var_os("MEKA_DATA_DIR")) {
        Override::Absolute(path) => Some(path),
        Override::Relative(_) => None,
        Override::Unset => dirs::data_dir().map(|base| base.join("meka")),
    }
}
/// `config.toml`'s path, under [`meka_config_dir`].
pub(crate) fn config_file_path() -> Option<PathBuf> {
    meka_config_dir().map(|dir| dir.join("config.toml"))
}

/// The skills directory Meka itself manages, under [`meka_config_dir`].
pub(crate) fn skills_dir() -> Option<PathBuf> {
    crate::paths::meka_config_dir().map(|dir| dir.join("skills"))
}
/// The roots to scan, in precedence order: Meka's own first, then `additional_directories` as
/// given.
///
/// Meka's own root leads because it is the store the user curates *through Meka*, and because it is
/// the only one anything writes to; a skill there should not be shadowed by a copy another client
/// installed.
pub(crate) fn skill_roots(extra: &[PathBuf]) -> Vec<PathBuf> {
    skills_dir()
        .into_iter()
        .chain(extra.iter().cloned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wsl_explorer_aliases_keep_guest_path_case_and_punctuation() {
        let expected = WslDirectory {
            distribution: "Ubuntu 24.04".to_string(),
            guest_path: "/home/dev/Build Tools/Éxample".to_string(),
        };
        for path in [
            r"\\wsl.localhost\Ubuntu 24.04\home\dev\Build Tools\Éxample",
            r"\\WSL$\Ubuntu 24.04\home\dev\Build Tools\Éxample\",
            r"\\?\UNC\wsl.localhost\Ubuntu 24.04\home\dev\Build Tools\Éxample",
            "//wsl.localhost/Ubuntu 24.04/home/dev/Build Tools/Éxample",
        ] {
            assert_eq!(
                WslDirectory::from_explorer_path(Path::new(path)),
                Ok(Some(expected.clone())),
                "{path}"
            );
        }
        assert_eq!(
            expected.to_string(),
            r"\\wsl.localhost\Ubuntu 24.04\home\dev\Build Tools\Éxample"
        );
    }

    #[test]
    fn invalid_wsl_roots_are_errors_not_native_paths() {
        for path in [
            r"\\wsl.localhost",
            r"\\wsl$\",
            r"\\wsl.localhost\Ubuntu",
            r"\\wsl$\Ubuntu\",
            r"\\wsl$\Ubuntu\home\..\etc",
            r"\\wsl.localhost\Ubuntu\home\.\dev",
            "\\\\wsl$\\Ubuntu\\embedded\0nul",
        ] {
            assert!(
                WslDirectory::from_explorer_path(Path::new(path)).is_err(),
                "{path}"
            );
        }
        for path in [
            r"C:\work",
            r".\wsl.localhost\Ubuntu",
            r"\\example.net\wsl$\Ubuntu\home",
            r"\\wsl.localhost.example.net\Ubuntu\home",
            r"\\?\C:\work",
        ] {
            assert_eq!(WslDirectory::from_explorer_path(Path::new(path)), Ok(None));
        }
    }

    #[cfg(windows)]
    #[test]
    fn a_non_unicode_guest_path_never_falls_back_to_native() {
        use std::{ffi::OsString, os::windows::ffi::OsStringExt};

        let units: Vec<_> = r"\\wsl$\Ubuntu\home\"
            .encode_utf16()
            .chain([0xd800])
            .collect();
        let path = PathBuf::from(OsString::from_wide(&units));
        assert!(WslDirectory::from_run_directory(&path).is_err());
    }

    /// A relative override is refused, and no directory is resolved from it meanwhile, neither
    /// the platform's nor one under the working directory; an empty one is unset.
    #[test]
    fn a_relative_directory_override_is_refused_and_resolves_to_nothing() {
        let _guard = crate::config::CONFIG_DIR_ENV_LOCK.blocking_lock();
        // SAFETY: guarded above.
        unsafe { std::env::set_var("MEKA_DATA_DIR", "relative/data") };
        let refused = refuse_relative_overrides();
        let resolved = meka_data_dir();
        // SAFETY: guarded above.
        unsafe { std::env::set_var("MEKA_DATA_DIR", "") };
        let unset = meka_data_dir();
        // SAFETY: guarded above.
        unsafe { std::env::remove_var("MEKA_DATA_DIR") };

        let refused = refused.expect_err("a relative override is refused");
        assert!(refused.contains("`MEKA_DATA_DIR`"), "{refused}");
        assert_eq!(resolved, None, "and resolves to no directory meanwhile");
        assert_eq!(
            unset,
            dirs::data_dir().map(|base| base.join("meka")),
            "an empty one is unset"
        );
    }
}
