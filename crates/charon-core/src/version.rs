// #![allow(missing_docs)]

use std::{cmp, fmt, sync::LazyLock};

type Result<T> = std::result::Result<T, VersionError>;

/// Errors that can occur when parsing or handling semantic versions.
#[derive(Debug, thiserror::Error)]
pub enum VersionError {
    /// Invalid version format when parsing a semantic version.
    #[error("Invalid version format")]
    InvalidFormat,
}

// TODO: Override at build time
const VERSION_STR: &'static str = "v1.7.1";

/// The branch version of the codebase.
///     - Main branch: v0.X-dev
///     - Release branch: v0.Y-rc
pub static VERSION: LazyLock<SemVer> = LazyLock::new(|| SemVer::try_from(VERSION_STR).unwrap());

// These variables are populated with build information via -ldflags when
// binaries are built, but not in Dockerfile.
const VCS_REVISION: &'static str = "";
const VCS_TIME: &'static str = "";

/// Git commit hash and timestamp from build info.
pub const fn git_commit() -> (&'static str, &'static str) {
    todo!()
}

/// Supported minor versions in order of precedence.
pub const SUPPORTED: &'static [SemVer] = {
    const fn v(major: usize, minor: usize) -> SemVer {
        SemVer {
            sem_ver_type: SemVerType::Minor,
            major,
            minor,
            patch: 0,
            pre_release: String::new(),
        }
    }

    &[
        v(1, 7),
        v(1, 6),
        v(1, 5),
        v(1, 4),
        v(1, 3),
        v(1, 2),
        v(1, 1),
        v(1, 0),
    ]
};

/// The type of semantic version, i.e., minor, patch, or pre-release.
#[derive(Eq, PartialEq, Debug)]
pub enum SemVerType {
    /// Only major and minor version present, e.g., v1.2
    Minor,
    /// Major, minor, and patch version present, e.g., v1.2.3
    Patch,
    /// Pre-release version present, e.g., v1.2.3-rc
    PreRelease,
}

/// Represents a semantic version. A valid [`SemVer`] contains a major and minor
/// version and optionally either a patch version or a pre-release label,
/// i.e., v1.2 or v1.2.3 or v1.2-rc.
#[derive(Debug)]
pub struct SemVer {
    sem_ver_type: SemVerType,
    major: usize,
    minor: usize,
    patch: usize,
    pre_release: String,
}

impl SemVer {
    /// Returns true if the [`SemVer`] represents a tag for a pre-release.
    pub fn is_pre_release(&self) -> bool {
        self.sem_ver_type == SemVerType::PreRelease
    }

    /// Produces the minor version of the semantic version.
    /// It strips the [`patch`] version and [`pre_release`] label if present.
    pub const fn is_minor(&self) -> SemVer {
        Self {
            sem_ver_type: SemVerType::Minor,
            major: self.major,
            minor: self.minor,
            patch: 0,
            pre_release: String::new(),
        }
    }
}

impl fmt::Display for SemVer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.sem_ver_type {
            SemVerType::Minor => write!(f, "v{}.{}", self.major, self.minor),
            SemVerType::Patch => write!(f, "v{}.{}.{}", self.major, self.minor, self.patch),
            SemVerType::PreRelease => {
                write!(
                    f,
                    "v{}.{}.{}-{}",
                    self.major, self.minor, self.patch, self.pre_release
                )
            }
        }
    }
}

impl PartialEq for SemVer {
    fn eq(&self, other: &Self) -> bool {
        self.partial_cmp(other).unwrap() == cmp::Ordering::Equal
    }
}

impl PartialOrd for SemVer {
    // Only major and minor versions are used for comparison, unless both self and
    // other have patch versions, in which case the patch version is also used.
    // Pre-release labels are ignored.
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        if self.major != other.major {
            if self.major < other.major {
                return Some(cmp::Ordering::Less);
            }

            return Some(cmp::Ordering::Greater);
        }

        if self.minor != other.minor {
            if self.minor < other.minor {
                return Some(cmp::Ordering::Less);
            }

            return Some(cmp::Ordering::Greater);
        }

        if self.sem_ver_type != SemVerType::Patch || other.sem_ver_type != SemVerType::Patch {
            return Some(cmp::Ordering::Equal);
        }

        if self.patch == other.patch {
            return Some(cmp::Ordering::Equal);
        } else if self.patch < other.patch {
            return Some(cmp::Ordering::Less);
        }

        return Some(cmp::Ordering::Greater);
    }
}

static SEMVER_REGEX: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^v(\d+)\.(\d+)(?:\.(\d+))?(?:-(.+))?$").unwrap());

impl TryFrom<&str> for SemVer {
    type Error = VersionError;

    fn try_from(value: &str) -> Result<Self> {
        let matches = SEMVER_REGEX
            .captures(value)
            .filter(|matches| !(matches.len() == 0 || matches.len() != 5))
            .ok_or(VersionError::InvalidFormat)?;

        let major = matches[1].parse().expect("regex ensures number");
        let minor = matches[2].parse().expect("regex ensures number");

        let mut patch = 0;
        let mut pre_release = "";
        let mut sem_ver_type = SemVerType::Minor;

        if let Some(m) = matches.get(3) {
            patch = m.as_str().parse().expect("regex ensures number");
            sem_ver_type = SemVerType::Patch;
        }

        if let Some(m) = matches.get(4) {
            pre_release = m.as_str();
            sem_ver_type = SemVerType::PreRelease;
        }

        Ok(SemVer {
            major,
            minor,
            patch,
            pre_release: pre_release.to_string(),
            sem_ver_type,
        })
    }
}
