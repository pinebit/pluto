use std::collections::HashMap;

use bon::Builder;

/// Configuration for the tracing.
#[derive(Debug, Clone, Default, Builder)]
pub struct TracingConfig {
    /// Loki configuration. Enables loki logging if provided. If not - no loki
    /// logging is enabled.
    pub loki: Option<LokiConfig>,

    /// Console configuration. Enables console logging if provided. If not - no
    /// console logging is enabled.
    pub console: Option<ConsoleConfig>,

    /// Enables metrics logging. If not - no metrics logging is enabled.
    pub metrics: bool,

    /// Overrides the environment filter. If not - the environment filter is
    /// used.
    pub override_env_filter: Option<String>,
}

/// Configuration for the loki logging.
#[derive(Debug, Clone, Builder)]
pub struct LokiConfig {
    /// URL of the Loki instance.
    pub loki_url: String,

    /// Labels to add to the Loki logs.
    pub labels: HashMap<String, String>,

    /// Extra fields to add to the Loki logs.
    pub extra_fields: HashMap<String, String>,
}

/// Configuration for the console logging.
#[derive(Debug, Clone, Builder)]
pub struct ConsoleConfig {
    /// Whether to include the target module in logs.
    pub with_target: bool,

    /// Whether to include the log level in logs.
    pub with_level: bool,

    /// Whether to include thread IDs in logs.
    pub with_thread_ids: bool,

    /// Whether to include the source file name in logs.
    pub with_file: bool,

    /// Whether to include line numbers in logs.
    pub with_line_number: bool,

    /// Whether to use ANSI colors in logs.
    pub with_ansi: bool,
}

impl Default for ConsoleConfig {
    fn default() -> Self {
        Self {
            with_target: true,
            with_level: true,
            with_thread_ids: false,
            with_file: false,
            with_line_number: false,
            with_ansi: true,
        }
    }
}
