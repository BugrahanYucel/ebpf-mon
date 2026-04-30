use core::fmt::Display;
use super::PathPattern;

impl Display for PathPattern {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

