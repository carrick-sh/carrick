use std::io::Write as _;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    Pass,
    Fail,
}

impl Status {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
        }
    }
}

#[derive(Debug)]
pub struct ProbeReport {
    name: &'static str,
    status: Status,
    fields: Vec<(&'static str, String)>,
}

impl ProbeReport {
    pub fn new(name: &'static str, status: Status) -> Self {
        Self {
            name,
            status,
            fields: Vec::new(),
        }
    }

    pub fn field(mut self, key: &'static str, value: impl ToString) -> Self {
        self.fields.push((key, value.to_string()));
        self
    }

    pub fn print(&self) {
        print!("probe={} status={}", self.name, self.status.as_str());
        for (key, value) in &self.fields {
            print!(" {key}={}", shell_escape(value));
        }
        println!();
        let _ = std::io::stdout().flush();
    }

    pub fn status(&self) -> Status {
        self.status
    }
}

fn shell_escape(value: &str) -> String {
    if value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'/' | b':')
    }) {
        return value.to_string();
    }

    let mut escaped = String::from("'");
    for ch in value.chars() {
        if ch == '\'' {
            escaped.push_str("'\\''");
        } else {
            escaped.push(ch);
        }
    }
    escaped.push('\'');
    escaped
}
