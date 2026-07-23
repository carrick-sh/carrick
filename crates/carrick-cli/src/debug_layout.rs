//! Portable machine-readable debug contracts shared by host backends.

pub(crate) fn native_x86_layout_json() -> serde_json::Value {
    let layout = carrick_runtime::x86_dsr_profiler_layout();
    serde_json::json!({
        "schema": "carrick.native-x86-profiler-layout.v1",
        "version": layout.version,
        "context_register": layout.context_register,
        "context_size": layout.context_size,
        "exit_resume_offset": layout.exit_resume_offset,
    })
}

#[cfg(test)]
mod tests {
    use super::native_x86_layout_json;

    #[test]
    fn native_x86_layout_uses_the_versioned_gateway_contract() {
        let json = native_x86_layout_json();
        assert_eq!(json["schema"], "carrick.native-x86-profiler-layout.v1");
        assert_eq!(json["version"], 1);
        assert_eq!(json["context_register"], "R_R15");
        assert_eq!(
            json["exit_resume_offset"],
            carrick_runtime::x86_dsr_profiler_layout().exit_resume_offset
        );
    }
}
