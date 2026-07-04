use conformance_probes::report;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

unsafe fn reset_errno() {
    #[cfg(any(target_env = "gnu", target_env = "musl"))]
    {
        *libc::__errno_location() = 0;
    }
}

fn main() {
    let payload = [b'x'];

    unsafe {
        reset_errno();
        let add_key = libc::syscall(
            217,
            c"user".as_ptr(),
            c"carrick_probe".as_ptr(),
            payload.as_ptr(),
            payload.len(),
            -2_i64,
        );
        let add_key_errno = errno();

        reset_errno();
        let request_key = libc::syscall(
            218,
            c"user".as_ptr(),
            c"missing_carrick_probe".as_ptr(),
            c"".as_ptr(),
            -2_i64,
        );
        let request_key_errno = errno();

        reset_errno();
        let keyctl_join = libc::syscall(219, 1_i64, c"carrick_probe".as_ptr());
        let keyctl_join_errno = errno();

        reset_errno();
        let keyctl_get_keyring_id = libc::syscall(219, 0_i64);
        let keyctl_get_keyring_id_errno = errno();

        report!(
            add_key_ret = add_key,
            add_key_errno = add_key_errno,
            request_key_ret = request_key,
            request_key_errno = request_key_errno,
            keyctl_join_ret = keyctl_join,
            keyctl_join_errno = keyctl_join_errno,
            keyctl_get_keyring_id_ret = keyctl_get_keyring_id,
            keyctl_get_keyring_id_errno = keyctl_get_keyring_id_errno,
        );
    }
}
