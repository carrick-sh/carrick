#![allow(dead_code, unused_macros)]

mod default_abi {
    #[rustfmt::skip]
    unsafe extern {
        fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
    }
}

mod c_abi {
    unsafe extern "C" {
        fn kill(pid: i32, signal: i32) -> i32;

        #[link_name = "waitpid"]
        fn carrier_wait(pid: i32) -> i32;
    }
}

mod c_unwind_abi {
    unsafe extern "C-unwind" {
        fn open(path: *const i8, flags: i32, ...) -> i32;
    }
}

macro_rules! declare_process_control {
    () => {
        unsafe extern "C" {
            fn fork() -> i32;
        }
    };
}
