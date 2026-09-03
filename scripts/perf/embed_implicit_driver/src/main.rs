use std::io::{self, Write};

use carrick_embed::ContainerBuilder;

struct Arguments {
    image: String,
    run_id: String,
    workdir: String,
    command: Vec<String>,
}

fn parse_arguments() -> Result<Arguments, String> {
    let mut args = std::env::args().skip(1);
    let image_flag = args.next();
    let image = args.next();
    let run_id_flag = args.next();
    let run_id = args.next();
    let workdir_flag = args.next();
    let workdir = args.next();
    let command = args.collect::<Vec<_>>();

    if image_flag.as_deref() != Some("--image")
        || run_id_flag.as_deref() != Some("--run-id")
        || workdir_flag.as_deref() != Some("--workdir")
        || image.as_ref().is_none_or(String::is_empty)
        || run_id.as_ref().is_none_or(String::is_empty)
        || workdir.as_ref().is_none_or(String::is_empty)
        || command.is_empty()
    {
        return Err(
            "usage: carrick-embed-implicit-driver --image IMAGE --run-id ID --workdir DIR COMMAND [ARG ...]"
                .to_string(),
        );
    }

    Ok(Arguments {
        image: image.expect("validated image"),
        run_id: run_id.expect("validated run id"),
        workdir: workdir.expect("validated workdir"),
        command,
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_arguments().map_err(io::Error::other)?;

    // This executable is single-threaded until Carrick starts its runtime, and
    // the variable is set exactly once before that point. The dedicated process
    // makes the launch identity explicit without adding an extension to the
    // public implicit-carrier API being measured.
    unsafe { std::env::set_var("CARRICK_RUN_ID", &args.run_id) };

    let result = ContainerBuilder::from_image(&args.image)
        .env("CARRICK_RUN_ID", &args.run_id)
        .workdir(&args.workdir)
        .command(args.command)
        .run_blocking()?
        .ensure_success()?;

    io::stdout().write_all(&result.stdout)?;
    io::stderr().write_all(&result.stderr)?;
    Ok(())
}
