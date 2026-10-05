use clap::Parser;

#[cfg(feature = "cli")]
mod cli;

#[cfg(feature = "cli")]
use cli::{
    bench::run_bench,
    commands::{run_compile, run_info, run_lookup},
    convert::run_convert,
    Cli, Commands,
};

fn main() -> anyhow::Result<()> {
    #[cfg(feature = "cli")]
    {
        let cli = Cli::parse();

        match cli.command {
            Commands::Compile(args) => run_compile(*args)?,
            Commands::Lookup(args) => run_lookup(args)?,
            Commands::Info(args) => run_info(args)?,
            Commands::Convert(args) => run_convert(args)?,
            Commands::Bench(args) => run_bench(args)?,
        }
    }

    Ok(())
}
