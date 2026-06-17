use clap::{Parser, Subcommand};
use password_manager::*;
use std::process;

#[derive(Parser)]
#[command(
    name = "pass-manager",
    version = "1.0",
    author = "https://github.com/Anthoxoo",
    about = "A simple password manager."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Add {
        #[arg(long)]
        url: String,

        #[arg(long)]
        username: String,
    },
    Delete {
        #[arg(long)]
        url: String,
    },
    Modify {
        #[arg(long)]
        url: String,

        #[arg(long)]
        new_username: String,
    },
    List,
}

fn main() {
    let cli = Cli::parse();

    let file_path = get_full_file_path("/.config/password-manager")
        .expect("Couldn't find the HOME env variable.");

    create_folder(&file_path).expect("Error creating or finding the folder.");

    let mut manager = launch_program();

    match cli.command {
        Commands::Add { url, username } => {
            let input_password = dialoguer::Password::new()
                .with_prompt("Enter the password associated with this url and username ")
                .interact()
                .unwrap();

            if let Err(e) = manager.add_password(url, username, input_password) {
                eprintln!("An error occurred : {}", e);
                process::exit(2);
            }
        }
        Commands::Delete { url } => {
            if let Err(e) = manager.delete_password(url) {
                eprintln!("An error occurred : {}", e);
                process::exit(3);
            }
        }
        Commands::Modify { url, new_username } => {
            let input_password = dialoguer::Password::new()
                .with_prompt("Enter your master password ")
                .interact()
                .unwrap();

            if let Err(e) = manager.modify_password(url, new_username, input_password) {
                eprintln!("An error occurred : {}", e);
                process::exit(3);
            }
        }
        Commands::List => {
            if let Err(e) = manager.list_passwords() {
                eprintln!("An error occurred : {}", e);
                process::exit(4);
            }
        }
    }

    manager.close_manager(file_path)
}
