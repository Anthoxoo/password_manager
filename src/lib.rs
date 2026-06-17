use bcrypt::{DEFAULT_COST, hash, verify};
use chrono::{DateTime, Duration, Utc};
use magic_crypt::{MagicCrypt256, MagicCryptTrait, new_magic_crypt};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::process;

#[derive(Serialize, Deserialize)]
pub struct PasswordManager {
    #[serde(skip)]
    state: State,
    master_password: String,
    #[serde(skip)]
    encryption_key: Option<String>,
    password: HashMap<String, Password>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Password {
    username: String,
    password: String,
}

#[derive(Debug, PartialEq, Default)]
enum State {
    #[default]
    Locked,
    Unlocked,
}
impl PasswordManager {
    pub fn new(master_password: String) -> Self {
        PasswordManager {
            state: State::Locked,
            master_password: hash(master_password, DEFAULT_COST)
                .expect("Error hashing the master password."),
            password: HashMap::new(),
            encryption_key: None,
        }
    }

    pub fn load(path: String) -> Result<Self, &'static str> {
        let new_path = format!("{}/passwords.json", path);
        if let Ok(json_data) = fs::read_to_string(new_path) {
            // File exists
            if let Ok(mut manager) = serde_json::from_str::<PasswordManager>(&json_data) {
                // We managed to read it properly
                manager.state = State::Locked;
                manager.encryption_key = None;
                // no need for the master pass and the passwords because serde did it for us by serialize it from the json file.
                return Ok(manager);
            } else {
                return Err("Error reading from json file, serde?");
            }
        }
        Err("Error loading the password.json file.")
    }

    fn unlock_manager(&mut self, master_pass: String) {
        self.state = State::Unlocked;
        self.encryption_key = Some(master_pass);
    }

    pub fn open_manager(&mut self, master_pass: String) -> Result<(), &'static str> {
        if verify(&master_pass, &self.master_password)
            .expect("Error hashing password to verify it.")
        {
            self.unlock_manager(master_pass);
            Ok(())
        } else {
            Err("Wrong password.")
        }
    }

    pub fn close_manager(&mut self, path: String) {
        self.state = State::Locked;
        self.encryption_key = None;
        self.save_config_file(path).expect("Error saving the file.")
    }

    pub fn add_password(
        &mut self,
        url: String,
        username: String,
        password: String,
    ) -> Result<(), &'static str> {
        if self.state == State::Locked {
            Err("The manager is locked.")
        } else {
            let key = self.encryption_key.as_ref().unwrap();
            let mc = new_magic_crypt!(key, 256);

            let new_password = Password {
                username: username,
                password: encrypt_password(password, mc),
            };

            self.password.insert(url, new_password);
            Ok(())
        }
    }

    pub fn modify_password(
        &mut self,
        url: String,
        username: String,
        new_password: String,
    ) -> Result<(), &'static str> {
        if self.state == State::Locked {
            return Err("The manager is locked.");
        }
        if let Some(entry) = self.password.get_mut(&url) {
            let key = self.encryption_key.as_ref().unwrap();
            let mc = new_magic_crypt!(key, 256);

            entry.username = username;
            entry.password = encrypt_password(new_password, mc);

            Ok(())
        } else {
            Err("Url not found.")
        }
    }

    pub fn delete_password(&mut self, url: String) -> Result<(), &'static str> {
        if self.state == State::Locked {
            return Err("The manager is locked.");
        }
        if self.password.remove(&url).is_some() {
            Ok(())
        } else {
            Err("Url not found.")
        }
    }

    pub fn list_passwords(&self) -> Result<(), &'static str> {
        if self.state == State::Locked {
            return Err("The manager is locked.");
        }
        let key = self.encryption_key.as_ref().unwrap();
        let mc = new_magic_crypt!(key, 256);

        for (url, entry) in self.password.iter() {
            let decrypted_password = decrypt_password(entry.password.clone(), mc.clone());

            println!(
                "URL : {} | username : {} | password : {}",
                url, entry.username, decrypted_password
            );
        }

        Ok(())
    }

    fn save_config_file(&self, path: String) -> Result<(), &'static str> {
        if self.state == State::Unlocked {
            return Err("The manager is unlocked, you must lock it before saving the file.");
        } else {
            let new_config_path = format!("{}/passwords.json", path);
            let json_data =
                serde_json::to_string_pretty(self).expect("Error serializing to the json format.");

            fs::write(new_config_path, json_data)
                .expect("Error trying to save the file on the disk.");
            Ok(())
        }
    }
}

fn encrypt_password(password: String, key: MagicCrypt256) -> String {
    key.encrypt_str_to_base64(password)
}

fn decrypt_password(password: String, key: MagicCrypt256) -> String {
    key.decrypt_base64_to_string(password)
        .expect("Error decrypting the password.")
}

pub fn launch_program() -> PasswordManager {
    let file_path = get_full_file_path("/.config/password-manager")
        .expect("Couldn't find the HOME env variable.");
    let tmp_file_path: &str = "/tmp/password-manager/timestamp.tmp";

    if let Ok(mut existing_manager) = PasswordManager::load(file_path.clone()) {
        // mut because open_manager takes a &mut self

        let current_time = Utc::now();

        if let Ok(tmp_file_content) = fs::read_to_string(tmp_file_path) {
            let vec_content: Vec<&str> = tmp_file_content.split("|").collect();

            let file_timestamp: DateTime<Utc> = vec_content[0].trim().parse().unwrap();
            let input_master = vec_content[1].trim().to_string();

            let ending_time = file_timestamp + Duration::minutes(5); // adds 5minutes to the time indicated in the tmp file.

            if current_time < ending_time {
                if existing_manager.open_manager(input_master.clone()).is_ok() {
                    save_tmp_file(tmp_file_path, input_master).expect("Error saving the tmp file");

                    return existing_manager;
                }
            }
        }

        let input_master = dialoguer::Password::new()
            .with_prompt("Enter your master password ")
            .interact()
            .unwrap();

        if let Err(e) = existing_manager.open_manager(input_master.clone()) {
            eprintln!("Denied acces ! : {}", e);
            process::exit(1);
        }

        save_tmp_file(tmp_file_path, input_master).expect("Error saving the tmp file");

        existing_manager
    } else {
        create_folder(&file_path).expect("Error creating config file.");
        println!("Welcome on our password manager !");

        let new_master = dialoguer::Password::new()
            .with_prompt("Create a master password (you'll have to remember it !!)")
            .interact()
            .unwrap();

        let mut new_manager = PasswordManager::new(new_master.clone());

        if let Err(e) = new_manager.save_config_file(file_path.clone()) {
            eprintln!("Error while saving the file on the disk : {}", e);
            process::exit(1);
        }

        new_manager
            .open_manager(new_master.clone())
            .expect("Error opening manager");

        save_tmp_file(tmp_file_path, new_master).expect("Error saving the tmp file");

        new_manager
    }
}

pub fn get_full_file_path(relative_path: &str) -> Result<String, &'static str> {
    if let Ok(home) = env::var("HOME") {
        return Ok(format!("{}{}", home, relative_path));
    } else {
        return Err("Couldn't find the HOME env variable.");
    }
}

pub fn create_folder(path: &str) -> Result<(), String> {
    if let Err(_) = fs::create_dir_all(&path) {
        return Err(format!("Error creating the {} folder", path));
    }
    Ok(())
}

fn save_tmp_file(path: &str, txt: String) -> Result<(), &'static str> {
    let tmp_txt: String = format!("{} | {}", Utc::now(), txt);
    fs::write(path, tmp_txt).expect("Error creating and / or writing in the tmp file.");
    Ok(())
}
