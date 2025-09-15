use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{SaltString, PasswordHash};
use rand_core::OsRng;
use std::env;

fn get_argon2() -> Argon2<'static> {
    let mem_cost = env::var("ARGON2_MEM_COST").unwrap_or("65536".to_string()).parse().unwrap();
    let time_cost = env::var("ARGON2_TIME_COST").unwrap_or("4".to_string()).parse().unwrap();
    let parallelism = env::var("ARGON2_PARALLELISM").unwrap_or("2".to_string()).parse().unwrap();

    let params = argon2::Params::new(mem_cost, time_cost, parallelism, None).unwrap();
    Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
}

pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = get_argon2();
    let hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    let parsed_hash = PasswordHash::new(hash);
    if parsed_hash.is_err() { return false; }
    let argon2 = get_argon2();
    argon2.verify_password(password.as_bytes(), &parsed_hash.unwrap()).is_ok()
}
