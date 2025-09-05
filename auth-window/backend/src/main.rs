use actix_web::{App, HttpServer, Responder, HttpResponse, post, web, Result};
use actix_cors::Cors;
use serde::{Deserialize, Serialize};
use validator::Validate;
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{SaltString, PasswordHash};
use rand_core::OsRng;
use jsonwebtoken::{encode, Header, EncodingKey};
use uuid::Uuid;
use std::sync::Mutex;
use std::collections::HashMap;
use std::env;
use dotenv::dotenv;
use chrono::{Utc, Duration};

#[derive(Debug, Deserialize, Validate)]
struct RegisterData {
    #[validate(length(min = 3))]
    username: String,
    #[validate(email)]
    email: String,
    #[validate(length(min = 6))]
    password: String,
    #[validate(length(min = 6))]
    confirm_password: String,
}

#[derive(Debug, Deserialize)]
struct LoginData {
    email: String,
    password: String,
}

#[derive(Serialize)]
struct Claims {
    sub: String,
    exp: usize,
}

#[derive(Serialize)]
struct AuthResponse {
    message: String,
    user_id: String,
    token: String,
}

struct AppState {
    users: Mutex<HashMap<String, (String, String)>>,
}

#[post("/register")]
async fn register(data: web::Json<RegisterData>, state: web::Data<AppState>) -> Result<impl Responder> {
    if let Err(errors) = data.validate() {
        return Ok(HttpResponse::BadRequest().json(
            serde_json::json!({"errors": errors.field_errors()})
        ));
    }

    if data.password != data.confirm_password {
        return Ok(HttpResponse::BadRequest().json(
            serde_json::json!({"errors": "Passwords do not match"})
        ));
    }

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hashed_password = argon2
        .hash_password(data.password.as_bytes(), &salt)
        .unwrap()
        .to_string();

    let user_id = Uuid::new_v4().to_string();
    let exp = (Utc::now() + Duration::days(7)).timestamp() as usize;
    let claims = Claims { sub: user_id.clone(), exp };
    let secret = env::var("JWT_SECRET").unwrap_or_else(|_| "secretkey".into());
    let token = match encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_bytes())) {
        Ok(t) => t,
        Err(_) => return Ok(HttpResponse::InternalServerError().body("Failed to generate token")),
    };

    let mut users = state.users.lock().unwrap();
    if users.contains_key(&data.email) {
        return Ok(HttpResponse::BadRequest().body("User with this email already exists"));
    }
    users.insert(data.email.clone(), (data.username.clone(), hashed_password));

    let response = AuthResponse {
        message: format!("User {} registered", data.username),
        user_id,
        token,
    };

    Ok(HttpResponse::Ok().json(response))
}

#[post("/login")]
async fn login(data: web::Json<LoginData>, state: web::Data<AppState>) -> Result<impl Responder> {
    let users = state.users.lock().unwrap();
    let (username, hashed_password) = match users.get(&data.email) {
        Some(u) => u,
        None => return Ok(HttpResponse::BadRequest().body("Invalid email or password")),
    };

    let parsed_hash = PasswordHash::new(&hashed_password).unwrap();
    let argon2 = Argon2::default();
    if argon2.verify_password(data.password.as_bytes(), &parsed_hash).is_err() {
        return Ok(HttpResponse::BadRequest().body("Invalid email or password"));
    }

    let user_id = Uuid::new_v4().to_string();
    let exp = (Utc::now() + Duration::days(7)).timestamp() as usize;
    let claims = Claims { sub: user_id.clone(), exp };
    let secret = env::var("JWT_SECRET").unwrap_or_else(|_| "secretkey".into());
    let token = match encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_bytes())) {
        Ok(t) => t,
        Err(_) => return Ok(HttpResponse::InternalServerError().body("Failed to generate token")),
    };

    let response = AuthResponse {
        message: format!("User {} logged in", username),
        user_id,
        token,
    };

    Ok(HttpResponse::Ok().json(response))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    let state = web::Data::new(AppState {
        users: Mutex::new(HashMap::new()),
    });

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .wrap(Cors::default()
                .allow_any_origin()
                .allow_any_method()
                .allow_any_header()
            )
            .service(register)
            .service(login)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
