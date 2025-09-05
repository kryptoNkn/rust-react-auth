use actix_web::{App, HttpServer, Responder, HttpResponse, post, web};
use actix_cors::Cors;
use serde::{Deserialize, Serialize};
use validator::Validate;
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::SaltString;
use rand_core::OsRng;
use jsonwebtoken::{encode, Header, EncodingKey};
use uuid::Uuid;
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

#[derive(Serialize)]
struct Claims {
    sub: String,
    exp: usize,
}

#[post("/register")]
async fn register(data: web::Json<RegisterData>) -> impl Responder {
    if let Err(errors) = data.validate() {
        return HttpResponse::BadRequest().json(
            serde_json::json!({"errors": errors.field_errors()})
        );
    }

    if data.password != data.confirm_password {
        return HttpResponse::BadRequest().json(
            serde_json::json!({"errors": "Passwords do not match"})
        );
    }

    // HASH
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hashed_password = argon2
        .hash_password(data.password.as_bytes(), &salt)
        .unwrap()
        .to_string();

    let user_id = Uuid::new_v4().to_string();

    // JWT
    let exp = (Utc::now() + Duration::days(7)).timestamp() as usize;
    let claims = Claims { sub: user_id.clone(), exp };
    let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes())
    ).unwrap();

    HttpResponse::Ok().json(serde_json::json!({
        "message": format!("User {} registered", data.username),
        "user_id": user_id,
        "token": token,
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    HttpServer::new(|| {
        App::new()
            .wrap(
                Cors::default()
                    .allow_any_origin()
                    .allow_any_method()
                    .allow_any_header()
            )
            .service(register)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
