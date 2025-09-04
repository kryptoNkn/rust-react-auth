use actix_web::{App, HttpServer, Responder, HttpResponse, post, web};
use actix_cors::Cors;
use serde::{Deserialize, Serialize};
use validator::Validate;
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::{SaltString};
use rand_core::OsRng;
use jsonwebtoken::{encode, Header, EncodingKey};
use uuid::Uuid;

#[derive(Debug, Deserialize, Validate)]
struct RegisterData {
    #[validate(length(min = 3))]
    username: String,
    #[validate(email)]
    email: String,
    #[validate(length(min = 6))]
    password: String
}

#[derive(Serialize)]
struct Claims {
    sub: String,
    exp: usize,
}

#[post("/register")]
async fn register(data: web::Json<RegisterData>) -> impl Responder {
    if let Err(errors) = data.validate() {
        return HttpResponse::BadRequest().json(serde_json::json!({"errors":errors.field_errors()}));
    }

    let salt = SaltString::generate(&mut OsRng);

    let argon2 = Argon2::default();
    let hashed_password = argon2
        .hash_password(data.password.as_bytes(), &salt)
        .unwrap()
        .to_string();

    let claims = Claims {
        sub: data.username.clone(),
        exp: 10000000000,
    };

    // JWT creating
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(b"secretkey")
    ).unwrap();

    HttpResponse::Ok().json(serde_json::json!({
        "message": format!("User {} registered", data.username),
        "token": token,
        "hashed_password": hashed_password
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
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
