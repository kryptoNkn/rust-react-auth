use actix_web::{App, HttpServer, HttpResponse, Responder, post, get, web, Result, HttpRequest};
use actix_cors::Cors;
use serde::{Deserialize, Serialize};
use validator_derive::Validate;
use validator::Validate;
use uuid::Uuid;
use std::sync::Mutex;
use std::collections::HashMap;
use std::env;
use dotenv::dotenv;
use chrono::{Utc, Duration};

mod security;
use security::{hash_password, verify_password};

mod jwt;
use jwt::{encode_token, decode_token, Claims};

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
struct AuthResponse {
    message: String,
    user_id: String,
    token: String,
}

#[derive(Clone)]
struct User {
    id: String,
    username: String,
    email: String,
    password_hash: String,
}

struct AppState {
    users: Mutex<HashMap<String, User>>,
    jwt_secret: String,
}

#[post("/register")]
async fn register(data: web::Json<RegisterData>, state: web::Data<AppState>) -> Result<impl Responder> {
    if let Err(errors) = data.validate() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({"errors": errors.field_errors()})));
    }
    if data.password != data.confirm_password {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({"errors": "Passwords do not match"})));
    }

    let hashed_password = match hash_password(&data.password) {
        Ok(h) => h,
        Err(_) => return Ok(HttpResponse::InternalServerError().body("Failed to hash password")),
    };

    let user_id = Uuid::new_v4().to_string();
    let exp = (Utc::now() + Duration::days(7)).timestamp() as usize;
    let claims = Claims { sub: user_id.clone(), exp };

    let token = match encode_token(&claims, &state.jwt_secret) {
        Ok(t) => t,
        Err(_) => return Ok(HttpResponse::InternalServerError().body("Failed to generate token")),
    };

    let mut users = state.users.lock().unwrap();
    if users.contains_key(&data.email) {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({"error": "User with this email already exists"})));
    }

    let user = User {
        id: user_id.clone(),
        username: data.username.clone(),
        email: data.email.clone(),
        password_hash: hashed_password,
    };
    users.insert(data.email.clone(), user);

    Ok(HttpResponse::Ok().json(AuthResponse {
        message: format!("User {} registered", data.username),
        user_id,
        token,
    }))
}

#[post("/login")]
async fn login(data: web::Json<LoginData>, state: web::Data<AppState>) -> Result<impl Responder> {
    let users = state.users.lock().unwrap();
    let user = match users.get(&data.email) {
        Some(u) => u,
        None => return Ok(HttpResponse::BadRequest().json(serde_json::json!({"error": "Invalid email or password"}))),
    };

    if !verify_password(&data.password, &user.password_hash) {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({"error": "Invalid email or password"})));
    }

    let exp = (Utc::now() + Duration::days(7)).timestamp() as usize;
    let claims = Claims { sub: user.id.clone(), exp };

    let token = match encode_token(&claims, &state.jwt_secret) {
        Ok(t) => t,
        Err(_) => return Ok(HttpResponse::InternalServerError().body("Failed to generate token")),
    };

    Ok(HttpResponse::Ok().json(AuthResponse {
        message: format!("User {} logged in", user.username),
        user_id: user.id.clone(),
        token,
    }))
}

#[get("/profile")]
async fn profile(req: HttpRequest, state: web::Data<AppState>) -> Result<impl Responder> {
    let auth_header = match req.headers().get("Authorization") {
        Some(h) => h.to_str().unwrap_or(""),
        None => return Ok(HttpResponse::Unauthorized().json(serde_json::json!({"error": "Missing Authorization header"}))),
    };

    let token = auth_header.replace("Bearer ", "");
    let decoded = decode_token(&token, &state.jwt_secret);

    match decoded {
        Ok(data) => Ok(HttpResponse::Ok().json(serde_json::json!({"message": "Protected route", "user_id": data.claims.sub}))),
        Err(_) => Ok(HttpResponse::Unauthorized().json(serde_json::json!({"error": "Invalid token"}))),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set in .env");

    let state = web::Data::new(AppState {
        users: Mutex::new(HashMap::new()),
        jwt_secret,
    });

    println!("Server running at http://127.0.0.1:8080");

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .wrap(Cors::default().allow_any_origin().allow_any_method().allow_any_header())
            .service(register)
            .service(login)
            .service(profile)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
