use actix_cors::Cors;
use actix_web::{ web, App, HttpServer, HttpResponse, Responder, post, get, HttpRequest, middleware};
use actix_web::cookie::{Cookie, SameSite};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, FromRow};
use uuid::Uuid;
use dotenv::dotenv;
use env_logger;
use std::env;
use time::Duration;
use std::sync::Mutex;
use std::collections::HashMap;
use std::time::SystemTime;
use lazy_static::lazy_static;

mod security;
mod jwt;

use security::{hash_password, verify_password};
use jwt::{generate_jwt, decode_token};

#[derive(Debug, Deserialize)]
struct RegisterInput {
    username: String,
    email: String,
    password: String,
    confirm_password: String,
}

#[derive(Debug, Deserialize)]
struct LoginInput {
    email: String,
    password: String,
}

#[derive(Debug, Serialize, FromRow)]
struct User {
    id: Uuid,
    username: String,
    email: String,
    password_hash: String,
    created_at: chrono::NaiveDateTime,
}

#[derive(Serialize)]
struct AuthResponse {
    message: String,
    user_id: Uuid,
}

fn format_error(message: &str) -> serde_json::Value {
    serde_json::json!({ "error": true, "message": message })
}

// ======== Brute-force protection ========
lazy_static::lazy_static! {
    static ref LOGIN_ATTEMPTS: Mutex<HashMap<String, (u8, SystemTime)>> = Mutex::new(HashMap::new());
}

fn check_login_attempts(email: &str) -> bool {
    let mut attempts = LOGIN_ATTEMPTS.lock().unwrap();
    let now = SystemTime::now();
    let entry = attempts.entry(email.to_string()).or_insert((0, now));

    if now.duration_since(entry.1).unwrap().as_secs() > 900 {
        *entry = (0, now);
    }

    entry.0 < 5
}

fn record_login_attempt(email: &str) {
    let mut attempts = LOGIN_ATTEMPTS.lock().unwrap();
    let now = SystemTime::now();
    let entry = attempts.entry(email.to_string()).or_insert((0, now));
    entry.0 += 1;
    entry.1 = now;
}
// =======================================

#[post("/register")]
async fn register(
    data: web::Json<RegisterInput>,
    pool: web::Data<PgPool>,
    secret: web::Data<String>
) -> impl Responder {
    if data.password != data.confirm_password {
        return HttpResponse::BadRequest().json(format_error("Passwords do not match"));
    }

    let password_hash = match hash_password(&data.password) {
        Ok(h) => h,
        Err(_) => return HttpResponse::InternalServerError().json(format_error("Password hashing failed")),
    };

    let user_id = Uuid::new_v4();
    let result = sqlx::query!(
        "INSERT INTO users (id, username, email, password_hash) VALUES ($1, $2, $3, $4)",
        user_id, data.username, data.email, password_hash
    )
    .execute(pool.get_ref())
    .await;

    if let Err(_) = result {
        return HttpResponse::InternalServerError().json(format_error("Internal server error"));
    }

    let token = generate_jwt(&user_id, secret.get_ref());

    let cookie = Cookie::build("auth_token", token.clone())
        .path("/")
        .http_only(true)
        .same_site(SameSite::Strict)
        .secure(true)
        .max_age(Duration::hours(24))
        .domain("127.0.0.1")
        .finish();

    HttpResponse::Ok()
        .cookie(cookie)
        .json(AuthResponse {
            message: format!("User {} registered", data.username),
            user_id,
        })
}

#[post("/login")]
async fn login(
    data: web::Json<LoginInput>,
    pool: web::Data<PgPool>,
    secret: web::Data<String>
) -> impl Responder {
    if !check_login_attempts(&data.email) {
        return HttpResponse::TooManyRequests().json(format_error("Too many login attempts. Try again later."));
    }

    let user = match sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = $1")
        .bind(&data.email)
        .fetch_optional(pool.get_ref())
        .await
    {
        Ok(u) => u,
        Err(_) => return HttpResponse::InternalServerError().json(format_error("Internal server error")),
    };

    if let Some(user) = user {
        if verify_password(&data.password, &user.password_hash) {
            let token = generate_jwt(&user.id, secret.get_ref());

            let cookie = Cookie::build("auth_token", token.clone())
                .path("/")
                .http_only(true)
                .same_site(SameSite::Strict)
                .secure(true)
                .max_age(Duration::hours(24))
                .domain("127.0.0.1")
                .finish();

            return HttpResponse::Ok()
                .cookie(cookie)
                .json(AuthResponse {
                    message: format!("User {} logged in", user.username),
                    user_id: user.id,
                });
        }
    }

    record_login_attempt(&data.email);

    HttpResponse::Unauthorized().json(format_error("Invalid email or password"))
}

#[get("/profile")]
async fn profile(
    req: HttpRequest,
    pool: web::Data<PgPool>,
    secret: web::Data<String>
) -> impl Responder {
    let cookie = match req.cookie("auth_token") {
        Some(c) => c.value().to_string(),
        None => return HttpResponse::Unauthorized().json(format_error("Missing auth cookie")),
    };

    let claims = match decode_token(&cookie, secret.get_ref()) {
        Ok(c) => c.claims,
        Err(_) => return HttpResponse::Unauthorized().json(format_error("Invalid token")),
    };

    let user_id = match Uuid::parse_str(&claims.sub) {
        Ok(id) => id,
        Err(_) => return HttpResponse::Unauthorized().json(format_error("Invalid token")),
    };

    let user = match sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(pool.get_ref())
        .await
    {
        Ok(u) => u,
        Err(_) => return HttpResponse::Unauthorized().json(format_error("User not found")),
    };

    HttpResponse::Ok().json(serde_json::json!({
        "message": "Protected route",
        "user_id": user.id,
        "username": user.username,
        "email": user.email
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let pool = PgPool::connect(&database_url).await.unwrap();

    HttpServer::new(move || {
        App::new()
            .wrap(Cors::permissive())
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(jwt_secret.clone()))
            .service(register)
            .service(login)
            .service(profile)
            .wrap(middleware::Logger::default())
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
