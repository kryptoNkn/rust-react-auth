use actix_cors::Cors;
use actix_web::{web, App, HttpServer, HttpResponse, Responder, post, get, HttpRequest, middleware};
use actix_web::cookie::{Cookie, SameSite};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, FromRow};
use uuid::Uuid;
use chrono::{Utc};
use dotenv::dotenv;
use std::env;
use validator::Validate;

mod security;
mod jwt;

use security::{hash_password, verify_password};
use jwt::{generate_jwt, decode_token};

#[derive(Debug, Deserialize, Validate)]
struct RegisterInput {
    #[validate(length(min = 3, message = "Username must be at least 3 characters"))]
    username: String,

    #[validate(email(message = "Invalid email format"))]
    email: String,

    #[validate(length(min = 6, message = "Password must be at least 6 characters"))]
    password: String,

    confirm_password: String,
}

#[derive(Debug, Deserialize, Validate)]
struct LoginInput {
    #[validate(email(message = "Invalid email format"))]
    email: String,

    #[validate(length(min = 6, message = "Password must be at least 6 characters"))]
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

#[post("/register")]
async fn register(data: web::Json<RegisterInput>, pool: web::Data<PgPool>, secret: web::Data<String>) -> impl Responder {
    
    if let Err(e) = data.validate() {
        let errors: Vec<String> = e.field_errors()
            .iter()
            .map(|(field, errs)| {
                let msgs: Vec<String> = errs.iter()
                    .filter_map(|err| err.message.clone())
                    .map(|m| m.to_string())
                    .collect();
                format!("{}: {}", field, msgs.join(", "))
            })
            .collect();

        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Validation failed",
            "details": errors
        }));
    }

    if data.password != data.confirm_password {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Passwords do not match"}));
    }

    let existing_user = sqlx::query_as::<_, User>(
        "SELECT id, username, email, password_hash, created_at FROM users WHERE email = $1"
    )
    .bind(&data.email)
    .fetch_optional(pool.get_ref())
    .await;

    if let Ok(Some(_)) = existing_user {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Email already registered"}));
    }

    let password_hash = match hash_password(&data.password) {
        Ok(hash) => hash,
        Err(_) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Password hashing failed"})),
    };

    let user_id = Uuid::new_v4();
    let result = sqlx::query!(
        "INSERT INTO users (id, username, email, password_hash) VALUES ($1, $2, $3, $4)",
        user_id, data.username, data.email, password_hash
    )
    .execute(pool.get_ref())
    .await;

    if let Err(err) = result {
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("DB error: {}", err)}));
    }

    let token = generate_jwt(&user_id, secret.get_ref());

    let cookie = Cookie::build("auth_token", token.clone())
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(true)
        .finish();

    HttpResponse::Ok()
        .cookie(cookie)
        .json(AuthResponse {
            message: format!("User {} registered", data.username),
            user_id,
        })
}

#[post("/login")]
async fn login(data: web::Json<LoginInput>, pool: web::Data<PgPool>, secret: web::Data<String>) -> impl Responder {

    if let Err(e) = data.validate() {
        let errors: Vec<String> = e.field_errors()
            .iter()
            .map(|(field, errs)| {
                let msgs: Vec<String> = errs.iter()
                    .filter_map(|err| err.message.clone())
                    .map(|m| m.to_string())
                    .collect();
                format!("{}: {}", field, msgs.join(", "))
            })
            .collect();

        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Validation failed",
            "details": errors
        }));
    }

    let user = match sqlx::query_as::<_, User>(
        "SELECT id, username, email, password_hash, created_at FROM users WHERE email = $1"
    )
    .bind(&data.email)
    .fetch_optional(pool.get_ref())
    .await
    {
        Ok(opt) => opt,
        Err(_) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": "DB error"})),
    };

    if let Some(user) = user {
        if verify_password(&data.password, &user.password_hash) {
            let token = generate_jwt(&user.id, secret.get_ref());
            let cookie = Cookie::build("auth_token", token.clone())
                .path("/")
                .http_only(true)
                .same_site(SameSite::Lax)
                .secure(true)
                .finish();

            return HttpResponse::Ok()
                .cookie(cookie)
                .json(AuthResponse {
                    message: format!("User {} logged in", user.username),
                    user_id: user.id,
                });
        }
    }

    HttpResponse::Unauthorized().json(serde_json::json!({"error": "Invalid email or password"}))
}

#[get("/profile")]
async fn profile(req: HttpRequest, pool: web::Data<PgPool>, secret: web::Data<String>) -> impl Responder {
    let cookie = match req.cookie("auth_token") {
        Some(c) => c.value().to_string(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Missing auth cookie"})),
    };

    let claims = match decode_token(&cookie, secret.get_ref()) {
        Ok(c) => c.claims,
        Err(_) => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Invalid token"})),
    };

    let user_id = match Uuid::parse_str(&claims.sub) {
        Ok(id) => id,
        Err(_) => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Invalid token"})),
    };

    let user = match sqlx::query_as::<_, User>(
        "SELECT id, username, email, password_hash, created_at FROM users WHERE id = $1"
    )
    .bind(user_id)
    .fetch_one(pool.get_ref())
    .await
    {
        Ok(u) => u,
        Err(_) => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "User not found"})),
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