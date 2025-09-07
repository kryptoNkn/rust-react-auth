use actix_cors::Cors;
use actix_web::{web, App, HttpServer, Responder, HttpResponse, post, get};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, FromRow};
use uuid::Uuid;
use argon2::{Argon2, PasswordHash, PasswordVerifier, PasswordHasher};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use chrono::{Utc, Duration};
use dotenv::dotenv;
use std::env;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

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
    token: String,
}

fn generate_jwt(user_id: &Uuid, secret: &str) -> String {
    let exp = Utc::now() + Duration::hours(24);
    let claims = Claims {
        sub: user_id.to_string(),
        exp: exp.timestamp() as usize,
    };
    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_ref())).unwrap()
}

#[post("/register")]
async fn register(data: web::Json<RegisterInput>, pool: web::Data<PgPool>) -> impl Responder {
    if data.password != data.confirm_password {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Passwords do not match"}));
    }

    let user_id = Uuid::new_v4();
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(data.password.as_bytes(), &argon2::password_hash::SaltString::generate(&mut rand_core::OsRng)).unwrap().to_string();

    let result = sqlx::query!(
        "INSERT INTO users (id, username, email, password_hash) VALUES ($1, $2, $3, $4)",
        user_id,
        data.username,
        data.email,
        password_hash
    )
    .execute(pool.get_ref())
    .await;

    if let Err(err) = result {
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("DB error: {}", err)}));
    }

    let secret = env::var("JWT_SECRET").unwrap();
    let token = generate_jwt(&user_id, &secret);

    HttpResponse::Ok().json(AuthResponse {
        message: format!("User {} registered", data.username),
        user_id,
        token,
    })
}

#[post("/login")]
async fn login(data: web::Json<LoginInput>, pool: web::Data<PgPool>) -> impl Responder {
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = $1")
        .bind(&data.email)
        .fetch_optional(pool.get_ref())
        .await
        .unwrap();

    if let Some(user) = user {
        let parsed_hash = PasswordHash::new(&user.password_hash).unwrap();
        if Argon2::default().verify_password(data.password.as_bytes(), &parsed_hash).is_ok() {
            let secret = env::var("JWT_SECRET").unwrap();
            let token = generate_jwt(&user.id, &secret);

            return HttpResponse::Ok().json(AuthResponse {
                message: format!("User {} logged in", user.username),
                user_id: user.id,
                token,
            });
        }
    }

    HttpResponse::Unauthorized().json(serde_json::json!({"error": "Invalid email or password"}))
}

#[get("/profile")]
async fn profile(req: actix_web::HttpRequest, pool: web::Data<PgPool>) -> impl Responder {
    let auth_header = req.headers().get("Authorization");
    if auth_header.is_none() {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Missing Authorization header"}));
    }

    let auth_header = auth_header.unwrap().to_str().unwrap();
    if !auth_header.starts_with("Bearer ") {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Invalid Authorization header"}));
    }

    let token = auth_header.trim_start_matches("Bearer ");
    let secret = env::var("JWT_SECRET").unwrap();

    let decoded = decode::<Claims>(&token, &DecodingKey::from_secret(secret.as_ref()), &Validation::default());
    if let Ok(decoded) = decoded {
        let user_id = Uuid::parse_str(&decoded.claims.sub).unwrap();

        let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(pool.get_ref())
            .await;

        if let Ok(user) = user {
            return HttpResponse::Ok().json(serde_json::json!({
                "message": "Protected route",
                "user_id": user.id,
                "username": user.username,
                "email": user.email
            }));
        }
    }

    HttpResponse::Unauthorized().json(serde_json::json!({"error": "Invalid token"}))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = PgPool::connect(&database_url).await.unwrap();

    HttpServer::new(move || {
        App::new()
            .wrap(Cors::permissive())
            .app_data(web::Data::new(pool.clone()))
            .service(register)
            .service(login)
            .service(profile)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}