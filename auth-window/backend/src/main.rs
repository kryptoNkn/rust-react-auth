use actix_web::{App, HttpServer, Responder, HttpResponse, post, web};
use actix_cors::Cors;
use serde::Deserialize;
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
struct RegisterData {
    #[validate(length(min = 3))]
    username: String,
    #[validate(email)]
    email: String,
    #[validate(length(min = 6))]
    password: String,
}

#[post("/register")]
async fn register(data: web::Json<RegisterData>) -> impl Responder {
    match data.validate() {
        Ok(_) => HttpResponse::Ok().json(format!("User {} registered", data.username)),
        Err(e) => HttpResponse::BadRequest().json(format!("Validation error: {}", e)),
    }
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
