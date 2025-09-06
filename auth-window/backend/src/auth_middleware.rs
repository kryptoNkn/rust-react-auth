use actix_web::{dev::{Service, ServiceRequest, ServiceResponse, Transform}, Error, HttpResponse, HttpMessage};
use futures::future::{LocalBoxFuture, ok, Ready};
use std::task::{Context, Poll};
use std::rc::Rc;
use crate::jwt::{decode_token, Claims};

pub struct AuthMiddleware {
    pub jwt_secret: String,
}

impl<S, B> Transform<S, ServiceRequest> for AuthMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = AuthMiddlewareMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(AuthMiddlewareMiddleware {
            service: Rc::new(service),
            jwt_secret: self.jwt_secret.clone(),
        })
    }
}

pub struct AuthMiddlewareMiddleware<S> {
    service: Rc<S>,
    jwt_secret: String,
}

impl<S, B> Service<ServiceRequest> for AuthMiddlewareMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, ctx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&self, mut req: ServiceRequest) -> Self::Future {
        let jwt_secret = self.jwt_secret.clone();
        let srv = self.service.clone();

        Box::pin(async move {
            let auth_header = req
                .headers()
                .get("Authorization")
                .and_then(|h| h.to_str().ok());

            if auth_header.is_none() {
                return Ok(req.into_response(
                    HttpResponse::Unauthorized()
                        .json(serde_json::json!({"error": "Missing Authorization header"}))
                        .into_body()
                ));
            }

            let token = auth_header.unwrap().replace("Bearer ", "");
            match decode_token(&token, &jwt_secret) {
                Ok(data) => {
                    req.extensions_mut().insert(data.claims);
                    srv.call(req).await
                }
                Err(_) => Ok(req.into_response(
                    HttpResponse::Unauthorized()
                        .json(serde_json::json!({"error": "Invalid token"}))
                        .into_body()
                )),
            }
        })
    }
}
