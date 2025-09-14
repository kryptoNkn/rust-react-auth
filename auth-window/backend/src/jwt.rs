use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{Utc, Duration};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey, TokenData};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

pub fn generate_jwt(user_id: &Uuid, secret: &str) -> String {
    let exp = Utc::now() + Duration::hours(24);
    let claims = Claims {
        sub: user_id.to_string(),
        exp: exp.timestamp() as usize,
    };
    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_ref())).unwrap()
}

pub fn decode_token(token: &str, secret: &str) -> Result<TokenData<Claims>, jsonwebtoken::errors::Error> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::default()
    )
}
