use jsonwebtoken::{encode, decode, Header, EncodingKey, DecodingKey, Validation, errors::Error};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

pub fn encode_token(claims: &Claims, secret: &str) -> Result<String, Error> {
    encode(&Header::default(), claims, &EncodingKey::from_secret(secret.as_bytes()))
}

pub fn decode_token(token: &str, secret: &str) -> Result<jsonwebtoken::TokenData<Claims>, Error> {
    decode::<Claims>(token, &DecodingKey::from_secret(secret.as_bytes()), &Validation::default())
}
