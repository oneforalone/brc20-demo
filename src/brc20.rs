use anyhow::Result;
use bitcoin::PublicKey;
use serde::Serialize;

use crate::inscription::OrdinalsInscription;

#[derive(Debug, Clone, Serialize, Default)]
pub struct Brc20Ticker(String);

impl Brc20Ticker {
    pub fn new(string: String) -> Result<Self, Box<dyn std::error::Error>> {
        if string.len() != 4 {
            return Err("Invalid brc20 ticker".into());
        }

        Ok(Brc20Ticker(string))
    }
}

#[derive(Debug, Default, Serialize)]
pub struct Brc20 {
    #[serde(rename = "p")]
    protocol: String,
    #[serde(rename = "op")]
    operation: String,
    #[serde(rename = "tick")]
    ticker: Brc20Ticker,
    #[serde(rename = "amt")]
    amount: String,
}

impl Brc20 {
    const MIME: &'static [u8] = b"text/plain;charset=utf-8";

    pub fn new(op: String, ticker: String, value: String) -> Self {
        Brc20 {
            protocol: "brc-20".to_owned(),
            operation: op,
            ticker: Brc20Ticker::new(ticker).unwrap(),
            amount: value,
        }
    }

    pub fn inscription(
        recipient: PublicKey,
        ticker: String,
        op: String,
        value: String,
    ) -> Result<OrdinalsInscription> {
        let data = Self::new(op, ticker, value);

        OrdinalsInscription::new(
            Self::MIME,
            &serde_json::to_vec(&data).expect("badly constructed Brc20 payload"),
            recipient,
        )
    }

    pub fn transfer(
        recipient: PublicKey,
        ticker: String,
        value: String,
    ) -> Result<OrdinalsInscription> {
        Self::inscription(recipient, ticker, "transfer".to_owned(), value)
    }

    pub fn mint(
        recipient: PublicKey,
        ticker: String,
        value: String,
    ) -> Result<OrdinalsInscription> {
        Self::inscription(recipient, ticker, "mint".to_owned(), value)
    }
}
