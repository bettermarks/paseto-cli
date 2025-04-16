use anyhow::{Ok, Result};
use base64::prelude::*;
use clap::{ArgAction, Parser, Subcommand};
use humantime::Duration;
use pasetors::{
    claims::Claims,
    keys::{Generate, SymmetricKey},
    local,
    version4::V4,
};
use std::io::{self, Read};
use std::str::FromStr;
use thiserror::Error;

#[derive(Error, Debug)]
enum CliError {
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Value parser for clap to parse a base64 encoded sysmmetric key for Paseto.
/// If "-" is used, we parse from stdin
pub fn parse_symmetric_key(arg: &str) -> Result<SymmetricKey<V4>> {
    let encoded_key = match arg {
        "-" => {
            let mut buffer = String::new();
            io::stdin().read_to_string(&mut buffer)?;
            buffer.trim().to_string()
        }
        _ => arg.to_string(),
    };
    Ok(SymmetricKey::from(&BASE64_STANDARD.decode(encoded_key)?)?)
}
#[derive(Parser, Debug)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Clone)]
struct CustomClaim(String, Option<String>);

fn parse_custom_claim(arg: &str) -> Result<CustomClaim> {
    if let Some((key, value)) = arg.split_once("=") {
        Ok(CustomClaim(key.into(), Some(value.into())))
    } else {
        Ok(CustomClaim(arg.into(), None))
    }
}

#[derive(Parser, Debug)]
struct V4Config {
    /// PASETO key
    #[arg(value_parser = parse_symmetric_key, default_value="-")]
    key: SymmetricKey<V4>,

    /// Issuer
    #[arg(long)]
    iss: Option<String>,

    /// Subject
    #[arg(long)]
    sub: Option<String>,

    /// Audience
    #[arg(long)]
    aud: Option<String>,

    /// Expiry
    #[arg(long, group = "expiry")]
    exp: Option<String>,

    /// Not before
    #[arg(long, group = "valid_at")]
    nbf: Option<String>,

    /// Issued at
    #[arg(long, group = "valid_at")]
    iat: Option<String>,

    /// Token identifier
    #[arg(long)]
    jti: Option<String>,

    /// Custom claim
    #[arg(short, long, value_parser = parse_custom_claim, value_name="KEY=VALUE")]
    claim: Option<Vec<CustomClaim>>,

    /// Relative expiry in humantime
    #[arg(long)]
    expires_in: Option<Duration>,

    /// Implicit assertion
    #[arg(long)]
    assertion: Option<String>,
}

impl V4Config {
    fn generate(&self) -> Result<String> {
        let mut claims = if let Some(ref duration) = self.expires_in {
            Claims::new_expires_in(duration)?
        } else {
            let mut claims = Claims::new()?;
            claims.non_expiring();
            claims
        };

        if let Some(ref aud) = self.aud {
            claims.audience(aud)?;
        }
        if let Some(ref sub) = self.sub {
            claims.subject(sub)?;
        }
        if let Some(ref iss) = self.iss {
            claims.issuer(iss)?;
        }
        if let Some(ref jti) = self.jti {
            claims.token_identifier(jti)?;
        }
        if let Some(ref iat) = self.iat {
            claims.issued_at(iat)?;
        }
        if let Some(ref nbf) = self.nbf {
            claims.not_before(nbf)?;
        }
        if let Some(ref exp) = self.exp {
            claims.expiration(exp)?;
        }

        if let Some(ref custom_claims) = self.claim {
            for claim in custom_claims {
                claims.add_additional(&claim.0, claim.clone().1)?;
            }
        }

        Ok(local::encrypt(
            &self.key,
            &claims,
            None,
            self.assertion.as_deref().map(str::as_bytes),
        )?)
    }
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate a paseto token
    Generate(Box<V4Config>),
    /// Generate a base64 encoded symmetric key
    Key,
}
impl Cli {
    fn execute(&self) -> Result<()> {
        match &self.command {
            Commands::Generate(config) => {
                println!("{}", config.generate()?);
                Ok(())
            }
            Commands::Key => {
                let key = SymmetricKey::<V4>::generate()?;
                println!("{}", BASE64_STANDARD.encode(key.as_bytes()));
                Ok(())
            }
        }
    }
}

#[allow(clippy::expect_used, reason = "unwrap or expect in main ok")]
fn main() {
    let cli = Cli::parse();
    if let Err(e) = cli.execute() {
        eprintln!("{}", e);
    }
}
