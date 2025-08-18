use anyhow::{Ok, Result};
use base64::prelude::*;
use clap::{Parser, Subcommand};
use colored::Colorize;
use humantime::Duration;
use pasetors::{
    claims::{Claims, ClaimsValidationRules},
    keys::{Generate, SymmetricKey},
    local, token,
    version4::{LocalToken, V4},
    Local,
};
use std::io::{self, IsTerminal, Read};
use thiserror::Error;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

#[derive(Error, Debug)]
enum CliError {
    #[error(transparent)]
    Other(#[from] anyhow::Error),
    #[error("stdin is a tty")]
    StdinTerminal,
}

/// Value parser for clap to parse a base64 encoded sysmmetric key for Paseto.
/// If "-" is used, we parse from stdin
pub fn parse_symmetric_key(arg: &str) -> Result<SymmetricKey<V4>> {
    let encoded_key = match arg {
        "-" => {
            let stdin = io::stdin();
            if stdin.is_terminal() {
                return Err(CliError::StdinTerminal.into());
            }
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
struct V4GenerateConfig {
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

    /// Relative valid-in in humantime
    #[arg(long)]
    valid_in: Option<Duration>,

    /// Implicit assertion
    #[arg(long)]
    assertion: Option<String>,
}

impl V4GenerateConfig {
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
        } else if let Some(ref valid_in) = self.valid_in {
            let now = OffsetDateTime::now_utc();
            let valid_at = now + **valid_in;
            claims.not_before(&valid_at.format(&Rfc3339)?)?;
        }

        if let Some(ref exp) = self.exp {
            claims.expiration(exp)?;
        }

        if let Some(ref custom_claims) = self.claim {
            for claim in custom_claims {
                let value = match &claim.1 {
                    Some(value) => serde_json::from_str(value)?,
                    None => serde_json::Value::Null,
                };
                claims.add_additional(&claim.0, value)?;
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

#[derive(Parser, Debug)]
struct V4ValidateConfig {
    /// Token
    #[arg()]
    token: String,

    /// PASETO key
    #[arg(value_parser = parse_symmetric_key, default_value="-")]
    key: SymmetricKey<V4>,

    /// Implicit assertion
    #[arg(long)]
    assertion: Option<String>,

    /// Validate issuer
    #[arg(long)]
    iss: Option<String>,

    /// Validate subject
    #[arg(long)]
    sub: Option<String>,

    /// Validate audience
    #[arg(long)]
    aud: Option<String>,

    /// Validate valid-at
    #[arg(long, action)]
    valid_at: bool,

    /// Validate expiry
    #[arg(long, action)]
    expires: bool,
}

impl V4ValidateConfig {
    fn get_claims(&self) -> Result<Claims> {
        let untrusted_token = token::UntrustedToken::<Local, V4>::try_from(&self.token)?;

        let token = LocalToken::decrypt(
            &self.key,
            &untrusted_token,
            None,
            self.assertion.as_deref().map(str::as_bytes),
        )?;

        Ok(Claims::from_string(token.payload())?)
    }

    pub fn validate(&self) -> Result<()> {
        // INFO: first show claims
        let claims = self.get_claims()?;
        println!("{}", serde_json::to_string_pretty(&claims)?);

        let mut validation_rules = ClaimsValidationRules::new();

        if let Some(ref iss) = self.iss {
            validation_rules.validate_issuer_with(iss);
        }
        if let Some(ref sub) = self.sub {
            validation_rules.validate_subject_with(sub);
        }
        if let Some(ref aud) = self.aud {
            validation_rules.validate_audience_with(aud);
        }
        if !self.expires {
            validation_rules.allow_non_expiring();
        }
        if !self.valid_at {
            validation_rules.disable_valid_at();
        }

        validation_rules.validate_claims(&claims)?;
        Ok(())
    }
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate a paseto token
    Generate(Box<V4GenerateConfig>),
    /// Generate a base64 encoded symmetric key
    Key,
    /// Validate a token
    Validate(Box<V4ValidateConfig>),
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
            Commands::Validate(config) => config.validate(),
        }
    }
}

#[allow(clippy::expect_used, reason = "unwrap or expect in main ok")]
fn main() {
    let cli = Cli::parse();
    if let Err(e) = cli.execute() {
        eprintln!("{}", format!("Error: {}", e).red());
    }
}
