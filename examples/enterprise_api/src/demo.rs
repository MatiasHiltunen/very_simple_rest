//! Explicit local-demo provisioning. No signing key or grant API is exposed over HTTP.
use crate::{
    Error,
    auth::{Claims, now},
    config::Config,
    contract::Contract,
    store,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

pub fn write_private(path: &Path, contents: &[u8]) -> Result<(), Error> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(contents)?;
    Ok(())
}

pub fn sign(claims: &Claims, kid: &str, private_pem: &[u8]) -> Result<String, Error> {
    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("at+jwt".into());
    header.kid = Some(kid.into());
    Ok(jsonwebtoken::encode(
        &header,
        claims,
        &EncodingKey::from_ec_pem(private_pem)?,
    )?)
}

pub async fn initialize(config: &Config) -> Result<(), Error> {
    if !config.listen.ip().is_loopback()
        || config.verification_keys.len() != 1
        || config.verification_keys[0].kid != "demo-es256"
    {
        return Err(
            "demo initialization requires a loopback listener and the demo-es256 key".into(),
        );
    }
    let key_path = &config.verification_keys[0].pem_file;
    if config.database.exists() || key_path.exists() {
        return Err("demo initialization refuses to overwrite an existing database or key".into());
    }
    let dir = key_path.parent().ok_or("missing key directory")?;
    fs::create_dir_all(dir)?;
    if let Some(parent) = config.database.parent() {
        fs::create_dir_all(parent)?;
    }
    let pair = rcgen::KeyPair::generate()?;
    let private = pair.serialize_pem();
    write_private(&dir.join("demo-private.pem"), private.as_bytes())?;
    write_private(key_path, pair.public_key_pem().as_bytes())?;
    let pool = store::connect(&config.database).await?;
    let contract: Contract =
        serde_json::from_str(include_str!(concat!(env!("OUT_DIR"), "/contract.json")))?;
    let mut tx = pool.begin().await?;
    let issued = now();
    for (id, tenant, name, roles) in [
        (1, 1, "alice", vec!["reader", "editor"]),
        (2, 1, "bob", vec!["reader", "editor"]),
        (3, 1, "carol", vec!["reader", "manager", "auditor"]),
        (4, 2, "dana", vec!["reader", "editor"]),
    ] {
        sqlx::query("INSERT INTO _principals VALUES(?,1,1)")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        for role in roles {
            sqlx::query("INSERT INTO _grants VALUES(?,?,?,?)")
                .bind(id)
                .bind(tenant)
                .bind(role)
                .bind(issued + 86400)
                .execute(&mut *tx)
                .await?;
        }
        let claims = Claims {
            sub: id.to_string(),
            tenant_id: tenant,
            ver: 1,
            jti: uuid::Uuid::new_v4().to_string(),
            iss: contract.issuer.clone(),
            aud: contract.audience.clone(),
            iat: issued,
            nbf: issued,
            exp: issued + contract.token_ttl,
        };
        let token = sign(&claims, "demo-es256", private.as_bytes())?;
        write_private(&dir.join(format!("{name}.token")), token.as_bytes())?;
    }
    tx.commit().await?;
    pool.close().await;
    println!(
        "Demo initialized. Short-lived bearer token files: {}",
        dir.display()
    );
    println!("Local demonstration only. Do not deploy its signing key or seeded identities.");
    Ok(())
}
