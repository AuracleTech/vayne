use actix_files::Files;
use actix_web::{
    middleware::{self, DefaultHeaders},
    web, App, HttpServer,
};
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::{env, fs::File, io::BufReader};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));
    let config = load_rustls_config();
    log::info!("Starting HTTPS server");
    let env_port = env::var("VAYNE_PORT").expect("Environment variable VAYNE_PORT missing");
    HttpServer::new(|| {
        let env_root = env::var("VAYNE_ROOT").expect("Environment variable VAYNE_ROOT missing");
        let env_dns = env::var("VAYNE_DNS").expect("Environment variable VAYNE_DNS missing");
        App::new().wrap(middleware::Logger::default()).service(
            web::scope("")
                .service(Files::new("/", env_root).index_file("index.html"))
                .wrap(
                    DefaultHeaders::new()
                        .add((
                            "Strict-Transport-Security",
                            "max-age=31536000; includeSubDomains",
                        ))
                        .add((
                            "Content-Security-Policy",
                            format!(
                                "frame-ancestors 'self' https://{} https://www.{}",
                                env_dns, env_dns
                            ),
                        ))
                        .add(("X-Frame-Options", "deny"))
                        .add(("X-Content-Type-Options", "nosniff"))
                        .add(("Referrer-Policy", "no-referrer"))
                        .add(("Permissions-Policy", "geolocation=*, fullscreen=()"))
                        .add(("X-XSS-Protection", "1; mode=block")),
                ),
        )
    })
    .bind_rustls(format!("0.0.0.0:{}", env_port), config)?
    .run()
    .await
}

fn load_rustls_config() -> ServerConfig {
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth();

    let env_cert = env::var("VAYNE_CERT").expect("Environment variable VAYNE_CERT missing");
    let cert_file = File::open(env_cert).expect("Could not open certificate file");
    let cert_reader = &mut BufReader::new(cert_file);

    let env_key = env::var("VAYNE_KEY").expect("Environment variable VAYNE_KEY missing");
    let key_file = File::open(env_key).expect("Could not open private key file");
    let key_reader = &mut BufReader::new(key_file);

    let env_chain = env::var("VAYNE_CHAIN").expect("Environment variable VAYNE_CHAIN missing");
    let chain_file = File::open(env_chain).expect("Could not open certificate chain file");
    let chain_reader = &mut BufReader::new(chain_file);

    let mut all_certs = Vec::new();
    all_certs.extend(certs(cert_reader).expect("Could not read certificate"));
    all_certs.extend(certs(chain_reader).expect("Could not read certificate chain"));

    let all_certs = all_certs.into_iter().map(Certificate).collect();

    let mut keys: Vec<PrivateKey> = pkcs8_private_keys(key_reader)
        .expect("Failed to load private key")
        .into_iter()
        .map(PrivateKey)
        .collect();

    if keys.is_empty() {
        eprintln!("Could not locate PKCS 8 private keys.");
        std::process::exit(1);
    }

    config
        .with_single_cert(all_certs, keys.remove(0))
        .expect("Failed to load certificate")
}
