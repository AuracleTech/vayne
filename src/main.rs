use actix_files::Files;
use actix_web::{
    middleware::{self, DefaultHeaders},
    web, App, HttpServer,
};
use certbot::CertPaths;
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::{fs::File, io::BufReader};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));
    let config = load_rustls_config();
    log::info!("Starting HTTPS server");
    HttpServer::new(|| {
        App::new().wrap(middleware::Logger::default()).service(
            web::scope("")
                .service(Files::new("/", "C:/www").index_file("index.html"))
                .wrap(
                    DefaultHeaders::new()
                        .add((
                            "Strict-Transport-Security",
                            "max-age=31536000; includeSubDomains",
                        ))
                        .add((
                            "Content-Security-Policy",
                            "frame-ancestors 'self' https://auracle.tk https://www.auracle.tk",
                        ))
                        .add(("X-Frame-Options", "deny"))
                        .add(("X-Content-Type-Options", "nosniff"))
                        .add(("Referrer-Policy", "no-referrer"))
                        .add(("Permissions-Policy", "geolocation=*, fullscreen=()")),
                ),
        )
    })
    .bind_rustls("0.0.0.0:443", config)?
    .run()
    .await
}

fn load_rustls_config() -> rustls::ServerConfig {
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth();

    let cert_paths = CertPaths {
        cert: "C:\\Certbot\\live\\auracle.tk\\cert.pem".into(),
        chain: "C:\\Certbot\\live\\auracle.tk\\chain.pem".into(),
        fullchain: "C:\\Certbot\\live\\auracle.tk\\fullchain.pem".into(),
        privkey: "C:\\Certbot\\live\\auracle.tk\\privkey.pem".into(),
    };

    let cert_file = &mut BufReader::new(File::open(cert_paths.cert).unwrap());
    let key_file = &mut BufReader::new(File::open(cert_paths.privkey).unwrap());

    let cert_chain = certs(cert_file)
        .expect("Failed to load certificate chain")
        .into_iter()
        .map(Certificate)
        .collect();
    let mut keys: Vec<PrivateKey> = pkcs8_private_keys(key_file)
        .expect("Failed to load private key")
        .into_iter()
        .map(PrivateKey)
        .collect();

    if keys.is_empty() {
        eprintln!("Could not locate PKCS 8 private keys.");
        std::process::exit(1);
    }

    config.with_single_cert(cert_chain, keys.remove(0)).unwrap()
}
