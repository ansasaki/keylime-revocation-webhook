use actix_files::NamedFile;
use actix_cors::Cors;
use actix_web::{
    App, HttpRequest, HttpResponse, HttpServer, Responder, get, http::header, post, rt, web,
};
use anyhow::{Context, Result, bail};
use clap::Parser;
use core::time;
use futures::try_join;
use futures_util::StreamExt;
use log::*;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod, SslVerifyMode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fmt::Debug,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{
    signal::unix::{SignalKind, signal},
    sync::{mpsc, watch},
};
use tokio_stream::wrappers::WatchStream;

pub const DEFAULT_IP: &str = "0.0.0.0";
pub const DEFAULT_PORT: u16 = 8080;
pub const DEFAULT_HTTPS_PORT: u16 = 8443;
pub const API_VERSION: &str = "v2.3";

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None, ignore_errors = true)]
struct Args {
    /// API version
    /// Default: "v2.3"
    #[arg(long, default_value = "v2.3")]
    api_version: Option<String>,
    /// CA certificate file
    #[arg(long, default_value = "/var/lib/keylime/cv_ca/cacert.crt")]
    ca_certificate: String,
    /// Client certificate file
    #[arg(long, default_value = "/var/lib/keylime/cv_ca/client-cert.crt")]
    client_certificate: String,
    /// Client private key file
    #[arg(
        short,
        long,
        default_value = "/var/lib/keylime/cv_ca/client-private.pem"
    )]
    client_key: String,
    /// Server certificate file
    #[arg(long, default_value = "/var/lib/keylime/cv_ca/server-cert.crt")]
    server_certificate: String,
    /// Server private key file
    #[arg(long, default_value = "/var/lib/keylime/cv_ca/server-private.pem")]
    server_key: String,
    /// Verifier URL
    #[arg(short, long, default_value = "https://127.0.0.1:8881")]
    verifier_url: String,
}

fn translate_operational_state(state: u32) -> String {
    match state {
        0 => "Registered",
        1 => "Start",
        2 => "Saved",
        3 => "GetQuote",
        4 => "GetQuoteRetry",
        5 => "ProvideV",
        6 => "ProvideVRetry",
        7 => "Failed",
        8 => "Terminated",
        9 => "InvalidQuote",
        10 => "TenantFailed",
        _ => "Unknown",
    }
    .to_string()
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub(crate) struct RevocationPayload {
    #[serde(rename(serialize = "type", deserialize = "type"))]
    pub(crate) type_: String,
    pub(crate) ip: String,
    pub(crate) agent_id: String,
    pub(crate) port: String,
    pub(crate) tpm_policy: Value,
    pub(crate) meta_data: Value,
    pub(crate) event_time: Value,
    pub(crate) event_id: String,
    pub(crate) severity_label: String,
    pub(crate) context: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub(crate) struct Revocation {
    pub(crate) msg: String,
    pub(crate) signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
enum EventMessage {
    Update(Update),
    //TODO make this to receive real revocation
    Revocation(Value),
    Shutdown,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
struct Machine {
    uuid: String,
    ip: String,
    state: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
struct Update {
    monitored: Vec<Machine>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
struct Status {
    #[serde(rename(serialize = "type", deserialize = "type"))]
    type_: String,
    msg: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
struct AgentsList {
    uuids: Vec<Vec<String>>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
struct TpmPolicy {
    mask: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub(crate) struct AgentInfo {
    pub(crate) operational_state: u32,
    pub(crate) v: Option<String>,
    pub(crate) ip: String,
    pub(crate) port: u32,
    pub(crate) tpm_policy: String,
    pub(crate) vtpm_policy: Option<String>,
    pub(crate) meta_data: Value,
    pub(crate) has_mb_refstate: u32,
    pub(crate) has_runtime_policy: u32,
    pub(crate) accept_tpm_hash_algs: Vec<String>,
    pub(crate) accept_tpm_encryption_algs: Vec<String>,
    pub(crate) accept_tpm_signing_algs: Vec<String>,
    pub(crate) hash_alg: String,
    pub(crate) enc_alg: String,
    pub(crate) sign_alg: String,
    pub(crate) verifier_id: String,
    pub(crate) verifier_ip: String,
    pub(crate) verifier_port: u32,
    pub(crate) severity_level: Option<u32>,
    pub(crate) last_event_id: Option<String>,
    pub(crate) attestation_count: u32,
    pub(crate) last_received_quote: u32,
    pub(crate) last_successful_attestation: u32,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct JsonWrapper<A> {
    pub code: u16,
    pub status: String,
    pub results: A,
}

impl JsonWrapper<Value> {
    pub(crate) fn error(code: u16, status: impl ToString) -> JsonWrapper<Value> {
        JsonWrapper {
            code,
            status: status.to_string(),
            results: json!({}),
        }
    }
}

impl<'de, A> JsonWrapper<A>
where
    A: Deserialize<'de> + Serialize + Debug,
{
    pub(crate) fn success(results: A) -> JsonWrapper<A> {
        JsonWrapper {
            code: 200,
            status: String::from("Success"),
            results,
        }
    }
}

#[get("/events")]
async fn events(data: web::Data<watch::Sender<Status>>) -> impl Responder {
    let rx = data.subscribe();

    let stream = WatchStream::new(rx).map(|event| {
        let json = serde_json::to_string(&event).unwrap();
        let sse_msg = format!("data: {}\n\n", json);
        Ok::<_, actix_web::Error>(web::Bytes::from(sse_msg))
    });

    HttpResponse::Ok()
        .insert_header(("Content-Type", "text/event-stream"))
        .insert_header(("Cache-Control", "no-cache"))
        .insert_header(("Connection", "keep-alive"))
        .insert_header((header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")) // Allow all origins
        .insert_header((header::ACCESS_CONTROL_ALLOW_METHODS, "GET")) // Allow specific HTTP methods
        .insert_header((header::ACCESS_CONTROL_ALLOW_HEADERS, "*")) // Allow all request headers
        .streaming(stream)
}

#[post("/")]
/// Handle revocation messages and forward the message for broadcasting
async fn revocation(
    body: web::Json<Revocation>,
    req: HttpRequest,
    data: web::Data<mpsc::Sender<EventMessage>>,
) -> impl Responder {
    info!("Got revocation request");
    debug!("{:?}", req);
    debug!("{:?}", body);
    debug!("{:?}", data);

    let r: Revocation = body.into_inner();
    let events_tx = &data;

    //TODO make it to receive RevocationPayload
    //match serde_json::from_str::<RevocationPayload>(r.msg.as_ref()) {
    match serde_json::from_str::<Value>(r.msg.as_ref()) {
        Ok(p) => {
            //TODO verify signature
            info!("Received revocation: {:?}", p);
            _ = events_tx.send(EventMessage::Revocation(p)).await;
            HttpResponse::Ok().json(JsonWrapper::success(()))
        }
        Err(e) => {
            let msg = "Failed to parse revocation message payload as JSON.";
            error!("{}: {e}", msg);
            HttpResponse::BadRequest().json(JsonWrapper::error(400, msg))
        }
    }
}

#[get("/")]
async fn index() -> actix_web::Result<impl Responder> {
    info!("Got request for index");
    let file = NamedFile::open_async("web/index.html").await?;

    let file = file
        .customize()
        .insert_header((header::ACCESS_CONTROL_ALLOW_ORIGIN, "http://127.0.0.1:8080, http://localhost:8080"))
        .insert_header((header::ACCESS_CONTROL_ALLOW_METHODS, "GET, OPTIONS, POST")) // Allow specific HTTP methods
        .insert_header((header::ACCESS_CONTROL_ALLOW_HEADERS, "*")); // Allow all request headers
    Ok(file)
}

/// Listen to events and broadcast to all subscribers
async fn broadcast_worker(
    mut events_rx: mpsc::Receiver<EventMessage>,
    broadcast_tx: watch::Sender<Status>,
) -> Result<()> {
    debug!("Starting broadcast worker");

    while let Some(event) = events_rx.recv().await {
        match event {
            EventMessage::Update(update) => {
                info!("Update: {:?}", update);
                let s = Status {
                    type_: "update".to_string(),
                    msg: serde_json::to_string(&update)?,
                };
                let _old = broadcast_tx.send_replace(s);
            }
            EventMessage::Revocation(rev) => {
                info!("Revocation: {:?}", rev);
                let s = Status {
                    type_: "revocation".to_string(),
                    msg: serde_json::to_string(&rev)?,
                };
                let _old = broadcast_tx.send_replace(s);
            }
            EventMessage::Shutdown => {
                break;
            }
        }
    }

    Ok(())
}

/// Get status updates and send to broadcast
async fn status_worker(
    events_tx: mpsc::Sender<EventMessage>,
    verifier_ip: String,
    ca_cert: &Path,
    client_cert: &Path,
    client_key: &Path,
) -> Result<()> {
    // Build URL
    let list_url = format!("{}/{}/agents/", verifier_ip, API_VERSION);

    // Get CA cert
    let mut buf = Vec::new();
    File::open(ca_cert)
        .context(format!("Failed to open '{}' file", ca_cert.display()))?
        .read_to_end(&mut buf)
        .context(format!("Failed to read '{}' to the end", ca_cert.display()))?;
    let ca_cert = reqwest::Certificate::from_pem(&buf).context(format!(
        "Failed to parse certificate from PEM file '{}'",
        ca_cert.display()
    ))?;

    // Get client key and certificate from files
    let cert = fs::read(client_cert).context(format!(
        "Failed to read client certificate from file '{}'",
        client_cert.display()
    ))?;
    let key = fs::read(client_key).context(format!(
        "Failed to read key from file '{}'",
        client_key.display()
    ))?;
    let identity = reqwest::Identity::from_pkcs8_pem(&cert, &key).context(format!(
        "Failed to add client identity from certificate '{}' and key '{}'",
        client_cert.display(),
        client_key.display()
    ))?;

    debug!("Starting status worker");

    loop {
        let list_client = reqwest::Client::builder()
            .connection_verbose(true)
            .add_root_certificate(ca_cert.clone())
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .identity(identity.clone())
            .build()?
            .get(list_url.clone());

        debug!("Requesting list of agents to {}", list_url);
        let list_resp = match list_client
            .json(&{})
            .timeout(Duration::from_secs(3))
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!("Failed to get list of agents from {}: {}", list_url, e);
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };

        if !list_resp.status().is_success() {
            warn!("Failed to get list of agents from {}", verifier_ip);
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        }

        let list_result = list_resp
            .json::<JsonWrapper<AgentsList>>()
            .await
            .expect("Failed to deserialize agent list response as JSON");

        let agents: Vec<String> = match list_result.code {
            200 => list_result.results.uuids.into_iter().flatten().collect(),
            _ => {
                warn!(
                    "Failed to get list of agents from {}: {}",
                    verifier_ip, list_result.status
                );
                tokio::time::sleep(Duration::from_secs(3)).await;
                continue;
            }
        };

        debug!("Obtained: {:?}", agents);
        let mut status: Vec<Machine> = Vec::new();
        for uuid in agents {
            // Build status URL
            let status_url = format!("{}/{}/agents/{}", verifier_ip, API_VERSION, uuid);
            let status_client = reqwest::Client::builder()
                .connection_verbose(true)
                .add_root_certificate(ca_cert.clone())
                .danger_accept_invalid_certs(true)
                .danger_accept_invalid_hostnames(true)
                .identity(identity.clone())
                .build()?
                .get(&status_url);

            debug!("Requesting status of agent {} to {}", uuid, &status_url);
            let status_resp = match status_client
                .json(&{})
                .timeout(Duration::from_secs(3))
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    warn!("Failed to get status of agent {}: {}", uuid, e);
                    continue;
                }
            };

            if !status_resp.status().is_success() {
                warn!("Failed to get status of agent {}", uuid);
                continue;
            }

            let status_result = status_resp
                .json::<JsonWrapper<AgentInfo>>()
                .await
                .expect("Failed to deserialize the status_result");

            let s = &status_result.results;

            let out = Machine {
                uuid,
                ip: s.ip.clone(),
                state: translate_operational_state(s.operational_state),
            };

            status.push(out)
        }

        debug!("Sending status to broadcast");
        _ = events_tx
            .send(EventMessage::Update(Update { monitored: status }))
            .await;

        tokio::time::sleep(time::Duration::from_secs(3)).await;
    }
}

#[actix_web::main]
async fn main() -> Result<()> {
    pretty_env_logger::init();

    let args = Args::parse();

    info!("Verifier IP: {}", args.verifier_url);
    debug!("CA certificate file: {}", args.ca_certificate);
    debug!("Client certificate file: {}", args.client_certificate);
    debug!("Client key file: {}", args.client_key);
    debug!("Server certificate file: {}", args.server_certificate);
    debug!("Server key file: {}", args.server_key);

    let ca_certificate = PathBuf::from(&args.ca_certificate);
    if !ca_certificate.exists() {
        bail!("CA certificate file {} not found", args.ca_certificate);
    }

    let client_cert = PathBuf::from(&args.client_certificate);
    if !client_cert.exists() {
        bail!("Certificate file {} not found", args.client_certificate);
    }

    let client_key = PathBuf::from(&args.client_key);
    if !client_key.exists() {
        bail!("Client key file {} not found", args.client_key);
    }

    let server_cert = PathBuf::from(&args.server_certificate);
    if !server_cert.exists() {
        bail!("Server file {} not found", args.server_certificate);
    }

    let server_key = PathBuf::from(&args.server_key);
    if !server_key.exists() {
        bail!("Server key file {} not found", args.server_key);
    }

    let initial_state = Status::default();

    // Shared watch channel
    let (broadcast_tx, _) = watch::channel(initial_state);

    let (events_tx, events_rx) = mpsc::channel::<EventMessage>(1);

    let etx = events_tx.clone();
    let btx = broadcast_tx.clone();

    info!("Starting Keylime revocation webhook server");
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    builder.set_private_key_file(server_key, SslFiletype::PEM)?;
    builder.set_certificate_file(server_cert, SslFiletype::PEM)?;
    builder.set_ca_file(ca_certificate.clone())?;

    // Require client certificate
    let mut verify_mode = SslVerifyMode::empty();
    verify_mode.set(SslVerifyMode::PEER, true);
    verify_mode.set(SslVerifyMode::FAIL_IF_NO_PEER_CERT, true);
    builder.set_verify(verify_mode);

    let revocation_server = HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(etx.clone()))
            .service(revocation)
    })
    .bind_openssl(format!("{}:{}", DEFAULT_IP, DEFAULT_HTTPS_PORT), builder)?
    .disable_signals()
    .run();

    let revocation_server_handle = revocation_server.handle();
    let revocation_server_task = rt::spawn(revocation_server);

    info!("Listening to revocations on https://{}:{}", DEFAULT_IP, DEFAULT_HTTPS_PORT);

    info!("Starting Keylime dashboard server");
    let dashboard_server = HttpServer::new(move || {
        App::new()
            .wrap(
                Cors::default()
                    .allowed_origin_fn(move |origin, _req_head| {
                        let allowed_origins = vec![
                            "http://127.0.0.1:8080",
                            "http://localhost:8080",
                        ];
                        allowed_origins.clone().iter().any(|o| origin.as_bytes() == o.as_bytes())
                    })
                    .allowed_methods(vec!["GET"])
                    .allowed_headers(vec!["Content-Type", "Authorization"])
                    .supports_credentials()
            )
            .app_data(web::Data::new(btx.clone()))
            .service(index)
            .service(events)
    })
    .bind((DEFAULT_IP, DEFAULT_PORT))?
    .disable_signals()
    .run();

    let dashboard_server_handle = dashboard_server.handle();
    let dashboard_server_task = rt::spawn(dashboard_server);

    info!("Listening to events on http://{}:{}", DEFAULT_IP, DEFAULT_PORT);

    let shutdown_task = rt::spawn(async move {
        let mut sigint = signal(SignalKind::interrupt()).unwrap(); //#[allow_ci]
        let mut sigterm = signal(SignalKind::terminate()).unwrap(); //#[allow_ci]

        tokio::select! {
            _ = sigint.recv() => {
                debug!("Received SIGINT signal");
            },
            _ = sigterm.recv() => {
                debug!("Received SIGTERM signal");
            },
            _ = broadcast_worker(events_rx, broadcast_tx) => {
                debug!("Broadcast worker died");
            }
            _ = status_worker(events_tx, args.verifier_url, &ca_certificate, &client_cert, &client_key) => {
                debug!("Status worker died");
            }
        }

        info!("Shutting down servers");

        // Shutdown servers
        let revocation_server_stop = revocation_server_handle.stop(true);
        let dashboard_server_stop = dashboard_server_handle.stop(true);

        // Await tasks shutdown
        revocation_server_stop.await;
        dashboard_server_stop.await;
    });

    let _returns = try_join!(shutdown_task, revocation_server_task, dashboard_server_task);

    Ok(())
}
