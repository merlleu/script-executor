use std::sync::Arc;

use actix::prelude::*;
use actix_cors::Cors;
use actix_files as fs;
use actix_web::{
    get, post, web, App, Error, HttpRequest, HttpResponse, HttpServer, Result,
};
use actix_web_actors::ws;
use branca::Branca;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::AsyncBufReadExt;

// Configuration structure
#[derive(Serialize, Deserialize, Clone, Debug)]
struct Config {
    secret_key: String,
    admin_password_hash: String,
    execution_user: String,
    bind_address: String,
    port: u16,
    static_dir: String,
}

// Data structures
#[derive(Serialize, Deserialize, Clone, Debug)]
struct TokenPayload {
    script: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct TokenResponse {
    token: String,
    script: String,
}

#[derive(Serialize, Deserialize)]
struct AuthRequest {
    password: String,
}

#[derive(Serialize, Deserialize)]
struct GenerateTokenRequest {
    password: String,
    script: String,
}

// WebSocket session for script output
struct OutputSession {
    script_path: String,
    user: String,
}
impl Actor for OutputSession {
    type Context = ws::WebsocketContext<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        let script_path = self.script_path.clone();
        let user = self.user.clone();
        if !script_path.starts_with('/') && !script_path.starts_with("./") {
            ctx.text("Invalid script path");
            ctx.stop();
            return;
        }

        let addr = ctx.address();

        ctx.spawn(actix::fut::wrap_future::<_, Self>(async move {
            let mut child = tokio::process::Command::new("su")
                .arg("-l")
                .arg("-c")
                .arg(&script_path)
                .arg(user)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .expect("Failed to spawn process");

            let stdout = child.stdout.take().expect("Failed to get stdout");
            let stderr = child.stderr.take().expect("Failed to get stderr");

            let stdout_reader = tokio::io::BufReader::new(stdout);
            let stderr_reader = tokio::io::BufReader::new(stderr);

            // Process stdout
            let stdout_handle = {
                let addr = addr.clone();
                tokio::spawn(async move {
                    let mut lines = stdout_reader.lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        addr.do_send(OutputMessage(line));
                    }
                })
            };

            // Process stderr
            let stderr_handle = {
                let addr = addr.clone();
                tokio::spawn(async move {
                    let mut lines = stderr_reader.lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        addr.do_send(OutputMessage(format!("ERR: {}", line)));
                    }
                })
            };

            // Wait for process completion
            let status = child.wait().await.expect("Failed to wait for process");

            // Wait for stdout/stderr processing to complete
            let _ = stdout_handle.await;
            let _ = stderr_handle.await;

            // Send completion message
            addr.do_send(OutputMessage(format!("Script completed with status: {}", status)));
        }));
    }
}

// Message to handle output lines
#[derive(Message)]
#[rtype(result = "()")]
struct OutputMessage(String);

impl Handler<OutputMessage> for OutputSession {
    type Result = ();

    fn handle(&mut self, msg: OutputMessage, ctx: &mut Self::Context) {
        // Send the message to the websocket
        ctx.text(msg.0);
    }
}

impl StreamHandler<Result<ws::Message, ws::ProtocolError>> for OutputSession {
    fn handle(&mut self, msg: Result<ws::Message, ws::ProtocolError>, ctx: &mut Self::Context) {
        match msg {
            Ok(ws::Message::Text(text)) => {
                if text == "ping" {
                    ctx.text("pong");
                }
            }
            Ok(ws::Message::Close(reason)) => {
                ctx.close(reason);
                ctx.stop();
            }
            _ => {}
        }
    }
}

impl OutputSession {
    fn new(script_path: String, user: String) -> Self {
        Self { script_path, user }
    }
}

struct AppState {
    branca: Branca,
    config: Arc<Config>,
}

// Endpoints
#[post("/api/authenticate")]
async fn authenticate(
    data: web::Data<AppState>,
    auth_req: web::Json<AuthRequest>,
) -> Result<HttpResponse> {
    // Hash the provided password
    let mut hasher = Sha256::new();
    hasher.update(auth_req.password.as_bytes());
    let password_hash = hex::encode(hasher.finalize());

    if password_hash != data.config.admin_password_hash {
        return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Invalid password"
        })));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Authentication successful"
    })))
}

#[post("/api/generate_token")]
async fn generate_token(
    data: web::Data<AppState>,
    token_req: web::Json<GenerateTokenRequest>,
) -> Result<HttpResponse> {
    // Verify admin password
    let mut hasher = Sha256::new();
    hasher.update(token_req.password.as_bytes());
    let password_hash = hex::encode(hasher.finalize());

    if password_hash != data.config.admin_password_hash {
        return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Invalid password"
        })));
    }

    // Create token payload
    let payload = TokenPayload {
        script: token_req.script.clone(),
    };

    // Generate token
    let token = match create_token(&data.branca, &payload) {
        Ok(token) => token,
        Err(_) => {
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to generate token"
            })));
        }
    };

    Ok(HttpResponse::Ok().json(TokenResponse {
        token,
        script: token_req.script.clone(),
    }))
}

#[post("/api/verify_token")]
async fn verify_token(
    data: web::Data<AppState>,
    token: web::Json<String>,
) -> Result<HttpResponse> {
    match verify_and_decode_token(&data.branca, &token.into_inner()) {
        Ok(payload) => Ok(HttpResponse::Ok().json(payload)),
        Err(e) => Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("Invalid token: {}", e)
        }))),
    }
}

#[get("/api/execute/{token}")]
async fn execute_script_ws(
    req: HttpRequest,
    stream: web::Payload,
    data: web::Data<AppState>,
    token: web::Path<String>,
) -> Result<HttpResponse, Error> {
    // Verify token
    let payload = match verify_and_decode_token(&data.branca, &token.into_inner()) {
        Ok(payload) => payload,
        Err(e) => {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Invalid token: {}", e)
            }))
            .into());
        }
    };

    // Create a new output session
    let session = OutputSession::new(payload.script, data.config.execution_user.clone());

    // Start the WebSocket connection
    ws::start(session, &req, stream)
}

// Helper functions
fn create_token(branca: &Branca, payload: &TokenPayload) -> Result<String, Box<dyn std::error::Error>> {
    let json = serde_json::to_string(payload)?;
    Ok(branca.clone().encode(json.as_bytes())?)
}

fn verify_and_decode_token(
    branca: &Branca,
    token: &str,
) -> Result<TokenPayload, Box<dyn std::error::Error>> {
    let decoded = branca.decode(token, 0)?; // 0 means no TTL check
    let payload = serde_json::from_slice::<TokenPayload>(&decoded)?;
    Ok(payload)
}


// Load configuration from file
fn load_config() -> std::io::Result<Config> {
    let file = std::fs::read("config.json")?;

    let config: Config = serde_json::from_slice(&file)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(config)
}

// Main entry point
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    // Load configuration
    let config = Arc::new(load_config()?);

    // Create Branca instance with the secret key from config
    let branca = Branca::new(config.secret_key.as_bytes()).unwrap();

    // Create App State
    let app_state = web::Data::new(AppState {
        branca,
        config: config.clone(),
    });

    // Construct the bind address from config
    let bind_addr = format!("{}:{}", config.bind_address, config.port);

    println!("Starting server at http://{}", bind_addr);
    println!("All scripts will execute as user: {}", config.execution_user);

    HttpServer::new(move || {
        // Configure CORS
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);

        App::new()
            .wrap(cors)
            .app_data(app_state.clone())
            .service(authenticate)
            .service(generate_token)
            .service(verify_token)
            .service(execute_script_ws)
            .service(fs::Files::new("/", &config.static_dir).index_file("index.html"))
    })
    .bind(bind_addr)?
    .run()
    .await
}
