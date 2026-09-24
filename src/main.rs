use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use vault_core::{self as vault, Entry, Vault, VaultError};
use zeroize::Zeroizing;

const SESSION_TTL: Duration = Duration::from_secs(15 * 60);

// ---------- shared state ----------

struct Session {
    master: Zeroizing<String>,
    vault: Vault,
    last_used: Instant,
}

struct AppState {
    vault_path: String,
    sessions: Mutex<HashMap<String, Session>>,
}

type SharedState = Arc<AppState>;

/*struct AuthedToken(String);

impl FromRequestParts<SharedState> for AuthedToken {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedState,
    ) -> Result<Self, Self::Rejection> {
        let auth = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or(ApiError::Unauthorized)?;
        let token = auth
            .strip_prefix("Bearer ")
            .ok_or(ApiError::Unauthorized)?
            .to_string();

        // Peek — don't hold the lock, just verify
        if !state.sessions.lock().await.contains_key(&token) {
            return Err(ApiError::Unauthorized);
        }
        Ok(AuthedToken(token))
    }
}*/

// ---------- errors ----------

enum ApiError {
    Unauthorized,
    NotFound(String),
    BadRequest(String),
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized".into()),
            ApiError::NotFound(s) => (StatusCode::NOT_FOUND, s),
            ApiError::BadRequest(s) => (StatusCode::BAD_REQUEST, s),
            ApiError::Internal(s) => (StatusCode::INTERNAL_SERVER_ERROR, s),
        };
        (status, Json(serde_json::json!({ "error": msg }))).into_response()
    }
}

impl From<VaultError> for ApiError {
    fn from(e: VaultError) -> Self {
        match e {
            VaultError::Decrypt => ApiError::Unauthorized,
            VaultError::NoEntry(s) => ApiError::NotFound(s),
            _ => ApiError::Internal(format!("{}", e)),
        }
    }
}

// ---------- auth ----------

fn extract_token(headers: &HeaderMap) -> Result<String, ApiError> {
    let value = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(ApiError::Unauthorized)?;
    let token = value.strip_prefix("Bearer ").ok_or(ApiError::Unauthorized)?;
    Ok(token.to_string())
}

// ---------- session routes ----------

#[derive(Deserialize)]
struct CreateSessionReq {
    password: String,
}

#[derive(Serialize)]
struct CreateSessionResp {
    token: String,
    expires_in_secs: u64,
}

async fn create_session(
    State(state): State<SharedState>,
    Json(req): Json<CreateSessionReq>,
) -> Result<Json<CreateSessionResp>, ApiError> {
    // Loads and decrypts the vault — this also verifies the password.
    let vault = vault::load_vault(&state.vault_path, &req.password)?;

    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let token = URL_SAFE_NO_PAD.encode(bytes);

    let session = Session {
        master: Zeroizing::new(req.password),
        vault,
        last_used: Instant::now(),
    };
    state.sessions.lock().await.insert(token.clone(), session);

    Ok(Json(CreateSessionResp {
        token,
        expires_in_secs: SESSION_TTL.as_secs(),
    }))
}

async fn revoke_session(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let token = extract_token(&headers)?;
    state.sessions.lock().await.remove(&token);
    Ok(StatusCode::NO_CONTENT)
}

// ---------- entry routes ----------

async fn list_entries(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<Json<Vec<Entry>>, ApiError> {
    let token = extract_token(&headers)?;
    let mut sessions = state.sessions.lock().await;
    let session = sessions.get_mut(&token).ok_or(ApiError::Unauthorized)?;
    session.last_used = Instant::now();
    Ok(Json(session.vault.entries.clone()))
}

#[derive(Deserialize)]
struct AddEntryReq {
    site: String,
    user: String,
    password: String,
    #[serde(default)]
    notes: String,
}

async fn add_entry(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<AddEntryReq>,
) -> Result<StatusCode, ApiError> {
    let token = extract_token(&headers)?;
    let mut sessions = state.sessions.lock().await;
    let session = sessions.get_mut(&token).ok_or(ApiError::Unauthorized)?;

    if session.vault.find(&req.site).is_some() {
        return Err(ApiError::BadRequest(format!(
            "entry '{}' already exists",
            req.site
        )));
    }

    session.vault.entries.push(Entry {
        site: req.site,
        user: req.user,
        password: req.password,
        notes: req.notes,
    });

    vault::save_vault(&state.vault_path, &session.vault, &session.master)?;
    session.last_used = Instant::now();

    Ok(StatusCode::CREATED)
}

async fn get_entry(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(site): Path<String>,
) -> Result<Json<Entry>, ApiError> {
    let token = extract_token(&headers)?;
    let mut sessions = state.sessions.lock().await;
    let session = sessions.get_mut(&token).ok_or(ApiError::Unauthorized)?;
    session.last_used = Instant::now();

    session
        .vault
        .find(&site)
        .cloned()
        .map(Json)
        .ok_or_else(|| ApiError::NotFound(site))
}

async fn delete_entry(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(site): Path<String>,
) -> Result<StatusCode, ApiError> {
    let token = extract_token(&headers)?;
    let mut sessions = state.sessions.lock().await;
    let session = sessions.get_mut(&token).ok_or(ApiError::Unauthorized)?;

    session.vault.remove(&site)?;
    vault::save_vault(&state.vault_path, &session.vault, &session.master)?;
    session.last_used = Instant::now();

    Ok(StatusCode::NO_CONTENT)
}

// ---------- main ----------

#[tokio::main]
async fn main() {
    let vault_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "vault.enc".into());

    let state: SharedState = Arc::new(AppState {
        vault_path,
        sessions: Mutex::new(HashMap::new()),
    });

    // Background task: prune expired sessions every 60 seconds.
let prune_state = state.clone();
tokio::spawn(async move {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    interval.tick().await; // first tick is immediate; skip it
    loop {
        interval.tick().await;
        let mut sessions = prune_state.sessions.lock().await;
        let before = sessions.len();
        sessions.retain(|_, s| s.last_used.elapsed() < SESSION_TTL);
        let after = sessions.len();
        if before != after {
            println!("Pruned {} expired session(s)", before - after);
        }
    }
});

    let app = Router::new()
        .route("/session", post(create_session).delete(revoke_session))
        .route("/entries", get(list_entries).post(add_entry))
        .route("/entries/{site}", get(get_entry).delete(delete_entry))
        .with_state(state);

    let addr = "127.0.0.1:3000";
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    println!("Listening on http://{}", addr);
    axum::serve(listener, app).await.unwrap();
}
