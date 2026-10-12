//! Durable path configuration in the deployment's SQL `path_contexts` table.
//! The bounded cache and refresh locks are process memory. Schema migrations
//! remain the database owner's responsibility; opening Search creates no tables.

use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use chrono::{NaiveDateTime, Utc};
use parking_lot::Mutex;
use sqlx::{postgres::PgPoolOptions, sqlite::SqlitePoolOptions, PgPool, SqlitePool};
use tokio::sync::OnceCell;

const MAX_CACHED_ZONES: usize = 2048;
const DEFAULT_FRESHNESS: Duration = Duration::from_secs(1);
const SELECT: &str =
    "SELECT zone_id, path_prefix, description, weight, created_at, updated_at FROM path_contexts";
const UPSERT: &str = "INSERT INTO path_contexts (zone_id, path_prefix, description, weight, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $5) ON CONFLICT (zone_id, path_prefix) DO UPDATE SET description = excluded.description, weight = excluded.weight, updated_at = excluded.updated_at RETURNING zone_id, path_prefix, description, weight, created_at, updated_at";
type Row = (
    String,
    String,
    String,
    Option<f64>,
    NaiveDateTime,
    NaiveDateTime,
);
pub type Boosts = HashMap<String, f32>;

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PathContextError {
    #[error("{0}")]
    InvalidArgument(&'static str),
    #[error("{0}")]
    Unavailable(&'static str),
    #[error("{0}")]
    NotFound(&'static str),
}

pub struct PathContextInput {
    pub zone_id: String,
    pub path_prefix: String,
    pub description: String,
    pub weight: Option<f64>,
}

#[derive(Debug)]
pub struct PathContextRecord {
    pub zone_id: String,
    pub path_prefix: String,
    pub description: String,
    pub weight: Option<f64>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

enum Database {
    Postgres(PgPool),
    Sqlite(SqlitePool),
}

struct CachedBoosts {
    value: Result<Arc<Boosts>, PathContextError>,
    loaded_at: Instant,
}

/// One store per Search service. Connections are opened on its async runtime.
pub struct PathContextStore {
    url: String,
    database: OnceCell<Database>,
    freshness: Duration,
    cache: Mutex<HashMap<String, CachedBoosts>>,
    // Fixed stripes bound lock memory and coalesce refreshes. Mutations take
    // the same stripe so a pre-write refresh cannot refill an invalidated cache.
    refresh: [tokio::sync::Mutex<()>; 64],
}

impl PathContextStore {
    pub fn new(url: impl Into<String>, freshness: Duration) -> Self {
        Self {
            url: url.into(),
            database: OnceCell::new(),
            freshness,
            cache: Mutex::new(HashMap::new()),
            refresh: std::array::from_fn(|_| tokio::sync::Mutex::new(())),
        }
    }

    pub fn from_env() -> Option<Self> {
        let url = ["DATABASE_URL", "NEXUS_DATABASE_URL"]
            .into_iter()
            .find_map(|key| std::env::var(key).ok().filter(|value| !value.is_empty()))?;
        let freshness = std::env::var("NEXUS_PATH_CONTEXT_FRESHNESS_SECONDS")
            .ok()
            .and_then(|value| value.trim().parse::<f64>().ok())
            .filter(|value| value.is_finite())
            .and_then(|value| Duration::try_from_secs_f64(value.max(0.0)).ok())
            .unwrap_or(DEFAULT_FRESHNESS);
        Some(Self::new(url, freshness))
    }

    async fn database(&self) -> Result<&Database, PathContextError> {
        self.database
            .get_or_try_init(|| async {
                // Accept the existing SQLAlchemy connection spellings too.
                let mut url = if let Some(rest) = self.url.strip_prefix("postgresql+asyncpg:") {
                    format!("postgresql:{rest}")
                } else if let Some(rest) = self.url.strip_prefix("sqlite+aiosqlite:") {
                    format!("sqlite:{rest}")
                } else {
                    self.url.clone()
                };
                // DATABASE_URL uses SQLAlchemy's SQLite URL convention:
                // three slashes introduce a relative filename, four an
                // absolute filename. SQLx consumes one fewer slash.
                if let Some(filename) = url.strip_prefix("sqlite:///") {
                    url = format!("sqlite://{filename}");
                }
                if url.starts_with("postgresql:") || url.starts_with("postgres:") {
                    PgPoolOptions::new()
                        .max_connections(8)
                        .acquire_timeout(Duration::from_secs(5))
                        .connect(&url)
                        .await
                        .map(Database::Postgres)
                        .map_err(database_error)
                } else if url.starts_with("sqlite:") {
                    SqlitePoolOptions::new()
                        .max_connections(1)
                        .acquire_timeout(Duration::from_secs(5))
                        .connect(&url)
                        .await
                        .map(Database::Sqlite)
                        .map_err(database_error)
                } else {
                    Err(PathContextError::Unavailable(
                        "path-context database URL must use PostgreSQL or SQLite",
                    ))
                }
            })
            .await
    }

    fn stripe(&self, zone: &str) -> &tokio::sync::Mutex<()> {
        let mut hash = DefaultHasher::new();
        zone.hash(&mut hash);
        &self.refresh[hash.finish() as usize % self.refresh.len()]
    }

    pub async fn list(
        &self,
        zone: Option<&str>,
    ) -> Result<Vec<PathContextRecord>, PathContextError> {
        let predicate = if zone.is_some() {
            "zone_id = $1"
        } else {
            "CAST($1 AS TEXT) IS NULL"
        };
        macro_rules! rows {
            ($pool:expr, $collation:literal) => {
                sqlx::query_as::<_, Row>(&format!(
                    "{SELECT} WHERE {predicate} ORDER BY zone_id COLLATE {}, path_prefix COLLATE {}",
                    $collation, $collation
                ))
                .bind(zone)
                .fetch_all($pool)
                .await
                .map_err(database_error)?
            };
        }
        let rows = match self.database().await? {
            Database::Postgres(pool) => rows!(pool, "\"C\""),
            Database::Sqlite(pool) => rows!(pool, "BINARY"),
        };
        Ok(rows.into_iter().map(from_row).collect())
    }

    pub async fn put(
        &self,
        mut request: PathContextInput,
    ) -> Result<PathContextRecord, PathContextError> {
        request.zone_id = checked_zone(&request.zone_id)?.to_owned();
        request.path_prefix = normalize_prefix(&request.path_prefix)?;
        let length = request.description.chars().count();
        if !(1..=4096).contains(&length) {
            return Err(PathContextError::InvalidArgument(
                "description must contain 1..4096 characters",
            ));
        }
        if request
            .weight
            .is_some_and(|weight| !weight.is_finite() || !(0.1..=10.0).contains(&weight))
        {
            return Err(PathContextError::InvalidArgument(
                "weight must be finite and between 0.1 and 10.0",
            ));
        }
        let _guard = self.stripe(&request.zone_id).lock().await;
        let now = Utc::now().naive_utc();
        macro_rules! put {
            ($pool:expr) => {
                sqlx::query_as::<_, Row>(UPSERT)
                    .bind(&request.zone_id)
                    .bind(&request.path_prefix)
                    .bind(&request.description)
                    .bind(request.weight)
                    .bind(now)
                    .fetch_one($pool)
                    .await
                    .map_err(database_error)?
            };
        }
        let row = match self.database().await? {
            Database::Postgres(pool) => put!(pool),
            Database::Sqlite(pool) => put!(pool),
        };
        self.cache.lock().remove(&request.zone_id);
        Ok(from_row(row))
    }

    pub async fn delete(&self, zone: &str, prefix: &str) -> Result<String, PathContextError> {
        let zone = checked_zone(zone)?;
        let prefix = normalize_prefix(prefix)?;
        let _guard = self.stripe(zone).lock().await;
        macro_rules! delete {
            ($pool:expr) => {
                sqlx::query("DELETE FROM path_contexts WHERE zone_id = $1 AND path_prefix = $2")
                    .bind(zone)
                    .bind(&prefix)
                    .execute($pool)
                    .await
                    .map_err(database_error)?
                    .rows_affected()
            };
        }
        let count = match self.database().await? {
            Database::Postgres(pool) => delete!(pool),
            Database::Sqlite(pool) => delete!(pool),
        };
        self.cache.lock().remove(zone);
        if count == 0 {
            return Err(PathContextError::NotFound("path context not found"));
        }
        Ok(prefix)
    }

    fn cached(&self, zone: &str) -> Option<Result<Arc<Boosts>, PathContextError>> {
        self.cache
            .lock()
            .get(zone)
            .filter(|entry| {
                entry.loaded_at.elapsed()
                    < if entry.value.is_ok() {
                        self.freshness
                    } else {
                        self.freshness.max(DEFAULT_FRESHNESS)
                    }
            })
            .map(|entry| entry.value.clone())
    }

    async fn load_boosts(&self, zone: &str) -> Result<Boosts, PathContextError> {
        // Query refreshes need only weights. Descriptions and timestamps stay
        // on the management read path, avoiding text copies on every refresh.
        macro_rules! rows {
            ($pool:expr) => {
                sqlx::query_as::<_, (String, Option<f64>)>(
                    "SELECT path_prefix, weight FROM path_contexts WHERE zone_id = $1",
                )
                .bind(zone)
                .fetch_all($pool)
                .await
                .map_err(database_error)?
            };
        }
        let rows = match self.database().await? {
            Database::Postgres(pool) => rows!(pool),
            Database::Sqlite(pool) => rows!(pool),
        };
        Ok(prefix_boosts(&rows))
    }

    pub async fn boosts(&self, zone: &str) -> Result<Arc<Boosts>, PathContextError> {
        if let Some(value) = self.cached(zone) {
            return value;
        }
        let _guard = self.stripe(zone).lock().await;
        if let Some(value) = self.cached(zone) {
            return value;
        }
        // Reload actual rows: COUNT/MAX timestamps cannot detect every update
        // (including clock changes). The TTL bounds external-write staleness.
        let value = self.load_boosts(zone).await.map(Arc::new);
        let mut cache = self.cache.lock();
        if cache.len() >= MAX_CACHED_ZONES && !cache.contains_key(zone) {
            if let Some(oldest) = cache
                .iter()
                .min_by_key(|(_, entry)| entry.loaded_at)
                .map(|(zone, _)| zone.clone())
            {
                cache.remove(&oldest);
            }
        }
        cache.insert(
            zone.to_owned(),
            CachedBoosts {
                value: value.clone(),
                loaded_at: Instant::now(),
            },
        );
        value
    }
}

fn database_error(_error: sqlx::Error) -> PathContextError {
    // Connection errors can contain connection parameters. Keep them out of
    // RPC responses and logs; callers can diagnose the deployment separately.
    PathContextError::Unavailable("path-context database operation failed")
}

fn from_row(row: Row) -> PathContextRecord {
    PathContextRecord {
        zone_id: row.0,
        path_prefix: row.1,
        description: row.2,
        weight: row.3,
        created_at: row.4,
        updated_at: row.5,
    }
}

pub fn checked_zone(zone: &str) -> Result<&str, PathContextError> {
    let zone = if zone.is_empty() {
        contracts::ROOT_ZONE_ID
    } else {
        zone
    };
    if zone.chars().count() > 255 || zone.chars().any(char::is_control) {
        return Err(PathContextError::InvalidArgument(
            "invalid path-context zone_id",
        ));
    }
    Ok(zone)
}

pub fn normalize_prefix(raw: &str) -> Result<String, PathContextError> {
    static FORBIDDEN: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"[\x00-\x1f\x7f\p{Cf}]").unwrap());
    if raw.chars().count() > 1024 || FORBIDDEN.is_match(raw.trim()) {
        return Err(PathContextError::InvalidArgument(
            "invalid path_prefix length or characters",
        ));
    }
    let prefix = raw.trim().trim_matches('/');
    if !prefix.is_empty()
        && prefix
            .split('/')
            .any(|part| matches!(part, "" | "." | ".."))
    {
        return Err(PathContextError::InvalidArgument(
            "path_prefix must not contain empty, '.' or '..' segments",
        ));
    }
    Ok(prefix.to_owned())
}

fn prefix_boosts(records: &[(String, Option<f64>)]) -> Boosts {
    if !records
        .iter()
        .any(|(_, weight)| weight.is_some_and(|weight| weight != 1.0))
    {
        return HashMap::new();
    }
    records
        .iter()
        .map(|(path_prefix, weight)| {
            let prefix = if path_prefix.is_empty() {
                String::new()
            } else {
                format!("/{path_prefix}/")
            };
            (prefix, weight.unwrap_or(1.0) as f32)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCHEMA: &str = "CREATE TABLE path_contexts (id INTEGER PRIMARY KEY, zone_id VARCHAR(255) NOT NULL DEFAULT 'root', path_prefix VARCHAR(1024) NOT NULL, description TEXT NOT NULL, weight FLOAT, created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL, UNIQUE(zone_id, path_prefix))";

    async fn sqlite_store(freshness: Duration) -> PathContextStore {
        let store = PathContextStore::new("sqlite::memory:", freshness);
        let Database::Sqlite(pool) = store.database().await.unwrap() else {
            unreachable!()
        };
        sqlx::query(SCHEMA).execute(pool).await.unwrap();
        store
    }

    fn request(zone: &str, prefix: &str, weight: Option<f64>) -> PathContextInput {
        PathContextInput {
            zone_id: zone.into(),
            path_prefix: prefix.into(),
            description: "durable configuration".into(),
            weight,
        }
    }

    async fn exercise_store(store: &PathContextStore) {
        let initial = store
            .put(request("alpha", "/docs/", Some(4.0)))
            .await
            .unwrap();
        assert_eq!(initial.path_prefix, "docs");
        assert_eq!(
            store.boosts("alpha").await.unwrap().get("/docs/"),
            Some(&4.0)
        );
        assert!(store.boosts("beta").await.unwrap().is_empty());
        store
            .put(request("alpha", "docs/plain", None))
            .await
            .unwrap();
        let boosts = store.boosts("alpha").await.unwrap();
        assert_eq!(boosts.get("/docs/plain/"), Some(&1.0));
        assert_eq!(boosts.get("/docs/"), Some(&4.0));
        let replacement = store.put(request("alpha", "docs", None)).await.unwrap();
        assert_eq!(replacement.created_at, initial.created_at);
        assert_eq!(replacement.weight, None);
        assert!(store.boosts("alpha").await.unwrap().is_empty());
        store.put(request("beta", "z", Some(2.0))).await.unwrap();
        let all = store.list(None).await.unwrap();
        assert_eq!(
            all.iter()
                .map(|r| (&*r.zone_id, &*r.path_prefix))
                .collect::<Vec<_>>(),
            [("alpha", "docs"), ("alpha", "docs/plain"), ("beta", "z")]
        );
        assert_eq!(store.list(Some("alpha")).await.unwrap().len(), 2);
        store.delete("beta", "/z/").await.unwrap();
        assert!(store.boosts("beta").await.unwrap().is_empty());
        assert_eq!(
            store.delete("beta", "z").await.unwrap_err(),
            PathContextError::NotFound("path context not found")
        );
    }

    #[tokio::test]
    async fn sqlite_durable_replacement_and_cache_invalidation() {
        exercise_store(&sqlite_store(Duration::from_secs(3600)).await).await;
    }

    #[tokio::test]
    async fn sqlalchemy_sqlite_urls_open_existing_files_and_memory() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("existing.db");
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(
                sqlx::sqlite::SqliteConnectOptions::new()
                    .filename(&path)
                    .create_if_missing(true),
            )
            .await
            .unwrap();
        sqlx::query(SCHEMA).execute(&pool).await.unwrap();
        pool.close().await;
        let url = format!(
            "sqlite+aiosqlite:///{}",
            path.to_string_lossy().replace('\\', "/")
        );
        let store = PathContextStore::new(url, Duration::ZERO);
        exercise_store(&store).await;
        let memory = PathContextStore::new("sqlite+aiosqlite:///:memory:", Duration::ZERO);
        let Database::Sqlite(pool) = memory.database().await.unwrap() else {
            unreachable!()
        };
        sqlx::query(SCHEMA).execute(pool).await.unwrap();
        exercise_store(&memory).await;
        let relative = tempfile::Builder::new()
            .prefix("search-path-context-")
            .tempfile_in(".")
            .unwrap()
            .into_temp_path();
        let filename = relative.file_name().unwrap().to_string_lossy();
        let pool = SqlitePoolOptions::new()
            .connect_with(sqlx::sqlite::SqliteConnectOptions::new().filename(&*relative))
            .await
            .unwrap();
        sqlx::query(SCHEMA).execute(&pool).await.unwrap();
        pool.close().await;
        let store = PathContextStore::new(format!("sqlite:///./{filename}"), Duration::ZERO);
        exercise_store(&store).await;
        let Database::Sqlite(pool) = store.database().await.unwrap() else {
            unreachable!()
        };
        pool.close().await;
    }

    #[tokio::test]
    #[ignore = "the required PostgreSQL CI job supplies a disposable database"]
    async fn postgres_durable_replacement_and_cache_invalidation() {
        // Required CI job supplies its disposable PostgreSQL database. Local
        // runs without PostgreSQL still execute the full SQLite contract.
        let url = std::env::var("NEXUS_PATH_CONTEXT_TEST_POSTGRES_URL")
            .expect("PostgreSQL test database must be configured");
        let store = PathContextStore::new(url, Duration::from_secs(3600));
        let Database::Postgres(pool) = store.database().await.unwrap() else {
            panic!("PostgreSQL test requires a PostgreSQL URL")
        };
        sqlx::query(
            &SCHEMA
                .replace("id INTEGER PRIMARY KEY", "id SERIAL PRIMARY KEY")
                .replace("weight FLOAT", "weight DOUBLE PRECISION"),
        )
        .execute(pool)
        .await
        .unwrap();
        exercise_store(&store).await;
    }

    #[tokio::test]
    async fn external_changes_reload_even_with_unchanged_fingerprint() {
        let store = sqlite_store(Duration::ZERO).await;
        store
            .put(request("alpha", "docs", Some(4.0)))
            .await
            .unwrap();
        assert_eq!(
            store.boosts("alpha").await.unwrap().get("/docs/"),
            Some(&4.0)
        );
        let Database::Sqlite(pool) = store.database().await.unwrap() else {
            unreachable!()
        };
        sqlx::query("UPDATE path_contexts SET weight = 2.0 WHERE zone_id = 'alpha'")
            .execute(pool)
            .await
            .unwrap();
        assert_eq!(
            store.boosts("alpha").await.unwrap().get("/docs/"),
            Some(&2.0)
        );
        sqlx::query("DELETE FROM path_contexts WHERE zone_id = 'alpha'")
            .execute(pool)
            .await
            .unwrap();
        assert!(store.boosts("alpha").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn concurrent_refresh_and_write_cannot_restore_stale_cache() {
        let store = Arc::new(sqlite_store(Duration::from_secs(3600)).await);
        store
            .put(request("alpha", "docs", Some(4.0)))
            .await
            .unwrap();
        let mut tasks = Vec::new();
        for _ in 0..32 {
            let store = Arc::clone(&store);
            tasks.push(tokio::spawn(
                async move { store.boosts("alpha").await.unwrap() },
            ));
        }
        store
            .put(request("alpha", "docs", Some(2.0)))
            .await
            .unwrap();
        for task in tasks {
            task.await.unwrap();
        }
        assert_eq!(
            store.boosts("alpha").await.unwrap().get("/docs/"),
            Some(&2.0)
        );
        assert_eq!(store.cache.lock().len(), 1);
    }

    #[tokio::test]
    async fn zone_cache_is_bounded() {
        let store = sqlite_store(Duration::from_secs(3600)).await;
        for i in 0..=MAX_CACHED_ZONES {
            assert!(store.boosts(&format!("zone-{i}")).await.unwrap().is_empty());
        }
        assert_eq!(store.cache.lock().len(), MAX_CACHED_ZONES);
    }

    #[tokio::test]
    async fn invalid_inputs_are_rejected_before_database_access() {
        let store = PathContextStore::new("unsupported://private-secret", Duration::ZERO);
        for prefix in ["docs//a", "../a", "docs/./a", "docs\u{200b}", "docs\0a"] {
            assert!(matches!(
                store.put(request("alpha", prefix, Some(2.0))).await,
                Err(PathContextError::InvalidArgument(_))
            ));
        }
        for weight in [0.0, 10.1, f64::NAN, f64::INFINITY] {
            assert!(matches!(
                store.put(request("alpha", "docs", Some(weight))).await,
                Err(PathContextError::InvalidArgument(_))
            ));
        }
        let status = store.boosts("alpha").await.unwrap_err();
        assert!(matches!(status, PathContextError::Unavailable(_)));
        assert!(!status.to_string().contains("private-secret"));
        assert!(store.cached("alpha").unwrap().is_err());
    }
}
