//! One small interface over SQLite and Postgres, shaped like the parts of
//! `rusqlite` the database code uses. SQL is written once with `?N` or `?`
//! placeholders; for Postgres they become `$N`.
//!
//! Postgres calls block the calling thread, as SQLite calls do. A
//! background runtime drives each connection, and callers wait on its
//! replies, so this works from async tasks and plain threads alike.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, OnceLock};

use bytes::BytesMut;
use tokio_postgres::types::{FromSql, IsNull, ToSql, Type, to_sql_checked};

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
pub enum Error {
    Sqlite(rusqlite::Error),
    Postgres(tokio_postgres::Error),
    NoRows,
    /// A value that does not fit the Rust type it is read into.
    Type(String),
    /// The connection broke during a transaction, or could not be made.
    Connection(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(e) => write!(f, "{e}"),
            Self::Postgres(e) => match e.as_db_error() {
                Some(db) => write!(f, "{}: {}", db.code().code(), db.message()),
                None => write!(f, "{e}"),
            },
            Self::NoRows => f.write_str("query returned no rows"),
            Self::Type(m) | Self::Connection(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for Error {}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        match e {
            rusqlite::Error::QueryReturnedNoRows => Self::NoRows,
            e => Self::Sqlite(e),
        }
    }
}

impl From<tokio_postgres::Error> for Error {
    fn from(e: tokio_postgres::Error) -> Self {
        Self::Postgres(e)
    }
}

pub trait OptionalExtension<T> {
    fn optional(self) -> Result<Option<T>>;
}

impl<T> OptionalExtension<T> for Result<T> {
    fn optional(self) -> Result<Option<T>> {
        match self {
            Ok(v) => Ok(Some(v)),
            Err(Error::NoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Int(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

impl From<i64> for Value {
    fn from(n: i64) -> Self {
        Self::Int(n)
    }
}
impl From<String> for Value {
    fn from(s: String) -> Self {
        Self::Text(s)
    }
}
impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Self::Text(s.to_owned())
    }
}

pub trait ToValue {
    fn to_value(&self) -> Value;
}

impl ToValue for Value {
    fn to_value(&self) -> Value {
        self.clone()
    }
}
impl ToValue for str {
    fn to_value(&self) -> Value {
        Value::Text(self.to_owned())
    }
}
impl ToValue for String {
    fn to_value(&self) -> Value {
        Value::Text(self.clone())
    }
}
impl ToValue for [u8] {
    fn to_value(&self) -> Value {
        Value::Blob(self.to_vec())
    }
}
impl ToValue for Vec<u8> {
    fn to_value(&self) -> Value {
        Value::Blob(self.clone())
    }
}
impl ToValue for f64 {
    fn to_value(&self) -> Value {
        Value::Real(*self)
    }
}
impl ToValue for bool {
    fn to_value(&self) -> Value {
        Value::Int(i64::from(*self))
    }
}
macro_rules! int_to_value {
    ($($t:ty),*) => {$(
        impl ToValue for $t {
            fn to_value(&self) -> Value {
                Value::Int(i64::try_from(*self).unwrap_or(i64::MAX))
            }
        }
    )*};
}
int_to_value!(i64, i32, u32, u64, usize);
impl<T: ToValue> ToValue for Option<T> {
    fn to_value(&self) -> Value {
        self.as_ref().map_or(Value::Null, ToValue::to_value)
    }
}
impl<T: ToValue + ?Sized> ToValue for &T {
    fn to_value(&self) -> Value {
        (**self).to_value()
    }
}

pub trait Params {
    fn values(self) -> Vec<Value>;
}

impl Params for () {
    fn values(self) -> Vec<Value> {
        Vec::new()
    }
}
impl Params for &[&dyn ToValue] {
    fn values(self) -> Vec<Value> {
        self.iter().map(|v| v.to_value()).collect()
    }
}
impl<T: ToValue, const N: usize> Params for [T; N] {
    fn values(self) -> Vec<Value> {
        self.iter().map(ToValue::to_value).collect()
    }
}

pub struct ParamsFromIter(Vec<Value>);

impl Params for ParamsFromIter {
    fn values(self) -> Vec<Value> {
        self.0
    }
}

pub fn params_from_iter(values: impl IntoIterator<Item = Value>) -> ParamsFromIter {
    ParamsFromIter(values.into_iter().collect())
}

#[macro_export]
macro_rules! sql_params {
    () => { &[] as &[&dyn $crate::db::sql::ToValue] };
    ($($p:expr),+ $(,)?) => {
        &[$(&$p as &dyn $crate::db::sql::ToValue),+] as &[&dyn $crate::db::sql::ToValue]
    };
}
pub use crate::sql_params as params;

pub trait FromValue: Sized {
    fn from_value(value: &Value) -> Result<Self>;
}

fn mismatch<T>(value: &Value) -> Error {
    Error::Type(format!(
        "cannot read {value:?} as {}",
        std::any::type_name::<T>()
    ))
}

impl FromValue for Value {
    fn from_value(value: &Value) -> Result<Self> {
        Ok(value.clone())
    }
}
impl FromValue for i64 {
    fn from_value(value: &Value) -> Result<Self> {
        match value {
            Value::Int(n) => Ok(*n),
            v => Err(mismatch::<Self>(v)),
        }
    }
}
macro_rules! int_from_value {
    ($($t:ty),*) => {$(
        impl FromValue for $t {
            fn from_value(value: &Value) -> Result<Self> {
                <$t>::try_from(i64::from_value(value)?).map_err(|_| mismatch::<Self>(value))
            }
        }
    )*};
}
int_from_value!(i32, u32, u64, usize);
impl FromValue for f64 {
    fn from_value(value: &Value) -> Result<Self> {
        match value {
            Value::Real(f) => Ok(*f),
            #[expect(clippy::cast_precision_loss, reason = "usage totals")]
            Value::Int(n) => Ok(*n as f64),
            v => Err(mismatch::<Self>(v)),
        }
    }
}
impl FromValue for bool {
    fn from_value(value: &Value) -> Result<Self> {
        Ok(i64::from_value(value)? != 0)
    }
}
impl FromValue for String {
    fn from_value(value: &Value) -> Result<Self> {
        match value {
            Value::Text(s) => Ok(s.clone()),
            v => Err(mismatch::<Self>(v)),
        }
    }
}
impl FromValue for Vec<u8> {
    fn from_value(value: &Value) -> Result<Self> {
        match value {
            Value::Blob(b) => Ok(b.clone()),
            v => Err(mismatch::<Self>(v)),
        }
    }
}
impl<T: FromValue> FromValue for Option<T> {
    fn from_value(value: &Value) -> Result<Self> {
        match value {
            Value::Null => Ok(None),
            v => T::from_value(v).map(Some),
        }
    }
}

pub trait RowIndex {
    fn index(self) -> usize;
}
impl RowIndex for usize {
    fn index(self) -> usize {
        self
    }
}

/// One result row, already read.
pub struct Row(Vec<Value>);

impl Row {
    pub fn get<I: RowIndex, T: FromValue>(&self, idx: I) -> Result<T> {
        let i = idx.index();
        let value = self
            .0
            .get(i)
            .ok_or_else(|| Error::Type(format!("no column {i}")))?;
        T::from_value(value)
    }
}

pub struct Rows {
    rows: std::vec::IntoIter<Row>,
    current: Option<Row>,
}

impl Rows {
    pub fn next(&mut self) -> Result<Option<&Row>> {
        self.current = self.rows.next();
        Ok(self.current.as_ref())
    }
}

pub enum Conn {
    Sqlite(rusqlite::Connection),
    Postgres(Pg),
}

impl Conn {
    pub fn is_postgres(&self) -> bool {
        matches!(self, Self::Postgres(_))
    }

    pub fn execute(&self, sql: &str, params: impl Params) -> Result<usize> {
        let values = params.values();
        match self {
            Self::Sqlite(c) => Ok(c
                .prepare_cached(sql)?
                .execute(rusqlite::params_from_iter(values.iter()))?),
            Self::Postgres(pg) => pg.execute(sql, &values),
        }
    }

    pub fn query_all(&self, sql: &str, params: impl Params) -> Result<Vec<Row>> {
        let values = params.values();
        match self {
            Self::Sqlite(c) => {
                let mut stmt = c.prepare_cached(sql)?;
                let columns = stmt.column_count();
                let mut rows = stmt.query(rusqlite::params_from_iter(values.iter()))?;
                let mut out = Vec::new();
                while let Some(row) = rows.next()? {
                    let mut cells = Vec::with_capacity(columns);
                    for i in 0..columns {
                        cells.push(from_sqlite(row.get_ref(i)?));
                    }
                    out.push(Row(cells));
                }
                Ok(out)
            }
            Self::Postgres(pg) => pg.query(sql, &values),
        }
    }

    pub fn query_row<T>(
        &self,
        sql: &str,
        params: impl Params,
        f: impl FnOnce(&Row) -> Result<T>,
    ) -> Result<T> {
        let rows = self.query_all(sql, params)?;
        rows.first().map_or(Err(Error::NoRows), f)
    }

    pub fn prepare(&self, sql: &str) -> Result<Statement<'_>> {
        Ok(Statement {
            conn: self,
            sql: sql.to_owned(),
        })
    }

    pub fn prepare_cached(&self, sql: &str) -> Result<Statement<'_>> {
        self.prepare(sql)
    }

    /// Runs statements separated by `;`, without parameters.
    pub fn execute_batch(&self, sql: &str) -> Result<()> {
        match self {
            Self::Sqlite(c) => Ok(c.execute_batch(sql)?),
            Self::Postgres(pg) => pg.batch(sql),
        }
    }

    pub fn transaction(&mut self) -> Result<Transaction<'_>> {
        match self {
            Self::Sqlite(c) => c.execute_batch("BEGIN")?,
            Self::Postgres(pg) => pg.begin()?,
        }
        Ok(Transaction {
            conn: self,
            done: false,
        })
    }
}

pub(super) fn from_sqlite(v: rusqlite::types::ValueRef<'_>) -> Value {
    use rusqlite::types::ValueRef;
    match v {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(n) => Value::Int(n),
        ValueRef::Real(f) => Value::Real(f),
        ValueRef::Text(t) => Value::Text(String::from_utf8_lossy(t).into_owned()),
        ValueRef::Blob(b) => Value::Blob(b.to_vec()),
    }
}

impl rusqlite::ToSql for Value {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        use rusqlite::types::{ToSqlOutput, ValueRef};
        Ok(ToSqlOutput::Borrowed(match self {
            Self::Null => ValueRef::Null,
            Self::Int(n) => ValueRef::Integer(*n),
            Self::Real(f) => ValueRef::Real(*f),
            Self::Text(s) => ValueRef::Text(s.as_bytes()),
            Self::Blob(b) => ValueRef::Blob(b),
        }))
    }
}

pub struct Statement<'c> {
    conn: &'c Conn,
    sql: String,
}

impl Statement<'_> {
    pub fn execute(&mut self, params: impl Params) -> Result<usize> {
        self.conn.execute(&self.sql, params)
    }

    pub fn query_map<T>(
        &mut self,
        params: impl Params,
        mut f: impl FnMut(&Row) -> Result<T>,
    ) -> Result<std::vec::IntoIter<Result<T>>> {
        let rows = self.conn.query_all(&self.sql, params)?;
        Ok(rows.iter().map(&mut f).collect::<Vec<_>>().into_iter())
    }

    pub fn query(&mut self, params: impl Params) -> Result<Rows> {
        Ok(Rows {
            rows: self.conn.query_all(&self.sql, params)?.into_iter(),
            current: None,
        })
    }

    pub fn exists(&mut self, params: impl Params) -> Result<bool> {
        Ok(!self.conn.query_all(&self.sql, params)?.is_empty())
    }
}

/// Rolls back when dropped without `commit`.
pub struct Transaction<'c> {
    conn: &'c mut Conn,
    done: bool,
}

impl Transaction<'_> {
    pub fn commit(mut self) -> Result<()> {
        self.done = true;
        match &*self.conn {
            Conn::Sqlite(c) => Ok(c.execute_batch("COMMIT")?),
            Conn::Postgres(pg) => pg.end("COMMIT"),
        }
    }
}

impl std::ops::Deref for Transaction<'_> {
    type Target = Conn;
    fn deref(&self) -> &Conn {
        self.conn
    }
}

impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        if !self.done {
            let _ = match &*self.conn {
                Conn::Sqlite(c) => c.execute_batch("ROLLBACK").map_err(Error::from),
                Conn::Postgres(pg) => pg.end("ROLLBACK"),
            };
        }
    }
}

/// Drives every Postgres connection of the process.
fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("spawnbox-postgres")
            .enable_all()
            .build()
            .expect("start the Postgres runtime")
    })
}

/// How to reach Postgres: a `postgres://` URL, and TLS.
#[derive(Clone)]
pub struct PgTarget {
    pub url: String,
    pub tls: Arc<rustls::ClientConfig>,
}

impl fmt::Debug for PgTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PgTarget").finish_non_exhaustive()
    }
}

impl PgTarget {
    /// With `ca_pem`, the server must show a certificate from it. Without,
    /// traffic is encrypted when the server offers TLS, and any certificate
    /// is accepted, as libpq's `sslmode=require` does.
    pub fn new(url: &str, ca_pem: Option<&[u8]>) -> anyhow::Result<Self> {
        use rustls::pki_types::CertificateDer;
        use rustls::pki_types::pem::PemObject;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()?;
        let tls = match ca_pem {
            Some(pem) => {
                let mut roots = rustls::RootCertStore::empty();
                for cert in CertificateDer::pem_slice_iter(pem) {
                    roots.add(cert?)?;
                }
                anyhow::ensure!(
                    !roots.is_empty(),
                    "the database CA file has no certificates"
                );
                builder.with_root_certificates(roots).with_no_client_auth()
            }
            None => builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AnyCert(provider)))
                .with_no_client_auth(),
        };
        Ok(Self {
            url: url.to_owned(),
            tls: Arc::new(tls),
        })
    }
}

#[derive(Debug)]
struct AnyCert(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Opens a connection and returns its client. The connection runs on the
/// background runtime until the client is dropped or the server hangs up.
pub fn pg_connect(target: &PgTarget) -> Result<tokio_postgres::Client> {
    let (tx, rx) = std::sync::mpsc::channel();
    let url = target.url.clone();
    let tls = tokio_postgres_rustls::MakeRustlsConnect::new((*target.tls).clone());
    runtime().spawn(async move {
        let connect = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            tokio_postgres::connect(&url, tls),
        );
        match connect.await {
            Ok(Ok((client, connection))) => {
                let _ = tx.send(Ok(client));
                if let Err(error) = connection.await {
                    eprintln!("postgres connection closed: {error}");
                }
            }
            Ok(Err(error)) => {
                let _ = tx.send(Err(Error::Postgres(error)));
            }
            Err(_) => {
                let _ = tx.send(Err(Error::Connection(
                    "connecting to Postgres timed out".into(),
                )));
            }
        }
    });
    rx.recv()
        .map_err(|_| Error::Connection("the Postgres runtime stopped".into()))?
}

/// Waits for a client call. Its future only talks to the connection task,
/// so it needs no runtime of its own.
pub fn wait<F: std::future::Future>(f: F) -> F::Output {
    futures_executor::block_on(f)
}

/// One Postgres connection, made again if it breaks between transactions.
pub struct Pg {
    target: PgTarget,
    client: RefCell<Option<tokio_postgres::Client>>,
    statements: RefCell<HashMap<String, tokio_postgres::Statement>>,
    in_tx: Cell<bool>,
}

impl Pg {
    pub fn connect(target: PgTarget) -> Result<Self> {
        let client = pg_connect(&target)?;
        Ok(Self {
            target,
            client: RefCell::new(Some(client)),
            statements: RefCell::default(),
            in_tx: Cell::new(false),
        })
    }

    fn with_client<T>(&self, f: impl FnOnce(&tokio_postgres::Client) -> Result<T>) -> Result<T> {
        let broken = self
            .client
            .borrow()
            .as_ref()
            .is_none_or(tokio_postgres::Client::is_closed);
        if broken {
            if self.in_tx.get() {
                return Err(Error::Connection(
                    "the Postgres connection broke during a transaction".into(),
                ));
            }
            self.statements.borrow_mut().clear();
            *self.client.borrow_mut() = None;
            *self.client.borrow_mut() = Some(pg_connect(&self.target)?);
        }
        let client = self.client.borrow();
        f(client.as_ref().expect("connected above"))
    }

    fn statement(
        &self,
        client: &tokio_postgres::Client,
        sql: &str,
    ) -> Result<tokio_postgres::Statement> {
        if let Some(s) = self.statements.borrow().get(sql) {
            return Ok(s.clone());
        }
        let s = wait(client.prepare(&numbered(sql)))?;
        self.statements
            .borrow_mut()
            .insert(sql.to_owned(), s.clone());
        Ok(s)
    }

    fn execute(&self, sql: &str, values: &[Value]) -> Result<usize> {
        self.with_client(|client| {
            let stmt = self.statement(client, sql)?;
            let args: Vec<&(dyn ToSql + Sync)> = values.iter().map(|v| v as _).collect();
            let n = wait(client.execute(&stmt, &args))?;
            Ok(usize::try_from(n).unwrap_or(usize::MAX))
        })
    }

    fn query(&self, sql: &str, values: &[Value]) -> Result<Vec<Row>> {
        self.with_client(|client| {
            let stmt = self.statement(client, sql)?;
            let args: Vec<&(dyn ToSql + Sync)> = values.iter().map(|v| v as _).collect();
            let rows = wait(client.query(&stmt, &args))?;
            rows.iter()
                .map(|row| {
                    (0..row.len())
                        .map(|i| row.try_get::<_, Value>(i).map_err(Error::from))
                        .collect::<Result<Vec<_>>>()
                        .map(Row)
                })
                .collect()
        })
    }

    fn batch(&self, sql: &str) -> Result<()> {
        self.with_client(|client| Ok(wait(client.batch_execute(sql))?))
    }

    fn begin(&self) -> Result<()> {
        self.batch("BEGIN")?;
        self.in_tx.set(true);
        Ok(())
    }

    fn end(&self, how: &str) -> Result<()> {
        let result = self.batch(how);
        self.in_tx.set(false);
        result
    }
}

/// `?N` becomes `$N`, and each bare `?` the next number, outside quotes.
fn numbered(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len() + 8);
    let mut next = 0;
    let mut quoted = false;
    let mut chars = sql.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\'' {
            quoted = !quoted;
        }
        if c != '?' || quoted {
            out.push(c);
            continue;
        }
        out.push('$');
        if chars.peek().is_some_and(char::is_ascii_digit) {
            while let Some(d) = chars.next_if(char::is_ascii_digit) {
                out.push(d);
            }
        } else {
            next += 1;
            out.push_str(&next.to_string());
        }
    }
    out
}

type BoxError = Box<dyn std::error::Error + Sync + Send>;

impl ToSql for Value {
    /// Encodes for the type Postgres inferred for the parameter.
    fn to_sql(&self, ty: &Type, out: &mut BytesMut) -> Result<IsNull, BoxError> {
        match self {
            Self::Null => Ok(IsNull::Yes),
            Self::Int(n) => match *ty {
                Type::INT8 => n.to_sql(ty, out),
                Type::INT4 => i32::try_from(*n)?.to_sql(ty, out),
                Type::INT2 => i16::try_from(*n)?.to_sql(ty, out),
                Type::BOOL => (*n != 0).to_sql(ty, out),
                #[expect(clippy::cast_precision_loss, reason = "as SQLite would")]
                Type::FLOAT8 => (*n as f64).to_sql(ty, out),
                Type::TEXT | Type::VARCHAR => n.to_string().to_sql(ty, out),
                _ => Err(format!("cannot send an integer as {ty}").into()),
            },
            Self::Real(f) => match *ty {
                Type::FLOAT8 => f.to_sql(ty, out),
                #[expect(clippy::cast_possible_truncation, reason = "as the column is")]
                Type::FLOAT4 => (*f as f32).to_sql(ty, out),
                _ => Err(format!("cannot send a float as {ty}").into()),
            },
            Self::Text(s) => s.as_str().to_sql(ty, out),
            Self::Blob(b) => b.as_slice().to_sql(ty, out),
        }
    }

    fn accepts(_: &Type) -> bool {
        true
    }

    to_sql_checked!();
}

impl<'a> FromSql<'a> for Value {
    fn from_sql(ty: &Type, raw: &'a [u8]) -> Result<Self, BoxError> {
        Ok(match *ty {
            Type::INT2 => Self::Int(i16::from_sql(ty, raw)?.into()),
            Type::INT4 => Self::Int(i32::from_sql(ty, raw)?.into()),
            Type::INT8 => Self::Int(i64::from_sql(ty, raw)?),
            Type::BOOL => Self::Int(bool::from_sql(ty, raw)?.into()),
            Type::FLOAT4 => Self::Real(f32::from_sql(ty, raw)?.into()),
            Type::FLOAT8 => Self::Real(f64::from_sql(ty, raw)?),
            Type::NUMERIC => numeric(raw)?,
            Type::BYTEA => Self::Blob(raw.to_vec()),
            _ => Self::Text(<&str>::from_sql(ty, raw)?.to_owned()),
        })
    }

    fn from_sql_null(_: &Type) -> Result<Self, BoxError> {
        Ok(Self::Null)
    }

    fn accepts(_: &Type) -> bool {
        true
    }
}

/// Reads Postgres's binary `numeric`, which `SUM` of integers returns.
fn numeric(raw: &[u8]) -> Result<Value, BoxError> {
    let word = |i: usize| -> Result<u16, BoxError> {
        let b = raw.get(i * 2..i * 2 + 2).ok_or("short numeric")?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    };
    let digits = usize::from(word(0)?);
    let weight = i32::from(word(1)?.cast_signed());
    let sign = word(2)?;
    let scale = word(3)?;
    if sign == 0xC000 {
        return Err("NaN numeric".into());
    }
    let mut value = 0f64;
    for i in 0..digits {
        let exp = weight - i32::try_from(i)?;
        value += f64::from(word(4 + i)?) * 10_000f64.powi(exp);
    }
    if sign == 0x4000 {
        value = -value;
    }
    #[expect(clippy::cast_possible_truncation, reason = "checked to be integral")]
    if scale == 0 && value.abs() < 9.0e15 {
        return Ok(Value::Int(value as i64));
    }
    Ok(Value::Real(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholders_are_numbered_outside_quotes() {
        assert_eq!(
            numbered("SELECT '?', ?2 FROM t WHERE a = ?11"),
            "SELECT '?', $2 FROM t WHERE a = $11"
        );
        assert_eq!(numbered("a = ? AND b = ?"), "a = $1 AND b = $2");
    }

    #[test]
    fn reads_numeric() {
        // 123456789 is 1 2345 6789 in base 10000, weight 2.
        let raw = [0, 3, 0, 2, 0, 0, 0, 0, 0, 1, 0x09, 0x29, 0x1a, 0x85];
        assert_eq!(numeric(&raw).unwrap(), Value::Int(123_456_789));
        let zero = [0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(numeric(&zero).unwrap(), Value::Int(0));
    }
}
