package store

import (
	"embed"
	"fmt"
	"github.com/go-sql-driver/mysql"
	"io/fs"
	"log"
	"net"
	"net/url"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/pkg/errors"
	migrate "github.com/rubenv/sql-migrate"
	"github.com/tkandal/cashier/server/config"
)

const (
	postgres    = "postgres"
	defaultPort = ":5432"
)

var (
	_                     CertStorer = (*sqlStore)(nil)
	ErrDriverNotSupported            = errors.New("sqlStore: driver is not supported")
)

//go:embed migrations
var migrationFS embed.FS

// sqlStore is a sql-based CertStorer
type sqlStore struct {
	conn *sqlx.DB

	get         *sqlx.Stmt
	set         *sqlx.Stmt
	listAll     *sqlx.Stmt
	listCurrent *sqlx.Stmt
	revoked     *sqlx.Stmt
	driver      string
}

// newSQLStore returns a *sql.DB CertStorer.
func newSQLStore(c config.Database) (*sqlStore, error) {
	var driver string
	var dsn string
	switch c["type"] {
	case "mysql":
		driver = "mysql"
		address := c["address"]
		_, _, err := net.SplitHostPort(address)
		if err != nil {
			address = address + ":3306"
		}
		m := mysql.NewConfig()
		m.User = c["username"]
		m.Passwd = c["password"]
		m.Addr = address
		m.Net = "tcp"
		m.DBName = c["dbname"]
		if m.DBName == "" {
			m.DBName = "certs" // Legacy database name
		}
		m.ParseTime = true
		dsn = m.FormatDSN()
	case "sqlite":
		driver = "sqlite3"
		dsn = c["filename"]
	case postgres:
		driver = postgres
		address := c["address"]
		_, _, err := net.SplitHostPort(address)
		if err != nil {
			address = address + defaultPort
		}
		pgURL := url.URL{
			Scheme: driver,
			User:   url.UserPassword(c["username"], c["password"]),
			Host:   address,
			Path:   c["dbname"],
		}
		q := pgURL.Query()
		q.Add("sslmode", "disable")
		q.Add("connect_timeout", "20")
		pgURL.RawQuery = q.Encode()
		dsn = pgURL.String()
	default:
		return nil, ErrDriverNotSupported
	}

	conn, err := sqlx.Connect(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlStore: could not get a connection: %v", err)
	}
	if err := autoMigrate(driver, conn); err != nil {
		return nil, fmt.Errorf("sqlStore: could not update schema: %v", err)
	}

	db := &sqlStore{
		conn:   conn,
		driver: driver,
	}

	switch driver {
	case postgres:
		db.set, err = conn.Preparex("INSERT INTO issued_certs (key_id, principals, created_at, expires_at, raw_key, message) VALUES ($1, $2, $3, $4, $5, $6)")
	case "mysql", "sqlite":
		db.set, err = conn.Preparex("INSERT INTO issued_certs (key_id, principals, created_at, expires_at, raw_key, message) VALUES (?, ?, ?, ?, ?, ?)")
	default:
		db.set, err = conn.Preparex("INSERT INTO issued_certs (key_id, principals, created_at, expires_at, raw_key, message) VALUES (?, ?, ?, ?, ?, ?)")
	}
	if err != nil {
		return nil, fmt.Errorf("sqlStore: prepare set: %v", err)
	}

	switch driver {
	case postgres:
		db.get, err = conn.Preparex("SELECT key_id, principals, created_at, expires_at, raw_key, message FROM issued_certs WHERE key_id = $1")
	case "mysql", "sqlite":
		db.get, err = conn.Preparex("SELECT key_id, principals, created_at, expires_at, raw_key, message FROM issued_certs WHERE key_id = ?")
	default:
		db.get, err = conn.Preparex("SELECT key_id, principals, created_at, expires_at, raw_key, message FROM issued_certs WHERE key_id = ?")
	}
	if err != nil {
		return nil, fmt.Errorf("sqlStore: prepare get: %v", err)
	}

	if db.listAll, err = conn.Preparex("SELECT key_id, principals, created_at, expires_at, raw_key, message FROM issued_certs"); err != nil {
		return nil, fmt.Errorf("sqlStore: prepare listAll: %v", err)
	}

	switch driver {
	case postgres:
		db.listCurrent, err = conn.Preparex("SELECT key_id, principals, created_at, expires_at, raw_key, message FROM issued_certs WHERE expires_at >= $1")
	case "mysql", "sqlite":
		db.listCurrent, err = conn.Preparex("SELECT key_id, principals, created_at, expires_at, raw_key, message FROM issued_certs WHERE expires_at >= ?")
	default:
		db.listCurrent, err = conn.Preparex("SELECT key_id, principals, created_at, expires_at, raw_key, message FROM issued_certs WHERE expires_at >= ?")
	}
	if err != nil {
		return nil, fmt.Errorf("sqlStore: prepare listCurrent: %v", err)
	}

	switch driver {
	case postgres:
		db.revoked, err = conn.Preparex("SELECT key_id, principals, created_at, expires_at, raw_key, message FROM issued_certs WHERE revoked = true AND $1 <= expires_at")
	case "mysql", "sqlite":
		db.revoked, err = conn.Preparex("SELECT key_id, principals, created_at, expires_at, raw_key, message FROM issued_certs WHERE revoked = 1 AND ? <= expires_at")
	default:
		db.revoked, err = conn.Preparex("SELECT key_id, principals, created_at, expires_at, raw_key, message FROM issued_certs WHERE revoked = 1 AND ? <= expires_at")
	}
	if err != nil {
		return nil, fmt.Errorf("sqlStore: prepare revoked: %v", err)
	}

	return db, nil
}

func autoMigrate(driver string, conn *sqlx.DB) error {
	_ = fs.WalkDir(migrationFS, ".", func(path string, d fs.DirEntry, err error) error {
		fmt.Println(path)
		return nil
	})
	log.Print("Executing any pending schema migrations")
	var err error
	migrate.SetTable("schema_migrations")
	srcs := &migrate.EmbedFileSystemMigrationSource{
		FileSystem: migrationFS,
		Root:       "migrations/" + driver,
	}
	n, err := migrate.Exec(conn.DB, driver, srcs, migrate.Up)
	if err != nil {
		err = multierror.Append(err)
		return err
	}
	log.Printf("Executed %d migrations", n)
	if err != nil {
		log.Fatalf("Errors were found running migrations: %v", err)
	}
	return nil
}

// Get a single *CertRecord
func (db *sqlStore) Get(id string) (*CertRecord, error) {
	if err := db.conn.Ping(); err != nil {
		return nil, errors.Wrap(err, "unable to connect to database")
	}
	r := &CertRecord{}
	return r, db.get.Get(r, id)
}

// SetRecord records a *CertRecord
func (db *sqlStore) SetRecord(rec *CertRecord) error {
	if err := db.conn.Ping(); err != nil {
		return errors.Wrap(err, "unable to connect to database")
	}
	_, err := db.set.Exec(rec.KeyID, rec.Principals, rec.CreatedAt, rec.Expires, rec.Raw, rec.Message)
	return err
}

// List returns all recorded certs.
// Default only active certs are returned.
func (db *sqlStore) List(includeExpired bool) ([]*CertRecord, error) {
	if err := db.conn.Ping(); err != nil {
		return nil, errors.Wrap(err, "unable to connect to database")
	}
	recs := make([]*CertRecord, 0)
	if includeExpired {
		if err := db.listAll.Select(&recs); err != nil {
			return nil, err
		}
	} else {
		if err := db.listCurrent.Select(&recs, time.Now()); err != nil {
			return nil, err
		}
	}
	return recs, nil
}

// Revoke an issued cert by id.
func (db *sqlStore) Revoke(ids []string) error {
	var err error
	if err = db.conn.Ping(); err != nil {
		return errors.Wrap(err, "unable to connect to database")
	}
	var q string
	var args []interface{}

	switch db.driver {
	case postgres:
		q = "UPDATE issued_certs SET revoked = true WHERE key_id = $1"
		for _, id := range ids {
			_, err = db.conn.Exec(q, id)
			if err != nil {
				return err
			}
		}
		return nil
	case "mysql", "sqlite":
		q, args, err = sqlx.In("UPDATE issued_certs SET revoked = 1 WHERE key_id IN (?)", ids)
	default:
		q, args, err = sqlx.In("UPDATE issued_certs SET revoked = 1 WHERE key_id IN (?)", ids)
	}
	if err != nil {
		return err
	}
	q = db.conn.Rebind(q)
	_, err = db.conn.Exec(q, args...)
	return err
}

// GetRevoked returns all revoked certs
func (db *sqlStore) GetRevoked() ([]*CertRecord, error) {
	if err := db.conn.Ping(); err != nil {
		return nil, errors.Wrap(err, "unable to connect to database")
	}
	var recs []*CertRecord
	if err := db.revoked.Select(&recs, time.Now().UTC()); err != nil {
		return nil, err
	}
	return recs, nil
}

// Close the connection to the database
func (db *sqlStore) Close() error {
	return db.conn.Close()
}
