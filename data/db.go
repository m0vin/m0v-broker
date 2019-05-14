package data

// this package opens and maintains database connections
// to postgres and provide some metrics for us

import (
	"database/sql"
	"flag"
	"fmt"
	pq "github.com/lib/pq"
	//"github.com/prometheus/client_golang/prometheus"
	//pp "golang.gurusys.co.uk/go-framework/profiling"
	"sync"
)

var (
	/*-- Database URL vs Command line parameters: --
	we are not using a DB Url here because the syntax of the url is driver/vendor specific.
	The abstraction into these variables puts the burden of generating a valid url into the code
	rather than requiring the user to know the syntax of the url of the specific driver/version/vendor
	the binary was compiled with.
	*/
	dbhost   = flag.String("dbhost", "localhost", "hostname of the postgres database rdbms")
	dbdb     = flag.String("dbdb", "", "database to use")
	dbuser   = flag.String("dbuser", "root", "username for the database to use")
	dbpw     = flag.String("dbpw", "pw", "password for the database to use")
	sqldebug = flag.Bool("sql_debug", false, "debug sql stuff")
	debug    = flag.Bool("debug", false, "debug sql stuff")
	implTime = flag.Int("impl_time", 4*60, "TEST ONLY: time in `minutes` to implmentation time. No guarantee requests will be POSTED if testPostTime is not set appropriately.")
	/*sqlTotalQueries = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sql_queries_executed",
			Help: "total number of sql queries started",
		},
		[]string{"database"},
	)
	sqlFailedQueries = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sql_queries_failed",
			Help: "total number of sql queries failed",
		},
		[]string{"database"},
	)*/
	/*
		poolSize = prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "sql_pool_size",
				Help: "how many connections are open",
			},
			[]string{"database"},
		)
	*/
	/*metricsRegistered   = false
	metricsRegisterLock sync.Mutex*/
	databases  []*DB
	opendblock sync.Mutex
)

type DB struct {
	dbcon  *sql.DB
	dbname string
	dbinfo string
}

func maxConnections() int {
	return 5
}
func maxIdle() int {
	return 4
}

// call this once when you startup and cache the result
// only if there is an error you'll need to retry
func Open() (*DB, error) {

	var err error
	var now string
	if *dbdb == "" {
		return nil, fmt.Errorf("Please specify -dbdb flag")
	}
	dbinfo := fmt.Sprintf("host=%s user=%s password=%s dbname=%s sslmode=require", *dbhost, *dbuser, *dbpw, *dbdb)

	// check if we already have an sql object that matches, if so return it
	for _, db := range databases {
		if db.dbinfo == dbinfo {
			return db, nil
		}
	}
	opendblock.Lock()
	defer opendblock.Unlock()
	// check again, with lock
	for _, db := range databases {
		if db.dbinfo == dbinfo {
			return db, nil
		}
	}

	/*if !metricsRegistered {
		metricsRegisterLock.Lock()
		if !metricsRegistered {
			prometheus.MustRegister(sqlTotalQueries, sqlFailedQueries, NewPoolSizeCollector())
			metricsRegistered = true
		}
		metricsRegisterLock.Unlock()
	}*/

	dbcon, err := sql.Open("postgres", dbinfo)
	if err != nil {
		fmt.Printf("Failed to connect to %s on host \"%s\" as \"%s\"\n", *dbdb, *dbhost, *dbuser)
		return nil, err
	}
	dbcon.SetMaxIdleConns(maxIdle())
	dbcon.SetMaxOpenConns(maxConnections()) // max connections per instance by default
	// force at least one connection to initialize
	err = dbcon.QueryRow("SELECT NOW() as now").Scan(&now)
	if err != nil {
		fmt.Printf("Failed to query db %s: %s\n", *dbdb, err)
		return nil, err
	}
	c := &DB{dbcon: dbcon, dbname: *dbdb, dbinfo: dbinfo}
	databases = append(databases, c)
	if len(databases) > 2 {
		fmt.Printf("[go-framework] WARNING OPENED %d databases\n", len(databases))
		for i, d := range databases {
			fmt.Printf("Opened database #%d: %s\n", i, d.dbinfo)
		}
		panic("too many databases")
	}
	return c, nil
}

/*****
// wrapping the calls
/**********/
func (d *DB) Query(query string, args ...interface{}) (*sql.Rows, error) {
	//pp.SqlEntered()
	//defer pp.SqlDone()
	if *sqldebug {
		fmt.Printf("[sql] Query %s\n", query)
	}
	//sqlTotalQueries.With(prometheus.Labels{"database": d.dbname}).Inc()
	r, err := d.dbcon.Query(query, args...)
	if err != nil {
		//sqlFailedQueries.With(prometheus.Labels{"database": d.dbname}).Inc()
	}
	return r, err
}
func (d *DB) Exec(query string, args ...interface{}) (sql.Result, error) {
	//pp.SqlEntered()
	//defer pp.SqlDone()
	if *sqldebug {
		fmt.Printf("[sql] Exec %s\n", query)
	}
	//sqlTotalQueries.With(prometheus.Labels{"database": d.dbname}).Inc()
	r, err := d.dbcon.Exec(query, args...)
	if err != nil {
		//sqlFailedQueries.With(prometheus.Labels{"database": d.dbname}).Inc()
	}
	return r, err
}
func (d *DB) QueryRow(query string, args ...interface{}) *sql.Row {
	//pp.SqlEntered()
	//defer pp.SqlDone()
	if *sqldebug {
		fmt.Printf("[sql] QueryRow %s\n", query)
	}
	//sqlTotalQueries.With(prometheus.Labels{"database": d.dbname}).Inc()
	return d.dbcon.QueryRow(query, args...)
}

func (d *DB) CheckDuplicateRowError(err error) bool {
	if err, ok := err.(*pq.Error); ok {
		if err.Code == "23505" {
			return true
		}
	}

	return false
}
