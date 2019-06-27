package newrelic

// DatastoreProduct is used to identify your datastore type in New Relic.  It
// is used in the DatastoreSegment Product field.  See
// https://github.com/newrelic/go-agent/blob/master/datastore.go for the full
// list of available DatastoreProducts.
type DatastoreProduct string

// Datastore names used across New Relic agents:
const (
	DatastoreCassandra     DatastoreProduct = "Cassandra"
	DatastoreDerby                          = "Derby"
	DatastoreElasticsearch                  = "Elasticsearch"
	DatastoreFirebird                       = "Firebird"
	DatastoreIBMDB2                         = "IBMDB2"
	DatastoreInformix                       = "Informix"
	DatastoreMemcached                      = "Memcached"
	DatastoreMongoDB                        = "MongoDB"
	DatastoreMySQL                          = "MySQL"
	DatastoreMSSQL                          = "MSSQL"
	DatastoreNeptune                        = "Neptune"
	DatastoreOracle                         = "Oracle"
	DatastorePostgres                       = "Postgres"
	DatastoreRedis                          = "Redis"
	DatastoreSolr                           = "Solr"
	DatastoreSQLite                         = "SQLite"
	DatastoreCouchDB                        = "CouchDB"
	DatastoreRiak                           = "Riak"
	DatastoreVoltDB                         = "VoltDB"
	DatastoreDynamoDB                       = "DynamoDB"
)
