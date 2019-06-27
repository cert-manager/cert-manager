// +build go1.10

package newrelic

import (
	"context"
	"database/sql/driver"
)

// SQLDriverSegmentBuilder populates DatastoreSegments for sql.Driver
// instrumentation.  Use this to instrument a database that is not supported by
// an existing integration package (nrmysql, nrpq, and nrsqlite3). See
// https://github.com/newrelic/go-agent/blob/master/_integrations/nrmysql/nrmysql.go
// for example use.
type SQLDriverSegmentBuilder struct {
	BaseSegment DatastoreSegment
	ParseQuery  func(segment *DatastoreSegment, query string)
	ParseDSN    func(segment *DatastoreSegment, dataSourceName string)
}

// InstrumentSQLDriver wraps a driver.Driver, adding instrumentation for exec
// and query calls made with a transaction-containing context.  Use this to
// instrument a database driver that is not supported by an existing integration
// package (nrmysql, nrpq, and nrsqlite3). See
// https://github.com/newrelic/go-agent/blob/master/_integrations/nrmysql/nrmysql.go
// for example use.
func InstrumentSQLDriver(d driver.Driver, bld SQLDriverSegmentBuilder) driver.Driver {
	return optionalMethodsDriver(&wrapDriver{bld: bld, original: d})
}

// InstrumentSQLConnector wraps a driver.Connector, adding instrumentation for
// exec and query calls made with a transaction-containing context.  Use this to
// instrument a database connector that is not supported by an existing
// integration package (nrmysql, nrpq, and nrsqlite3). See
// https://github.com/newrelic/go-agent/blob/master/_integrations/nrmysql/nrmysql.go
// for example use.
func InstrumentSQLConnector(connector driver.Connector, bld SQLDriverSegmentBuilder) driver.Connector {
	return &wrapConnector{original: connector, bld: bld}
}

func (bld SQLDriverSegmentBuilder) useDSN(dsn string) SQLDriverSegmentBuilder {
	if f := bld.ParseDSN; nil != f {
		f(&bld.BaseSegment, dsn)
	}
	return bld
}

func (bld SQLDriverSegmentBuilder) useQuery(query string) SQLDriverSegmentBuilder {
	if f := bld.ParseQuery; nil != f {
		f(&bld.BaseSegment, query)
	}
	return bld
}

func (bld SQLDriverSegmentBuilder) startSegment(ctx context.Context) DatastoreSegment {
	segment := bld.BaseSegment
	segment.StartTime = StartSegmentNow(FromContext(ctx))
	return segment
}

type wrapDriver struct {
	bld      SQLDriverSegmentBuilder
	original driver.Driver
}

type wrapConnector struct {
	bld      SQLDriverSegmentBuilder
	original driver.Connector
}

type wrapConn struct {
	bld      SQLDriverSegmentBuilder
	original driver.Conn
}

type wrapStmt struct {
	bld      SQLDriverSegmentBuilder
	original driver.Stmt
}

func (w *wrapDriver) Open(name string) (driver.Conn, error) {
	original, err := w.original.Open(name)
	if err != nil {
		return nil, err
	}
	return optionalMethodsConn(&wrapConn{
		original: original,
		bld:      w.bld.useDSN(name),
	}), nil
}

// OpenConnector implements DriverContext.
func (w *wrapDriver) OpenConnector(name string) (driver.Connector, error) {
	original, err := w.original.(driver.DriverContext).OpenConnector(name)
	if err != nil {
		return nil, err
	}
	return &wrapConnector{
		original: original,
		bld:      w.bld.useDSN(name),
	}, nil
}

func (w *wrapConnector) Connect(ctx context.Context) (driver.Conn, error) {
	original, err := w.original.Connect(ctx)
	if nil != err {
		return nil, err
	}
	return optionalMethodsConn(&wrapConn{
		bld:      w.bld,
		original: original,
	}), nil
}

func (w *wrapConnector) Driver() driver.Driver {
	return optionalMethodsDriver(&wrapDriver{
		bld:      w.bld,
		original: w.original.Driver(),
	})
}

func prepare(original driver.Stmt, err error, bld SQLDriverSegmentBuilder, query string) (driver.Stmt, error) {
	if nil != err {
		return nil, err
	}
	return optionalMethodsStmt(&wrapStmt{
		bld:      bld.useQuery(query),
		original: original,
	}), nil
}

func (w *wrapConn) Prepare(query string) (driver.Stmt, error) {
	original, err := w.original.Prepare(query)
	return prepare(original, err, w.bld, query)
}

// PrepareContext implements ConnPrepareContext.
func (w *wrapConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	original, err := w.original.(driver.ConnPrepareContext).PrepareContext(ctx, query)
	return prepare(original, err, w.bld, query)
}

func (w *wrapConn) Close() error {
	return w.original.Close()
}

func (w *wrapConn) Begin() (driver.Tx, error) {
	return w.original.Begin()
}

// BeginTx implements ConnBeginTx.
func (w *wrapConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	return w.original.(driver.ConnBeginTx).BeginTx(ctx, opts)
}

// Exec implements Execer.
func (w *wrapConn) Exec(query string, args []driver.Value) (driver.Result, error) {
	return w.original.(driver.Execer).Exec(query, args)
}

// ExecContext implements ExecerContext.
func (w *wrapConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	segment := w.bld.useQuery(query).startSegment(ctx)
	result, err := w.original.(driver.ExecerContext).ExecContext(ctx, query, args)
	if err != driver.ErrSkip {
		segment.End()
	}
	return result, err
}

// CheckNamedValue implements NamedValueChecker.
func (w *wrapConn) CheckNamedValue(v *driver.NamedValue) error {
	return w.original.(driver.NamedValueChecker).CheckNamedValue(v)
}

// Ping implements Pinger.
func (w *wrapConn) Ping(ctx context.Context) error {
	return w.original.(driver.Pinger).Ping(ctx)
}

func (w *wrapConn) Query(query string, args []driver.Value) (driver.Rows, error) {
	return w.original.(driver.Queryer).Query(query, args)
}

// QueryContext implements QueryerContext.
func (w *wrapConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	segment := w.bld.useQuery(query).startSegment(ctx)
	rows, err := w.original.(driver.QueryerContext).QueryContext(ctx, query, args)
	if err != driver.ErrSkip {
		segment.End()
	}
	return rows, err
}

// ResetSession implements SessionResetter.
func (w *wrapConn) ResetSession(ctx context.Context) error {
	return w.original.(driver.SessionResetter).ResetSession(ctx)
}

func (w *wrapStmt) Close() error {
	return w.original.Close()
}

func (w *wrapStmt) NumInput() int {
	return w.original.NumInput()
}

func (w *wrapStmt) Exec(args []driver.Value) (driver.Result, error) {
	return w.original.Exec(args)
}

func (w *wrapStmt) Query(args []driver.Value) (driver.Rows, error) {
	return w.original.Query(args)
}

// ColumnConverter implements ColumnConverter.
func (w *wrapStmt) ColumnConverter(idx int) driver.ValueConverter {
	return w.original.(driver.ColumnConverter).ColumnConverter(idx)
}

// CheckNamedValue implements NamedValueChecker.
func (w *wrapStmt) CheckNamedValue(v *driver.NamedValue) error {
	return w.original.(driver.NamedValueChecker).CheckNamedValue(v)
}

// ExecContext implements StmtExecContext.
func (w *wrapStmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	segment := w.bld.startSegment(ctx)
	result, err := w.original.(driver.StmtExecContext).ExecContext(ctx, args)
	segment.End()
	return result, err
}

// QueryContext implements StmtQueryContext.
func (w *wrapStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	segment := w.bld.startSegment(ctx)
	rows, err := w.original.(driver.StmtQueryContext).QueryContext(ctx, args)
	segment.End()
	return rows, err
}

var (
	_ interface {
		driver.Driver
		driver.DriverContext
	} = &wrapDriver{}
	_ interface {
		driver.Connector
	} = &wrapConnector{}
	_ interface {
		driver.Conn
		driver.ConnBeginTx
		driver.ConnPrepareContext
		driver.Execer
		driver.ExecerContext
		driver.NamedValueChecker
		driver.Pinger
		driver.Queryer
		driver.QueryerContext
	} = &wrapConn{}
	_ interface {
		driver.Stmt
		driver.ColumnConverter
		driver.NamedValueChecker
		driver.StmtExecContext
		driver.StmtQueryContext
	} = &wrapStmt{}
)
