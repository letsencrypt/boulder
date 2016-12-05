package prefixdb

import "database/sql/driver"

// New clones a database driver to create a new driver with the property that
// every statement executed will have the given prefix prepended.
// This is useful, for instance, to set statement-level variables like
// max_statement_time and long_query_time.
func New(prefix string, underlying driver.Driver) driver.Driver {
	return &prefixedDB{
		prefix:     prefix,
		underlying: underlying,
	}
}

type prefixedDB struct {
	prefix     string
	underlying driver.Driver
}

func (p *prefixedDB) Open(name string) (driver.Conn, error) {
	conn, err := p.underlying.Open(name)
	if err != nil {
		return nil, err
	}
	return &prefixedConn{
		prefix: p.prefix,
		conn:   conn,
	}, nil
}

type prefixedConn struct {
	prefix string
	conn   driver.Conn
}

func (c *prefixedConn) Prepare(query string) (driver.Stmt, error) {
	return c.conn.Prepare(c.prefix + " " + query)
}

func (c *prefixedConn) Close() error {
	return c.conn.Close()
}

func (c *prefixedConn) Begin() (driver.Tx, error) {
	return c.conn.Begin()
}
