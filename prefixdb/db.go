package prefixdb

import "database/sql/driver"

// New clones a database driver to create a new driver with the property that
// every connection created will have a query executed before it is used.
// This is useful, for instance, to set conenction-level variables like
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
	stmt, err := conn.Prepare(p.prefix)
	if err != nil {
		return nil, err
	}
	_, err = stmt.Exec(nil)
	if err != nil {
		return nil, err
	}
	return conn, nil
}
