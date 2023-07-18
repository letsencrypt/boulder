# Boulder's Object Relational Persistence

Once upon a time, there was [gorp](https://github.com/go-gorp/gorp/). Gorp was
good, and Let's Encrypt's adopted it for Boulder's database persistence layer.
The maintainers became busy with other projects, and gorp stopped getting
updated. However, it's still very useful to Boulder, and there are a few tweaks
we'd like to make for our own purposes, so we've forked it.

We maintain this primarily for Boulder's own use, and intend to make some API
breaking changes during 2023. You are welcome to use our fork if you like it, but
we do not expect to spend a lot of time maintaining it for non-Boulder uses.

In particular we maintain this to use with MariaDB 10.5+ and InnoDB.

## Quickstart

```go
package main

import (
    "database/sql"
    "github.com/letsencrypt/borp"
    _ "github.com/mattn/go-sqlite3"
    "log"
    "time"
)

func main() {
    // initialize the DbMap
    dbmap := initDb()
    defer dbmap.Db.Close()

    // delete any existing rows
    err := dbmap.TruncateTables()
    checkErr(err, "TruncateTables failed")

    // create two posts
    p1 := newPost("Go 1.1 released!", "Lorem ipsum lorem ipsum")
    p2 := newPost("Go 1.2 released!", "Lorem ipsum lorem ipsum")

    // insert rows - auto increment PKs will be set properly after the insert
    err = dbmap.Insert(&p1, &p2)
    checkErr(err, "Insert failed")

    // use convenience SelectInt
    count, err := dbmap.SelectInt("select count(*) from posts")
    checkErr(err, "select count(*) failed")
    log.Println("Rows after inserting:", count)

    // update a row
    p2.Title = "Go 1.2 is better than ever"
    count, err = dbmap.Update(&p2)
    checkErr(err, "Update failed")
    log.Println("Rows updated:", count)

    // fetch one row - note use of "post_id" instead of "Id" since column is aliased
    //
    err = dbmap.SelectOne(&p2, "select * from posts where post_id=?", p2.Id)
    checkErr(err, "SelectOne failed")
    log.Println("p2 row:", p2)

    // fetch all rows
    var posts []Post
    _, err = dbmap.Select(&posts, "select * from posts order by post_id")
    checkErr(err, "Select failed")
    log.Println("All rows:")
    for x, p := range posts {
        log.Printf("    %d: %v\n", x, p)
    }

    // delete row by PK
    count, err = dbmap.Delete(&p1)
    checkErr(err, "Delete failed")
    log.Println("Rows deleted:", count)

    // delete row manually via Exec
    _, err = dbmap.Exec("delete from posts where post_id=?", p2.Id)
    checkErr(err, "Exec failed")

    // confirm count is zero
    count, err = dbmap.SelectInt("select count(*) from posts")
    checkErr(err, "select count(*) failed")
    log.Println("Row count - should be zero:", count)

    log.Println("Done!")
}

type Post struct {
    // db tag lets you specify the column name if it differs from the struct field
    Id      int64  `db:"post_id"`
    Created int64
    Title   string `db:",size:50"`               // Column size set to 50
    Body    string `db:"article_body,size:1024"` // Set both column name and size
}

func newPost(title, body string) Post {
    return Post{
        Created: time.Now().UnixNano(),
        Title:   title,
        Body:    body,
    }
}

func initDb() *borp.DbMap {
    // connect to db using standard Go database/sql API
    // use whatever database/sql driver you wish
    db, err := sql.Open("sqlite3", "/tmp/post_db.bin")
    checkErr(err, "sql.Open failed")

    // construct a borp DbMap
    dbmap := &borp.DbMap{Db: db, Dialect: borp.SqliteDialect{}}

    // add a table, setting the table name to 'posts' and
    // specifying that the Id property is an auto incrementing PK
    dbmap.AddTableWithName(Post{}, "posts").SetKeys(true, "Id")

    // create the table. in a production system you'd generally
    // use a migration tool, or create the tables via scripts
    err = dbmap.CreateTablesIfNotExists()
    checkErr(err, "Create tables failed")

    return dbmap
}

func checkErr(err error, msg string) {
    if err != nil {
        log.Fatalln(msg, err)
    }
}
```

## Examples

### Mapping structs to tables

First define some types:

```go
type Invoice struct {
    Id       int64
    Created  int64
    Updated  int64
    Memo     string
    PersonId int64
}

type Person struct {
    Id      int64
    Created int64
    Updated int64
    FName   string
    LName   string
}

// Example of using tags to alias fields to column names
// The 'db' value is the column name
//
// A hyphen will cause borp to skip this field, similar to the
// Go json package.
//
// This is equivalent to using the ColMap methods:
//
//   table := dbmap.AddTableWithName(Product{}, "product")
//   table.ColMap("Id").Rename("product_id")
//   table.ColMap("Price").Rename("unit_price")
//   table.ColMap("IgnoreMe").SetTransient(true)
//
// You can optionally declare the field to be a primary key and/or autoincrement
//
type Product struct {
    Id         int64     `db:"product_id, primarykey, autoincrement"`
    Price      int64     `db:"unit_price"`
    IgnoreMe   string    `db:"-"`
}
```

Then create a mapper, typically you'd do this one time at app startup:

```go
// connect to db using standard Go database/sql API
// use whatever database/sql driver you wish
db, err := sql.Open("mymysql", "tcp:localhost:3306*mydb/myuser/mypassword")

// construct a borp DbMap
dbmap := &borp.DbMap{Db: db, Dialect: borp.MySQLDialect{"InnoDB", "UTF8"}}

// register the structs you wish to use with borp
// you can also use the shorter dbmap.AddTable() if you
// don't want to override the table name
//
// SetKeys(true) means we have a auto increment primary key, which
// will get automatically bound to your struct post-insert
//
t1 := dbmap.AddTableWithName(Invoice{}, "invoice_test").SetKeys(true, "Id")
t2 := dbmap.AddTableWithName(Person{}, "person_test").SetKeys(true, "Id")
t3 := dbmap.AddTableWithName(Product{}, "product_test").SetKeys(true, "Id")
```

### Struct Embedding

borp supports embedding structs.  For example:

```go
type Names struct {
    FirstName string
    LastName  string
}

type WithEmbeddedStruct struct {
    Id int64
    Names
}

es := &WithEmbeddedStruct{-1, Names{FirstName: "Alice", LastName: "Smith"}}
err := dbmap.Insert(es)
```

See the `TestWithEmbeddedStruct` function in `borp_test.go` for a full example.

### Create/Drop Tables ###

Automatically create / drop registered tables.  This is useful for unit tests
but is entirely optional.  You can of course use borp with tables created manually,
or with a separate migration tool (like [sql-migrate](https://github.com/rubenv/sql-migrate), [goose](https://bitbucket.org/liamstask/goose) or [migrate](https://github.com/mattes/migrate)).

```go
// create all registered tables
dbmap.CreateTables()

// same as above, but uses "if not exists" clause to skip tables that are
// already defined
dbmap.CreateTablesIfNotExists()

// drop
dbmap.DropTables()
```

### SQL Logging

Optionally you can pass in a logger to trace all SQL statements.
I recommend enabling this initially while you're getting the feel for what
borp is doing on your behalf.

Borp defines a `GorpLogger` interface that Go's built in `log.Logger` satisfies.
However, you can write your own `GorpLogger` implementation, or use a package such
as `glog` if you want more control over how statements are logged.

```go
// Will log all SQL statements + args as they are run
// The first arg is a string prefix to prepend to all log messages
dbmap.TraceOn("[gorp]", log.New(os.Stdout, "myapp:", log.Lmicroseconds))

// Turn off tracing
dbmap.TraceOff()
```

### Insert

```go
// Must declare as pointers so optional callback hooks
// can operate on your data, not copies
inv1 := &Invoice{0, 100, 200, "first order", 0}
inv2 := &Invoice{0, 100, 200, "second order", 0}

// Insert your rows
err := dbmap.Insert(inv1, inv2)

// Because we called SetKeys(true) on Invoice, the Id field
// will be populated after the Insert() automatically
fmt.Printf("inv1.Id=%d  inv2.Id=%d\n", inv1.Id, inv2.Id)
```

### Update

Continuing the above example, use the `Update` method to modify an Invoice:

```go
// count is the # of rows updated, which should be 1 in this example
count, err := dbmap.Update(inv1)
```

### Delete

If you have primary key(s) defined for a struct, you can use the `Delete`
method to remove rows:

```go
count, err := dbmap.Delete(inv1)
```

### Select by Key

Use the `Get` method to fetch a single row by primary key.  It returns
nil if no row is found.

```go
// fetch Invoice with Id=99
obj, err := dbmap.Get(Invoice{}, 99)
inv := obj.(*Invoice)
```

### Ad Hoc SQL

#### SELECT

`Select()` and `SelectOne()` provide a simple way to bind arbitrary queries to a slice
or a single struct.

```go
// Select a slice - first return value is not needed when a slice pointer is passed to Select()
var posts []Post
_, err := dbmap.Select(&posts, "select * from post order by id")

// You can also use primitive types
var ids []string
_, err := dbmap.Select(&ids, "select id from post")

// Select a single row.
// Returns an error if no row found, or if more than one row is found
var post Post
err := dbmap.SelectOne(&post, "select * from post where id=?", id)
```

Want to do joins?  Just write the SQL and the struct. Borp will bind them:

```go
// Define a type for your join
// It *must* contain all the columns in your SELECT statement
//
// The names here should match the aliased column names you specify
// in your SQL - no additional binding work required.  simple.
//
type InvoicePersonView struct {
    InvoiceId   int64
    PersonId    int64
    Memo        string
    FName       string
}

// Create some rows
p1 := &Person{0, 0, 0, "bob", "smith"}
err = dbmap.Insert(p1)
checkErr(err, "Insert failed")

// notice how we can wire up p1.Id to the invoice easily
inv1 := &Invoice{0, 0, 0, "xmas order", p1.Id}
err = dbmap.Insert(inv1)
checkErr(err, "Insert failed")

// Run your query
query := "select i.Id InvoiceId, p.Id PersonId, i.Memo, p.FName " +
	"from invoice_test i, person_test p " +
	"where i.PersonId = p.Id"

// pass a slice to Select()
var list []InvoicePersonView
_, err := dbmap.Select(&list, query)

// this should test true
expected := InvoicePersonView{inv1.Id, p1.Id, inv1.Memo, p1.FName}
if reflect.DeepEqual(list[0], expected) {
    fmt.Println("Woot! My join worked!")
}
```

#### SELECT string or int64

Borp provides a few convenience methods for selecting a single string or int64.

```go
// select single int64 from db
i64, err := dbmap.SelectInt("select count(*) from foo where blah=?", blahVal)

// select single string from db:
s, err := dbmap.SelectStr("select name from foo where blah=?", blahVal)

```

#### Named bind parameters

You may use a map or struct to bind parameters by name.  This is supported in
the Exec and Select* functions on DbMap and Transaction. It is not supported by
Prepare, Query, or QueryRow.

```go
_, err := dbm.Select(&dest, "select * from Foo where name = :name and age = :age", map[string]interface{}{
  "name": "Rob",
  "age": 31,
})
```

#### UPDATE / DELETE

You can execute raw SQL if you wish.  Particularly good for batch operations.

```go
res, err := dbmap.Exec("delete from invoice_test where PersonId=?", 10)
```

### Transactions

You can batch operations into a transaction:

```go
func InsertInv(dbmap *DbMap, inv *Invoice, per *Person) error {
    // Start a new transaction
    trans, err := dbmap.Begin()
    if err != nil {
        return err
    }

    err = trans.Insert(per)
    checkErr(err, "Insert failed")

    inv.PersonId = per.Id
    err = trans.Insert(inv)
    checkErr(err, "Insert failed")

    // if the commit is successful, a nil error is returned
    return trans.Commit()
}
```

### Hooks

Use hooks to update data before/after saving to the db. Good for timestamps:

```go
// implement the PreInsert and PreUpdate hooks
func (i *Invoice) PreInsert(s borp.SqlExecutor) error {
    i.Created = time.Now().UnixNano()
    i.Updated = i.Created
    return nil
}

func (i *Invoice) PreUpdate(s borp.SqlExecutor) error {
    i.Updated = time.Now().UnixNano()
    return nil
}

// You can use the SqlExecutor to cascade additional SQL
// Take care to avoid cycles. Borp won't prevent them.
//
// Here's an example of a cascading delete
//
func (p *Person) PreDelete(s borp.SqlExecutor) error {
    query := "delete from invoice_test where PersonId=?"

    _, err := s.Exec(query, p.Id)
    if err != nil {
        return err
    }
    return nil
}
```

Full list of hooks that you can implement:

    PostGet
    PreInsert
    PostInsert
    PreUpdate
    PostUpdate
    PreDelete
    PostDelete

    All have the same signature.  for example:

    func (p *MyStruct) PostUpdate(s borp.SqlExecutor) error

### Optimistic Locking

#### Note that this behaviour has changed in v2. See [Migration Guide](#migration-guide).

Borp provides a simple optimistic locking feature, similar to Java's
JPA, that will raise an error if you try to update/delete a row whose
`version` column has a value different than the one in memory.  This
provides a safe way to do "select then update" style operations
without explicit read and write locks.

```go
// Version is an auto-incremented number, managed by borp
// If this property is present on your struct, update
// operations will be constrained
//
// For example, say we defined Person as:

type Person struct {
    Id       int64
    Created  int64
    Updated  int64
    FName    string
    LName    string

    // automatically used as the Version col
    // use table.SetVersionCol("columnName") to map a different
    // struct field as the version field
    Version  int64
}

p1 := &Person{0, 0, 0, "Bob", "Smith", 0}
err = dbmap.Insert(p1)  // Version is now 1
checkErr(err, "Insert failed")

obj, err := dbmap.Get(Person{}, p1.Id)
p2 := obj.(*Person)
p2.LName = "Edwards"
_,err = dbmap.Update(p2)  // Version is now 2
checkErr(err, "Update failed")

p1.LName = "Howard"

// Raises error because p1.Version == 1, which is out of date
count, err := dbmap.Update(p1)
_, ok := err.(borp.OptimisticLockError)
if ok {
    // should reach this statement

    // in a real app you might reload the row and retry, or
    // you might propegate this to the user, depending on the desired
    // semantics
    fmt.Printf("Tried to update row with stale data: %v\n", err)
} else {
    // some other db error occurred - log or return up the stack
    fmt.Printf("Unknown db err: %v\n", err)
}
```
### Adding INDEX(es) on column(s) beyond the primary key ###

Indexes are frequently critical for performance. Here is how to add
them to your tables.

In the example below we put an index both on the Id field, and on the
AcctId field.

```
type Account struct {
	Id      int64
	AcctId  string // e.g. this might be a long uuid for portability
}

// indexType (the 2nd param to AddIndex call) is "Btree" or "Hash" for MySQL.
// demonstrate adding a second index on AcctId, and constrain that field to have unique values.
dbm.AddTable(iptab.Account{}).SetKeys(true, "Id").AddIndex("AcctIdIndex", "Btree", []string{"AcctId"}).SetUnique(true)

err = dbm.CreateTablesIfNotExists()
checkErr(err, "CreateTablesIfNotExists failed")

err = dbm.CreateIndex()
checkErr(err, "CreateIndex failed")

```
Check the effect of the CreateIndex() call in mysql:
```
$ mysql

MariaDB [test]> show create table Account;
+---------+--------------------------+
| Account | CREATE TABLE `Account` (
  `Id` bigint(20) NOT NULL AUTO_INCREMENT,
  `AcctId` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`Id`),
  UNIQUE KEY `AcctIdIndex` (`AcctId`) USING BTREE   <<<--- yes! index added.
) ENGINE=InnoDB DEFAULT CHARSET=utf8
+---------+--------------------------+

```


## Database Drivers

borp uses the Go 1 `database/sql` package.  A full list of compliant
drivers is available here:

http://code.google.com/p/go-wiki/wiki/SQLDrivers

Sadly, SQL databases differ on various issues. borp provides a Dialect
interface that should be implemented per database vendor.  Dialects
are provided for:

* MySQL
* sqlite3

Each of these three databases pass the test suite.  See `borp_test.go`
for example DSNs for these three databases.

## Sqlite3 Extensions

In order to use sqlite3 extensions you need to first register a custom driver:

```go
import (
	"database/sql"

	// use whatever database/sql driver you wish
	sqlite "github.com/mattn/go-sqlite3"
)

func customDriver() (*sql.DB, error) {

	// create custom driver with extensions defined
	sql.Register("sqlite3-custom", &sqlite.SQLiteDriver{
		Extensions: []string{
			"mod_spatialite",
		},
	})

	// now you can then connect using the 'sqlite3-custom' driver instead of 'sqlite3'
	return sql.Open("sqlite3-custom", "/tmp/post_db.bin")
}
```

## Known Issues

### time.Time and time zones

borp will pass `time.Time` fields through to the `database/sql`
driver, but note that the behavior of this type varies across database
drivers.

MySQL users should be especially cautious.  See:
https://github.com/ziutek/mymysql/pull/77

To avoid any potential issues with timezone/DST, consider:

- Using an integer field for time data and storing UNIX time.
- Using a custom time type that implements some SQL types:
  - [`"database/sql".Scanner`](https://golang.org/pkg/database/sql/#Scanner)
  - [`"database/sql/driver".Valuer`](https://golang.org/pkg/database/sql/driver/#Valuer)

## Running the tests

The included tests may be run against MySQL or sqlite3.
You must set two environment variables so the test code knows which
driver to use, and how to connect to your database.

```sh
# MySQL example:
export GORP_TEST_DSN=gomysql_test/gomysql_test/abc123
export GORP_TEST_DIALECT=mysql

# run the tests
go test

# run the tests and benchmarks
go test -bench="Bench" -benchtime 10
```

Valid `GORP_TEST_DIALECT` values are: "mysql"(for mymysql),
"gomysql"(for go-sql-driver), or "sqlite" See the
`test_all.sh` script for examples of all 3 databases.  This is the
script I run locally to test the library.


## Contributors

* matthias-margush - column aliasing via tags
* Rob Figueiredo - @robfig
* Quinn Slack - @sqs
