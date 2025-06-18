// Copyright 2012 James Cooper. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

// Package borp provides a simple way to marshal Go structs to and from
// SQL databases.  It uses the database/sql package, and should work with any
// compliant database/sql driver.
//
// Source code, additional documentation, and examples:
// https://github.com/letsencrypt/borp
//
// # Query Parameters
//
// Borp's Exec, Select*, Query, and QueryRow methods accept placeholder
// parameters in the query, to be filled from the args parameters to these
// functions. Borp supports some additional styles for placeholder parameters:
//
// # Named Bind Parameters
//
// For the Exec and Select* methods on DbMap and Transaction, Borp supports
// named bind parameters. To use named bind parameters, instead of a list of
// parameters, pass a single `map[string]interface{}` to these functions. And
// instead of using ? in the query, use placeholder parameters of the form :word.
// Before running the query, Borp will bind each named placeholder parameter to the
// corresponding value found by looking up "word" in the map.
//
// Example:
//
//	_, err := dbm.Select(&dest, "select * from Foo where name = :name and age = :age",
//	  map[string]interface{}{
//	    "name": "Rob",
//	    "age": 31,
//	  })
//
// # Expanding Slices
//
// If you set the ExpandSlices field of DbMap to true, placeholders that bind to
// slices will be handled specially. Borp will modify the query, adding more
// placeholders to match the number of entries in the slice.
//
// For example, given the scenario bellow:
//
//	dbmap.Select(&output, "SELECT 1 FROM example WHERE id IN (:IDs)", map[string]interface{}{
//	  "IDs": []int64{1, 2, 3},
//	})
//
// The executed query would be:
//
//	SELECT 1 FROM example WHERE id IN (:IDs0,:IDs1,:IDs2)
//
// With the mapper:
//
//	map[string]interface{}{
//	  "IDs":  []int64{1, 2, 3},
//	  "IDs0": int64(1),
//	  "IDs1": int64(2),
//	  "IDs2": int64(3),
//	}
//
// It is also flexible for custom slice types. The value just need to
// implement stringer or numberer interfaces.
//
//	type CustomValue string
//
//	const (
//	  CustomValueHey CustomValue = "hey"
//	  CustomValueOh  CustomValue = "oh"
//	)
//
//	type CustomValues []CustomValue
//
//	func (c CustomValues) ToStringSlice() []string {
//	  values := make([]string, len(c))
//	  for i := range c {
//	    values[i] = string(c[i])
//	  }
//	  return values
//	}
//
//	func query() {
//	  // ...
//	  result, err := dbmap.Select(&output, "SELECT 1 FROM example WHERE value IN (:Values)", map[string]interface{}{
//	    "Values": CustomValues([]CustomValue{CustomValueHey}),
//	  })
//	  // ...
//	}
package borp
