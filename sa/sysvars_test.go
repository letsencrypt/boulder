package sa

import (
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/letsencrypt/boulder/test"
)

func TestCheckMariaDBSystemVariables(t *testing.T) {
	type testCase struct {
		key string
		value string
		expectErr string
	  }
	
	  for _, tc := range []testCase{
		{"autocommit","0",""},
		{"check_constraint_checks","1",""},
		{"log_slow_query","true", ""},
		{"foreign_key_checks","false",""},
		{"sql_warnings","TrUe",""},
		{"tx_read_only","FalSe",""},
		{"sql_notes","on",""},
		{"tcp_nodelay","off",""},
	  } {
		t.Run(tc.name, func()) {
		  err := checkMariaDBSystemVariables(tc.key, tc.value)
		  if tc.expectErr == "" {
			test.AssertNotError(t, err)
		  } else {
			test.AssertContains(t, err.Error(), tc.expectErr)
		  }
		}
	  }
	}

/*
	conf := &mysql.Config{}
	err := adjustMySQLConfig(conf)
	test.AssertNotError(t, err, "unexpected err setting server variables")
	test.AssertDeepEquals(t, conf.Params, map[string]string{
		"sql_mode": "'STRICT_ALL_TABLES'",
	})

	conf = &mysql.Config{ReadTimeout: 100 * time.Second}
	err = adjustMySQLConfig(conf)
	test.AssertNotError(t, err, "unexpected err setting server variables")
	test.AssertDeepEquals(t, conf.Params, map[string]string{
		"sql_mode":           "'STRICT_ALL_TABLES'",
		"max_statement_time": "95",
		"long_query_time":    "80",
	})

	conf = &mysql.Config{
		ReadTimeout: 100 * time.Second,
		Params: map[string]string{
			"max_statement_time": "0",
		},
	}
	err = adjustMySQLConfig(conf)
	test.AssertNotError(t, err, "unexpected err setting server variables")
	test.AssertDeepEquals(t, conf.Params, map[string]string{
		"sql_mode":        "'STRICT_ALL_TABLES'",
		"long_query_time": "80",
	})

	conf = &mysql.Config{
		Params: map[string]string{
			"max_statement_time": "0",
		},
	}
	err = adjustMySQLConfig(conf)
	test.AssertNotError(t, err, "unexpected err setting server variables")
	test.AssertDeepEquals(t, conf.Params, map[string]string{
		"sql_mode": "'STRICT_ALL_TABLES'",
	})

	conf = &mysql.Config{
		Params: map[string]string{
			"myBabies": "'kids_I_tell_ya'",
		},
	}
	err = adjustMySQLConfig(conf)
	test.AssertError(t, err, "variable not found in the curated system var list")

	conf = &mysql.Config{
		Params: map[string]string{
			"sql_mode": "'STRICT_ALL_TABLES",
		},
	}
	err = adjustMySQLConfig(conf)
	test.AssertError(t, err, "value was incorrectly quoted, right hand side quote missing")

	conf = &mysql.Config{
		Params: map[string]string{
			"sql_mode": "%27STRICT_ALL_TABLES%27",
		},
	}
	err = adjustMySQLConfig(conf)
	test.AssertError(t, err, "value was incorrectly quoted after being parsed from DSN")

	conf = &mysql.Config{
		Params: map[string]string{
			"completion_type": "1",
		},
	}
	err = adjustMySQLConfig(conf)
	test.AssertNotError(t, err, "key is an integer enum, but incorrectly errored")

	conf = &mysql.Config{
		Params: map[string]string{
			"completion_type": "'2'",
		},
	}
	err = adjustMySQLConfig(conf)
	test.AssertError(t, err, "key is an integer enum, but should not have been quoted")

	conf = &mysql.Config{
		Params: map[string]string{
			"completion_type": "RELEASE",
		},
	}
	err = adjustMySQLConfig(conf)
	test.AssertError(t, err, "key is a string enum, but was not quoted")

	conf = &mysql.Config{
		Params: map[string]string{
			"completion_type": "'CHAIN'",
		},
	}
	err = adjustMySQLConfig(conf)
	test.AssertNotError(t, err, "key is a string enum, but incorrectly quoted")

	conf = &mysql.Config{
		Params: map[string]string{
			"autocommit":              "0",
			"check_constraint_checks": "1",
			"log_slow_query":          "true",
			"foreign_key_checks":      "false",
			"sql_warnings":            "TrUe",
			"tx_read_only":            "FalSe",
			"sql_notes":               "on",
			"tcp_nodelay":             "off",
		},
	}
	err = adjustMySQLConfig(conf)
	test.AssertNotError(t, err, "expected a boolean value")

	conf = &mysql.Config{
		Params: map[string]string{
			"autocommit": "2",
		},
	}
	err = adjustMySQLConfig(conf)
	test.AssertError(t, err, "boolean value was not provided")
	*/
}
