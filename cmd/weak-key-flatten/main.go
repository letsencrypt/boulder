package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/letsencrypt/boulder/cmd"
)

func main() {
	inputs := flag.String("inputs", "", "comma separated list of files to flatten")
	output := flag.String("output", "", "path to save flattened JSON file to")
	flag.Parse()

	if *inputs == "" || *output == "" {
		fmt.Fprintln(os.Stderr, "both --inputs and --output are required")
		os.Exit(1)
	}

	flattened := map[string]struct{}{}
	files := strings.Split(*inputs, ",")

	for _, fp := range files {
		f, err := ioutil.ReadFile(fp)
		cmd.FailOnError(err, fmt.Sprintf("failed to read %s", err))
		for i, l := range strings.Split(string(f), "\n") {
			if strings.HasPrefix(l, "#") || l == "" {
				continue
			}
			if len(l) != 20 {
				fmt.Fprintf(os.Stderr, "line %d in %s is not expected length (20 characters)\n", i, fp)
				os.Exit(1)
			}
			flattened[l] = struct{}{}
		}
	}

	list := []string{}
	for k := range flattened {
		list = append(list, k)
	}
	jsonList, err := json.Marshal(list)
	cmd.FailOnError(err, "failed to marshal list")
	err = ioutil.WriteFile(*output, jsonList, os.ModePerm)
	cmd.FailOnError(err, fmt.Sprintf("fail to write to %s", *output))
}
