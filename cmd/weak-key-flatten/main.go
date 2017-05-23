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
	inputs := flag.String("inputs", "", "comma separated list of files to flatten from debian weak key packages (i.e. openssl-blacklist, openssh-blacklist, openvpn-blacklist)")
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
		cmd.FailOnError(err, fmt.Sprintf("reading %s", err))
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

	var list []string
	for k := range flattened {
		list = append(list, k)
	}
	jsonList, err := json.MarshalIndent(list, "", "\t")
	cmd.FailOnError(err, "marshalling list")
	err = ioutil.WriteFile(*output, jsonList, os.FileMode(0640))
	cmd.FailOnError(err, fmt.Sprintf("fail to write to %s", *output))
}
