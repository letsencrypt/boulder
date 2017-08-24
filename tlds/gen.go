//+build ignore

package main

import (
	"bytes"
	"go/format"
	"io/ioutil"
	"os"
	"strings"

	"github.com/alecthomas/template"
	"github.com/miekg/dns"
)

var templateStr = `package tlds

var tlds = map[string]struct{}{
{{range $key, $value := .}}	"{{$key}}": struct{}{},
{{end}}}
`

func main() {
	zonefile, err := ioutil.ReadFile("root.zone")
	if err != nil {
		panic(err)
	}
	tlds := map[string]struct{}{}
	for x := range dns.ParseZone(strings.NewReader(string(zonefile)), "", "") {
		if ns, ok := x.RR.(*dns.NS); ok {
			if ns.Hdr.Name == "." {
				continue
			}
			tlds[strings.TrimRight(ns.Hdr.Name, ".")] = struct{}{}
		}
	}

	output, err := os.OpenFile("tlds.go", os.O_RDWR|os.O_TRUNC|os.O_CREATE, 0664)
	if err != nil {
		panic(err)
	}
	defer output.Close()

	t := template.Must(template.New("tld").Parse(templateStr))
	buf := bytes.NewBuffer(nil)
	err = t.Execute(buf, tlds)
	if err != nil {
		panic(err)
	}
	res, err := format.Source(buf.Bytes())
	if err != nil {
		panic(err)
	}
	_, err = output.Write(res)
	if err != nil {
		panic(err)
	}
}
