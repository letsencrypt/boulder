/*
Copyright (c) 2014, Richard Johnson
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
 * Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	toml "github.com/BurntSushi/toml"
	safebrowsing "github.com/rjohnsondev/go-safe-browsing-api"
	"net/http"
	"os"
)

type Config struct {
	Address        string
	GoogleApiKey   string
	DataDir        string
	EnableFormPage bool
}

var sb *safebrowsing.SafeBrowsing

func main() {

	flag.Parse()
	if len(flag.Args()) < 1 {
		fmt.Printf("Usage: webserver config-file.toml")
		os.Exit(1)
	}

	var conf Config
	if _, err := toml.DecodeFile(flag.Arg(0), &conf); err != nil {
		fmt.Printf(
			"Error reading config file %s: %s",
			flag.Arg(0),
			err,
		)
		os.Exit(1)
	}

	var err error
	sb, err = safebrowsing.NewSafeBrowsing(
		conf.GoogleApiKey,
		conf.DataDir,
	)
	if err != nil {
		panic(err)
	}

	if conf.EnableFormPage {
		http.HandleFunc("/form", handleHtml)
	}
	http.HandleFunc("/", handler)
	http.ListenAndServe(conf.Address, nil)
}

type UrlResponse struct {
	IsListed          bool   `json:"isListed"`
	List              string `json:"list,omitempty"`
	Error             string `json:"error,omitempty"`
	WarningTitle      string `json:"warningTitle,omitempty"`
	WarningText       string `json:"warningText,omitempty"`
	FullHashRequested bool   `json:"fullHashRequested,omitempty"`
}

var warnings map[string]map[string]string = map[string]map[string]string{
	"goog-malware-shavar": map[string]string{
		"title": "Warning - Visiting this web site may harm your computer.",
		"text": "This page may be a forgery or imitation of another website, " +
			"designed to trick users into sharing personal or financial " +
			"information. Entering any personal information on this page " +
			"may result in identity theft or other abuse. You can find " +
			"out more about phishing from http://www.antiphishing.org/",
	},
	"googpub-phish-shavar": map[string]string{
		"title": "Warning - Suspected phishing page.",
		"text": "This page appears to contain malicious code that could be " +
			"downloaded to your computer without your consent. You can " +
			"learn more about harmful web content including viruses and " +
			"other malicious code and how to protect your computer at " +
			"http://StopBadware.org/",
	},
}

func handleHtml(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
	<html>
	<body>
	<div style="margin: auto; width: 800px; font-family: sans-serif;">
	<h2>Example JSON usage:</h2>
	Request Object:<br />
	<textarea id="txtJson" rows="6" style="width: 100%;">[
	"http://www.google.com/",
	"http://www.ianfette.org/",
	"http://www.evil.com/"
]
	</textarea><br />
	<br />
	<label><input type="checkbox" id="blocking" /> Have server block to confirm suspect URLs*</label><br />
	<small>
		* As the server contains only partial hash matches for URLs, the first time a URL
		matches a bad hash the server needs to consult Google's Safe Browsing service
		to fetch the full hash before it is able to confirm it is indeed a bad URL.<br />
		<br />
		By default, the server returns immediately and spawns a goroutine to fetch the
		full hash in the background, meaning the first query on a bad URL will return:
		<code>{ isListed: false, fullHashRequested: true }</code>.  If however you wish
		to wait for this request for full hashes to happen and not miss the first query
		about a bad URL, check this box to pass through the blocking=1 parameter.
	</small><br />
	<br />
	<input type="button" value="Submit" onclick="fireRequest();" /><br />
	<br />
	Output:<br />
	<pre id="output" style="border: 1px solid #CCC; padding: 5px; overflow: auto;"></pre><br/>
	<br />
	JS code:<br />
	<pre style="padding: 5px; border: 1px solid #CCC;">
var obj = {"urls": $("#txtJson").val(), "block": $("#blocking").prop("checked")};
$.post("/", obj, function(data, textStatus, jqXHR) {
	$("#output").text(data);
});
	</pre>
	<script>
		fireRequest = function() {
			var obj = {"urls": $("#txtJson").val(), "block": $("#blocking").prop("checked")};
			$.post("/", obj, function(data, textStatus, jqXHR) {
				$("#output").text(data);
			});
		}
	</script>
	<script src="//ajax.googleapis.com/ajax/libs/jquery/1.11.1/jquery.min.js"></script>
	</div>
	</body>
	</html>
	`
	fmt.Fprint(w, html)
}

func queryUrl(url string, isBlocking bool) (response *UrlResponse) {
	response = new(UrlResponse)

	list := ""
	var err error
	fullHashMatch := false

	if isBlocking {
		list, err = sb.IsListed(url)
		fullHashMatch = true
	} else {
		list, fullHashMatch, err = sb.MightBeListed(url)
	}

	if err != nil {
		fmt.Sprintf(response.Error, "Error looking up url: %s", err.Error())
	}
	if list != "" {
		if fullHashMatch && sb.IsUpToDate() {
			response.IsListed = true
			response.List = list
			response.WarningTitle = warnings[list]["title"]
			response.WarningText = warnings[list]["text"]
		} else {
			response.IsListed = false
			response.List = list
			response.FullHashRequested = true
			// Requesting full hash in background...
			go sb.IsListed(url)
		}
	}

	return response
}

func handler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		fmt.Fprintf(w, "Error loading form: %s", err.Error())
		return
	}
	isBlocking := (r.FormValue("block") != "" &&
		r.FormValue("block") != "false" &&
		r.FormValue("block") != "0")

	urls := make([]string, 0)
	err = json.Unmarshal([]byte(r.FormValue("urls")), &urls)
	if err != nil {
		fmt.Fprintf(w, "Error reading json: %s", err.Error())
		return
	}

	output := make(map[string]*UrlResponse, 0)
	for _, url := range urls {
		output[url] = queryUrl(url, isBlocking)
	}
	txtOutput, err := json.MarshalIndent(output, "", "    ")
	if err != nil {
		fmt.Fprintf(w, "Error marshalling response: %s", err.Error())
		return
	}
	fmt.Fprint(w, string(txtOutput))
}
