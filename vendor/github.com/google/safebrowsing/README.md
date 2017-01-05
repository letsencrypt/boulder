[![Build Status](https://travis-ci.org/google/safebrowsing.svg?branch=master)](https://travis-ci.org/google/safebrowsing)

# Reference Implementation for the Usage of Google Safe Browsing APIs (v4)

The `safebrowsing` Go package can be used with the
[Google Safe Browsing APIs (v4)](https://developers.google.com/safe-browsing/v4/)
to access the Google Safe Browsing lists of unsafe web resources. Inside the
`cmd` sub-directory, you can find two programs: `sblookup` and `sbserver`. The
`sbserver` program creates a proxy local server to check URLs and a URL
redirector to redirect users to a warning page for unsafe URLs. The `sblookup`
program is a command line service that can also be used to check URLs.

This **README.md** is a quickstart guide on how to build, deploy, and use the
`safebrowsing` Go package. It can be used out-of-the-box. The GoDoc and API
documentation provide more details on fine tuning the parameters if desired.


# Setup

To use the `safebrowsing` Go package you must obtain an *API key* from the
[Google Developer Console](https://console.developers.google.com/). For more
information, see the *Get Started* section of the Google Safe Browsing APIs (v4)
documentation.


# How to Build

To download and install from the source, run the following command:

```
go get github.com/google/safebrowsing
```

The programs below execute from your `$GOPATH/bin` folder. 
Add that to your `$PATH` for convenience:

```
export PATH=$PATH:$GOPATH/bin
```


# Proxy Server

The `sbserver` server binary runs a Safe Browsing API lookup proxy that allows
users to check URLs via a simple JSON API. The server also runs an URL
redirector to show an interstitial for anything marked unsafe. The interstitial
shows warnings recommended by Safe Browsing.

1.	Once the Go environment is setup, run the following command with your API
key:

	```
	go get github.com/google/safebrowsing/cmd/sbserver
	sbserver -apikey $APIKEY
	```

	With the default settings this will start a local server at **127.0.0.1:8080**.

2.  Load the proxy server redirector in any web browser. Try these URLs:

	```
	127.0.0.1:8080/r?url=http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL/
	127.0.0.1:8080/r?url=http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/SOCIAL_ENGINEERING/URL/
	127.0.0.1:8080/r?url=http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/UNWANTED_SOFTWARE/URL/
	127.0.0.1:8080/r?url=http://www.google.com/
	```

3.	To use the local proxy server to check a URL, send a POST request with the
following JSON body:

	```json
	{
		"threatInfo": {
			"threatEntries": [
				{"url": "google.com"},
				{"url": "http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL/"}
			]
		}
	}
	```

	Refer to the [Google Safe Browsing APIs (v4)]
	(https://developers.google.com/safe-browsing/v4/)
	for the format of the JSON request.


# Command-Line Lookup

The `sblookup` command-line binary is another example of how the Go Safe
Browsing library can be used to protect users from unsafe URLs. This
command-line tool filters unsafe URLs piped via STDIN. Example usage:

```
$ go get github.com/google/safebrowsing/cmd/sblookup
$ echo "http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL/" | sblookup -apikey=$APIKEY
  Unsafe URL found:  http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL/ [{testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL/ {MALWARE ANY_PLATFORM URL}}]
```


# Safe Browsing System Test
To perform an end-to-end test on the package with the Safe Browsing backend,
run the following command:

```
go test github.com/google/safebrowsing -v -run TestSafeBrowser -apikey $APIKEY
```
