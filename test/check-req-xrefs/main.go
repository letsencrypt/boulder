// check-req-xrefs verifies that references to requirements documents correctly
// quote their source, so we can ensure that implementations do not drift from
// the requirements they are implementing.
//
// All cross-references are of the form:
//
//	// https://github.com/<org>/<repo>/blob/<ref>/path/to/doc.md?plain=1#L<num>
//	// Exact quote of the linked-to line of the document.
//
// The tool requires network access to fetch the referenced document. It ensures
// that the following quoted line is correct, modulo trailing whitespace. It
// does not check whether the URL points to the latest version of the quoted
// document.
//
// It exits with a nonzero status and a report of every discrepancy if any
// cross-reference is broken.
package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// urlLine matches a comment line consisting solely of a cross-reference URL,
// capturing the org/repo/blob/ref/path portion and the line number. This regex
// is purposefully broad to ensure we capture all lines which intend to be
// cross-references, even if the author typo'd the URL.
var urlLine = regexp.MustCompile(`^\s*// https://github\.com/([^?#\s]+)\?plain=1#L(\d+)\s*$`)

// blobPath splits the path portion of a cross-reference URL into the org/repo
// and the ref/path, the two components of a GitHub URL. The ref and the path
// can't be separated from each other, because refs may themselves contain
// slashes.
var blobPath = regexp.MustCompile(`^([^/]+/[^/]+)/blob/(.+)$`)

// quoteLine matches the comment line following a URL, capturing the quote.
var quoteLine = regexp.MustCompile(`^\s*// (.*)$`)

// getDocument returns the lines of the document at the given URL.
func getDocument(url string) ([]string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching %s: status %s", url, resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", url, err)
	}
	return strings.Split(string(body), "\n"), nil
}

func main() {
	paths := os.Args[1:]
	if len(paths) == 0 {
		fmt.Fprintln(os.Stderr, "usage: check-req-xrefs <file>...")
		os.Exit(1)
	}

	// A cache of fetched documents, keyed by URL.
	documents := make(map[string][]string)

	checked := 0
	failed := 0
	for _, path := range paths {
		contents, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		lines := strings.Split(string(contents), "\n")
		for i, line := range lines {
			match := urlLine.FindStringSubmatch(line)
			if match == nil {
				continue
			}
			checked++

			complain := func(format string, args ...any) {
				failed++
				fmt.Fprintf(os.Stderr, "%s:%d: %s\n", path, i+1, fmt.Sprintf(format, args...))
			}

			doc := match[1]
			pathMatch := blobPath.FindStringSubmatch(doc)
			if pathMatch == nil {
				complain("cross-reference URL is not a GitHub blob URL")
				continue
			}

			num, err := strconv.Atoi(match[2])
			if err != nil {
				complain("unparseable line number %q: %s", match[2], err)
				continue
			}

			rawURL := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s", pathMatch[1], pathMatch[2])
			document, ok := documents[rawURL]
			if !ok {
				document, err = getDocument(rawURL)
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
					os.Exit(1)
				}
				documents[rawURL] = document
			}

			if num < 1 || num > len(document) {
				complain("references line %d, but %s has only %d lines", num, doc, len(document))
				continue
			}
			want := strings.TrimRight(document[num-1], " \t\r")

			if i+1 >= len(lines) {
				complain("cross-reference URL is not followed by a quote")
				continue
			}

			quoteMatch := quoteLine.FindStringSubmatch(lines[i+1])
			if quoteMatch == nil {
				complain("cross-reference URL is not followed by a comment quoting line %d", num)
				continue
			}
			got := strings.TrimRight(quoteMatch[1], " \t\r")

			if got != want {
				complain("quote does not match line %d of %s:\n\tquoted: %s\n\tactual: %s", num, doc, got, want)
			}
		}
	}

	fmt.Printf("checked %d cross-references in %d files: %d incorrect\n", checked, len(paths), failed)
	if failed > 0 {
		os.Exit(1)
	}
}
