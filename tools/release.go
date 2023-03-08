package main

// release.go creates a new version tag and pushes it to GitHub. It has two
// main modes of operation:
// * default: fetch origin/main, tag that commit with Major.Minor.Patch version
//   of 0.YYYYMMDD.0, and push the tag.
// * hotfix: fetch the named release tag, create a new branch starting from
//   that commit, cherry-pick the named commit(s) onto that branch, tag the
//   new branch head with a Major.Minor.Patch that matches the Major.Minor of
//   named release tag and a Patch that is one greater, and push that tag.

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

func runOrDie(cmd *exec.Cmd) string {
	fmt.Println(cmd.String())
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Print(string(out))
		fmt.Println(err)
		os.Exit(1)
	}
	return string(out)
}

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "hotfix" {
		os.Args = append([]string{os.Args[0]}, os.Args[2:]...)
		hotfix()
	} else {
		release()
	}
}

func release() {
	var push bool
	flag.BoolVar(&push, "f", false, "If set, push the resulting release tag to GitHub.")
	flag.Parse()

	// Fetch all of the latest commits and refs from origin, so that we can ensure
	// we're tagging the correct commit and not recreating an existing tag.
	runOrDie(exec.Command("git", "fetch", "origin"))

	// We use semver's vMajor.Minor.Patch format, where the Major version is
	// always 0 (no backwards compatibility guarantees), the Minor version is
	// the date of the release, and the Patch number is zero for normal releases
	// and only non-zero for hotfix releases.
	minor := time.Now().Format("20060102")
	version := fmt.Sprintf("v0.%s.0", minor)
	message := fmt.Sprintf("Release %s", version)

	// Produce the tag, using -s to PGP sign it. This will fail if a tag with
	// that name already exists.
	runOrDie(exec.Command("git", "tag", "-s", "-m", message, version, "origin/main"))

	// Show the result of the tagging operation, including the tag message and
	// signature, and the commit hash and message, but not the diff.
	show := runOrDie(exec.Command("git", "show", "-s", version))
	fmt.Print(show)

	if push {
		runOrDie(exec.Command("git", "push", "origin", version))
	} else {
		fmt.Printf("created tag %s, exiting\n", version)
	}
}

func hotfix() {
	var cherryPicks string
	flag.StringVar(&cherryPicks, "c", "", "Comma-separated list of commit hashes to cherry-pick on top of the prior release.")
	var onto string
	flag.StringVar(&onto, "o", "", "Name of the existing release tag to base this hotfix on top of.")
	var push bool
	flag.BoolVar(&push, "f", false, "If set, push the resulting release tag to GitHub.")
	flag.Parse()

	if !semver.IsValid(onto) {
		fmt.Printf("Tag name %q is not a valid release tag\n", onto)
		os.Exit(1)
	}

	if len(cherryPicks) == 0 {
		fmt.Printf("You must specify one or more commits to cherry-pick\n")
		os.Exit(1)
	}

	// Fetch all of the latest commits and refs from origin, so that we can ensure
	// we're hotfixing an existing release and cherry-picking on to the correct
	// branch.
	runOrDie(exec.Command("git", "fetch", "origin"))

	// Confirm that the release tag we're cherry-picking onto actually exists and
	// is a tag.
	runOrDie(exec.Command("git", "rev-parse", "--verify", fmt.Sprintf("%s^{tag}", onto)))

	// Check out the tag that is our starting point. This will put us into a
	// "detached HEAD" state, but that's okay, because we're going to explicitly
	// specify the branch we're pushing to when we're done.
	runOrDie(exec.Command("git", "checkout", onto))

	// Cherry-pick each of the commits specified by the -c flag. If any of these
	// fails, including because the commit can't be found, just bail out. Use the
	// -x flag so that each of these cherry-picked commits has a commit message
	// which indicates the original commit that it came from.
	for _, sha := range strings.Split(cherryPicks, ",") {
		runOrDie(exec.Command("git", "cherry-pick", "-x", sha))
	}

	// Compute the next tag name by splitting the current tag into its component
	// parts, incrementing the Patch version, and smooshing it back together.
	// Unfortunately, the semver package doesn't provide a .Patch() method.
	parts := strings.SplitN(onto, ".", 3)
	if len(parts) != 3 {
		fmt.Printf("Failed to parse patch version from release tag %q\n", onto)
		os.Exit(1)
	}
	patch, err := strconv.Atoi(parts[2])
	if err != nil {
		fmt.Printf("Failed to parse patch version %q as an integer\n", parts[2])
		os.Exit(1)
	}
	parts[2] = strconv.Itoa(patch + 1)
	version := strings.Join(parts, ".")
	message := fmt.Sprintf("Release %s", version)

	// Produce the tag, using -s to PGP sign it. This will fail if a tag with
	// that name already exists.
	runOrDie(exec.Command("git", "tag", "-s", "-m", message, version, "HEAD"))

	// Show the result of the tagging operation, including the tag message and
	// signature, and the commit hash and message, but not the diff.
	show := runOrDie(exec.Command("git", "show", "-s", version))
	fmt.Print(show)

	// Compute the name of the release branch that will contain the cherry-picked
	// commits. This branch may or may not exist already, and it doesn't matter:
	// when we push to it, it will either be updated or created, as appropriate.
	branch := semver.MajorMinor(onto)

	if push {
		runOrDie(exec.Command("git", "push", "origin", fmt.Sprintf("HEAD:%s", branch), version))
	} else {
		fmt.Printf("created tag %s on branch %s, exiting\n", version, branch)
	}
}
