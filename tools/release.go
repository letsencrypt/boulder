/*
release.go creates a new Boulder release tag and pushes it to GitHub. It ensures
that the release tag points to the correct commit, has standardized formatting
of both the tag itself and its message, and is GPG-signed.

It always produces Semantic Versioning tags of the form v0.YYYYMMDD.N, where:
  - the major version of 0 indicates that we are not committing to any
    backwards-compatibility guarantees;
  - the minor version of the current date provides a human-readable date for the
    release, and ensures that minor versions will be monotonically increasing;
    and
  - the patch version is always 0 for mainline releases, and a monotonically
    increasing number for hotfix releases.

Usage:

	go run tools/release.go [-push]

	go run tools/release.go hotfix -pick <committish>[,<committish>] -onto <prior tag> [-push]

In the first (default) mode, it fetches 'origin/main', creates a new tag
pointing at the HEAD of that ref, and prints the result to the terminal for the
user to inspect. If the -push flag is supplied, it also immediately pushes the
newly-created tag to the remote 'origin'.

In the hotfix mode, two additional flags must be supplied: one or more
comma-separated commits to be cherry-picked into the hotfix, and the tag of the
release on which this hotfix should be based. If this is the first hotfix
release on top of a particular main-line release, it creates a new release
branch named after the major and minor portions of the version number. It
cherry-picks each commit given by the -pick flag on top of the release commit
indicated by the -onto flag. It then creates and signs a tag whose patch version
is one greater than the version given by the -onto flag. When all of this is
complete, it behaves like the default command, either printing the tag, or
pushing it if the -push flag was supplied.
*/
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

type cmdError struct {
	error
	output string
}

func run(cmd *exec.Cmd) (string, error) {
	fmt.Println("Running:", cmd.String())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), cmdError{
			error:  fmt.Errorf("running %q: %w", cmd.String(), err),
			output: string(out),
		}
	}
	return string(out), nil
}

func show(output string) {
	for line := range strings.SplitSeq(strings.TrimSpace(output), "\n") {
		fmt.Println("  ", line)
	}
}

func main() {
	var err error
	if len(os.Args) >= 2 && os.Args[1] == "hotfix" {
		err = hotfix(os.Args[2:])
	} else {
		err = release(os.Args[1:])
	}
	if err != nil {
		var cmdErr cmdError
		if errors.As(err, &cmdErr) {
			show(cmdErr.output)
		}
		fmt.Println(err.Error())
		os.Exit(1)
	}
}

func release(args []string) error {
	fs := flag.NewFlagSet("release", flag.ContinueOnError)
	var push bool
	fs.BoolVar(&push, "push", false, "If set, push the resulting release tag to GitHub.")
	err := fs.Parse(args)
	if err != nil {
		return fmt.Errorf("invalid flags: %w", err)
	}

	// Fetch all of the latest commits and refs from origin, so that we can ensure
	// we're tagging the correct commit and not recreating an existing tag.
	_, err = run(exec.Command("git", "fetch", "origin"))
	if err != nil {
		return err
	}

	// We use semver's vMajor.Minor.Patch format, where the Major version is
	// always 0 (no backwards compatibility guarantees), the Minor version is
	// the date of the release, and the Patch number is zero for normal releases
	// and only non-zero for hotfix releases.
	minor := time.Now().Format("20060102")
	version := fmt.Sprintf("v0.%s.0", minor)
	message := fmt.Sprintf("Release %s", version)

	// Produce the tag, using -s to PGP sign it. This will fail if a tag with
	// that name already exists.
	_, err = run(exec.Command("git", "tag", "-s", "-m", message, version, "origin/main"))
	if err != nil {
		return err
	}

	// Show the result of the tagging operation, including the tag message and
	// signature, and the commit hash and message, but not the diff.
	out, err := run(exec.Command("git", "show", "-s", version))
	if err != nil {
		return err
	}
	show(out)

	if push {
		_, err = run(exec.Command("git", "push", "origin", version))
		if err != nil {
			return err
		}
	} else {
		fmt.Println("please inspect the tag above, then run:")
		fmt.Printf("    git push origin %s\n", version)
	}
	return nil
}

func hotfix(args []string) error {
	fs := flag.NewFlagSet("hotfix", flag.ContinueOnError)
	var cherryPicks string
	fs.StringVar(&cherryPicks, "pick", "", "Comma-separated list of commit hashes to cherry-pick on top of the prior release.")
	var onto string
	fs.StringVar(&onto, "onto", "", "Name of the existing release tag to base this hotfix on top of.")
	var push bool
	fs.BoolVar(&push, "push", false, "If set, push the resulting release tag to GitHub.")
	err := fs.Parse(args)
	if err != nil {
		return fmt.Errorf("invalid flags: %w", err)
	}

	if !semver.IsValid(onto) {
		return fmt.Errorf("tag name %q is not a valid release tag", onto)
	}

	if len(cherryPicks) == 0 {
		return errors.New("you must specify one or more commits to cherry-pick")
	}

	// Fetch all of the latest commits and refs from origin, so that we can ensure
	// we're hotfixing an existing release and cherry-picking on to the correct
	// branch.
	_, err = run(exec.Command("git", "fetch", "origin"))
	if err != nil {
		return err
	}

	// Confirm that the release tag we're cherry-picking onto actually exists and
	// is a tag.
	_, err = run(exec.Command("git", "rev-parse", "--verify", fmt.Sprintf("%s^{tag}", onto)))
	if err != nil {
		return fmt.Errorf("tag %q given by -onto does not exist: %w", onto, err)
	}

	// Check out the tag that is our starting point. This will put us into a
	// "detached HEAD" state, but that's okay, because we're going to explicitly
	// specify the branch we're pushing to when we're done.
	_, err = run(exec.Command("git", "checkout", onto))
	if err != nil {
		return err
	}

	// Cherry-pick each of the commits specified by the -c flag. If any of these
	// fails, including because the commit can't be found, just bail out. Use the
	// -x flag so that each of these cherry-picked commits has a commit message
	// which indicates the original commit that it came from.
	for committish := range strings.SplitSeq(cherryPicks, ",") {
		// First, confirm that the target commit is reachable from origin/main (i.e.
		// has been reviewed and merged) and is not reachable from the current HEAD
		// (i.e. isn't already incorporated into this release).
		_, err = run(exec.Command("git", "merge-base", "--is-ancestor", committish, "origin/main"))
		if err != nil {
			return fmt.Errorf("committish %q is not reachable from origin/main, may not be properly reviewed and merged: %w", committish, err)
		}

		_, err = run(exec.Command("git", "merge-base", "--is-ancestor", committish, onto))
		if err == nil { // inverted! we want this command to fail.
			return fmt.Errorf("committish %q is reachable from %q, may not need to be cherry-picked: %w", committish, onto, err)
		}

		_, err = run(exec.Command("git", "cherry-pick", "-x", committish))
		if err != nil {
			return err
		}
	}

	// Compute the next tag name by splitting the current tag into its component
	// parts, incrementing the Patch version, and smooshing it back together.
	// Unfortunately, the semver package doesn't provide a .Patch() method.
	parts := strings.SplitN(onto, ".", 3)
	if len(parts) != 3 {
		return fmt.Errorf("failed to parse patch version from release tag %q", onto)
	}
	patch, err := strconv.Atoi(parts[2])
	if err != nil {
		return fmt.Errorf("failed to parse patch version %q as an integer", parts[2])
	}
	parts[2] = strconv.Itoa(patch + 1)
	version := strings.Join(parts, ".")
	message := fmt.Sprintf("Release %s", version)

	// Produce the tag, using -s to PGP sign it. This will fail if a tag with
	// that name already exists.
	_, err = run(exec.Command("git", "tag", "-s", "-m", message, version, "HEAD"))
	if err != nil {
		return err
	}

	// Show the result of the tagging operation, including the tag message and
	// signature, and the commit hash and message, but not the diff.
	out, err := run(exec.Command("git", "show", "-s", version))
	if err != nil {
		return err
	}
	show(out)

	// Compute the name of the release branch that will contain the cherry-picked
	// commits. This branch may or may not exist already, and it doesn't matter:
	// when we push to it, it will either be updated or created, as appropriate.
	branch := semver.MajorMinor(onto)
	refspec := fmt.Sprintf("HEAD:%s", branch)

	if push {
		_, err = run(exec.Command("git", "push", "origin", refspec, version))
		if err != nil {
			return cmdError{output: out, error: err}
		}
	} else {
		fmt.Println("please inspect the tag above, then run:")
		fmt.Printf("    git push origin %s %s\n", refspec, version)
	}
	return nil
}
