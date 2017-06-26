Thanks for helping us build Boulder! This page contains requirements and guidelines for Boulder contributions.

# Patch Requirements
* All new functionality and fixed bugs must be accompanied by tests.
* All patches must meet the deployability requirements listed below.
* We prefer pull requests from external forks be created with the ["Allow edits from maintainers"](https://github.com/blog/2247-improving-collaboration-with-forks) checkbox selected.
* Boulder currently implements something we internally refer to as "ACME v1". It is largely the same as the IETF ACME protocol's current most draft ([ACME draft-06](https://tools.ietf.org/html/draft-ietf-acme-acme-06)). The [acme-divergences](https://github.com/letsencrypt/boulder/blob/master/docs/acme-divergences.md) document outlines the places where Boulder differs from the IETF drafts. Our [plans for an "ACME v2" endpoint](https://letsencrypt.org/2017/06/14/acme-v2-api.html) describe how we will resolve the divergences when ACME leaves draft status. If a protocol spec change is required for Boulder functionality, you should propose it on the ACME mailing list (acme@ietf.org), possibly accompanied by a pull request on the [spec repo](https://github.com/ietf-wg-acme/acme/).

# Review Requirements
* All pull requests must receive at least one positive review. Contributors are
  strongly encouraged to get two positives reviews before merging whenever
  possible.
* Exception:
  * Pull requests from current master into the 'staging' branch can be merged without review. This is because any code in master has already been through the normal code review process. Similarly, pull requests from the current 'staging' branch into the 'release' branch can be merged without review. Pull requests into 'staging' or 'release' that aren't directly from master require the normal code review process. These pull requests should be marked by the submitter with the r0=branch-merge label.
* We indicate review approval through GitHub's code review facility.
* New commits pushed to a branch invalidate previous reviews. In other words, a reviewer must give positive reviews of a branch after its most recent pushed commit.
* You cannot review your own code.
* If a branch contains commits from multiple authors, it needs a reviewer who is not an author of commits on that branch.
* If a branch contains updates to files in the vendor/ directory, the author is responsible for running tests in all updated dependencies, and commenting in the review thread that they have done so. Reviewers must not approve reviews that have changes in vendor/ but lack a comment about tests.
* Review changes to or addition of tests just as rigorously as you review code changes. Consider: Do tests actually test what they mean to test? Is this the best way to test the functionality in question? Do the tests cover all the functionality in the patch, including error cases?
* Are there new RPCs or config fields? Make sure the patch meets the Deployability rules below.

# Patch Guidelines
* Please include helpful comments. No need to gratuitously comment clear code, but make sure it's clear why things are being done.
* Include information in your pull request about what you're trying to accomplish with your patch.
* Do not include `XXX`s or naked `TODO`s. Use the formats:
```
// TODO(<email-address>): Hoverboard + Time-machine unsupported until upstream patch.
// TODO(Issue #<num>): Pending hoverboard/time-machine interface.
```

# Squash merging

Once a pull requests has two reviews and the tests are passing, we'll merge it. We always use [squash merges](https://github.com/blog/2141-squash-your-commits) via GitHub's web interface. That means that during the course of your review you should generally not squash or amend commits, or force push. Even if the changes in each commit are small, keeping them separate makes it easier for us to review incremental changes to a pull request. Rest assured that those tiny changes will get squashed into a nice meaningful-size commit when we merge.

When submitting a squash merge, the merger should copy the URL of the pull
request into the body of the commit message.

If the Travis tests are failing on your branch, you should look at the logs to figure out why. Sometimes they fail spuriously, in which case you can post a comment requesting that a project owner kick the build.

# Deployability

We want to ensure that a new Boulder revision can be deployed to the currently running Boulder production instance without requiring config changes first. We also want to ensure that during a deploy, services can be restarted in any order. That means two things:

## Good zero values for config fields

Any newly added config field must have a usable [zero value](https://tour.golang.org/basics/12). That is to say, if a config field is absent, Boulder shouldn't crash or misbehave. If that config file names a file to be read, Boulder should be able to proceed without that file being read.

Note that there are some config fields that we want to be a hard requirement. To handle such a field, first add it as optional, then file an issue to make it required after the next deploy is complete.

In general, we would like our deploy process to be: deploy new code + old config; then immediately after deploy the same code + new config. This makes deploys cheaper so we can do them more often, and allows us to more readily separate deploy-triggered problems from config-triggered problems.

## Flag-gating features

When adding significant new features or replacing existing RPCs the `boulder/features` package should be used to gate its usage. To add a flag a new `const FeatureFlag` should be added and its default value specified in `features.features` in `features/features.go`. In order to test if the flag is enabled elsewhere in the codebase you can use `features.Enabled(features.ExampleFeatureName)` which returns a `bool` indicating if the flag is enabled or not.

Each service should include a `map[string]bool` named `Features` in its configuration object at the top level and call `features.Set` with that map immediately after parsing the configuration. For example to enable `UseNewMetrics` and disable `AccountRevocation` you would add this object:

```
{
    ...
    "features": {
        "UseNewMetrics": true,
        "AccountRevocation": false,
    }
}
```

Feature flags are meant to be used temporarily and should not be used for permanent boolean configuration options. Once a feature has been enabled in both staging and production the flag should be removed making the previously gated functionality the default in future deployments.

### Gating RPCs

When you add a new RPC to a Boulder service (e.g. `SA.GetFoo()`), all components that call that RPC should gate those calls using a feature flag. Since the feature's zero value is false, a deploy with the existing config will not call `SA.GetFoo()`. Then, once the deploy is complete and we know that all SA instances support the `GetFoo()` RPC, we do a followup config deploy that sets the default value to true, and finally remove the flag entirely once we are confident the functionality it gates behaves correctly.

### Gating migrations

We use [database migrations](https://en.wikipedia.org/wiki/Schema_migration)
to modify the existing schema. These migrations will be run on live
data while Boulder is still running, so we need Boulder code at any given commit to
be capable of running without depending on any changes in schemas that have not
yet been applied.

For instance, if we're adding a new column to an existing table, Boulder should
run correctly in three states:
 1. Migration not yet applied.
 2. Migration applied, flag not yet flipped.
 3. Migration applied, flag flipped.

Specifically, that means that all of our `SELECT` statements should enumerate
columns to select, and not use `*`. Also, generally speaking, we will need a
separate model `struct` for serializing and deserializing data before and after the
migration. This is because the ORM package we use,
[`gorp`](https://github.com/go-gorp/gorp), expects every field in a struct to
map to a column in the table. If we add a new field to a model struct and
Boulder attempts to write that struct to a table that doesn't yet have the
corresponding column (case 1), gorp wil fail with
`Insert failed table posts has no column named Foo`.
There are examples of such models in sa/model.go, along with code to
turn a model into a `struct` used internally. 

An example of a flag-gated migration, adding a new `IsWizard` field to Person
controlled by a `AllowWizards` feature flag:

```
# features/features.go:

const (
	unused FeatureFlag = iota // unused is used for testing
	AllowWizards // Added!
)

...

var features = map[FeatureFlag]bool{
	unused: false,
	AllowWizards: false, // Added!
}

# sa/sa.go:

struct Person {
  HatSize  int
  IsWizard bool // Added!
}

struct personModelv1 {
  HatSize int
}

// Added!
struct personModelv2 {
  personModelv1
  IsWizard bool
}

func (ssa *SQLStorageAuthority) GetPerson() (Person, error) {
  if features.Enabled(features.AllowWizards) { // Added!
    var model personModelv2
    ssa.dbMap.SelectOne(&model, "SELECT hatSize, isWizard FROM people")
    return Person{
      HatSize:  model.HatSize,
      IsWizard: model.IsWizard,
    }
  } else {
    var model personModelv1
    ssa.dbMap.SelectOne(&model, "SELECT hatSize FROM people")
    return Person{
      HatSize:  model.HatSize,
    }
  }
}

func (ssa *SQLStorageAuthority) AddPerson(p Person) (error) {
  if features.Enabled(features.AllowWizards) { // Added!
    return ssa.dbMap.Insert(personModelv2{
      personModelv1: {
        HatSize:  p.HatSize,
      },
      IsWizard: p.IsWizard,
    })
  } else {
    return ssa.dbMap.Insert(personModelv1{
      HatSize:  p.HatSize,
      // p.IsWizard ignored
    })
  }
}
```

You will also need to update the `initTables` function from `sa/database.go` to
tell Gorp which table to use for your versioned model structs. Make sure to
consult the flag you defined so that only **one** of the table maps is added at
any given time, otherwise Gorp will error.  Depending on your table you may also
need to add `SetKeys` and `SetVersionCol` entries for your versioned models.
Example:

```
func initTables(dbMap *gorp.DbMap) {
 // < unrelated lines snipped for brevity >

 if features.Enabled(features.AllowWizards) {
    dbMap.AddTableWithName(personModelv2, "person")
 } else {
    dbMap.AddTableWithName(personModelv1, "person")
 }
}
```

You can then add a migration with:

`$ goose -path ./sa/_db/ create AddWizards sql`

Finally, edit the resulting file (`sa/_db/20160915101011_WizardMigrations.sql`) to define your migration:

```
-- +goose Up
ALTER TABLE people ADD isWizard BOOLEAN SET DEFAULT false;

-- +goose Down
ALTER TABLE people DROP isWizard BOOLEAN SET DEFAULT false;
```


# Dependencies

We vendorize all our dependencies using `godep`. Vendorizing means we copy the contents of those dependencies into our own repo. This has a few advantages:
  - If the remote sites that host our various dependencies are unreachable, it is still possible to build Boulder solely from the contents of its repo.
  - The versions of our dependencies can't change out from underneath us.

Note that this makes it possible to edit the local copy of our dependencies rather than the upstream copy. Occasionally we do this in great emergencies, but in general this is a bad idea because it means the next person to update that dependency will overwrite the changes.

Instead, it's better to contribute a patch upstream, then pull down changes. For dependencies that we expect to update semi-regularly, we create a fork in the letsencrypt organization, and vendorize that fork. For such forked dependencies, make changes by submitting a pull request to the letsencrypt fork. Once the pull request is reviewed and merged, (a) submit the changes as an upstream pull request, and (b) run `godep` to update to the latest version in the main Boulder. There are two advantages to this approach:
  - If upstream is slow to merge for any reason, we don't have to wait.
  - When we make changes, our first review is from other Boulder contributors rather than upstream. That way we make sure code meets our needs first before asking someone else to spend time on it.

When vendorizing dependencies, it's important to make sure tests pass on the version you are vendorizing. Currently we enforce this by requiring that pull requests containing a dependency update include a comment indicating that you ran the tests and that they succeeded, preferably with the command line you run them with.

## Problems or questions?

The best place to ask dev related questions is either [IRC](https://webchat.freenode.net/?channels=#letsencrypt-dev) or the [Community Forums](https://community.letsencrypt.org/)
