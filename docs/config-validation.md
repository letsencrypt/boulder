# Configuration Validation

We use a fork of
[github.com/go-playground/validator](https://github.com/go-playground/validator)
to enable validation of our configuration files using struct tags. The validator
is configured to validate the configuration file at component startup if the
`-validate` command line flag is set. If the supplied configuration file is
valid, the component will exit with a zero exit code, otherwise it will exit
with a non-zero exit code and print the validation errors to stderr.

## Struct Tag Tips

You can find the full list of struct tags supported by the validator [here]
(https://pkg.go.dev/github.com/go-playground/validator/v10#section-documentation).
The following are some tips for struct tags that are commonly used in our
configuration files.

### `required`

This only validates that the value is not the data types default zero value. For
numbers ensures value is not zero. For strings ensures value is not "". For
slices, maps, pointers, interfaces, channels and functions ensures the value is
not nil. Note, this does not validate slices, maps, etc., as they are not nil.
For these fields you should use `min=1` or `gte=1` to validate the supplied
values are not empty.

### `omitempty`

The validator will always run any present validations unless the field is also
tagged with `omitempty`. Said another way, if a validation is present, and that
validation cannot be satisfied by the zero-value of that field type, then that
field is also (technically) required. However, when `omitempty` is present,
validations will only run when the condition of a `required_` (`with`,
`with_all`, `unless`, etc.) tag is met.

### `-`
This tag is used to ignore a struct or field. It can be useful if you have a
struct that is nested into various other structs but isn't always required. This
is the same as saying a struct and all of its fields are optional. We use this
tag for many config duration and password file struct valued fields which are
optional in some configs but required in others.

### `structonly`

Very similar to `omitempty`, but used to control whether or not the validator
will run validations present for the fields of a nested struct. When a nested
struct is tagged with `structonly` the validations for its fields will only run
when the condition of a `required_` (`with`, `with_all`, `unless`, etc.) tag is
met.

### `nostructlevel`

The same as `structonly`, but it will never run the validations on the nested
struct, even if one of the `required_` conditions is met. When this tag is
present, the validator will only validate the value of the struct itself is
non-nil.

### `min=1`, `gte=1`, `gt=0`

These validate that the value is greater than zero. On its face you might assume
that these would only validate integers, but when specified on a slice or map it
will validate that the length of the slice or map is greater than zero.

Note: we encourage the use of `min=1` or `gte=1` over `gt=0` because it's more
readable.

For instance, the following would be valid config for a slice valued field
tagged with `required`.
```json
{
  "foo": [],
}
```

But, only the following would be valid config for a slice valued field tagged
with `min=1`.
```json
{
  "foo": ["bar", ...],
}
```

### `len`

Same as `eq` (equal to) but can also be used to validate the length of the
strings.

### `hostname_port`

The
[docs](https://pkg.go.dev/github.com/go-playground/validator/v10#hdr-HostPort)
for this tag are scant with detail, but it validates that the value is a valid
RFC 1123 hostname and port. It is used to validate many of the the
`ListenAddress` and `DebugAddr` fields of our components.

#### Future Work

This tag is compatible with IPv4 addresses, but not IPv6 addresses. We should
consider fixing this in our fork of the validator.

### `dive`
This tag is used to validate the values of a slice or map. For instance, the
following would be valid config for a slice valued field (`[]string`) tagged
with `min=1,dive,oneof=bar baz`.

```json
{
  "foo": [
    "bar",
    "baz",
  ],
}
```

Note that the `dive` tag introduces an order-dependence in writing tags: tags
that come before `dive` apply to the current field, while tags that come after
`dive` apply to the current field's child values. In the example above: `min=1`
applies to the length of the slice (`[]string`), while `oneof=bar baz` applies
to the value of each string in the slice.

We can also use `dive` to validate the values of a map. For instance, the
following would be valid config for a map valued field (`map[string]string`)
tagged with `min=1,dive,oneof=bar baz`.

```json
{
  "foo": {
    "bar": "baz",
    "baz": "bar"
  },
}
```

`dive` can also be invoked multiple times to validate the values of nested
slices or maps. For instance, the following would be valid config for a slice of
slice valued field (`[][]string`) tagged with `min=1,dive,min=2,dive,oneof=bar
baz`.

```json
{
  "foo": [
    [
      "bar",
      "baz",
    ],
    [
      "baz",
      "bar",
    ],
  ],
}
```

```go
foo [][]string `validate:"min=1,dive,gt=1,dive,oneof=bar baz"`
```

- `min=1` will be applied to the outer slice (`[]`).
- `gt=1` will be applied to inner slice (`[]string`).
- `oneof=bar baz` will be applied to each string in the inner slice.

### `keys` and `endkeys`
These tags are used to validate the keys of a map. For instance, the following
would be valid config for a map valued field (`map[string]string`) tagged with
`min=1,dive,keys,eq=1|eq=2,endkeys,required`.

```json
{
  "foo": {
    "1": "bar",
    "2": "baz",
  },
}
```

```go
foo map[string]string `validate:"min=1,dive,keys,eq=1|eq=2,endkeys,required"`
```

- `min=1` will be applied to the map itself
- `eq=1|eq=2` will be applied to the map keys
- `required` will be applied to map values


## Package

Our fork of
[github.com/go-playground/validator](https://github.com/go-playground/validator)
can be found at https://github.com/letsencrypt/validator. This fork removes a
number of dependencies that we don't need. It may eventually diverge further
from the upstream validator but for now it is a simple fork.
