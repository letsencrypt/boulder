# Error Handling Guidance

Previously Boulder has used a mix of various error types to represent errors internally, mainly the `core.XXXError` types and `probs.ProblemDetails`, without any guidance on which should be used when or where.

We have switched away from this to using a single unified internal error type, `boulder/errors.BoulderError` which should be used anywhere we are passing errors around internally. `probs.ProblemDetails` should only be used in the WFE when creating a problem document to pass directly back to the user client.

A mapping exists in the WFE to map all of the available `boulder/errors.ErrorType`s to the relevant `probs.ProblemType`s. Internally errors should be wrapped when doing so provides some further context to the error that aides in debugging or will be passed back to the user client. An error may be unwrapped, or a simple stdlib `error` may be used, but doing so means the `probs.ProblemType` mapping will always be `probs.ServerInternalProblem` so should only be used for errors that do not need to be presented back to the user client.

Error type testing should be done with `boulder/errors.Is` instead of locally doing a type cast test. 
