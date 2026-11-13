
### Deliberately not moved

`useragent/useragent_test.go` resets the package's private `value` and `once` state
between cases. `Set("")` cannot substitute because it is a no-op, and the symbols are
unexported, so an external test package cannot reach them. Keeping it beside the code is
the honest option; rewriting it would mean subprocess isolation for the same assertion.

`third_party/norma/agentcore` keeps all 7 of its test files. Three read the private
`Session.compactor` and `Session.registry` fields, and the 7 share helpers, so moving the
4 clean ones would strand the other 3 and force duplicated helpers. `export_test.go`
does not help: Go compiles a package's `_test.go` files only for tests in that package's
own directory, so an external test package never sees the accessors — verified with a
throwaway module. The only route would be exporting two accessors in production code
purely for tests, which is not a trade worth making.

`server`, `agent`, `db`, `notify`, `traffic`, `intercept`, `guard`, `mcphttp`, `llmrec`,
`sidequestion`, `llmpool`, `egress`, `limits`, `evidence`, `cmd/m1nervac0nsole` and the remaining
`third_party/norma` packages stay beside their code for the same reason at larger scale:
`server` alone touches 351 unexported identifiers.
