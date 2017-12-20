package mock_metrics

//go:generate mockgen -package mock_metrics -destination ./mock_scope.go github.com/letsencrypt/boulder/metrics Scope
//go:generate sed -i mock_scope.go -e s,github.com/letsencrypt/boulder/vendor/,,
