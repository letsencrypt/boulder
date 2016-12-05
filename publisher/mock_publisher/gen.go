package mock_publisher

//go:generate mockgen -package mock_publisher -destination ./mock_publisher.go github.com/letsencrypt/boulder/core Publisher
