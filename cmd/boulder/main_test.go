package main

import (
	"fmt"
	"os"
	"testing"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/test"
)

// TestConfigValidation checks that each of the components which register a
// validation tagged Config struct at init time can be used to successfully
// validate their corresponding test configuration files.
func TestConfigValidation(t *testing.T) {
	// The list of components to test. Each component is a pair of at lease one
	// `test/config` file path and a `cmd` package name.
	components := make(map[string][]string)

	configPath := "../../test/config"
	if os.Getenv("BOULDER_CONFIG_DIR") == "test/config-next" {
		configPath = "../../test/config-next"
	}

	// For each component, add a list of paths to the `test/config` directory.
	// The paths should be relative to the `test/config` directory.
	for _, cmdName := range cmd.AvailableConfigs() {
		var configPaths []string
		switch cmdName {
		case "boulder-publisher":
			configPaths = []string{fmt.Sprintf("%s/publisher.json", configPath)}
		case "boulder-wfe2":
			configPaths = []string{fmt.Sprintf("%s/wfe2.json", configPath)}
		case "boulder-va":
			configPaths = []string{fmt.Sprintf("%s/va.json", configPath)}
		case "boulder-remoteva":
			configPaths = []string{
				fmt.Sprintf("%s/va-remote-a.json", configPath),
				fmt.Sprintf("%s/va-remote-b.json", configPath),
			}
		case "boulder-ra":
			configPaths = []string{fmt.Sprintf("%s/ra.json", configPath)}
		case "nonce-service":
			configPaths = []string{
				fmt.Sprintf("%s/nonce-a.json", configPath),
				fmt.Sprintf("%s/nonce-b.json", configPath),
			}
		case "boulder-ca":
			configPaths = []string{
				fmt.Sprintf("%s/ca-a.json", configPath),
				fmt.Sprintf("%s/ca-b.json", configPath)}
		case "boulder-sa":
			configPaths = []string{fmt.Sprintf("%s/sa.json", configPath)}
		case "boulder-observer":
			configPaths = []string{fmt.Sprintf("%s/observer.yml", configPath)}

		default:
			configPaths = []string{fmt.Sprintf("%s/%s.json", configPath, cmdName)}
		}
		components[cmdName] = append(components[cmdName], configPaths...)
	}

	for cmdName, paths := range components {
		for _, path := range paths {
			t.Run(path, func(t *testing.T) {
				err := cmd.ReadAndValidateConfigFile(cmdName, path)
				test.AssertNotError(t, err, fmt.Sprintf("Failed to validate config file %q", path))
			})
		}
	}
}
