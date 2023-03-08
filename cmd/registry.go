package cmd

import (
	"fmt"
	"sort"
	"sync"

	"github.com/letsencrypt/validator/v10"
)

type ConfigValidator struct {
	Config     interface{}
	Validators map[string]validator.Func
}

var registry struct {
	sync.Mutex
	commands map[string]func()
	configs  map[string]*ConfigValidator
}

// Register a subcommand and its corresponding config validator. The provided
// func() is called when the subcommand is invoked on the command line. The
// ConfigValidator is optional and used to validate the config file for the
// subcommand.
func RegisterCommand(name string, f func(), cv *ConfigValidator) {
	registry.Lock()
	defer registry.Unlock()

	if registry.commands == nil {
		// Initialize the commands map.
		registry.commands = make(map[string]func())
	}

	if registry.commands[name] != nil {
		// This should never happen.
		panic(fmt.Sprintf("command %q was registered twice", name))
	}

	// Register the command.
	registry.commands[name] = f

	if cv == nil {
		return
	}

	if registry.configs == nil {
		fmt.Println("init configs")
		// Initialize the configs map.
		registry.configs = make(map[string]*ConfigValidator)
	}

	if registry.configs[name] != nil {
		// This should never happen.
		panic(fmt.Sprintf("config %q was registered twice", name))
	}

	// Register the config validator.
	registry.configs[name] = cv
}

func LookupCommand(name string) func() {
	registry.Lock()
	defer registry.Unlock()
	return registry.commands[name]
}

func AvailableCommands() []string {
	registry.Lock()
	defer registry.Unlock()
	var avail []string
	for name := range registry.commands {
		avail = append(avail, name)
	}
	sort.Strings(avail)
	return avail
}

func lookupConfig(name string) *ConfigValidator {
	registry.Lock()
	defer registry.Unlock()
	return registry.configs[name]
}

func AvailableConfigs() []string {
	registry.Lock()
	defer registry.Unlock()
	var avail []string
	for name := range registry.configs {
		avail = append(avail, name)
	}
	sort.Strings(avail)
	return avail
}
