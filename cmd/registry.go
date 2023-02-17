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
	config   map[string]*ConfigValidator
}

// Register a boulder subcommand to be run when the binary name matches `name`.
func RegisterCommand(name string, f func()) {
	registry.Lock()
	defer registry.Unlock()

	if registry.commands == nil {
		registry.commands = make(map[string]func())
	}

	if registry.commands[name] != nil {
		panic(fmt.Sprintf("command %q was registered twice", name))
	}
	registry.commands[name] = f
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

// Register a boulder config struct.
func RegisterConfig(name string, f *ConfigValidator) {
	registry.Lock()
	defer registry.Unlock()

	if registry.config == nil {
		registry.config = make(map[string]*ConfigValidator)
	}

	if registry.config[name] != nil {
		panic(fmt.Sprintf("config %q was registered twice", name))
	}
	registry.config[name] = f
}

func LookupConfig(name string) *ConfigValidator {
	registry.Lock()
	defer registry.Unlock()
	return registry.config[name]
}

func AvailableConfigs() []string {
	registry.Lock()
	defer registry.Unlock()
	var avail []string
	for name := range registry.config {
		avail = append(avail, name)
	}
	sort.Strings(avail)
	return avail
}
