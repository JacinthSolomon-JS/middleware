package modules

import "middleware/pkg/storage"

// PersistentState is the subset of the storage layer
type PersistentState interface {
	// Dynamic blocklist
	ListDynamicDomains() ([]string, error)
	AddDynamicDomain(domain string) error
	RemoveDynamicDomain(domain string) error

	// Dynamic Ip blocklist (CIDR entries)
	ListDynamicIps() ([]string, error)
	AddDynamicIp(address string) error
	RemoveDynamicIp(address string) error

	// Allowlist
	ListAllowlistDomains() ([]string, error)
	AddAllowlistDomain(domain string) error
	RemoveAllowlistDomain(domain string) error

	// Source toggles
	ListSourceToggles() (map[string]bool, error)
	SaveSourceToggle(id string, active bool) error

	// Custom sources
	ListCustomSources() ([]storage.CustomSource, error)
	SaveCustomSource(c storage.CustomSource) error
	DeleteCustomSource(id string) error

	// Generic settings
	GetSetting(key string) (string, bool, error)
	SetSetting(key, value string) error
}
