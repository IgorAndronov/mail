package config

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/spf13/viper"
)

// Config structure for application configuration
type Config struct {
	SMTPHost         string
	SMTPPort         int
	WebHost          string
	WebPort          int
	Domain           string
	OwnDomains       []string
	DB               DBConfig
	TrustedDomains   []string
	JWTSecret        string
	CertFile         string
	KeyFile          string
	EmailStoragePath string
	// DKIM settings
	DKIMSelector       string
	DKIMPrivateKeyPath string
}

// DBConfig for database connection
type DBConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	DBName   string
	SSLMode  string
}

// LoadConfig loads application configuration from file and environment
func LoadConfig(configFile string) (Config, error) {
	// Set up viper
	v := viper.New()
	v.SetConfigType("yaml")

	// Set defaults
	v.SetDefault("smtp.host", "0.0.0.0")
	v.SetDefault("smtp.port", 25)
	v.SetDefault("web.host", "0.0.0.0")
	v.SetDefault("web.port", 8080)
	v.SetDefault("domain", "example.com")
	v.SetDefault("db.sslmode", "disable")
	v.SetDefault("email_storage_path", "./emails")

	// If config file is provided, use it
	if configFile != "" {
		v.SetConfigFile(configFile)
	} else {
		// Otherwise look in default locations
		v.SetConfigName("config")
		v.AddConfigPath(".")
		v.AddConfigPath("./config")
	}

	// Read config
	if err := v.ReadInConfig(); err != nil {
		log.Printf("Warning: Could not read config file: %v. Using defaults and environment variables.\n", err)
	}

	// Check environment variables
	v.AutomaticEnv()
	v.SetEnvPrefix("EMAILSERVER")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Parse into config struct
	config := Config{
		SMTPHost:   v.GetString("smtp.host"),
		SMTPPort:   v.GetInt("smtp.port"),
		WebHost:    v.GetString("web.host"),
		WebPort:    v.GetInt("web.port"),
		Domain:     v.GetString("domain"),
		OwnDomains: v.GetStringSlice("own_domains"),
		DB: DBConfig{
			Host:     v.GetString("db.host"),
			Port:     v.GetInt("db.port"),
			User:     v.GetString("db.user"),
			Password: v.GetString("db.password"),
			DBName:   v.GetString("db.name"),
			SSLMode:  v.GetString("db.sslmode"),
		},
		TrustedDomains:   v.GetStringSlice("trusted_domains"),
		JWTSecret:        v.GetString("jwt_secret"),
		CertFile:         v.GetString("tls.cert_file"),
		KeyFile:          v.GetString("tls.key_file"),
		EmailStoragePath: v.GetString("email_storage_path"),
	}

	// If own_domains is empty, default to the main domain
	if len(config.OwnDomains) == 0 {
		config.OwnDomains = []string{config.Domain}
	}

	// Create email storage directory if it doesn't exist
	if err := os.MkdirAll(config.EmailStoragePath, 0755); err != nil {
		return config, fmt.Errorf("failed to create email storage directory: %w", err)
	}

	return config, nil
}
