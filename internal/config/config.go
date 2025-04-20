package config

import (
	"fmt"
	"github.com/spf13/viper"
	"os"
)

/* ---------- raw structs (unchanged names) ---------- */

type DBConfig struct {
	Host, User, Password, DBName, SSLMode string
	Port                                  int
}

type Config struct {
	SMTPHost, WebHost, Domain, JWTSecret, CertFile, KeyFile, EmailStoragePath string
	SMTPPort, WebPort                                                         int
	TrustedDomains                                                            []string
	DB                                                                        DBConfig
}

/* ---------- loader (logic identical to old loadConfig) ---------- */

func Load() (Config, error) {

	viper.SetDefault("smtp.host", "0.0.0.0")
	viper.SetDefault("smtp.port", 25)
	viper.SetDefault("web.host", "0.0.0.0")
	viper.SetDefault("web.port", 8080)
	viper.SetDefault("domain", "example.com")
	viper.SetDefault("db.sslmode", "disable")
	viper.SetDefault("email_storage_path", "./emails")

	_ = viper.ReadInConfig() // ignore missing config file

	c := Config{
		SMTPHost: viper.GetString("smtp.host"),
		SMTPPort: viper.GetInt("smtp.port"),
		WebHost:  viper.GetString("web.host"),
		WebPort:  viper.GetInt("web.port"),
		Domain:   viper.GetString("domain"),
		DB: DBConfig{
			Host:     viper.GetString("db.host"),
			Port:     viper.GetInt("db.port"),
			User:     viper.GetString("db.user"),
			Password: viper.GetString("db.password"),
			DBName:   viper.GetString("db.name"),
			SSLMode:  viper.GetString("db.sslmode"),
		},
		TrustedDomains:   viper.GetStringSlice("trusted_domains"),
		JWTSecret:        viper.GetString("jwt_secret"),
		CertFile:         viper.GetString("tls.cert_file"),
		KeyFile:          viper.GetString("tls.key_file"),
		EmailStoragePath: viper.GetString("email_storage_path"),
	}

	// ---- OVERRIDE WITH ENV VARS (STRICT) ----
	if v := os.Getenv("EMAILSERVER_DB_HOST"); v != "" {
		c.DB.Host = v
	}
	if v := os.Getenv("EMAILSERVER_DB_PORT"); v != "" {
		fmt.Sscanf(v, "%d", &c.DB.Port)
	}
	if v := os.Getenv("EMAILSERVER_DB_USER"); v != "" {
		c.DB.User = v
	}
	if v := os.Getenv("EMAILSERVER_DB_PASSWORD"); v != "" {
		c.DB.Password = v
	}
	if v := os.Getenv("EMAILSERVER_DB_NAME"); v != "" {
		c.DB.DBName = v
	}
	if v := os.Getenv("EMAILSERVER_DOMAIN"); v != "" {
		c.Domain = v
	}
	if v := os.Getenv("EMAILSERVER_JWT_SECRET"); v != "" {
		c.JWTSecret = v
	}

	// ---- CREATE STORAGE PATH DIR ----
	if err := os.MkdirAll(c.EmailStoragePath, 0o755); err != nil {
		return Config{}, fmt.Errorf("mkdir email storage: %w", err)
	}

	return c, nil
}
