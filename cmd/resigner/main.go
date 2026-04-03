package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"howett.net/plist"
	"resigner/pkg/codesign"
	"resigner/pkg/fs"
	"resigner/pkg/keychain"
	"resigner/pkg/macho"
)

var VCSRevision string = "unknown"

func main() {
	cli.VersionFlag = &cli.BoolFlag{} // disable to avoid conflict with verbose flags

	app := &cli.App{
		Usage:   "resigner <target>",
		Version: VCSRevision,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "p12-file",
				Usage: "Path to PKCS12 keychain file",
			},
			&cli.StringFlag{
				Name:  "p12-password",
				Usage: "Password for PKCS12 keychain file",
			},
			&cli.StringSliceFlag{
				Name:  "profile",
				Usage: "Provisioning profile directory path(s) to use",
			},
			&cli.BoolFlag{
				Name:  "force",
				Usage: "force resigner if already signed",
			},
			&cli.BoolFlag{
				Name:  "only-verify",
				Usage: "only check if already signed",
			},
			&cli.BoolFlag{
				Name:  "inspect",
				Usage: "inspect bundle identifiers and current signing certificates for target app/ipa",
			},
			&cli.StringFlag{
				Name:  "bundle-version",
				Usage: "bundle version to use",
			},
			&cli.StringFlag{
				Name:  "bundle-id",
				Usage: "bundle id to force/set (overrides existing bundle id)",
			},
			&cli.StringSliceFlag{
				Name:  "bundle-id-remap",
				Usage: "bundle id remapping old=new (used when --bundle-id is not set)",
			},
			&cli.StringFlag{
				Name:  "team-id",
				Usage: "team id to filter/select provisioning profile (also checked in verification)",
			},
			&cli.StringFlag{
				Name:  "udid",
				Usage: "target device udid used to match provisioning profile eligibility",
			},
			&cli.StringFlag{
				Name:  "entitlements",
				Usage: "file containing entitlements. get-task-allow, application-identifier, keychain-access-groups and com.apple.developer.team-identifier will be overridden by default",
			},
			&cli.BoolFlag{
				Name:    "verbose",
				Aliases: []string{"v"},
				Usage:   "increase verbosity",
			},
		},
		Action: func(c *cli.Context) error {
			if c.NArg() != 1 {
				_ = cli.ShowCommandHelp(c, c.Command.Name)
				return nil
			}
			level := zap.NewAtomicLevelAt(zap.InfoLevel)

			loggerConfig := zap.Config{
				Level:            level,
				Development:      true,
				Encoding:         "console",
				EncoderConfig:    zap.NewDevelopmentEncoderConfig(),
				OutputPaths:      []string{"stderr"},
				ErrorOutputPaths: []string{"stderr"},
			}

			logger, err := loggerConfig.Build()
			if err != nil {
				log.Fatalf("can't initialize zap logger: %v", err)
			}
			defer func() { _ = logger.Sync() }()

			if c.Bool("verbose") {
				level.SetLevel(zap.DebugLevel)
			}

			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()

			targetFilename := c.Args().Get(0)
			root := fs.DirFS(filepath.Dir(targetFilename))
			targetPath := filepath.Base(targetFilename)

			if c.Bool("inspect") {
				entries, err := collectPrintEntries(root, targetPath)
				if err != nil {
					return err
				}
				printEntries(entries)
				return nil
			}

			bundleVersion := c.String("bundle-version")
			bundleID := c.String("bundle-id")
			bundleIDMap := make(map[string]string)
			for _, remap := range c.StringSlice("bundle-id-remap") {
				parts := strings.SplitN(remap, "=", 2)
				if len(parts) != 2 {
					return fmt.Errorf("invalid bundle id remap: %s", remap)
				}
				bundleIDMap[parts[0]] = parts[1]
			}
			teamID := c.String("team-id")

			entitlementsFilename := c.String("entitlements")
			preserveEntitlements := entitlementsFilename == "preserve"

			var entitlements macho.Entitlements
			if entitlementsFilename != "" {
				entitlementsData, err := os.ReadFile(entitlementsFilename)
				if err != nil {
					return err
				}

				_, err = plist.Unmarshal(entitlementsData, &entitlements)
				if err != nil {
					return err
				}
			}

			config := codesign.SigningConfig{
				Force:      c.Bool("force"),
				OnlyVerify: c.Bool("only-verify"),
				UDID:       c.String("udid"),

				BundleVersion: bundleVersion,

				BundleID:    bundleID,
				BundleIDMap: bundleIDMap,
				TeamID:      teamID,

				PreserveEntitlements: preserveEntitlements,
				Entitlements:         entitlements,
			}

			keychainFilePath := c.String("p12-file")
			keychainPassword := c.String("p12-password")

			if keychainFilePath != "" {
				keychainData, err := os.ReadFile(keychainFilePath)
				if err != nil {
					return fmt.Errorf("could not read keychain file: %w", err)
				}

				config.Keychain, err = keychain.LocalKeychainFromPKCS12(keychainData, keychainPassword)
				if err != nil {
					return fmt.Errorf("could not parse keychain: %w", err)
				}
			}

			profileSpecs := c.StringSlice("profile")
			if len(profileSpecs) > 0 {
				providers := make([]codesign.ProfileProvider, 0, len(profileSpecs))
				for _, profileDir := range profileSpecs {
					expanded := profileDir
					if strings.HasPrefix(expanded, "~/") {
						homeDir, homeErr := os.UserHomeDir()
						if homeErr != nil {
							return homeErr
						}
						expanded = filepath.Join(homeDir, expanded[2:])
					}

					stat, statErr := os.Stat(expanded)
					if statErr != nil {
						return fmt.Errorf("invalid profile directory %q: %w", profileDir, statErr)
					}
					if !stat.IsDir() {
						return fmt.Errorf("profile path must be a directory: %s", profileDir)
					}

					provider, providerErr := codesign.NewDirProfileProvider(fs.DirFS(expanded), ".", nil)
					if providerErr != nil {
						return providerErr
					}
					providers = append(providers, provider)
				}

				config.ProfileProvider = codesign.MultiProfileProvider(providers...)
			}

			signer, err := codesign.NewNativeCodeSigner()
			if err != nil {
				return err
			}

			return codesign.Sign(ctx, logger, signer, root, targetPath, config)
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
}

func collectPrintEntries(root fs.ReadWriteFS, targetPath string) ([]codesign.BundlePrintEntry, error) {
	info, err := root.Stat(targetPath)
	if err != nil {
		return nil, err
	}

	if info.IsDir() {
		return codesign.CollectBundlePrintEntries(root, targetPath)
	}

	if strings.HasSuffix(info.Name(), ".ipa") {
		archive, err := root.OpenRW(targetPath)
		if err != nil {
			return nil, err
		}
		defer archive.Close()

		archiveInfo, err := archive.Stat()
		if err != nil {
			return nil, err
		}

		mem := fs.NewMemFS()
		appBundle, err := codesign.UnzipIPA(archive, archiveInfo.Size(), mem, ".")
		if err != nil {
			return nil, fmt.Errorf("could not unzip IPA: %w", err)
		}

		return codesign.CollectBundlePrintEntries(mem, appBundle)
	}

	return nil, fmt.Errorf("--inspect supports app bundle directories or .ipa files")
}

func printEntries(entries []codesign.BundlePrintEntry) {
	if len(entries) == 0 {
		fmt.Println("No bundles found")
		return
	}

	for _, entry := range entries {
		codeID := entry.CodeIdentifier
		if codeID == "" {
			codeID = "-"
		}

		teamID := entry.TeamID
		if teamID == "" {
			teamID = "-"
		}

		cert := entry.Certificate
		if cert == "" {
			cert = "-"
		}

		fmt.Printf("Path: %s\n", entry.Path)
		fmt.Printf("BundleID: %s\n", entry.BundleID)
		fmt.Printf("CodeIdentifier: %s\n", codeID)
		fmt.Printf("TeamID: %s\n", teamID)
		fmt.Printf("Certificate: %s\n", cert)
		fmt.Println("---")
	}
}
