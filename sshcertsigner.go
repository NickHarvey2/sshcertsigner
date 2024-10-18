package main

import (
    "encoding/json"
    "errors"
    "flag"
    "os"

    fiberprometheus "github.com/ansrivas/fiberprometheus/v2"
    jwtware "github.com/gofiber/contrib/jwt"
    "github.com/gofiber/fiber/v2"
    "github.com/gofiber/fiber/v2/middleware/logger"

    "github.com/rs/zerolog"
    log "github.com/rs/zerolog/log"

    "sshcertsigner/jwtparse"
    "sshcertsigner/sshcert"
)

type Config struct {
    Orgs map[string]sshcert.OrgConfig
}

func main() {
    ready := false

    // #######################################################################################################################################
    // logging infrastructure
    zerolog.SetGlobalLevel(zerolog.InfoLevel)

    app := fiber.New()
    app.Use("/", logger.New(logger.Config{
        Format:     "{\"level\":\"access\",\"time\":\"${time}\",\"path\":\"${path}\",\"method\":\"${method}\",\"statuscode\":\"${status}\"}\n",
        TimeFormat: "2006-01-02T15:04:05Z",
        TimeZone:   "UTC",
    }))

    prometheus := fiberprometheus.New("sshcertsigner")
    prometheus.RegisterAt(app, "/metrics")
    app.Use(prometheus.Middleware)

    // #######################################################################################################################################
    log.Info().Msg("Load config")
    var configFilePath string
    flag.StringVar(&configFilePath, "c", "", "Specify path to configuration file")
    flag.Parse()
    if configFilePath == "" {
        err := errors.New("No config provided")
        panic(err)
    }
    configFileData, err := os.ReadFile(configFilePath)
    if err != nil {
        panic(err)
    }
    var config Config
    err = json.Unmarshal(configFileData, &config)
    if err != nil {
        panic(err)
    }
    log.Info().Msg("done")

    // #######################################################################################################################################
    log.Info().Msg("Configure liveness check")
    app.Get("/self", func(c *fiber.Ctx) error {
        return c.SendString("It is live ")
    })
    log.Info().Msg("done")

    log.Info().Msg("Configure readiness check")
    app.Get("/ready", func(c *fiber.Ctx) error {
        if ready {
            return c.SendString("It is ready ")
        }
        panic("It is not ready ")
    })
    log.Info().Msg("done")

    // #######################################################################################################################################
    log.Info().Msg("Configure signing infrastructure")
    certGenerators := make(map[string]sshcert.CertGenerator)
    for orgName, org := range config.Orgs {
        certGenerators[orgName], err = sshcert.CreateGenerator(org)
        if err != nil {
            panic(err)
        }
    }
    log.Info().Msg("done")

    // #######################################################################################################################################
    log.Info().Msg("Configure JWT middleware")
    var jwksUris []string
    for _, org := range config.Orgs {
        jwksUris = append(jwksUris, org.JwksUri)
    }
    app.Use(jwtware.New(jwtware.Config{
        JWKSetURLs: jwksUris,
    }))
    log.Info().Msg("done")

    // #######################################################################################################################################
    log.Info().Msg("Configure request handler")
    app.Post("/:org/:username", func(c *fiber.Ctx) error {
        c.Accepts("text/plain")
        c.Set("Content-Type", "text/plain")

        _, exists := config.Orgs[c.Params("org")]
        if !exists {
            return fiber.ErrNotFound
        }

        sub, err := jwtparse.GetClaim(string(c.Request().Header.Peek("Authorization")), "sub")
        if err != nil {
            log.Error().Err(err).Msg("Unable to parse authorization header")
            return fiber.NewError(fiber.ErrBadRequest.Code, "Unable to parse authorization header")
        }

        sshCert, err := certGenerators[c.Params("org")](sub, c.Params("username"), c.BodyRaw())
        if err != nil {
            log.Error().Err(err).Msg("Error signing ssh certificate")
            return fiber.NewError(fiber.ErrBadRequest.Code, "Error signing ssh certificate")
        }

        return c.SendString(string(sshCert))
    })
    log.Info().Msg("done")

    ready = true

    log.Fatal().Err(app.Listen(":8080"))
}
