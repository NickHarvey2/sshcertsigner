package sshcert

import (
    "crypto/rand"
    "fmt"
    "strings"
    "time"

    "golang.org/x/crypto/ssh"
)

type CertGenerator func(string, string, []byte) (string, error)

type OrgConfig struct {
    JwksUri       string
    CaPrivateKey  string
    Passphrase    string
    TtlInDays     int
    SourceAddress string
}

func CreateGenerator(params OrgConfig) (CertGenerator, error) {
    var caSigner ssh.Signer
    var err error
    if params.Passphrase == "" {
        caSigner, err = ssh.ParsePrivateKey([]byte(params.CaPrivateKey))
        if err != nil {
            return nil, err
        }
    } else {
        caSigner, err = ssh.ParsePrivateKeyWithPassphrase([]byte(params.CaPrivateKey), []byte(params.Passphrase))
        if err != nil {
            return nil, err
        }
    }

    return func(keyId string, username string, userPubKeyBytes []byte) (string, error) {
        pubKey, comment, _, _, err := ssh.ParseAuthorizedKey(userPubKeyBytes)
        if err != nil {
            return "", err
        }

        critOpts := map[string]string{}
        if len(params.SourceAddress) > 0 {
            critOpts = map[string]string{
                "source-address": params.SourceAddress,
            }
        }

        // Construct the certificate
        cert := &ssh.Certificate{
            Key:         pubKey,
            // since this is specifically to support ssh cert authn to GH, serial isn't needed (since GH offers no revocation process anyway)
            // if these certs are shared and used for another purpose, or if GH ever adds a feature to revoke by serial, this should be changed
            Serial:      0,
            CertType:    ssh.UserCert,
            KeyId:       keyId,
            ValidAfter:  uint64(time.Now().Unix()),
            ValidBefore: uint64(time.Now().AddDate(0, 0, params.TtlInDays).Unix()),
            Permissions: ssh.Permissions{
                Extensions: map[string]string{
                    "login@github.com": username,
                },
                CriticalOptions: critOpts,
            },
        }

        // Sign the certificate
        err = cert.SignCert(rand.Reader, caSigner)
        if err != nil {
            return "", err
        }

        // Serialize the certificate
        certBytes := ssh.MarshalAuthorizedKey(cert)
        return fmt.Sprintf("%s %s", strings.Trim(string(certBytes), "\n "), comment), nil
    }, nil
}
