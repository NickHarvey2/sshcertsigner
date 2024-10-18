package sshcert

import (
    "golang.org/x/crypto/ssh"
    "testing"
)

// TestCreateGenerator calls the CreateGenerator function to create the certificate generator,
// then uses the generator to create and sign the certificate and verifies the claims on
// the resulting cert match expected values
func TestCreateGenerator(t *testing.T) {
    fakeConfig := new(OrgConfig)
    fakeConfig.CaPrivateKey = "-----BEGIN OPENSSH PRIVATE KEY----- \nb3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCzBWamyP \n3tNO17EAuzkCUuAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIAH3+drBPsHjkf5+ \nc+w/S4quU3m0/T9sj1jPzqSynIb1AAAAkF0gaakx9/4H4I8eonpR1yU+VpDy3e7sWU9elw \nm/Z4fbjfo8tAnVRZik25ne0gGrpXFbNibRWQqV23qDV3Dk+HvfhDDnqdnejZaUDbmK0Y9a \n8yL/L3bH4FSSGCTxrGPMTPZSuV7Re3frtH3SwGz1gE3EpSNdMq7STMjtRewn35QAXY1Zv6 \nSxznA1eBwXGTIv7w== \n-----END OPENSSH PRIVATE KEY----- \n"
    fakeConfig.Passphrase = "supersecure"
    fakeConfig.TtlInDays = 10
    fakeConfig.SourceAddress = "172.0.0.1"

    generator, err := CreateGenerator(*fakeConfig)
    if err != nil {
        t.Errorf("encountered error %s", err.Error())
    }

    keyId := "kid"
    username := "user"
    userPubKeyBytes := []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMHpkpQ/1+RlV3L26iBSoKeRqtUqxt2QYu7dCR/RtRKK comment")

    encodedCert, err := generator(keyId, username, userPubKeyBytes)
    if err != nil {
        t.Errorf("encountered error %s", err.Error())
    }

    certKey, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(encodedCert))

    switch cert := certKey.(type) {
    case *ssh.Certificate:
        if comment != "comment" {
            t.Errorf("wanted Comment 'comment', got '%s'", comment)
        }

        if cert.Type() != "ssh-ed25519-cert-v01@openssh.com" {
            t.Errorf("wanted Type 'ssh-ed25519-cert-v01@openssh.com', got '%s'", cert.Type())
        }

        if cert.CertType != ssh.UserCert {
            t.Errorf("wanted CertType %d, got %d", ssh.UserCert, cert.CertType)
        }

        if cert.KeyId != keyId {
            t.Errorf("wanted KeyId '%s', got '%s'", keyId, cert.KeyId)
        }

        if cert.Extensions["login@github.com"] != username {
            t.Errorf("wanted username '%s', got '%s'", username, cert.Extensions["login@github.com"])
        }

        if cert.CriticalOptions["source-address"] != fakeConfig.SourceAddress {
            t.Errorf("wanted critical option 'source-address' to be '%s', got '%s'", fakeConfig.SourceAddress, cert.CriticalOptions["source-address"])
        }
    default:
        t.Error("Read key is not of type ssh.Certificate")
    }
}

// TestCreateGenerator calls the CreateGenerator function to create the certificate generator,
// then uses the generator to create and sign the certificate and verifies the claims on
// the resulting cert match expected values.
// This version does not specify a source address, and verifies that the resulting certificate
// doesn't have the relevant claim at all
func TestCreateGeneratorWithoutSourceAddress(t *testing.T) {
    fakeConfig := new(OrgConfig)
    fakeConfig.CaPrivateKey = "-----BEGIN OPENSSH PRIVATE KEY----- \nb3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCzBWamyP \n3tNO17EAuzkCUuAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIAH3+drBPsHjkf5+ \nc+w/S4quU3m0/T9sj1jPzqSynIb1AAAAkF0gaakx9/4H4I8eonpR1yU+VpDy3e7sWU9elw \nm/Z4fbjfo8tAnVRZik25ne0gGrpXFbNibRWQqV23qDV3Dk+HvfhDDnqdnejZaUDbmK0Y9a \n8yL/L3bH4FSSGCTxrGPMTPZSuV7Re3frtH3SwGz1gE3EpSNdMq7STMjtRewn35QAXY1Zv6 \nSxznA1eBwXGTIv7w== \n-----END OPENSSH PRIVATE KEY----- \n"
    fakeConfig.Passphrase = "supersecure"
    fakeConfig.TtlInDays = 10
    fakeConfig.SourceAddress = ""

    generator, err := CreateGenerator(*fakeConfig)
    if err != nil {
        t.Errorf("encountered error %s", err.Error())
    }

    keyId := "kid"
    username := "user"
    userPubKeyBytes := []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMHpkpQ/1+RlV3L26iBSoKeRqtUqxt2QYu7dCR/RtRKK comment")

    encodedCert, err := generator(keyId, username, userPubKeyBytes)
    if err != nil {
        t.Errorf("encountered error %s", err.Error())
    }

    certKey, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(encodedCert))

    switch cert := certKey.(type) {
    case *ssh.Certificate:
        if comment != "comment" {
            t.Errorf("wanted Comment 'comment', got '%s'", comment)
        }

        if cert.Type() != "ssh-ed25519-cert-v01@openssh.com" {
            t.Errorf("wanted Type 'ssh-ed25519-cert-v01@openssh.com', got '%s'", cert.Type())
        }

        if cert.CertType != ssh.UserCert {
            t.Errorf("wanted CertType %d, got %d", ssh.UserCert, cert.CertType)
        }

        if cert.KeyId != keyId {
            t.Errorf("wanted KeyId '%s', got '%s'", keyId, cert.KeyId)
        }

        if cert.Extensions["login@github.com"] != username {
            t.Errorf("wanted username '%s', got '%s'", username, cert.Extensions["login@github.com"])
        }

        srcAddr, exists := cert.CriticalOptions["source-address"]
        if exists {
            t.Errorf("wanted critical option 'source-address' to not exist, but it does with a value '%s'", srcAddr)
        }
    default:
        t.Error("Read key is not of type ssh.Certificate")
    }
}
