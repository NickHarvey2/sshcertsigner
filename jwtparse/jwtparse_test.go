package jwtparse

import (
    "encoding/base64"
    "testing"
    "fmt"
)

// TestGetClaim calls the GetClaim function, passing in a correctly structured JWT authorization header
// and validates that the correct claim value is returned
func TestGetClaim(t *testing.T) {
    header := "{\"kid\":\"D0-0jXWPWk_B7zZCdFmhyo5kUh17giOqYZNoSqKd27s\",\"alg\":\"RS256\"}"
    body := "{\"ver\":1,\"iss\":\"https://authzserver.com\",\"aud\":\"api\",\"iat\":1709864259,\"exp\":1709867859,\"cid\":\"5678\",\"uid\":\"1234\",\"scp\":[\"openid\",\"email\"],\"auth_time\":1709864248,\"sub\":\"thisisthesubclaim\",\"lastName\":\"Lastname\",\"firstName\":\"Firstname\",\"displayName\":\"Firstname Lastname\",\"groups\":[\"Test Group 0\",\"Test Group 1\"],\"email\":\"user@host.domain\"}"
    authzHeader := fmt.Sprintf("Bearer %s.%s.fakesignature", base64.RawURLEncoding.EncodeToString([]byte(header)), base64.RawURLEncoding.EncodeToString([]byte(body)))
    claim := "sub"
    got, err := GetClaim(authzHeader, claim)
    want := "thisisthesubclaim"

    if err != nil {
        t.Errorf("encountered error: %s", err)
    }

    if got != want {
        t.Errorf("got %s, wanted %s", got, want)
    }
}

// TestGetClaimMissingClaim calls the GetClaim function, passing in a correctly structured JWT authorization header
// that does not contain the requested claim, and validates that the expected error is returned
func TestGetClaimMissingClaim(t *testing.T) {
    header := "{\"kid\":\"D0-0jXWPWk_B7zZCdFmhyo5kUh17giOqYZNoSqKd27s\",\"alg\":\"RS256\"}"
    body := "{\"ver\":1,\"iss\":\"https://authzserver.com\",\"aud\":\"api\",\"iat\":1709864259,\"exp\":1709867859,\"cid\":\"5678\",\"uid\":\"1234\",\"scp\":[\"openid\",\"email\"],\"auth_time\":1709864248,\"lastName\":\"Lastname\",\"firstName\":\"Firstname\",\"displayName\":\"Firstname Lastname\",\"groups\":[\"Test Group 0\",\"Test Group 1\"],\"email\":\"user@host.domain\"}"
    authzHeader := fmt.Sprintf("Bearer %s.%s.fakesignature", base64.RawURLEncoding.EncodeToString([]byte(header)), base64.RawURLEncoding.EncodeToString([]byte(body)))
    claim := "sub"
    _, err := GetClaim(authzHeader, claim)
    want := fmt.Sprintf("Unable to parse %s claim from JWT", claim)

    if err == nil || err.Error() != want {
        t.Errorf("got error %s, wanted error %s", err, want)
    }
}

// TestGetClaimBase64DecodeFailure calls the GetClaim function, passing in an invalidly structured JWT authorization header
// in particular, one that has a body that cannot be base64 decoded, and validates that the expected error is returned
func TestGetClaimBase64DecodeFailure(t *testing.T) {
    header := "{\"kid\":\"D0-0jXWPWk_B7zZCdFmhyo5kUh17giOqYZNoSqKd27s\",\"alg\":\"RS256\"}"
    authzHeader := fmt.Sprintf("Bearer %s.%s.fakesignature", base64.RawURLEncoding.EncodeToString([]byte(header)), "==this cannot be base64 decoded==")
    _, err := GetClaim(authzHeader, "sub")
    want := "illegal base64 data at input byte 0"

    if err == nil || err.Error() != want {
        t.Errorf("got error %s, wanted error %s", err, want)
    }
}

// TestGetClaimBase64DecodeFailure calls the GetClaim function, passing in an invalidly structured JWT authorization header
// in particular, one that has a body that cannot be parsed as json after base64 decoding, and validates that the expected error is returned
func TestGetClaimJsonDecodeFailure(t *testing.T) {
    header := "{\"kid\":\"D0-0jXWPWk_B7zZCdFmhyo5kUh17giOqYZNoSqKd27s\",\"alg\":\"RS256\"}"
    body := "{this is not valid json}"
    authzHeader := fmt.Sprintf("Bearer %s.%s.fakesignature", base64.RawURLEncoding.EncodeToString([]byte(header)), base64.RawURLEncoding.EncodeToString([]byte(body)))
    _, err := GetClaim(authzHeader, "sub")
    want := "invalid character 't' looking for beginning of object key string"

    if err == nil || err.Error() != want {
        t.Errorf("got error %s, wanted error %s", err, want)
    }
}
