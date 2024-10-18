package jwtparse

import (
    "encoding/base64"
    "encoding/json"
    "errors"
    "strings"
)

func GetClaim(authzHeader string, claim string) (string, error) {
    encodedJwtBody := strings.Split(authzHeader[7:], ".")[1]
    jwtBody, err := base64.RawURLEncoding.DecodeString(encodedJwtBody)
    if err != nil {
        return "", err
    }

    var jwtBodyData map[string]interface{}
    err = json.Unmarshal(jwtBody, &jwtBodyData)
    if err != nil {
        return "", err
    }
    sub, ok := jwtBodyData[claim].(string)
    if !ok {
        err = errors.New("Unable to parse sub claim from JWT")
        return "", err
    }

    return sub, nil
}
