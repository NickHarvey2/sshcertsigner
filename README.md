# sshcertsigner

## Project Description
This is a ReST API that accepts public SSH keys and responds with SSH certificates that can be used to authenticate to GitHub orgs configured to use SSH Certificate authentication.

## Usage

```sh
jwt=$(step oauth --client-id {client id} --provider {authorization server URL} --listen localhost:10000 | jq -r '.access_token') # use [step cli](https://github.com/smallstep/cli) to generate a JWT and use jq to extract the JWT (this assumes PKCE, so no client secret is required)
ssh_certificate=$(cat ~/.ssh/id_ed25519.pub | https POST {hostname where sshcertsigner is hosted}/{GitHub org name}/{your GH username} Accept:text/plain Authorization:"Bearer $jwt") # use [httpie cli](https://github.com/httpie/cli) to send your ssh public key to the API (replace the path used for `cat` as needed, and insert your own GH user name)
ssh_certificate=$(curl https://{hostname where sshcertsigner is hosted}/{GitHub org name}/{your GH username} -H "Accept:text/plain" -H "Authorization:Bearer $jwt" -d @./.ssh/id_ed25519.pub -sL) # or do the same with curl
echo $ssh_certificate | ssh-keygen -Lf - # decode and print the certificate to check that we got a valid one
echo $ssh_certifciate > ~/.ssh/id_ed25519-cert.pub # pipe the certificate into the file that you will reference in your ssh config
```

example config:
```json
{
    "orgs": {
        "GitHub Org Name": {
            "jwksUri": "",
            "caPrivateKey": "-----BEGIN OPENSSH PRIVATE KEY----- \nb3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCzBWamyP \n3tNO17EAuzkCUuAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIAH3+drBPsHjkf5+ \nc+w/S4quU3m0/T9sj1jPzqSynIb1AAAAkF0gaakx9/4H4I8eonpR1yU+VpDy3e7sWU9elw \nm/Z4fbjfo8tAnVRZik25ne0gGrpXFbNibRWQqV23qDV3Dk+HvfhDDnqdnejZaUDbmK0Y9a \n8yL/L3bH4FSSGCTxrGPMTPZSuV7Re3frtH3SwGz1gE3EpSNdMq7STMjtRewn35QAXY1Zv6 \nSxznA1eBwXGTIv7w== \n-----END OPENSSH PRIVATE KEY----- \n",
            "passphrase": "supersecure",
            "ttlInDays": 7,
            "SourceAddress": "192.168.0.1/16,172.16.0.0/12"
        }
    }
}

```
