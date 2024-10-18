build:
    go build

watch-run:
    find . -type f -name "*.go" | entr -cr go run sshcertsigner.go -c testconfig.json

test-all:
    go test -v ./jwtparse ./sshcert

test TEST:
    go test -v {{TEST}}

watch-test:
    find . -type f -name "*.go" | entr -c go test -v ./jwtparse ./sshcert
