FROM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org
COPY deploy/gateway/go.mod deploy/gateway/go.sum ./
RUN go mod download && go mod verify
COPY deploy/gateway/main.go ./
RUN go build -mod=readonly -trimpath -buildvcs=false -tags=nobadger,nomysql,nopgx -ldflags="-s -w" -o /out/caddy .

# Retain the official image's paths, environment, entrypoint and CA storage.
# Only the Caddy binary is replaced with the pinned, upstream-compatible build.
FROM caddy:2.11.9-alpine@sha256:003a97808e781aa9f7e75cc2f43d34d461099031faf5e20faefb9f61126836f0
COPY --from=build /out/caddy /usr/bin/caddy
