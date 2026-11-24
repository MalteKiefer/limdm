# Build the server from source. Release images are built by GoReleaser from
# the same static binary (Dockerfile.release).
FROM golang:1.27-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/limdm-server ./cmd/limdm-server

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/limdm-server /usr/bin/limdm-server
ENV LIMDM_CA_DIR=/var/lib/limdm-server/ca
VOLUME ["/var/lib/limdm-server"]
EXPOSE 8080 8444
USER 65532:65532
ENTRYPOINT ["/usr/bin/limdm-server"]
CMD ["serve"]
