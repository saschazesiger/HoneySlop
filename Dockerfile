# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS TARGETARCH VERSION=dev
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/honeyslop .

FROM gcr.io/distroless/static-debian12
LABEL org.opencontainers.image.title="HoneySlop" \
      org.opencontainers.image.description="AI-powered honeypot: every request gets a convincing, LLM-generated vulnerable response" \
      org.opencontainers.image.source="https://github.com/saschazesiger/HoneySlop" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /out/honeyslop /honeyslop
ENV DATA_DIR=/data
VOLUME /data
EXPOSE 80 443
ENTRYPOINT ["/honeyslop"]
