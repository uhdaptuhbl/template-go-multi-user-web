# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Build stage
# ---------------------------------------------------------------------------
FROM golang:1.27-bookworm AS build

WORKDIR /src

# Dependencies first, so a source-only change does not re-download the module
# cache on every build.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

# CGO is disabled so the result is a static binary the distroless static image
# can run with no libc present.
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
    -o /out/service ./cmd/service

# ---------------------------------------------------------------------------
# Runtime stage
# ---------------------------------------------------------------------------
# distroless/static carries CA certificates, timezone data, and nothing else:
# no shell, no package manager, and a non-root user by default.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/service /usr/local/bin/service

# The application listener only. The administrative listener binds loopback by
# default and is deliberately not published; reaching it requires setting
# SERVICE_ADMIN_ADDR and a network policy that restricts who may connect.
EXPOSE 8080

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/service"]
