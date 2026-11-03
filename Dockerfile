# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM node:24-bookworm-slim AS web
WORKDIR /src/web
RUN npm install --global pnpm@12.14.0
COPY web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml ./
RUN mkdir -p .agents/skills && pnpm install --frozen-lockfile
COPY web/ ./
RUN pnpm run build

FROM golang:1.27.3-bookworm AS api
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /out/auth-service . \
 && CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /out/oauthctl ./cmd/oauthctl

FROM debian:bookworm-slim
RUN apt-get update && apt-get install --yes --no-install-recommends ca-certificates openssl curl \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --gid 10001 app && useradd --uid 10001 --gid app --no-create-home app \
 && mkdir -p /app/data /app/keys && chown -R app:app /app
WORKDIR /app
COPY --from=api /out/auth-service /out/oauthctl ./
COPY --from=web /src/handlers/web/dist ./handlers/web/dist
COPY resources ./resources
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/app/auth-service"]
