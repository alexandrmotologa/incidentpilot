# Stage 1: Build React 19 War Room Studio
FROM node:22-alpine AS ui-builder
WORKDIR /app/ui
COPY ui/package*.json ./
RUN npm ci
COPY ui ./
RUN npm run build

# Stage 2: Build Go Single Binary
FROM golang:1.24-alpine AS go-builder
WORKDIR /app
RUN apk add --no-cache git ca-certificates
COPY go.mod go.sum ./
RUN go mod download
COPY pkg ./pkg
COPY internal ./internal
COPY cmd ./cmd
COPY --from=ui-builder /app/internal/server/dist ./internal/server/dist
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/incidentpilot ./cmd/incidentpilot

# Stage 3: Minimal Production Container
FROM alpine:3.21
RUN apk add --no-cache git ca-certificates tzdata
WORKDIR /app
COPY --from=go-builder /bin/incidentpilot /usr/local/bin/incidentpilot
COPY incidentpilot.yaml runbooks.yaml ./

VOLUME /app/data
EXPOSE 8080

ENTRYPOINT ["incidentpilot"]
CMD ["serve", "--config", "/app/incidentpilot.yaml", "--port", "8080"]
