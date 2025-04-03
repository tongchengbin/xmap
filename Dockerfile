FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o xmap main.go

# Create a minimal image
FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy the binary from builder
COPY --from=builder /app/xmap .
COPY --from=builder /app/pkg/probe /root/pkg/probe

# Set the entrypoint
ENTRYPOINT ["./xmap"]

# Default command
CMD ["-h"]
