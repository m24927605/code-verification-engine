FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /usr/local/bin/cve ./cmd/cve

FROM alpine:3.20

RUN apk add --no-cache git

COPY --from=builder /usr/local/bin/cve /usr/local/bin/cve

RUN mkdir -p /workspace/output

ENTRYPOINT ["sleep", "infinity"]
