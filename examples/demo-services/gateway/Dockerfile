FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY main.go .
RUN CGO_ENABLED=0 go build -o gateway main.go

FROM alpine:latest
COPY --from=builder /app/gateway /usr/local/bin/
EXPOSE 8081
CMD ["gateway"]
