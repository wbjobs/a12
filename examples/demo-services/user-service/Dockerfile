FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY main.go .
RUN CGO_ENABLED=0 go build -o user-service main.go

FROM alpine:latest
COPY --from=builder /app/user-service /usr/local/bin/
EXPOSE 8082
CMD ["user-service"]
