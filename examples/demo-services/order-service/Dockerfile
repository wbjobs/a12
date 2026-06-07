FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY main.go .
RUN CGO_ENABLED=0 go build -o order-service main.go

FROM alpine:latest
COPY --from=builder /app/order-service /usr/local/bin/
EXPOSE 8083
CMD ["order-service"]
