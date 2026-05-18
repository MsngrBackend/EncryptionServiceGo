FROM golang:1.26-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/encryption-service ./cmd


FROM alpine:3.23

WORKDIR /app

COPY --from=builder /app/encryption-service .

EXPOSE 8081

CMD ["./encryption-service"]