FROM golang:1.25 AS builder

WORKDIR /app

COPY go.mod go.sum ./

# 关键：提前复制 go.mod 中 replace 指向的本地模块
COPY packages/local-router ./packages/local-router

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o app .

FROM alpine:3.20

WORKDIR /app

RUN apk add --no-cache ca-certificates

COPY --from=builder /app/app .

EXPOSE 8080

CMD ["./app"]
