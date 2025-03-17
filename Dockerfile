FROM golang:1.24-alpine

RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

COPY . .
RUN go mod download

RUN go build -o main ./cmd/main.go

RUN chown -R appuser:appgroup /app
USER appuser

CMD ["./main"]
