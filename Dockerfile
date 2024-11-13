FROM golang:1.22.0 as builder

WORKDIR /app

COPY go.* ./ 
RUN go mod download
COPY . ./

RUN CGO_ENABLED=0 GOOS=linux go build -v -o /out/main ./cmd/go-client

FROM alpine:3.12
COPY --from=builder /out/main /app/main

CMD ["/app/main"]
# CMD ["tail -f /dev/null"]
