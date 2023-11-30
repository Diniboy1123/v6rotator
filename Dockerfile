FROM docker.io/golang:alpine AS builder

COPY src/ /src
WORKDIR /src

RUN apk add --no-cache upx

RUN go build -ldflags="-s -w" -o /tmp/v6rotator && \
    upx --lzma /tmp/v6rotator

FROM alpine:latest

COPY --from=builder /tmp/v6rotator /v6rotator
COPY setup_network.sh /setup_network.sh
RUN chmod +x /setup_network.sh

ENTRYPOINT ["/setup_network.sh"]