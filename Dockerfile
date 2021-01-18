FROM golang:alpine AS builder

WORKDIR /src
COPY . /src
RUN go build -o /fchannel-client

FROM alpine
COPY --from=builder /fchannel-client /fchannel-client
COPY ./static /static
ENTRYPOINT ["/fchannel-client"]
