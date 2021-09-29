FROM golang:1.17.1-alpine AS builder

LABEL maintainer="Alireza Josheghani <josheghani.dev@gmail.com>"

# Creating work directory
WORKDIR /build

# Adding project to work directory
ADD . /build

# build project
RUN go build -o server .

FROM alpine AS app

WORKDIR /godns
COPY --from=builder /build/server /godns/server

EXPOSE 53

ENTRYPOINT ["/godns/server"]
CMD ["--config-file", "/data/config.yaml"]
