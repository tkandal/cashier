FROM golang:latest as build
LABEL maintainer="trond.kandal@ntnu.no"
WORKDIR /build
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 GOOS=linux make install-cashierd

# FROM gcr.io/distroless/base
FROM debian:stable-slim
LABEL maintainer="nsheridan@gmail.com"
WORKDIR /cashier
COPY --from=build /go/bin/cashierd /
ENTRYPOINT ["/cashierd"]
