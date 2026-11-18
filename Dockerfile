FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/dockyard ./cmd/dockyard

FROM alpine:3.21
RUN adduser -D -H -u 10001 dockyard
WORKDIR /app
COPY --from=build /out/dockyard /usr/local/bin/dockyard
RUN mkdir -p /data && chown dockyard:dockyard /data
USER dockyard
EXPOSE 8091
ENV DOCKYARD_ADDR=0.0.0.0:8091
ENV DOCKYARD_DATA_DIR=/data
ENTRYPOINT ["dockyard"]
