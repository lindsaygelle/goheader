FROM golang:1.16

WORKDIR /go/src/github/lindsaygelle/w3g

COPY . .

RUN go mod download && go mod verify
