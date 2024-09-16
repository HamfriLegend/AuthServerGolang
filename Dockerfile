FROM golang:1.23

WORKDIR /build
COPY go.mod go.sum ./

RUN go mod download && go mod verify

COPY . .
RUN go build -v -o main .
CMD ["./main"]
