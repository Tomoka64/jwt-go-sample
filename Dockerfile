FROM golang:latest

WORKDIR /go
ADD . /go

RUN go get github.com/dgrijalva/jwt-go

CMD ["go", "run", "main.go"]