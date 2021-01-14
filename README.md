
Setup:

Install golang

Set these enviroment variables:
export GOROOT=/usr/lib/go
export GOPATH=$HOME/.local/go //or where ever you have you go src dir
export PATH="$PATH:$GOPATH/bin"

run
go get github.com/gomodule/redigo/redis //sessions
go get github.com/satori/go.uuid //sessions
go get github.com/lib/pq //database

create a database and user with psql and run
psql -U (user) -d (database) -f databaseschema.psql

set db user, password, name in main.go
set the Domain variable to the server you want to pull from
set the LocalDomain for this clients address

run
go run .

Note:
clientkey has the current key for this program execution. Use this to access admistration options. You will need boardaccess credientials from the server to do anything
The clientkey changes each time the program is executed