echo "Building intake..."
GOOS=linux GOARCH=amd64 time go build -o ../bin/intake-linux64 ../cmd/intake
echo "Building deliver..."
GOOS=linux GOARCH=amd64 time go build -o ../bin/deliver-linux64 ../cmd/deliver
echo "Building validate..."
GOOS=linux GOARCH=amd64 time go build -o ../bin/validate-linux64 ../cmd/validate
