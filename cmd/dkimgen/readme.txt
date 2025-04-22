The DKIM key generation utility would be its own separate command that you could run independently to generate DKIM keys for your domains.
You would then build and run it using:

go build -o dkimgen ./cmd/dkimgen
./dkimgen --domain example.com --selector mail --output ./keys
