# ovnkube-trace

See: ```https://docs.google.com/document/d/1mjYt5RsB70IV0NLqodDkIUJA0UVAn2PNKYEJ07QBhG4/edit#heading=h.wr55qteuwbni```

Note: That doc changed steps 4 & 8.  What's currently in the code reflects the earlier version of that doc.


To compile:

```export GO111MODULE=on go mod tidy && go mod vendor && go mod verify ```

```podman run --privileged --rm --env HOME=/root -v `pwd`:/src -w /src docker.io/library/golang:1.13 go build ovnkube-trace.go```



