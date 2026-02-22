FROM	docker.io/library/golang AS builder

WORKDIR	/go/src/mdnsquery
COPY	. .

RUN	make

FROM	scratch
COPY	--from=builder /go/src/mdnsquery/mdnsquery /usr/local/bin/mdnsquery

ENTRYPOINT ["/usr/local/bin/mdnsquery"]
