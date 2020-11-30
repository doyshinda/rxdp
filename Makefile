.PHONY: docker-% dev test

docker: Dockerfile startup.sh
	docker build -t "rxdp:latest" .

dev:
	/bin/bash

test:
	cargo test

docker-%: docker
	docker run -ti --rm --privileged -v "$(PWD)":/rxdp -v /tmp/rxdp_cache/:/tmp/cache/ -e CARGO_HOME=/tmp/cache/ rxdp:latest make $*
