.PHONY: docker-% dev test bench

docker: Dockerfile startup.sh
	docker build -t "rxdp:latest" .
	touch docker

dev:
	/bin/bash

test:
	cargo test

bench:
	cargo bench

docker-%: docker
	docker run -ti --rm --privileged -v "$(PWD)":/rxdp -v /tmp/rxdp_cache/:/tmp/cache/ -e CARGO_HOME=/tmp/cache/ rxdp:latest make $*
