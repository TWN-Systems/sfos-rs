# Packaging for sfos-rs. See docs/packaging.md.
#
#   make docker   # build the minimal scratch container image
#   make deb      # build the static, dependency-free .deb into dist/
#   make clean    # remove dist/

IMAGE ?= sfos-rs
TAG   ?= local

.PHONY: docker deb clean

docker:
	docker build -t $(IMAGE):$(TAG) .

deb:
	packaging/deb/build-deb.sh

clean:
	rm -rf dist
