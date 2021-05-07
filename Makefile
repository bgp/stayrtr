EXTENSION ?= 
DIST_DIR ?= dist/
GOOS ?= linux
ARCH ?= $(shell uname -m)
BUILDINFOSDET ?= 

DOCKER_REPO   := bgp/
STAYRTR_NAME    := stayrtr
STAYRTR_VERSION := $(shell git describe --tags $(git rev-list --tags --max-count=1))
VERSION_PKG   := $(shell echo $(STAYRTR_VERSION) | sed 's/^v//g')
ARCH          := x86_64
LICENSE       := BSD-3
URL           := https://github.com/bgp/stayrtr
DESCRIPTION   := StayRTR: a RPKI-to-Router server
BUILDINFOS    :=  ($(shell date +%FT%T%z)$(BUILDINFOSDET))
LDFLAGS       := '-X main.version=$(STAYRTR_VERSION) -X main.buildinfos=$(BUILDINFOS)'

RTRDUMP_NAME  := rtrdump
RTRMON_NAME   := rtrmon

OUTPUT_STAYRTR := $(DIST_DIR)stayrtr-$(STAYRTR_VERSION)-$(GOOS)-$(ARCH)$(EXTENSION)
OUTPUT_RTRDUMP := $(DIST_DIR)rtrdump-$(STAYRTR_VERSION)-$(GOOS)-$(ARCH)$(EXTENSION)
OUTPUT_RTRMON := $(DIST_DIR)rtrmon-$(STAYRTR_VERSION)-$(GOOS)-$(ARCH)$(EXTENSION)

.PHONY: vet
vet:
	go vet cmd/stayrtr/stayrtr.go

.PHONY: test
test:
	go test -v github.com/bgp/stayrtr/lib
	go test -v github.com/bgp/stayrtr/prefixfile

.PHONY: prepare
prepare:
	mkdir -p $(DIST_DIR)

.PHONY: clean
clean:
	rm -rf $(DIST_DIR)

.PHONY: dist-key
dist-key: prepare
	cp cmd/stayrtr/cf.pub $(DIST_DIR)

.PHONY: build-stayrtr
build-stayrtr: prepare
	go build -ldflags $(LDFLAGS) -o $(OUTPUT_STAYRTR) cmd/stayrtr/stayrtr.go 

.PHONY: build-rtrdump
build-rtrdump:
	go build -ldflags $(LDFLAGS) -o $(OUTPUT_RTRDUMP) cmd/rtrdump/rtrdump.go 

.PHONY: build-rtrmon
build-rtrmon:
	go build -ldflags $(LDFLAGS) -o $(OUTPUT_RTRMON) cmd/rtrmon/rtrmon.go 

.PHONY: docker-stayrtr
docker-stayrtr:
	docker build -t $(DOCKER_REPO)$(STAYRTR_NAME):$(STAYRTR_VERSION) --build-arg LDFLAGS=$(LDFLAGS) -f Dockerfile.stayrtr .

.PHONY: docker-rtrdump
docker-rtrdump:
	docker build -t $(DOCKER_REPO)$(RTRDUMP_NAME):$(STAYRTR_VERSION) --build-arg LDFLAGS=$(LDFLAGS) -f Dockerfile.rtrdump .

.PHONY: docker-rtrmon
docker-rtrmon:
	docker build -t $(DOCKER_REPO)$(RTRMON_NAME):$(STAYRTR_VERSION) --build-arg LDFLAGS=$(LDFLAGS) -f Dockerfile.rtrmon .

.PHONY: package-deb-stayrtr
package-deb-stayrtr: prepare
	fpm -s dir -t deb -n $(STAYRTR_NAME) -v $(VERSION_PKG) \
        --description "$(DESCRIPTION)"  \
        --url "$(URL)" \
        --architecture $(ARCH) \
        --license "$(LICENSE)" \
        --package $(DIST_DIR) \
        $(OUTPUT_STAYRTR)=/usr/bin/stayrtr \
        package/stayrtr.service=/lib/systemd/system/stayrtr.service \
        package/stayrtr.env=/etc/default/stayrtr \
        cmd/stayrtr/cf.pub=/usr/share/stayrtr/cf.pub \
        $(OUTPUT_RTRDUMP)=/usr/bin/rtrdump \
        $(OUTPUT_RTRMON)=/usr/bin/rtrmon

.PHONY: package-rpm-stayrtr
package-rpm-stayrtr: prepare
	fpm -s dir -t rpm -n $(STAYRTR_NAME) -v $(VERSION_PKG) \
	--description "$(DESCRIPTION)" \
	--url "$(URL)" \
	--architecture $(ARCH) \
	--license "$(LICENSE) "\
	--package $(DIST_DIR) \
	$(OUTPUT_STAYRTR)=/usr/bin/stayrtr \
	package/stayrtr.service=/lib/systemd/system/stayrtr.service \
	package/stayrtr.env=/etc/default/stayrtr \
	cmd/stayrtr/cf.pub=/usr/share/stayrtr/cf.pub \
	$(OUTPUT_RTRDUMP)=/usr/bin/rtrdump \
	$(OUTPUT_RTRMON)=/usr/bin/rtrmon
