EXTENSION ?= 
DIST_DIR ?= dist/
GOOS ?= linux
GOARCH ?= x86_64
ARCH ?= $(GOARCH)
BUILDINFOSDET ?= 

DOCKER_REPO   := rpki/
STAYRTR_NAME    := stayrtr
STAYRTR_VERSION := $(shell git describe --always --tags $(git rev-list --tags --max-count=1))
VERSION_PKG   := $(shell echo $(STAYRTR_VERSION) | sed 's/^v//g')
LICENSE       := BSD-3
URL           := https://github.com/bgp/stayrtr
DESCRIPTION   := StayRTR: a RPKI-to-Router server
BUILDINFOS    :=  ($(shell date +%FT%T%z)$(BUILDINFOSDET))
LDFLAGS       ?= '-X main.version=$(STAYRTR_VERSION) -X main.buildinfos=$(BUILDINFOS)'

RTRDUMP_NAME  := rtrdump
RTRMON_NAME   := rtrmon

SUFFIX ?= -$(STAYRTR_VERSION)-$(GOOS)-$(ARCH)$(EXTENSION)

OUTPUT_STAYRTR := $(DIST_DIR)stayrtr$(SUFFIX)
OUTPUT_RTRDUMP := $(DIST_DIR)rtrdump$(SUFFIX)
OUTPUT_RTRMON := $(DIST_DIR)rtrmon$(SUFFIX)

export CGO_ENABLED ?= 0


.PHONY: build-all
build-all: vet build-stayrtr build-rtrdump build-rtrmon

.PHONY: vet
vet:
	go vet cmd/stayrtr/stayrtr.go

.PHONY: test
test:
	go test -v github.com/bgp/stayrtr/lib
	go test -v github.com/bgp/stayrtr/prefixfile
	go test -v github.com/bgp/stayrtr/cmd/rtrmon
	go test -v github.com/bgp/stayrtr/cmd/stayrtr

.PHONY: prepare
prepare:
	mkdir -p $(DIST_DIR)

.PHONY: clean
clean:
	rm -rf $(DIST_DIR)

.PHONY: build-stayrtr
build-stayrtr: prepare
	go build -trimpath -ldflags $(LDFLAGS) -o $(OUTPUT_STAYRTR) cmd/stayrtr/stayrtr.go

.PHONY: build-rtrdump
build-rtrdump:
	go build -trimpath -ldflags $(LDFLAGS) -o $(OUTPUT_RTRDUMP) cmd/rtrdump/rtrdump.go

.PHONY: build-rtrmon
build-rtrmon:
	go build -trimpath -ldflags $(LDFLAGS) -o $(OUTPUT_RTRMON) cmd/rtrmon/rtrmon.go

.PHONY: docker
docker:
	docker build -t $(DOCKER_REPO)$(STAYRTR_NAME) --target stayrtr .
	docker build -t $(DOCKER_REPO)$(RTRDUMP_NAME) --target rtrdump .
	docker build -t $(DOCKER_REPO)$(RTRMON_NAME) --target rtrmon .

.PHONY: package-deb-stayrtr
package-deb-stayrtr: prepare
	fpm -s dir -t deb -n $(STAYRTR_NAME) -v $(VERSION_PKG) \
        --description "$(DESCRIPTION)"  \
        --url "$(URL)" \
        --architecture $(ARCH) \
        --license "$(LICENSE)" \
        --package $(DIST_DIR) \
		--after-install package/after-install-debian.sh \
		package/.keep=/usr/share/stayrtr/.keep \
        $(OUTPUT_STAYRTR)=/usr/bin/stayrtr \
        package/stayrtr.service=/lib/systemd/system/stayrtr.service \
        package/stayrtr.env=/etc/default/stayrtr \
        $(OUTPUT_RTRDUMP)=/usr/bin/rtrdump \
        $(OUTPUT_RTRMON)=/usr/bin/rtrmon

.PHONY: package-rpm-stayrtr
package-rpm-stayrtr: prepare
	fpm -s dir -t rpm -n $(STAYRTR_NAME) -v $(VERSION_PKG) \
	--description "$(DESCRIPTION)" \
	--url "$(URL)" \
	--architecture $(ARCH) \
	--license "$(LICENSE) "\
	$(OUTPUT_STAYRTR)=/usr/bin/stayrtr \
	package/.keep=/usr/share/stayrtr/.keep \
	package/stayrtr.service=/lib/systemd/system/stayrtr.service \
	package/stayrtr.env=/etc/default/stayrtr \
	$(OUTPUT_RTRDUMP)=/usr/bin/rtrdump \
	$(OUTPUT_RTRMON)=/usr/bin/rtrmon
	mv *.rpm dist/ # It's unclear why we need to do this, but i assume it's a FPM bug.
