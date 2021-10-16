###############
# Build stage #
###############
ARG src_dir="/stayrtr"

FROM golang:alpine as builder
ARG src_dir

RUN apk --update --no-cache add git make && \
    mkdir -p ${src_dir}

WORKDIR ${src_dir}
COPY . .

RUN SUFFIX= make build-all

################
# Keygen stage #
################
FROM alpine:latest as keygen

RUN apk --update --no-cache add openssl
RUN openssl ecparam -genkey -name prime256v1 -noout -outform pem > private.pem

#################
# StayRTR stage #
#################
FROM alpine:latest AS stayrtr

RUN apk --update --no-cache add ca-certificates && \
    adduser -S -D -H -h / rtr
USER rtr
COPY --from=builder /stayrtr/dist/stayrtr /
COPY --from=keygen /private.pem /private.pem
ENTRYPOINT ["./stayrtr"]

#################
# RTRdump stage #
#################
FROM alpine:latest AS rtrdump

RUN apk --update --no-cache add ca-certificates && \
    adduser -S -D -H -h / rtr
USER rtr
COPY --from=builder /stayrtr/dist/rtrdump /
ENTRYPOINT ["./rtrdump"]

#################
# RTRmon stage #
#################
FROM alpine:latest AS rtrmon

RUN apk --update --no-cache add ca-certificates && \
    adduser -S -D -H -h / rtr
USER rtr
COPY --from=builder /stayrtr/dist/rtrmon /
ENTRYPOINT ["./rtrmon"]
