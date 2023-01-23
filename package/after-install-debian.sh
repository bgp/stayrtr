#!/bin/sh

# Debian convention is to auto start software

systemctl daemon-reload
systemctl enable stayrtr
systemctl start stayrtr