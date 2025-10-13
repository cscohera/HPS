#!/bin/bash
for u in $(awk -F: '$1!="root" && $3<1000 && $7!~/nologin|false/ {print $1}' /etc/passwd); do passwd -l $u; done