#!/bin/bash

rm -f mirai.oxt && \
zip -r mirai.oxt ../Accelerators.xcu ../Addons.xcu ../description.xml ../main.py ../META-INF/ ../registration/ ../assets/ ../icons/ \
   -x "dist/*" -x "*.git*" -x "*.DS_Store"
