#!/bin/sh
# verifies our own output
# 
java -classpath tsik.jar:. Verify ../in/out.xml
java -classpath tsik.jar:. Verify ../in/cert_only_out.xml


