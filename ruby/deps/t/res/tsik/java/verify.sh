#!/bin/sh
# verifies output from sxip
# 
java -classpath tsik.jar:. Verify ../../out_1.xml ../keys/Alice.cer
java -classpath tsik.jar:. Verify ../../out_2.xml
java -classpath tsik.jar:. Verify ../../out_3.xml



