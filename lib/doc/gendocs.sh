#!/bin/bash

BASE=$(dirname $0)
DOCPROC="${BASE}/bin/docproc"
KERNELDOC="${BASE}/bin/kernel-doc"
TYPE=$1

compile() {
	gcc -o $DOCPROC ${DOCPROC}.c
}

cleanup() {
	rm -f $DOCPROC
	rm -f ${BASE}/*.pdf
	rm -f ${BASE}/*.xml
	rm -f ${BASE}/*.ps
	rm -f ${BASE}/*.t
	rm -rf ${BASE}/man/
	rm -rf ${BASE}/html/
}

if [ "$TYPE" = "clean" ]
then
	cleanup
	exit 0
fi

check_xmlto() {
	if ! $(which xmlto > /dev/null 2>&1)
	then
		echo "xmlto missing -- install xmlto"
		exit 0
	fi
}

check_db() {
	if ! $(which db2${TYPE} > /dev/null 2>&1)
	then
		echo "db2${TYPE} missing -- install docbook-utils"
		exit 0
	fi
}

compile

for i in ${BASE}/*.tmpl
do
	tmp=${i%%.tmpl}.t
	xmlfile=${i%%.tmpl}.xml
	cp -f $i $tmp
	sed -i "s/@@LIBVERSION@@/$LIBVERSION/" $tmp
	case "$TYPE" in
		"pdf")
			check_db
			SRCTREE=. $DOCPROC doc $tmp > $xmlfile
			db2pdf -o $BASE $xmlfile
			;;
		"ps")
			check_db
			SRCTREE=. $DOCPROC doc $tmp > $xmlfile
			db2ps -o $BASE $xmlfile
			;;
		"man")
			check_xmlto
			SRCTREE=. $DOCPROC doc $tmp > $xmlfile
			rm -rf ${BASE}/man > /dev/null 2>&1
			mkdir ${BASE}/man > /dev/null 2>&1
			xmlto man -m ${BASE}/stylesheet.xsl --skip-validation -o ${BASE}/man/ $xmlfile
			gzip -f ${BASE}/man/*.3
			;;
		"html")
			check_xmlto
			SRCTREE=. $DOCPROC doc $tmp > $xmlfile
			target=${BASE}/html/
			rm -rf $target
			mkdir $target > /dev/null 2>&1
			xmlto html -m ${BASE}/stylesheet.xsl --skip-validation -o $target $xmlfile
			;;
		*)
			echo "Unknown $TYPE"
			;;
	esac
done
