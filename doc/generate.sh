#!/bin/bash

if [[ "$1" == "clean" ]]
then
	ls ./|grep -v 'Makefile\|txt\|generate'|xargs rm
else
	for page in *.txt;do a2x -f manpage $page;done
fi
