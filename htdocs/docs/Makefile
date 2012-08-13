all:
	for i in ../../doc/*txt;do cat $$i|sed 's;<[a-z-]\+@[a-z.]\+\(com\|net\|be\)>;;g' |sed  's;Report bugs to;Report bugs at http://sourceforge.net/projects/pam-abl/support;' > ./`basename $$i`;done
	for i in ./*txt;do a2x -D . -f xhtml $$i;done
	echo Done!
