all:
	cd ./src/file-5.09	&&	sh configure
	cd ./src/libxml2-2.7.2	&& 	sh configure 	&& 	make
	cd ./src/pcre-8.33	&& 	sh configure 	&& 	make
	cd ./src/zlib-1.2.7	&& 	sh configure 	&& 	make
	cd ./src/PF_RING	&& 	make
install:
	cd ./src/file-5.09 	&& 	make install
	cd ./src/libxml2-2.7.2 	&& 	make install
	cd ./src/pcre-8.33 	&& 	make install
	cd ./src/zlib-1.2.7	&& 	make install
	cd ./src/PF_RING/kernel 	&& 	insmod pf_ring.ko
	cd ./src/Email 		&& 	make
	cd ./src/FTP 		&& 	make
	cd ./src/		&& 	make
clean:
	cd ./src/Email 		&& 	make clean
	cd ./src/FTP 		&& 	make clean
	cd ./src/file-5.09	&&	make clean
	cd ./src/libxml2-2.7.2	&& 	make clean
	cd ./src/pcre-8.33	&& 	make clean
	cd ./src/zlib-1.2.7 	&& 	make clean
	cd ./src/PF_RING	&& 	make clean
	cd ./src/		&& 	make clean
