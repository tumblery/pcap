pcap_test: pcap_test.o
	gcc -o pcap_test pcap_test.o

pcap_test.o: pcap_test.c
	gcc -c -o pcap_test.o pcap_test.c

clean:
	rm -f *.o pcap_test
