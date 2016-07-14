pcap_test: pcap_test.c
	gcc -o pcap_test pcap_test.c -lpcap

clean:
	rm -f *.o pcap_test
