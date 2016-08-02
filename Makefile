arp_spoof: main.cpp
	g++ -o arp_spoof main.cpp -L./ -lpcap

clean:
	rm -f *.o arp_spoof

