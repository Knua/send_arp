# target dependency
# 	command

# 최상단의 all target 은 암묵적 약속
all: send_arp

# target 이 빌드되기 위해 command 명령어가 실행되는 조건 -> dependency 의 날짜가 target 보다 최신인 경우
send_arp: send_arp.o arp_packet.o
	g++ -o send_arp send_arp.o arp_packet.o

send_arp.o: send_arp.c arp_packet.h
	g++ -c -o send_arp.o send_arp.c

arp_packet.o: arp_packet.c arp_packet.h
	g++ -c -o arp_packet.o arp_packet.c

# 최하단의 clean target 또한 암묵적 약속
clean:
	rm -f send_arp *.o