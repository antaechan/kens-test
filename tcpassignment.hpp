/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_

#include <set>
#include <map>
#include <list>
#include <vector>
#include <string>

#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_TimerModule.hpp>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <E/E_TimeUtil.hpp>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>





namespace E {
	const Time TIMEOUT = TimeUtil::makeTime(120,TimeUtil::SEC);
	const Time RETRANS_TIMEOUT = TimeUtil::makeTime(100,TimeUtil::MSEC);

	/* MSS는 <= 2^16 B 보다 작아야 한다. data_offset 2B로 할당 */
	const uint32_t MSS = 1024;

	const uint32_t RECV_BUFFER_MAX_SIZE = 250000;
	const uint32_t SEND_BUFFER_MAX_SIZE = 250000;

	const uint32_t HEADER_SIZE = 54;
	const uint32_t TCP_HEADER_SIZE = 20;
	const uint32_t TCP_HEADER_OFFSET = HEADER_SIZE - TCP_HEADER_SIZE;

	const uint32_t SRCIP_SIZE = 4;
	const uint32_t DESTIP_SIZE = 4;

	const uint32_t HEADER_SRCIP_OFFSET = TCP_HEADER_OFFSET - SRCIP_SIZE - DESTIP_SIZE;
	const uint32_t HEADER_DESTIP_OFFSET = TCP_HEADER_OFFSET - DESTIP_SIZE;

	const uint16_t DEFAULT_WINDOW_SIZE = 50000;

	const uint8_t SYN = (1 << 1);
	const uint8_t ACK = (1 << 4);
	const uint8_t FIN = 1;
	
enum
{
	STATE_LISTEN,
	STATE_SYNSENT,
	STATE_ESTAB,
	STATE_SYNRCVD,
	STATE_FIN_WAIT_1,
	STATE_FIN_WAIT_2,
	STATE_TIME_WAIT,
	STATE_CLOSED,
	STATE_CLOSE_WAIT,
	STATE_CLOSING,
	STATE_LAST_ACK,
	RETRANS_CLOSE,
	RETRANS_DATA,
	RETRANS_SYN,
	RETRANS_FIN 
};

class Socket
{
	public:
		int fd, pid, backlog, status;

		uint32_t ip, peerip;
		uint16_t port, peerport;

		bool isBound, isAcceptBlocked, isReadBlocked, isWriteBlocked, isRetransTimerOn;


		/* BLOCK handling */
		UUID sysid;


		/* syscall connect, accept BLOCK */
		struct sockaddr_in * client_addr;
		socklen_t * addrlen;

		/* syscall write,read BLOCK */
		size_t count_saved;
		void * buffer_saved;
		
		UUID timer, retranstimer, syntimer, fintimer;

		uint32_t myseq, myack, peerseq, peerack;

		/* to prevent overflow */
		uint32_t peer_initial_seq_number, initial_seq_number;

		uint32_t peer_max_ack, expected_max_ack;
		uint32_t expected_ack_fin;
	
		std::set<Socket *> connecting, established;


		std::list<Packet *> recvBuffer;
		uint32_t recvstart, recvend;
		
		std::list<Packet *> sendBuffer;

		uint16_t peer_window_size;
		

		uint32_t fincnt;

		bool sentSYN, sentACK;
		
		Packet * syn_ack_packet;
		Packet * ack_packet;

	Socket()
	{
		sentSYN = sentACK = false;
		this->fd = this->pid = -1;
		ip = port = 0;
		peerip = peerport = 0;
		backlog = 0;
		sysid = 0;
		isAcceptBlocked = isReadBlocked = isWriteBlocked = false;
		this->isBound = false;

		this->status = STATE_CLOSED;
		this->myseq = this->myack = 0;
		this->peerseq = this->peerack = 0;

		this->peer_window_size = DEFAULT_WINDOW_SIZE;

		fincnt = 0;
	}

	void setSeqNumber(uint32_t seq_number) {
		this->myseq = seq_number;
	}
	void setAckNumber(uint32_t ack_number) {
		this->myack = ack_number;
	}
	void setPeerSeqNumber(uint32_t peer_seq_number) {
		this->peerseq = peer_seq_number;
	}
	void setPeerAckNumber(uint32_t peer_ack_number) {
		this->peerack = peer_ack_number;
	}

	void setIp(uint32_t ip) {
		this->ip = ip;
	}
	void setPort(uint32_t port) {
		this->port = port;
	}
	void setPeerIp(uint32_t peer_ip) {
		this->peerip = peer_ip;
	}
	void setPeerPort(uint32_t peer_port) {
		this->peerport = peer_port;
	}

	uint32_t getReadableDataSize();
	uint32_t getWriteableDataSize();
	uint32_t getRecvBufferSize();
	uint32_t getSendBufferSize();

	void writeRecvBuffer(Packet * packet)
	{
		uint32_t seqNumberInPacket, dataSizeInPacket;
		uint32_t seqNumberInRecvBuffer, dataSizeInRecvBuffer;
		Packet *packetInRecvBuffer;

		packet->readData(TCP_HEADER_OFFSET + 4, &seqNumberInPacket, 4);
		seqNumberInPacket = ntohl(seqNumberInPacket) - this->peer_initial_seq_number;

		dataSizeInPacket = packet->getSize() - HEADER_SIZE;

		auto iter = this->recvBuffer.begin();
		for(;iter != this->recvBuffer.end(); iter++) {
			packetInRecvBuffer = (*iter);

			packetInRecvBuffer->readData(TCP_HEADER_OFFSET + 4, &seqNumberInRecvBuffer, 4);
			seqNumberInRecvBuffer = ntohl(seqNumberInRecvBuffer) - this->peer_initial_seq_number;

			dataSizeInRecvBuffer = packetInRecvBuffer->getSize() - HEADER_SIZE;

			if(seqNumberInRecvBuffer + dataSizeInRecvBuffer > seqNumberInPacket + dataSizeInPacket)
				break;
		}
		
		this->recvBuffer.insert(iter, packet);

		for(iter = this->recvBuffer.begin(); iter != this->recvBuffer.end(); iter++)
		{
			packetInRecvBuffer = (*iter);
			packetInRecvBuffer->readData(TCP_HEADER_OFFSET + 4, &seqNumberInRecvBuffer, 4);
			seqNumberInRecvBuffer = ntohl(seqNumberInRecvBuffer) - this->peer_initial_seq_number;

			dataSizeInRecvBuffer = packetInRecvBuffer->getSize() - HEADER_SIZE;
			if(seqNumberInRecvBuffer <= this->recvend - this->peer_initial_seq_number){
				this->recvend = std::max(this->recvend - this->peer_initial_seq_number, seqNumberInRecvBuffer + dataSizeInRecvBuffer) + this->peer_initial_seq_number;
			}
		}

		this->myack = this->recvend;
	}

	void readRecvBuffer(void * buf, uint32_t count)
	{
		uint16_t data_offset;
		uint16_t initial_data_offset;

		uint32_t seqNumber, dataSize;

		Packet *packet;
		bool isReadableByte;

		for(auto iter = this->recvBuffer.begin(); iter != this->recvBuffer.end(); iter++)
		{
			packet = (*iter);
			
			packet->readData(TCP_HEADER_OFFSET + 4, &seqNumber, 4);
			packet->readData(TCP_HEADER_OFFSET + 18, &initial_data_offset, 2);

			seqNumber = ntohl(seqNumber)- this->peer_initial_seq_number;

			dataSize = packet->getSize() - HEADER_SIZE;

			for(data_offset = initial_data_offset; data_offset < dataSize; data_offset++)
			{
				isReadableByte = ((this->recvstart - this->peer_initial_seq_number) <= (seqNumber + data_offset))
				&& ((seqNumber + data_offset) < ((this->recvstart - this->peer_initial_seq_number) + count));

				if(isReadableByte){
					packet->readData(HEADER_SIZE + data_offset, ((uint8_t *)buf) + ((seqNumber + data_offset) - (this->recvstart - this->peer_initial_seq_number)), 1);
				}
				else break;				
			}

			packet->writeData(TCP_HEADER_OFFSET + 18, &data_offset, 2);
		}

		/* Received에 count만큼의 data가 할당된 Packet을 모두 지운다 */
		for(auto iter = this->recvBuffer.begin(); iter != this->recvBuffer.end(); iter++)
		{
			packet = (*iter);
			packet->readData(TCP_HEADER_OFFSET + 4, &seqNumber, 4);

			packet->readData(TCP_HEADER_OFFSET + 18, &data_offset, 2);

			seqNumber = ntohl(seqNumber) - this->peer_initial_seq_number;
			dataSize = packet->getSize() - HEADER_SIZE;

			if(((seqNumber + dataSize) <= ((this->recvstart - this->peer_initial_seq_number) + count)) 
			&& (data_offset == dataSize)) {
				iter = this->recvBuffer.erase(iter);
			}
			else break;
		}

		this->recvstart += count;
	}


	void insertSendBuffer(Packet * packet)
	{

		uint32_t seqNumberInSendBuffer, dataSizeinSendBuffer;
		uint32_t seqNumberInPacket, dataSizeInPacket;
		Packet *packetInSendBuffer;

		packet->readData(TCP_HEADER_OFFSET + 4, &seqNumberInPacket, 4);
		seqNumberInPacket = ntohl(seqNumberInPacket) - this->initial_seq_number;

		dataSizeInPacket = packet->getSize() - HEADER_SIZE;

		auto iter = this->sendBuffer.begin();
		for(; iter!=this->sendBuffer.end(); iter++)
		{
			packetInSendBuffer = (*iter);

			packetInSendBuffer->readData(TCP_HEADER_OFFSET + 4, &seqNumberInSendBuffer, 4);
			seqNumberInSendBuffer = ntohl(seqNumberInSendBuffer) - this->initial_seq_number;

			dataSizeinSendBuffer = packetInSendBuffer->getSize() - HEADER_SIZE;

			if(seqNumberInSendBuffer + dataSizeinSendBuffer > seqNumberInPacket + dataSizeInPacket)
				break;
		}

		this->sendBuffer.insert(iter, packet);
	}

	void removeSendBuffer()
	{
		uint32_t seqNumber, dataSize;
		Packet *packet;
		
		for(auto iter = this->sendBuffer.begin(); iter != this->sendBuffer.end(); ){
			packet = (*iter);
			packet->readData(TCP_HEADER_OFFSET + 4, &seqNumber, 4);

			seqNumber = ntohl(seqNumber) - this->initial_seq_number;

			dataSize = packet->getSize() - HEADER_SIZE;

			if(seqNumber + dataSize <= this->peer_max_ack - this->initial_seq_number)
				iter = this->sendBuffer.erase(iter);
			else {
				break;
			}
		}
	}

};

class SocketTimer
{
	public:
		int retrans_status;
		Socket * socket;
		Packet * packet;
};

 /*
    TCP Header 
 */
class TCPHeader {
	private:

		/* host order 상태로 저장 */
		uint16_t srcPort;
		uint16_t destPort;

		uint32_t seqNumber;
		uint32_t ackNumber;

		uint8_t flags;

		uint16_t winSize;

		uint16_t data_offset = 0;

		bool isSYN, isACK, isFIN;

		uint8_t mask = 5 << 4;

	public:
		TCPHeader() {
		}

	    TCPHeader(uint16_t srcPort, uint16_t destPort, uint32_t seqNumber, uint32_t ackNumber, uint8_t flags, uint16_t winSize) {
			this->srcPort = srcPort;
			this->destPort = destPort;
			this->seqNumber = seqNumber;
			this->ackNumber = ackNumber;
			this->flags = flags;
			this->winSize = winSize;
		}

		void readHeader(Packet *packet) {
			
			packet->readData(34 + 0, &srcPort, 2);
			packet->readData(34 + 2, &destPort, 2);

			packet->readData(34 + 4, &seqNumber, 4);
			seqNumber = ntohl(seqNumber);
			
			packet->readData(34 + 8, &ackNumber, 4);
			ackNumber = ntohl(ackNumber);
			
			packet->readData(34 + 13, &flags, 1);
			packet->readData(34 + 14, &winSize, 2);
			winSize = ntohs(winSize);

			isSYN = !!(flags & SYN);
			isACK = !!(flags & ACK);
			isFIN = !!(flags & FIN);
		}

		void writeHeader(Packet *packet) {

			packet->writeData(34 + 0, &srcPort, 2);
			packet->writeData(34 + 2, &destPort, 2);

			seqNumber = htonl(seqNumber);
			packet->writeData(34 + 4, &seqNumber, 4);
			seqNumber = ntohl(seqNumber);

			ackNumber = htonl(ackNumber);
			packet->writeData(34 + 8, &ackNumber, 4);
			ackNumber = ntohl(ackNumber);

			packet->writeData(34 + 12, &mask, 1);
			packet->writeData(34 + 13, &flags, 1);

			winSize = htons(winSize);
			packet->writeData(34 + 14, &winSize, 2);
			winSize = ntohs(winSize);

			/* Data offset default 값 0으로 설정 */
			packet->writeData(34 + 18, &data_offset, 2);
		}

		uint16_t getSrcPort(){
			return this->srcPort;
		}

		uint16_t getDestPort(){
			return this->destPort;
		}

		uint32_t getSeqNumber(){
			return this->seqNumber;
		}

		uint32_t getAckNumber(){
			return this->ackNumber;
		}

		bool getSYN() {
			return this->isSYN;
		}

		bool getACK() {
			return this->isACK;
		}
		
		bool getFIN() {
			return this->isFIN;
		}

		uint16_t getWindowSize(){
			return this->winSize;
		}

};

/* 
 Packet의 정보를 저장하는 class
*/
class PacketHolder {
	private:
		uint32_t srcIp;
		uint32_t destIp;
		
		TCPHeader *tcp_header;

		uint32_t dataSize;

		/* host order */
		uint16_t checksum;

		/* checksum을 계산하기 위해 필요 */
		uint8_t packetBuffer[HEADER_SIZE + MSS];

		uint8_t mask = 5 << 4;
	
	public:
		PacketHolder(){
		}

		PacketHolder(
			uint32_t srcIp,
			uint32_t destIp,
			uint16_t srcPort,
			uint16_t destPort,
			uint32_t seqNumber,
			uint32_t ackNumber,
			uint8_t flags,
			uint16_t winSize,
			uint8_t *data,
			uint32_t dataSize
		) {
			this->srcIp = srcIp;
			this->destIp = destIp;

			TCPHeader *tcp_header = new TCPHeader(
				srcPort,
				destPort,
				seqNumber,
				ackNumber,
				flags,
				winSize
			);
			this->tcp_header = tcp_header;

			this->dataSize = dataSize;

			memset(packetBuffer, 0, HEADER_SIZE + MSS);

			memcpy(packetBuffer + 34 - 8, &srcIp, 4);
			memcpy(packetBuffer + 34 - 4, &destIp, 4);


			memcpy(packetBuffer + 34 + 0, &srcPort, 2);
			memcpy(packetBuffer + 34 + 2, &destPort, 2);

			seqNumber = htonl(seqNumber);
			memcpy(packetBuffer + 34 + 4, &seqNumber, 4);
			seqNumber = ntohl(seqNumber);

			ackNumber = htonl(ackNumber);
			memcpy(packetBuffer + 34 + 8, &ackNumber, 4);
			ackNumber = ntohl(ackNumber);

			memcpy(packetBuffer + 34 + 12, &mask, 1);
			memcpy(packetBuffer + 34 + 13, &flags, 1);

			winSize = htons(winSize);
			memcpy(packetBuffer + 34 + 14, &winSize, 2);
			winSize = ntohs(winSize);

			/* copy data */
			if(data != NULL)
				memcpy(packetBuffer + HEADER_SIZE, data, dataSize);
		}

		void readPacket(Packet *packet){

			packet->readData(34 - 8, &srcIp, 4);
			packet->readData(34 - 4, &destIp, 4);

			TCPHeader *tcp_header = new TCPHeader;
			tcp_header->readHeader(packet);
			this->tcp_header = tcp_header;

			this->dataSize = packet->getSize() - HEADER_SIZE;

			packet->readData(34 + 16, &checksum, 2);
			checksum = ntohs(checksum);

			memset(packetBuffer, 0, HEADER_SIZE + MSS);
			packet->readData(0, packetBuffer, packet->getSize());
		}

		void writePacket(Packet *packet){
			
			packet->writeData(34 - 8, &srcIp, 4);
			packet->writeData(34 - 4, &destIp, 4);

			tcp_header->writeHeader(packet);

			if(dataSize > 0)
				packet->writeData(HEADER_SIZE, packetBuffer + HEADER_SIZE, dataSize);


			checksum = calculateCheckSum();
			checksum = htons(checksum);
			packet->writeData(34 + 16, &checksum, 2);
			checksum = ntohs(checksum);
		}

		bool isCheckSumValid(){

			bool isCheckSumValid = true;
			
			/* both host order */
			if(checksum != calculateCheckSum())
				isCheckSumValid = false;
			  
			return isCheckSumValid;
		}

		uint16_t calculateCheckSum()
		{
			uint16_t checksum, tempsum;

			memset(packetBuffer + TCP_HEADER_OFFSET + 16, 0, 2);
			tempsum = NetworkUtil::tcp_sum(srcIp, destIp, packetBuffer + TCP_HEADER_OFFSET, TCP_HEADER_SIZE + dataSize);

			checksum = ~tempsum;

			if(checksum == 0xFFFF){
				checksum = 0;
			}
			return checksum;
		}
		
		uint32_t getDestIp(){
			return this->destIp;
		}

		uint32_t getSrcIp(){
			return this->srcIp;
		}

		uint16_t getDestPort(){
			return this->tcp_header->getDestPort();
		}

		uint16_t getSrcPort(){
			return this->tcp_header->getSrcPort();
		}

		uint32_t getSeqNumber(){
			return this->tcp_header->getSeqNumber();
		}

		uint32_t getAckNumber(){
			return this->tcp_header->getAckNumber();
		}
		
		bool getSYN() {
			return this->tcp_header->getSYN();
		}

		bool getACK() {
			return this->tcp_header->getACK();
		}
		
		bool getFIN() {
			return this->tcp_header->getFIN();
		}

		uint16_t getWindowSize(){
			return this->tcp_header->getWindowSize();
		}

		uint32_t getDataSize(){
			return this->dataSize;
		}
};

class TCPAssignment : 
    public HostModule,
    private RoutingInfoInterface,
    public SystemCallInterface,
    public NetworkSystem,
    public TimerModule {
		private:
			
			
			std::map<std::pair<int,int>, Socket *> pidfd_to_socket;
			
			std::map<std::tuple<uint32_t, uint16_t, uint32_t, uint16_t>, Socket * > srcdest_to_socket;
			std::map<std::pair<uint32_t, uint16_t>, Socket * > syn_ready;
			std::set<std::pair<uint32_t, uint16_t> > bound_set;

			std::map<uint16_t, std::set<uint32_t> > port_to_bound_ip;
        
		private:
			virtual void timerCallback(std::any payload) final;
			

		public:
			TCPAssignment(Host &host);
			virtual void initialize();
			virtual void finalize();
			virtual ~TCPAssignment();

		protected:
			virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter &param) final;

			virtual void syscall_socket(UUID syscallUUID, int pid, int domain, int protocol);
			virtual void syscall_close(UUID syscallUUID, int pid, int fd_to_close);
			virtual void close_cleanup(UUID syscallUUID, int pid, int fd_to_close, Socket *);
			virtual void syscall_getsockname(UUID syscallUUID, int pid, int fd, struct sockaddr * addr, socklen_t * len);
			virtual void syscall_bind(UUID syscallUUID, int pid, int fd, struct sockaddr *, socklen_t);
			virtual void syscall_connect(UUID syscallUUID, int pid, int fd, struct sockaddr * addr, socklen_t len);
			virtual void syscall_listen(UUID syscallUUID, int pid, int fd, int backlog);
			virtual void syscall_accept(UUID syscallUUID, int pid, int fd, struct sockaddr * addr, socklen_t * addrlen);
			virtual void syscall_getpeername(UUID syscallUUID, int pid, int fd, struct sockaddr * addr, socklen_t * len);
			virtual void syscall_read(UUID syscallUUID, int pid, int fd, void * buf, size_t count);
			virtual void syscall_write(UUID syscallUUID, int pid, int fd, void * buf, size_t count);
			

			virtual Socket * find_connected_socket(std::tuple<uint32_t, uint16_t, uint32_t, uint16_t> key);
			virtual Socket * find_handshake_socket(std::pair<uint32_t, uint16_t> key);	
			virtual Socket * find_established_socket(std::tuple<uint32_t, uint16_t, uint32_t, uint16_t> key);

			virtual Packet * allocatePacket(size_t size);
			virtual Packet sendPacketForm(Packet *packet);
			virtual Packet *clonePacket(Packet *packet);
			virtual void packetArrived(std::string fromModule, Packet &&packet) final;
		};

	class TCPAssignmentProvider {
		private:
		TCPAssignmentProvider() {}
		~TCPAssignmentProvider() {}

		public:
		static void allocate(Host &host) { host.addHostModule<TCPAssignment>(host); }
	};
} // namespace E

#endif /* E_TCPASSIGNMENT_HPP_ */