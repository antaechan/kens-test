/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#include "TCPAssignment.hpp"
#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Packet.hpp>
#include <cerrno>
#include <map>
#include <any>

/*
  20190366 AnTaechan
  20200639 ChaeWoojin
*/

#define mp(X, Y) std::make_pair(X, Y)
#define mt(X, Y, Z, W) std::make_tuple(X, Y, Z, W)

namespace E
{	
	TCPAssignment::TCPAssignment(Host &host): 
		HostModule("TCP", host), RoutingInfoInterface(host),
		SystemCallInterface(AF_INET, IPPROTO_TCP, host),
		TimerModule("TCP", host) {}

	TCPAssignment::~TCPAssignment()
	{

	}

	void TCPAssignment::initialize()
	{

	}

	void TCPAssignment::finalize()
	{

	}

	void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int protocol)
	{
		Socket *socket = new Socket;
		int fd = this->createFileDescriptor(pid);

		socket->fd = fd;
		socket->pid = pid;
		this->pidfd_to_socket[mp(pid, fd)] = socket;

		this->returnSystemCall(syscallUUID, fd);
	}

	void TCPAssignment::close_cleanup(UUID syscallUUID, int pid, int fd, Socket * mysock)
	{
		if(this->pidfd_to_socket.find(mp(pid, fd)) == this->pidfd_to_socket.end()){
			this->returnSystemCall(syscallUUID, -1);
			return;
		}
		
		if(this->pidfd_to_socket[mp(pid, fd)]->isBound == true)
		{
			auto ip = this->pidfd_to_socket[mp(pid, fd)]->ip;
			auto port = this->pidfd_to_socket[mp(pid, fd)]->port;
			this->bound_set.erase(mp(ip, port));
			this->port_to_bound_ip[port].erase(ip);
			this->pidfd_to_socket[mp(pid, fd)]->isBound = false;
		}
		for(auto it = this->srcdest_to_socket.begin(); it!=this->srcdest_to_socket.end(); it++)
		{
			if(it->second == this->pidfd_to_socket[mp(pid, fd)])
			{
				this->srcdest_to_socket.erase(it);
				break;
			}
		}
		for(auto it = this->syn_ready.begin(); it!=this->syn_ready.end(); it++)
		{
			if(it->second == this->pidfd_to_socket[mp(pid, fd)])
			{
				this->syn_ready.erase(it);
				break;
			}
		}

		this->pidfd_to_socket[mp(pid, fd)]->recvBuffer.clear();
		this->pidfd_to_socket[mp(pid, fd)]->sendBuffer.clear();
		this->pidfd_to_socket[mp(pid, fd)]->connecting.clear();
		this->pidfd_to_socket[mp(pid, fd)]->established.clear();
		delete this->pidfd_to_socket[mp(pid, fd)];
		this->pidfd_to_socket.erase(mp(pid, fd));
		this->removeFileDescriptor(pid, fd);

		this->returnSystemCall(syscallUUID, 0);
	}

	void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd)
	{
		if(this->pidfd_to_socket.find(mp(pid, fd)) == this->pidfd_to_socket.end()) {
			this->returnSystemCall(syscallUUID, -1);
			return;
		}

		Socket *current_socket = this->pidfd_to_socket[mp(pid, fd)];

		switch(current_socket->status)
		{
			case STATE_SYNSENT:
				current_socket->status = STATE_CLOSED;
				this->close_cleanup(syscallUUID, pid, fd, current_socket);
				return;

			case STATE_ESTAB:
			case STATE_SYNRCVD:
				current_socket->status = STATE_FIN_WAIT_1;
				current_socket->sysid = syscallUUID;
				break;

			case STATE_CLOSE_WAIT:
				current_socket->status = STATE_LAST_ACK;
				current_socket->sysid = syscallUUID;
				break;

			default:
				this->close_cleanup(syscallUUID, pid, fd, current_socket);
				return;
		}
		
		Packet *fin_packet = this->allocatePacket(HEADER_SIZE);

		PacketHolder *packet_holder = new PacketHolder(
			current_socket->ip,
			current_socket->peerip,
			current_socket->port,
			current_socket->peerport, 
			current_socket->myseq,
			current_socket->myack,
			FIN,
			DEFAULT_WINDOW_SIZE,
			NULL,
			0
		);

		packet_holder->writePacket(fin_packet);
		delete packet_holder;
		
		this->sendPacket("IPv4", this->sendPacketForm(fin_packet));

		current_socket->expected_ack_fin = current_socket->myseq + 1;

		SocketTimer *payload = new SocketTimer;
		payload->socket = current_socket;
		payload->packet = fin_packet;
		payload->retrans_status = RETRANS_FIN;
		current_socket->fintimer = this->addTimer((void*)payload, RETRANS_TIMEOUT);
		current_socket->myseq++;
	}

	void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int fd, struct sockaddr * addr, socklen_t len)
	{
		 /* No such socket exists */
		if(this->pidfd_to_socket.find(mp(pid, fd)) == this->pidfd_to_socket.end()){
			this->returnSystemCall(syscallUUID, -1);
			return;
		}

		/* socket is already bound */
		if(this->pidfd_to_socket[mp(pid, fd)]->isBound){
			this->returnSystemCall(syscallUUID, -1);
			return;
		}

		Socket *socket = this->pidfd_to_socket[mp(pid, fd)];
		struct sockaddr_in * socket_addr = (struct sockaddr_in *)addr;

		auto ip_port = mp(socket_addr->sin_addr.s_addr, socket_addr->sin_port);
		if(ip_port.first == htonl(INADDR_ANY) && (!this->port_to_bound_ip[ip_port.second].empty()))
		{
			/* Check if it trys to occupy same pair of Ip and Port */
			this->returnSystemCall(syscallUUID, -1);
			return;

		}
		
		if(this->bound_set.find(ip_port) != this->bound_set.end()
		|| this->bound_set.find(mp(htonl(INADDR_ANY), ip_port.second)) != this->bound_set.end()){
			/* another socket is already bound to this addr */
			this->returnSystemCall(syscallUUID, -1);
		}

		this->bound_set.insert(ip_port);
		this->port_to_bound_ip[ip_port.second].insert(ip_port.first);
		socket->ip = ip_port.first;
		socket->port = ip_port.second;
		socket->isBound = true;
		this->returnSystemCall(syscallUUID, 0);

	}

	void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int fd, struct sockaddr * addr, socklen_t * len)
	{
		if(this->pidfd_to_socket.find(mp(pid, fd)) == this->pidfd_to_socket.end() || *len < sizeof(struct sockaddr)){
			this->returnSystemCall(syscallUUID, -1);
			return;
		}

		Socket *current_socket = this->pidfd_to_socket[mp(pid, fd)];
		
		/* Store socket's address on structure 'addr' */
		((struct sockaddr_in *)addr)->sin_family = AF_INET;
		((struct sockaddr_in *)addr)->sin_addr.s_addr = current_socket->ip;
		((struct sockaddr_in *)addr)->sin_port = current_socket->port;

		this->returnSystemCall(syscallUUID, 0);
	}

	void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int fd, struct sockaddr * addr, socklen_t * len)
	{
		if(this->pidfd_to_socket.find(mp(pid, fd)) == this->pidfd_to_socket.end()){
			this->returnSystemCall(syscallUUID, -1);
			return;
		}

		Socket *current_socket = this->pidfd_to_socket[mp(pid, fd)];		

		((struct sockaddr_in *)addr)->sin_family = AF_INET;
		((struct sockaddr_in *)addr)->sin_addr.s_addr = current_socket->peerip;
		((struct sockaddr_in *)addr)->sin_port = current_socket->peerport;
		
		this->returnSystemCall(syscallUUID, 0);
	}

	void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int fd, struct sockaddr * addr, socklen_t len)
	{
		char str_buffer[128];
		uint32_t srcip;
		uint16_t srcport;
		uint16_t checksum;

		struct sockaddr_in * serv_addr = (struct sockaddr_in *)addr;
		uint32_t servip = serv_addr->sin_addr.s_addr;
		if(this->pidfd_to_socket.find(mp(pid, fd)) == this->pidfd_to_socket.end())
			this->returnSystemCall(syscallUUID, -1);
		

		Socket *current_socket = pidfd_to_socket[mp(pid, fd)];

		if(current_socket->status == STATE_SYNSENT)
			this->returnSystemCall(syscallUUID, -1);
		
		if(current_socket->status == STATE_ESTAB)
			this->returnSystemCall(syscallUUID, -1);
		

		current_socket->myseq = current_socket->initial_seq_number = random();
		
		if(!current_socket->isBound)
		{
			ipv4_t d_ip;
			/* inet_addr */
			d_ip[0] = (servip >> 24)&0xff;
			d_ip[1] = (servip >> 16)&0xff;
			d_ip[2] = (servip >> 8)&0xff;
			d_ip[3] = servip &0xff;

			int interface = getRoutingTable((const ipv4_t)d_ip);
			std::optional<ipv4_t> test_ip = getIPAddr(interface);
			if(test_ip.has_value()) {
				ipv4_t s_ip = test_ip.value();
				snprintf(str_buffer, sizeof(str_buffer), "%u.%u.%u.%u", s_ip[0], s_ip[1], s_ip[2], s_ip[3]);
				srcip = inet_addr(str_buffer);
			}
			do { current_socket->port = random() % 65536; } 
			while(this->port_to_bound_ip[current_socket->port].find(srcip) != this->port_to_bound_ip[current_socket->port].end());
			this->port_to_bound_ip[current_socket->port].insert(srcip);
			this->bound_set.insert(mp(srcip, current_socket->port));
		} 
		else /* already bound */
		{
			srcip = current_socket->ip;
			srcport = current_socket->port;
		}
		current_socket->ip = srcip;  
		current_socket->port = srcport;  
		current_socket->isBound = true;

		/* send SYN packet */
		Packet *synpacket = this->allocatePacket(HEADER_SIZE);

		PacketHolder *packet_holder = new PacketHolder(
			srcip,
			servip,
			current_socket->port,
			serv_addr->sin_port,
			current_socket->myseq,
			0,
			SYN,
			DEFAULT_WINDOW_SIZE,
			NULL,
			0
		);

		packet_holder->writePacket(synpacket);
		delete packet_holder;

		current_socket->sysid = syscallUUID;
		current_socket->status = STATE_SYNSENT;
		current_socket->peerip = servip;
		current_socket->peerport = serv_addr->sin_port;
		this->srcdest_to_socket[mt(current_socket->ip, current_socket->port, servip, serv_addr->sin_port)] = current_socket;
		this->syn_ready[mp(current_socket->ip, current_socket->port)] = current_socket;
		this->sendPacket("IPv4", this->sendPacketForm(synpacket));

		SocketTimer * pay = new SocketTimer;
		pay->retrans_status = RETRANS_SYN;
		pay->socket = current_socket;
		pay->packet = synpacket;

		if(current_socket->sentSYN)	this->cancelTimer(current_socket->syntimer);
		current_socket->syntimer = this->addTimer((void*)pay, RETRANS_TIMEOUT);
		current_socket->sentSYN = true;
		current_socket->myseq++;
	}

	void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int fd, int backlog)
	{
		Socket *current_socket = this->pidfd_to_socket[mp(pid, fd)];

		current_socket->status = STATE_LISTEN;
		current_socket->backlog = backlog;

		this->syn_ready[mp(current_socket->ip, current_socket->port)] = current_socket;

		this->returnSystemCall(syscallUUID, 0);
	}

	void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int fd, struct sockaddr * addr, socklen_t * addrlen)
	{
		if(this->pidfd_to_socket.find(mp(pid, fd)) == this->pidfd_to_socket.end())
		{
			this->returnSystemCall(syscallUUID, -1);
			return;
		}
		auto welcsock = this->pidfd_to_socket[mp(pid, fd)];
		if(welcsock->status != STATE_LISTEN)
		{
			this->returnSystemCall(syscallUUID, -1);
			return;
		}
		if(!welcsock->established.empty())
		{
			auto newsock = *(welcsock->established.begin());
			welcsock->established.erase(welcsock->established.begin());
			int newfd = this->createFileDescriptor(pid);
			newsock->fd = newfd;
			newsock->pid = pid;
			this->pidfd_to_socket[mp(pid, newfd)] = newsock;
			welcsock->isAcceptBlocked = false;
			*addrlen = sizeof(struct sockaddr_in);
			struct sockaddr_in * clntaddr = (struct sockaddr_in *)addr;
			clntaddr->sin_family = AF_INET;
			clntaddr->sin_port = newsock->peerport;
			clntaddr->sin_addr.s_addr = newsock->peerip;
			this->srcdest_to_socket[mt(newsock->ip, newsock->port, newsock->peerip, newsock->peerport)] = newsock;
			this->returnSystemCall(syscallUUID, newfd);
		}
		else
		{
			welcsock->isAcceptBlocked = true;
			welcsock->sysid = syscallUUID;
			welcsock->pid = pid;
			welcsock->fd = fd;
			welcsock->client_addr = (struct sockaddr_in *)addr;
			welcsock->addrlen = addrlen;
		}
	}

	void TCPAssignment::syscall_read(UUID syscallUUID, int pid, int fd, void * buf, size_t count)
	{
		size_t dataSizeInRecvBuffer;
		uint32_t readByte;

		if(this->pidfd_to_socket.find(mp(pid, fd)) == this->pidfd_to_socket.end())
		{
			this->returnSystemCall(syscallUUID, -1);
			return;
		}

		Socket *current_socket = this->pidfd_to_socket[mp(pid, fd)];	

		dataSizeInRecvBuffer = current_socket->getReadableDataSize();
		
		if(dataSizeInRecvBuffer > 0)
		{
			readByte = std::min(count, dataSizeInRecvBuffer);
			current_socket->readRecvBuffer(buf, readByte);
			current_socket->isReadBlocked = false;

			this->returnSystemCall(syscallUUID, readByte);
		}
		else
		{
			current_socket->isReadBlocked = true;
			current_socket->sysid = syscallUUID;
			current_socket->buffer_saved = buf;
			current_socket->count_saved = count;
		}
		
	}

	void TCPAssignment::syscall_write(UUID syscallUUID, int pid, int fd, void * buf, size_t count)
	{
		uint32_t total_write_byte = 0;
		uint32_t remaining_byte;
		uint32_t write_byte;

		Packet *packet;
		uint16_t checksum;

		if(this->pidfd_to_socket.find(mp(pid, fd)) == this->pidfd_to_socket.end())
		{
			this->returnSystemCall(syscallUUID, -1);
			return;
		}

		Socket *current_socket = this->pidfd_to_socket[mp(pid, fd)];

		if(current_socket->getWriteableDataSize() > 0)
		{	
			remaining_byte = std::min((uint32_t)count, current_socket->getWriteableDataSize());
			while(remaining_byte > 0) {
				
				write_byte = std::min(MSS, remaining_byte);
				packet = this->allocatePacket(HEADER_SIZE + write_byte);

				PacketHolder *packet_holder = new PacketHolder(
					current_socket->ip,
					current_socket->peerip,
					current_socket->port,
					current_socket->peerport,
					current_socket->myseq,
					current_socket->myack,
					ACK,
					RECV_BUFFER_MAX_SIZE - current_socket->getRecvBufferSize(),
					(uint8_t *)buf + total_write_byte,
					write_byte
				);

				packet_holder->writePacket(packet);
				delete packet_holder;

				if(current_socket->sendBuffer.empty()) {

					SocketTimer * payload = new SocketTimer;
					
					payload->socket = current_socket;
					current_socket->isRetransTimerOn = true;
					payload->retrans_status = RETRANS_DATA;
					current_socket->retranstimer = this->addTimer((void *)payload, RETRANS_TIMEOUT);
				}

				current_socket->insertSendBuffer(this->clonePacket(packet));

				current_socket->myseq += write_byte;
				current_socket->expected_max_ack = current_socket->myseq;

				this->sendPacket("IPv4", this->sendPacketForm(packet));

				total_write_byte += write_byte;
				remaining_byte -= write_byte;
			}
		
			this->returnSystemCall(syscallUUID, total_write_byte);
			current_socket->isWriteBlocked = false;
		}
		else
		{
			/* write blocked */
			current_socket->isWriteBlocked = true;
			current_socket->sysid = syscallUUID;
			current_socket->buffer_saved = buf;
			current_socket->count_saved = count;
		}
	}

	void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
	{
		switch (param.syscallNumber) {
		case SOCKET:
			this->syscall_socket(syscallUUID, pid, std::get<int>(param.params[0]), 
													std::get<int>(param.params[1]));
			break;
		case CLOSE:
			this->syscall_close(syscallUUID, pid, std::get<int>(param.params[0]));
			break;
		case READ:
			this->syscall_read(syscallUUID, pid, std::get<int>(param.params[0]),
								std::get<void *>(param.params[1]),
								std::get<int>(param.params[2]));
			break;
		case WRITE:
			this->syscall_write(syscallUUID, pid, std::get<int>(param.params[0]),
								std::get<void *>(param.params[1]),
								std::get<int>(param.params[2]));
			break;
		case CONNECT:
			this->syscall_connect(
				syscallUUID, pid, std::get<int>(param.params[0]),
				static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
				(socklen_t)std::get<int>(param.params[2]));
			break;
			case LISTEN:
			this->syscall_listen(syscallUUID, pid, std::get<int>(param.params[0]),
								std::get<int>(param.params[1]));
			break;
		case ACCEPT:
			this->syscall_accept(
				syscallUUID, pid, std::get<int>(param.params[0]),
				static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
				static_cast<socklen_t *>(std::get<void *>(param.params[2])));
			break;
		case BIND:
			this->syscall_bind(
					syscallUUID, pid, std::get<int>(param.params[0]),
					static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
					(socklen_t)std::get<int>(param.params[2]));
			break;
		case GETSOCKNAME:
			this->syscall_getsockname(
					syscallUUID, pid, std::get<int>(param.params[0]),
					static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
					static_cast<socklen_t *>(std::get<void *>(param.params[2])));
			break;
		case GETPEERNAME:
			this->syscall_getpeername(
					syscallUUID, pid, std::get<int>(param.params[0]),
					static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
					static_cast<socklen_t *>(std::get<void *>(param.params[2])));
			break;
		default:
			assert(0);
		}
	}

	void TCPAssignment::packetArrived(std::string fromModule, Packet &&packet)
	{
		uint32_t myip, peerip, peerseq, peerack, datasz;
		uint16_t myport, peerport, checksum, winsize;
		bool isSYN, isACK, isFIN;

		Socket * current_socket = 0;


		PacketHolder *packet_holder_arrived = new PacketHolder;
		packet_holder_arrived->readPacket(&packet);

		/* bit corruption이 발생 */
		if(!packet_holder_arrived->isCheckSumValid()){
			return;
		}
			
		myip = packet_holder_arrived->getDestIp();
		peerip = packet_holder_arrived->getSrcIp();
		myport = packet_holder_arrived->getDestPort();
		peerport = packet_holder_arrived->getSrcPort();
		peerseq = packet_holder_arrived->getSeqNumber();
		peerack = packet_holder_arrived->getAckNumber();
		isSYN = packet_holder_arrived->getSYN();
		isACK = packet_holder_arrived->getACK();
		isFIN = packet_holder_arrived->getFIN();
		winsize = packet_holder_arrived->getWindowSize();
		datasz = packet_holder_arrived->getDataSize();

		delete packet_holder_arrived;

      	/* new Code */
		if(isSYN && !isACK) /* SYN */
		{/* Possible State: MYLISTEN(Normal Situation), SYNRCVD(Retransmittion) */
			Socket *server_socket = this->find_handshake_socket(mp(myip, myport));
			for(auto it : server_socket->connecting)
			{
				if(it->ip == myip && it->port == myport && it->peerip == peerip && it->peerport == peerport)
				{
					server_socket = it;
					break;
				}
			}
			if(server_socket == 0) server_socket = this->find_connected_socket(mt(myip, myport, peerip, peerport));
			if(server_socket == 0) server_socket = this->find_established_socket(mt(myip, myport, peerip, peerport));
			if(server_socket != 0)
			{
				if(server_socket->status == STATE_LISTEN && server_socket->backlog <= (int)server_socket->connecting.size()){}
				else if(server_socket->status == STATE_LISTEN) /* Backlog Value Set: Need to insert in connecting set */
				{
					Socket * server_backlog_socket = new Socket;
					server_backlog_socket->peer_initial_seq_number = peerseq;
					server_backlog_socket->recvstart = peerseq + 1;
					server_backlog_socket->recvend = peerseq + 1;

					server_backlog_socket->setSeqNumber(random());
					server_backlog_socket->setAckNumber(peerseq+1);

					server_backlog_socket->setPeerSeqNumber(peerseq);
					server_backlog_socket->setPeerAckNumber(peerack);


					server_backlog_socket->initial_seq_number = server_backlog_socket->myseq;


					server_backlog_socket->setIp(myip);
					server_backlog_socket->setPort(myport);
					server_backlog_socket->setPeerIp(peerip);
					server_backlog_socket->setPeerPort(peerport);


					server_backlog_socket->isBound = true;
					server_backlog_socket->status = STATE_SYNRCVD;
					server_socket->connecting.insert(server_backlog_socket);

					auto synackpacket = this->allocatePacket(HEADER_SIZE);

					PacketHolder *packet_holder = new PacketHolder(
						myip,
						peerip,
						myport,
						peerport,
						server_backlog_socket->initial_seq_number,
						server_backlog_socket->myack,
						SYN + ACK,
						DEFAULT_WINDOW_SIZE,
						NULL,
						0
					);

					packet_holder->writePacket(synackpacket);
					delete packet_holder;

					this->sendPacket(fromModule, this->sendPacketForm(synackpacket));
					
					SocketTimer * pay = new SocketTimer;
					pay->retrans_status = RETRANS_SYN;
					pay->socket = server_backlog_socket;
					pay->packet = synackpacket;
					
					if(server_backlog_socket->sentSYN) this->cancelTimer(server_backlog_socket->syntimer);
					server_backlog_socket->syntimer = this->addTimer((void*)pay, RETRANS_TIMEOUT);
					server_backlog_socket->sentSYN = true;
					server_backlog_socket->sentACK = true;
					server_backlog_socket->syn_ack_packet = synackpacket;
					server_backlog_socket->myseq++;
				}
				else if(server_socket->status == STATE_SYNSENT) /* Simultaneous Open */
				{
					server_socket->peer_initial_seq_number = peerseq;
					server_socket->recvstart = peerseq + 1;
					server_socket->recvend = peerseq + 1;
					
				
					server_socket->setSeqNumber(random());
					server_socket->setAckNumber(peerseq+1);
					server_socket->setPeerSeqNumber(peerseq);
					server_socket->setPeerAckNumber(peerack);

					
					server_socket->initial_seq_number = server_socket->myseq;


					server_socket->setIp(myip);
					server_socket->setPort(myport);
					server_socket->setPeerIp(peerip);
					server_socket->setPeerPort(peerport);


					server_socket->isBound = true;
					server_socket->status = STATE_SYNRCVD;

					auto synackpacket = this->allocatePacket(HEADER_SIZE);

					PacketHolder *packet_holder = new PacketHolder(
						myip,
						peerip,
						myport,
						peerport,
						server_socket->initial_seq_number,
						server_socket->myack,
						SYN + ACK,
						DEFAULT_WINDOW_SIZE,
						NULL,
						0
					);

					packet_holder->writePacket(synackpacket);
					delete packet_holder;

					this->sendPacket(fromModule, this->sendPacketForm(synackpacket));
					
					SocketTimer * pay = new SocketTimer;
					pay->retrans_status = RETRANS_SYN;
					pay->socket = server_socket;
					pay->packet = synackpacket;
					
					if(server_socket->sentSYN) this->cancelTimer(server_socket->syntimer);
					server_socket->syntimer = this->addTimer((void*)pay, RETRANS_TIMEOUT);
					server_socket->sentSYN = true;
					server_socket->sentACK = true;
					server_socket->syn_ack_packet = synackpacket;
					server_socket->myseq++;
				}
				else if(server_socket->status == STATE_SYNRCVD) 
				{
					if(server_socket->sentACK && server_socket->sentSYN) /* Retransmittion */
					{  	/* 
						Client -----(SYN)-----> Server (OK)
						Client <---(SYN+ACK)--- Server (X)
							.
							.
						(Timeout)
						Client -----(SYN)-----> Server (OK) / Retransmittion
						*/
						this->sendPacket(fromModule, this->sendPacketForm(server_socket->syn_ack_packet));
					}
				}
			}

		}
		if(isSYN && isACK) /* SYN + ACK */
		{
			Socket *client_socket = this->find_connected_socket(mt(myip, myport, peerip, peerport));
			if(client_socket != 0)
			{
				if(client_socket->status == STATE_SYNSENT) /* Simultaneous Open */
				{
					client_socket->peer_initial_seq_number = peerseq;
					client_socket->recvstart = peerseq + 1;
					client_socket->recvend = peerseq + 1;

					client_socket->setSeqNumber(client_socket->myseq);
					client_socket->setAckNumber(peerseq+1);
					client_socket->setPeerSeqNumber(peerseq);
					client_socket->setPeerAckNumber(peerack);
					
					client_socket->setIp(myip);
					client_socket->setPort(myport);
					client_socket->setPeerIp(peerip);
					client_socket->setPeerPort(peerport);

					client_socket->status = STATE_SYNRCVD;
				}

				auto ackpacket = this->allocatePacket(HEADER_SIZE);
				PacketHolder *packet_holder = new PacketHolder(
					myip,
					peerip,
					myport,
					peerport, 
					client_socket->initial_seq_number + 1,
					client_socket->myack,
					ACK,
					DEFAULT_WINDOW_SIZE,
					NULL,
					0
				);
				packet_holder->writePacket(ackpacket);
				delete packet_holder;

				this->sendPacket(fromModule, this->sendPacketForm(ackpacket));
			}
		}
		if(isACK)/* else if(syn == 0 && ack == 1 && fin == 0) */
		{
			/* */
			// welcsock = this->find_handshake_socket(mp(myip, myport));
			Socket *server_socket = this->find_handshake_socket(mp(myip, myport));
			if(server_socket != 0)
			{
				if(server_socket->status == STATE_LISTEN)
				{
					for(Socket * ptr : server_socket->connecting)
					{
						if(ptr->peerip == peerip && ptr->peerport == peerport && ptr->status == STATE_SYNRCVD)
						{
							current_socket = ptr;
							break;
						}
					}
					if(current_socket != 0)
					{
						if(current_socket->sentSYN) this->cancelTimer(current_socket->syntimer);
						current_socket->sentSYN = false;
						current_socket->peer_window_size = winsize;
						current_socket->status = STATE_ESTAB;
						current_socket->peerack = current_socket->peer_max_ack = peerack;
						server_socket->connecting.erase(server_socket->connecting.find(current_socket));
						server_socket->established.insert(current_socket);
						if(server_socket->isAcceptBlocked == true)
						{ /* syscall_accept call 다시 불러주면 됨 */
							syscall_accept(server_socket->sysid, server_socket->pid, server_socket->fd, (struct sockaddr *)server_socket->client_addr, server_socket->addrlen);
							return;
						}
					}
				}	
			}
				
			
			current_socket = this->find_connected_socket(mt(myip, myport, peerip, peerport));
			if(current_socket == 0) current_socket = this->find_established_socket(mt(myip, myport, peerip, peerport));
			if(current_socket != 0)
			{
				if(current_socket->sentSYN)	this->cancelTimer(current_socket->syntimer);
				current_socket->sentSYN = false;
				current_socket->peer_window_size = winsize;
				current_socket->peerack = peerack;
				
				if(current_socket->peer_max_ack - current_socket->initial_seq_number < peerack - current_socket->initial_seq_number
				&& current_socket->expected_ack_fin != peerack)
				{
					current_socket->peer_max_ack = peerack;
					if(current_socket->isRetransTimerOn) this->cancelTimer(current_socket->retranstimer);
					current_socket->isRetransTimerOn = false;
					if(peerack < current_socket->expected_max_ack)
					{
						SocketTimer * payload = new SocketTimer;

						payload->socket = current_socket;
						current_socket->isRetransTimerOn = true;
						payload->retrans_status = RETRANS_DATA;
						current_socket->retranstimer = this->addTimer((void *)payload, RETRANS_TIMEOUT);
					}
				}
				
				current_socket->removeSendBuffer();
				if(current_socket->isWriteBlocked && current_socket->getWriteableDataSize() > 0)
				{
					this->syscall_write(current_socket->sysid, current_socket->pid, 
										current_socket->fd, current_socket->buffer_saved, current_socket->count_saved);
				}
				if(peerack == current_socket->expected_ack_fin)
				{
					if(current_socket->isRetransTimerOn) this->cancelTimer(current_socket->retranstimer);
					current_socket->isRetransTimerOn = false;
					switch(current_socket->status)
					{
						case STATE_FIN_WAIT_1:
							current_socket->status = STATE_FIN_WAIT_2;
							this->cancelTimer(current_socket->fintimer);
							break;
						case STATE_CLOSING:
						{
							SocketTimer * payload = new SocketTimer;				
							current_socket->status = STATE_TIME_WAIT;
							payload->retrans_status = RETRANS_CLOSE;
							payload->socket = current_socket;
							this->cancelTimer(current_socket->fintimer);
							current_socket->timer = this->addTimer((void *)payload, TIMEOUT);
						}
							break;
						case STATE_LAST_ACK:
							current_socket->status = STATE_CLOSED;
							this->cancelTimer(current_socket->fintimer);
							this->close_cleanup(current_socket->sysid, current_socket->pid, current_socket->fd, current_socket);
							break;
						default:
							break;
					}
				}
				else if(current_socket->status == STATE_SYNRCVD)
				{
					current_socket->status = STATE_ESTAB;
					current_socket->peer_max_ack = peerack;
					if(current_socket->sentSYN) this->cancelTimer(current_socket->syntimer);
					current_socket->sentSYN = false;
					this->returnSystemCall(current_socket->sysid, 0);/* return for connect() */
				}
			}

		}
		if(isFIN)/* else if(syn == 0 && ack == 0 && fin == 1) */
		{
			current_socket = this->find_connected_socket(mt(myip, myport, peerip, peerport));
			if(current_socket == 0) current_socket = this->find_established_socket(mt(myip, myport, peerip, peerport));
			if(current_socket != 0)
			{
				current_socket->peer_window_size = winsize;
				bool sendACK = false;
				
				if(peerseq == current_socket->myack)
				{
					if(current_socket->isReadBlocked)
					{
						current_socket->isReadBlocked = false;
						this->returnSystemCall(current_socket->sysid , -1);
					}
					current_socket->myack++;
					switch(current_socket->status)
					{
						case STATE_ESTAB:
							current_socket->peerseq = peerseq;
							current_socket->status = STATE_CLOSE_WAIT;
							sendACK = true;
							break;
						case STATE_FIN_WAIT_1:
							current_socket->peerseq = peerseq;
							current_socket->status = STATE_CLOSING;
							sendACK = true;
							break;
						case STATE_FIN_WAIT_2:
						{
							SocketTimer * payload = new SocketTimer;				
							current_socket->peerseq = peerseq;
							current_socket->status = STATE_TIME_WAIT;
							payload->retrans_status = RETRANS_CLOSE;
							payload->socket = current_socket;
							current_socket->timer = this->addTimer((void *)payload, TIMEOUT);
							sendACK = true;
						}
							break;
						case STATE_CLOSE_WAIT:
						case STATE_CLOSING:
						case STATE_TIME_WAIT:
							sendACK = true;
							break;
						default: break;
					}
				}
				if(true)/* if(sendACK) */
				{
					auto ackpacket = this->allocatePacket(HEADER_SIZE);

					PacketHolder *packet_holder = new PacketHolder(
						myip,
						peerip,
						myport,
						peerport,
						current_socket->myseq,
						current_socket->myack,
						ACK,
						DEFAULT_WINDOW_SIZE,
						NULL,
						0
					);

					packet_holder->writePacket(ackpacket);
					delete packet_holder;

					this->sendPacket(fromModule, this->sendPacketForm(ackpacket));
				}
			}
			
		}
		if(datasz > 0)/* received some data */
		{	
			current_socket = this->find_connected_socket(mt(myip, myport, peerip, peerport));
			if(current_socket != 0)
			{
				current_socket->peer_window_size = winsize;
				if(current_socket->getRecvBufferSize() + packet.getSize() <= RECV_BUFFER_MAX_SIZE)
				{
					Packet *packetCloned = this->clonePacket(&packet);
					current_socket->writeRecvBuffer(packetCloned);

					if(current_socket->isReadBlocked && current_socket->getReadableDataSize() > 0)
						syscall_read(current_socket->sysid, current_socket->pid, current_socket->fd, current_socket->buffer_saved, current_socket->count_saved);	
					
					auto ackpacket = this->allocatePacket(HEADER_SIZE);

					PacketHolder *packet_holder = new PacketHolder(
						myip,
						peerip,
						myport,
						peerport,
						current_socket->myseq,
						current_socket->myack,
						ACK,
						RECV_BUFFER_MAX_SIZE - current_socket->getRecvBufferSize(),
						NULL,
						0
					);

					packet_holder->writePacket(ackpacket);
					delete packet_holder;

					this->sendPacket(fromModule, this->sendPacketForm(ackpacket));
				}
			}
		}
		return;
	
	}

	void TCPAssignment::timerCallback(std::any payload)
	{
		SocketTimer *current_payload = (SocketTimer *)std::any_cast<void *>(payload);
		Socket *current_socket;
		Packet *packet;

		switch(current_payload->retrans_status){
			
			case RETRANS_SYN:
				this->sendPacket("IPv4", this->sendPacketForm(current_payload->packet));
				current_payload->socket->syntimer = this->addTimer((void*)current_payload, RETRANS_TIMEOUT);
				break;

			case RETRANS_FIN:
				this->sendPacket("IPv4", this->sendPacketForm(current_payload->packet));

				if(current_payload->socket->fincnt < 10)
					current_payload->socket->fintimer = this->addTimer((void*)current_payload, RETRANS_TIMEOUT);

				current_payload->socket->fincnt++;
				break;

			case RETRANS_DATA:
				
				/* send all data in send_buffer */
				for(auto it = current_payload->socket->sendBuffer.begin(); it != current_payload->socket->sendBuffer.end(); it++)
				{
					packet = (*it);
					this->sendPacket("IPv4", this->sendPacketForm(packet));
				}
				
				current_payload->socket->isRetransTimerOn = false;
				if(!current_payload->socket->sendBuffer.empty()) 
				{
					SocketTimer * payload = new SocketTimer;

					payload->socket = current_payload->socket;
					current_payload->socket->isRetransTimerOn = true;
					payload->retrans_status = RETRANS_DATA;
					current_payload->socket->retranstimer = this->addTimer((void *)payload, RETRANS_TIMEOUT);
				}


				delete current_payload;
				break;
			
			case RETRANS_CLOSE:
				current_socket = current_payload->socket;
				current_socket->status = STATE_CLOSED;

				this->close_cleanup(current_socket->sysid, current_socket->pid, current_socket->fd, current_socket);

				delete current_payload;
				break;

			default:
				assert(0);
		}
	}

	Socket * TCPAssignment::find_handshake_socket(std::pair<uint32_t, uint16_t> key)
	{
		if(this->syn_ready.find(key) != this->syn_ready.end()) return this->syn_ready[key];
		key.first = INADDR_ANY;
		if(this->syn_ready.find(key) != this->syn_ready.end()) return this->syn_ready[key];
		return 0;
	}

	Socket * TCPAssignment::find_connected_socket(std::tuple<uint32_t, uint16_t, uint32_t, uint16_t> key)
	{
		if(this->srcdest_to_socket.find(key) != this->srcdest_to_socket.end()) return this->srcdest_to_socket[key];
		std::get<0>(key) = INADDR_ANY;
		if(this->srcdest_to_socket.find(key) != this->srcdest_to_socket.end()) return this->srcdest_to_socket[key];
		return 0;
	}

	Socket * TCPAssignment::find_established_socket(std::tuple<uint32_t, uint16_t, uint32_t, uint16_t> key)
	{
		auto welcsock = this->find_handshake_socket(mp(std::get<0>(key), std::get<1>(key)));
		if(welcsock != 0)
		{
			for(auto ptr : welcsock->established)
			{
				if(ptr->peerip == std::get<2>(key) && ptr->peerport == std::get<3>(key))
					return ptr;
			}
		}
		return 0;
	}

	uint32_t Socket::getReadableDataSize()
	{
		return this->recvend - this->recvstart;
	}

	uint32_t Socket::getWriteableDataSize()
	{
		uint32_t ret = 0;
		
		if(this->getSendBufferSize() < this->peer_window_size)
			ret = this->peer_window_size - this->getSendBufferSize();

		if(this->getSendBufferSize() < SEND_BUFFER_MAX_SIZE)
		{
			if(ret > 0) ret = std::min(ret, SEND_BUFFER_MAX_SIZE - this->getSendBufferSize());
			else ret = SEND_BUFFER_MAX_SIZE - this->getSendBufferSize();
		}

		return ret;
	}

	uint32_t Socket::getRecvBufferSize()
	{
		uint32_t total_recv_size = 0;

		for(Packet *packet : this->recvBuffer)
			total_recv_size += packet->getSize();

		return total_recv_size;
	}

	uint32_t Socket::getSendBufferSize()
	{
		
		uint32_t total_sent_size = 0;

		for(Packet *packet : this->sendBuffer)
			total_sent_size += packet->getSize();
		
		return total_sent_size;
		
	}


	Packet* TCPAssignment::allocatePacket(size_t size)
	{
		Packet *packet = new Packet(size);
		return packet;
	}

	Packet TCPAssignment::sendPacketForm(Packet *packet)
	{
		Packet packetCloned = packet->clone();
		return std::move(packetCloned);
	}

	Packet *TCPAssignment::clonePacket(Packet *packet)
	{
		size_t size = packet->getSize();
		uint8_t seg[size];

		Packet *clonedPacket = new Packet(size);

		packet->readData(0, seg, size);
		clonedPacket->writeData(0, seg, size);
		return clonedPacket;
	}
}