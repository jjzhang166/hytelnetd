#include <stdio.h>
#include <list>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <arpa/telnet.h>
#include <termios.h>
#include <sys/utsname.h>
#include <signal.h> 
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/ioctl.h>
#include "/usr/include/linux/socket.h"
#include <netdb.h>
#include <netinet/tcp.h>
#include <cstdlib>
#include "ptypes/pasync.h"
#include <pthread.h>

//定义线程数量
#define thread_num 100
#define MYPORT 3490    //定义监听端口
#define BACKLOG 100    //监听端口的最大数量

#define BUFSIZE (6 * 1024)

//定义条件变量
pthread_cond_t cond[thread_num + 1];
pthread_mutex_t mutex[thread_num + 1];
pthread_mutex_t mainMutex;

pthread_cond_t mainCond;
pthread_mutex_t mainmutex;

static const char fmtstr_d[] = "%A, %d %B %Y";
static const char fmtstr_t[] = "%H:%M:%S";

//函数声明
int xgetpty(char *line, char *nowClientIp);
int xopen(const char *pathname, int flags);
void xdup2(int from, int to);
int xopen3(const char *pathname, int flags, int mode);
void print_login_issue(const char *issue_file, const char *tty);
int bb_execvp(const char *file, char * const argv[]);
int ndelay_on(int fd);
int close_on_exec_on(int fd);
void bb_signals(int sigs, void (*f)(int));
ssize_t safe_read_ptyfd(int fd, void *buf, size_t count, pid_t sonPid, int *retry);
unsigned char *remove_iacs(unsigned char *ts, int tsLen, int ttyFd,
		int *pnum_totty);
ssize_t safe_write(int fd, const void *buf, size_t count);
size_t iac_safe_write(int fd, const char *buf, size_t count);
ssize_t safe_read_socket(int fd, void *buf, size_t count);
int readValue(char *redName, char *value);

const int const_int_1 = 1;

//发送数据
int socketSend(int Socket, char *sendStr, int sendLen) {
	int rvCount = 0;
	int allC = 0;

	while (1) {
		rvCount = send(Socket, sendStr, sendLen, 0);
		if (rvCount <= 0) {
			return -1;
		}
		allC = allC + rvCount;
		if (allC >= sendLen) {
			break;
		}
	}
	return sendLen;
}
int socketRecv(int Socket, char *readStr, int readLen) {
	int rvCount = 0;
	int allCout = 0;
	while (1) {
		rvCount = recv(Socket, readStr, readLen, 0);
		if (rvCount <= 0) {
			return -1;
		}
		allCout = allCout + rvCount;
		if (allCout >= readLen) {
			break;
		}
	}
	return readLen;
}


int runLinuxShell(char *shellStr) {
	FILE *fp;
	fp = popen(shellStr, "r");
	pclose(fp);
	return 0;
}

void sig_int(int sig) {
//	char strCh[128];
//	memset(strCh, 0x00, 128);
//	sprintf(strCh, "fuser -k %s", ttyName);
//	runLinuxShell(strCh);
	exit(0);
	return;
}

//客户端服务进程执行过程实现
//
void socketClientServerThreadPro(int clientSocket, char *clientIp) {
	char str[256];
	int pid = 0;
	int ret = 0;
	fd_set rdfdset, wrfdset;	//创建描述符集合
	char *login_argv[2];
	struct termios termbuf;
	int count = 0;
	int fdMax = 0;
	char recvData[512];
	char strCh[128];
	char ttyTypeS[8];
	char ttyName[128]; //tty名称

	int keepAlive = 1;	//设定KeepAlive
	int keepIdle = 100;	//开始首次KeepAlive探测前的TCP空闭时间
	int keepInterval = 500;	//两次KeepAlive探测间的时间间隔
	int keepCount = 3;	//判定断开前的KeepAlive探测次数

	struct timeval timeout;

	int ptyfd;	//pty句柄
	int ttyfd;	//tty句柄
	pid_t shell_pid;
	unsigned char buf1[BUFSIZE];	//接收socket发过来的数据
	int buf1Len;
	unsigned char buf2[BUFSIZE];	//发送给socket的数据
	int buf2Len;
	unsigned char LsStr[BUFSIZE];
	unsigned char *ptrBuf1;
	unsigned char *ptrBuf2;

	ptrBuf1 = buf1;
	ptrBuf2 = buf2;
	ptyfd = 0;

	buf1Len = 0;
	buf2Len = 0;
	char iacs_to_send[] = {
	IAC, DO, TELOPT_ECHO,
	IAC, DO, TELOPT_NAWS,
	/* This requires telnetd.ctrlSQ.patch (incomplete) */
	/*IAC, DO, TELOPT_LFLOW,*/
	IAC, WILL, TELOPT_ECHO,
	IAC, WILL, TELOPT_SGA };

	while (1) {
		ptyfd = xgetpty(ttyName, clientIp);
		if (ptyfd < 0) {
			socketSend(clientSocket, "未找到空闲可用的tty设备,请检查分配的tty号是否正确!",
					strlen("未找到空闲可用的tty设备,请检查分配的tty号是否正确!!"));
			close(ptyfd);
			close(clientSocket);
			exit(0);
		}
		ndelay_on(ptyfd);
		close_on_exec_on(ptyfd);

		if (setsockopt(clientSocket, SOL_SOCKET, SO_KEEPALIVE,
				(void*) &keepAlive, sizeof(keepAlive)) == -1) {
		}
		if (setsockopt(clientSocket, SOL_TCP, TCP_KEEPIDLE, (void *) &keepIdle,
				sizeof(keepIdle)) == -1) {
		}
		if (setsockopt(clientSocket, SOL_TCP, TCP_KEEPINTVL,
				(void *) &keepInterval, sizeof(keepInterval)) == -1) {
		}
		if (setsockopt(clientSocket, SOL_TCP, TCP_KEEPCNT, (void *) &keepCount,
				sizeof(keepCount)) == -1) {
		}
		ndelay_on(clientSocket);

		//<3>告诉前端
		if (socketSend(clientSocket, iacs_to_send, sizeof(iacs_to_send))
				== -1) {
		}
		//关闭
		fflush(NULL);
		::signal(SIGPIPE, SIG_IGN);		//忽略socket错误产生的SIGPIPE信号,防止进程异常退出
		::signal(SIGCHLD, SIG_IGN);		//忽略子进程退出信号
		::signal(SIGSEGV, &sig_int);		//另一端断开
		pid = fork();
		if (pid > 0) {
			buf1Len = 0;
			buf2Len = 0;
			shell_pid = pid;		//子进程的ID
			int trycount = 0;
			while (1) {
				FD_ZERO(&rdfdset);		//可读描述符集合清0
				FD_ZERO(&wrfdset);		//可写描述符集合清0

				if (buf1Len > 0) {
					FD_SET(ptyfd, &wrfdset);		//判断tty是否可写入
					if (ptyfd > fdMax) {
						fdMax = ptyfd;
					}
				}
				if (buf2Len > 0) {
					FD_SET(clientSocket, &wrfdset);		//判断socket是否可写入
					if (clientSocket > fdMax) {
						fdMax = clientSocket;
					}
				}
				if (buf1Len < BUFSIZE) {
					FD_SET(clientSocket, &rdfdset);		//判断socket是否可读
					if (clientSocket > fdMax) {
						fdMax = clientSocket;
					}
				}
				if (buf2Len < BUFSIZE) {
					FD_SET(ptyfd, &rdfdset);		//判断是否可从pty中读取
					if (ptyfd > fdMax) {
						fdMax = ptyfd;
					}
				}
				//socket是否有读写，超时时间30秒
				count = 0;
				if (fdMax < 0) {
					fdMax = 0;
				}
				timeout.tv_sec = 30;		//超时判断为30秒
				timeout.tv_usec = 0;

				count = select(fdMax + 1, &rdfdset, &wrfdset, NULL, &timeout);
				if (count == 0) {
					continue;
				} else if (count < 0) {
					kill(shell_pid, SIGKILL);
					waitpid(shell_pid, NULL, 0);
					close(ttyfd);
					close(ptyfd);
					close(clientSocket);
//					memset(strCh, 0x00, 128);
//					sprintf(strCh, "fuser -k %s", ttyName);
//					runLinuxShell(strCh);
					exit(0);
				} else {
					//有读写数据
					//判断sokcket是否有可读数据，如果有则把数据读出放入buf1
					count = 0;
					memset(str, 0x00, 256);
					if (FD_ISSET(clientSocket, &rdfdset)) {
						memset(recvData, 0x00, 512);
						count = safe_read_socket(clientSocket, recvData, 256);//向buf1中读入socket发来数据
						memcpy(ptrBuf1, recvData, count);
						if (count <= 0) {
							break;					//关闭当前连接
						} else {
							ptrBuf1 = ptrBuf1 + count;
							buf1Len = buf1Len + count;
						}
					}
					//判断pty是否可以读出数据，如果有则把数据读出到buf2
					count = 0;
					if (FD_ISSET(ptyfd, &rdfdset)) {
						int retry = 0;
						count = safe_read_ptyfd(ptyfd, ptrBuf2, 256, shell_pid, &retry);
						if (count < 0) {
							if (retry == 0 || trycount++ > 10) {
								break;
							}
						} else {
							trycount = 0;
							ptrBuf2 = ptrBuf2 + count;
							buf2Len = buf2Len + count;
						}
					}
					//判断pty是否可以写入数据，如果可以则把buf1写入pty1
					count = 0;
					if ((FD_ISSET(ptyfd, &wrfdset)) && (buf1Len > 0)) {
						int num_totty;
						unsigned char *ptr;
						//printf("<3>向TTY中写入数据\n");
						ptr = remove_iacs((unsigned char *) buf1, buf1Len,
								ptyfd, &num_totty);					//去掉特殊字符
						count = safe_write(ptyfd, ptr, num_totty);
						if (count < 0) {
							if (errno != EAGAIN) {//应用程序现在没有数据可写请稍后再试
								break;					//关闭当前连接
							}
						} else {
							//printf("<3>向TTY中写入数据%s\n",ptr);
							memcpy(LsStr, ptr + count, num_totty - count);
							buf1Len = num_totty - count;
							//memset(buf1,0x00,BUFSIZE);
							memcpy(buf1, LsStr, buf1Len);
							ptrBuf1 = buf1 + buf1Len;
							//printf("写入pty后，buf1中的数据%s\n",buf1);
						}
					}
					//判断socket是否可以写入数据，如果可以则把buf2写入socket
					count = 0;
					if ((FD_ISSET(clientSocket, &wrfdset)) && (buf2Len > 0)) {
						//printf("<4>向socket中写入数据\n");
						count = iac_safe_write(clientSocket, (char *) buf2,
								buf2Len);
						if (count < 0) {
							if (errno != EAGAIN) {			//如果不能写入，则继续下一步检查
								break;					//关闭当前连接
							}
						} else {
							memcpy(LsStr, buf2 + count, buf2Len - count);
							buf2Len = buf2Len - count;
							memcpy(buf2, LsStr, buf2Len);
							ptrBuf2 = buf2 + buf2Len;
						}
					}
				}
			}
			//交互完成后把login子进程kill掉
			kill(shell_pid, SIGKILL);
			waitpid(shell_pid, NULL, 0);
			close(ttyfd);
			close(ptyfd);
			close(clientSocket);
			continue;
		}
		if (pid < 0) {
			close(ttyfd);
			close(ptyfd);
			close(clientSocket);
			continue;
		}
		//////////////////////////////////////////////////////////
		//子进程开始执行
		//设置TTY模式环境变量(读配置文件)
		memset(ttyTypeS, 0x00, 7);
		readValue("vttype", ttyTypeS);
		memset(strCh, 0x00, 128);
		memcpy(strCh, ttyTypeS, 5);
		//printf("ttytype is ：%s\n",strCh);
		setenv("TERM", strCh, 1);
		//bb_signals((1 << SIGCHLD) + (1 << SIGPIPE), SIG_DFL);
		setsid();
		//<4>打开tty
		close(0);
		ret = xopen(ttyName, O_RDWR); /* becomes our ctty */
		//printf("打开TTY后的状态%d\n",ret);
		xdup2(0, 1);
		xdup2(0, 2);
		pid = getpid();
		tcsetpgrp(0, pid); /* switch this tty's process group to us */
		ttyfd = ret;
		//<5>设定终端的参数
		tcgetattr(0, &termbuf);
		termbuf.c_lflag |= ECHO; /* if we use readline we dont want this */
		termbuf.c_oflag |= ONLCR | XTABS;
		termbuf.c_iflag |= ICRNL;
		termbuf.c_iflag &= ~IXOFF;
		/*termbuf.c_lflag &= ~ICANON;*/
		tcsetattr(STDIN_FILENO, TCSANOW, &termbuf);

		print_login_issue("/etc/issue.net", ttyName);
		//<6>
		login_argv[0] = "/bin/login";
		;
		login_argv[1] = '\0';
		bb_execvp("/bin/login", (char **) login_argv);
	}
}
//主监听线程
class socketMainThread: public pt::thread {
protected:
	int id;
	virtual void execute();
public:

	socketMainThread(int _id) :
			pt::thread(false), id(_id) {
	}
	;
	~socketMainThread() {
		waitfor();
	}
	;
};
//主监听线程的执行
void socketMainThread::execute() {
	int sockfd = 0, new_fd = 0;
	int yes = 1;
	struct sockaddr_in my_addr;    //服务器socket参数
	struct sockaddr_in their_addr;    //客户端参数
	socklen_t sin_size = 0;
	int port = 0;
	char strChar[128];
	int pid;
	char nowClientIp[128];

	//<1>创建监听socket对象
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		//printf("监听线程创建socket失败!");
		return;
	}
	//<2>设置socket相关参数
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
		//printf("监听线程设置socket失败!");
		return;
	}
	//读配置文件
	memset(strChar, 0x00, 128);
	readValue("port", strChar);
	port = atoi(strChar);

	//<3>设置通信参数
	my_addr.sin_family = AF_INET;         // host byte order   
	my_addr.sin_port = htons(port);     // short, network byte order
	my_addr.sin_addr.s_addr = INADDR_ANY; // automatically fill with my IP
	memset(&(my_addr.sin_zero), '\0', 8); // zero the rest of the struct
	//<4>绑定端口
	if (bind(sockfd, (struct sockaddr *) &my_addr, sizeof(struct sockaddr))
			== -1) {
		//printf("监听线程绑定socket端口失败!");
		return;
	}
	close_on_exec_on(sockfd);
	//<5>打开监听
	if (listen(sockfd, BACKLOG) == -1) {
		//printf("监听线程打开socket监听端口失败!");
		return;
	}
	//<6>开始接受连接请求
	while (1) {
		sin_size = sizeof(struct sockaddr_in);
		if ((new_fd = accept(sockfd, (struct sockaddr *) &their_addr, &sin_size))
				== -1) {
			// printf("监听线程接收socket连接失败!");
			continue;
		}
		memset(nowClientIp, 0x00, 128);
		sprintf(nowClientIp, "%s", inet_ntoa(their_addr.sin_addr));
		close_on_exec_on(new_fd);
		pid = fork();
		if (pid > 0) {
			//printf("父进程继续运行,pid:%d子进程id:%d\n",getpid(),pid);
			close(new_fd);
			continue;
		} else if (pid == 0) {
			close(sockfd);
			//子进程启动
			//printf("开启子进程成功pid:%d\n",getpid());

			//进入子进程的工作
			socketClientServerThreadPro(new_fd, nowClientIp);
			//processchild(sockfd);
			exit(0);
		} else {
			//启动工作系统失败,向前端发送失败信息
			continue;//返回继续监听
		}
	}
	//向主进程发信号，让主进程退出
	pthread_cond_signal(&mainCond);
}

socketMainThread *pMainTemp = NULL;

void releaseChildPro(int sig) {
	waitpid(-1, NULL, WNOHANG);
}

int main() {
	::signal(SIGCHLD, &releaseChildPro);			//忽略子进程退出信号

	//创建监听线程，并启动监听
	pMainTemp = new socketMainThread(0);
	pMainTemp->start();
	pthread_mutex_init(&mainMutex, NULL);
	pthread_cond_wait(&mainCond, &mainmutex);
	return 0;
}

//从配置文件中读取pty定义号
int ReadALine(char *fileName, char *ipAddr, int screenId, char *ptyName) {
	FILE *fp = NULL;
	char strChar[2048];
	char *ptr = NULL;
	char *ptr2 = NULL;
	char *ptr3 = NULL;
	char screenNum[16];

	fp = fopen(fileName, "r");
	if (fp == NULL) {
		return -1;
	}
	if (feof(fp)) {
		fclose(fp);
		fp = NULL;
		return -1;
	}
	while (!feof(fp)) {
		memset(strChar, 0x00, 2048);
		ptr = fgets(strChar, 2048, fp);
		if (ptr == NULL) {
			fclose(fp);
			return -1;
		} else {
			ptr2 = NULL;
			ptr2 = strstr(strChar, "#");
			if (ptr2 != NULL) {
				continue;
			}
			ptr2 = NULL;
			ptr2 = strstr(strChar, ipAddr);
			if (ptr2 != NULL) {
				//再找到屏号
				memset(screenNum, 0x00, 16);
				sprintf(screenNum, "[%d]", screenId);
				ptr3 = strstr(strChar, screenNum);
				if (ptr3 != NULL) {
					//找到IP地址
					if (strChar[5] == 32) {
						memcpy(ptyName, strChar, 5);
					} else if (strChar[6] == 32) {
						memcpy(ptyName, strChar, 6);
					} else if (strChar[7] == 32) {
						memcpy(ptyName, strChar, 7);
					} else if (strChar[8] == 32) {
						memcpy(ptyName, strChar, 8);
					}
					//printf("ptyName is :%s\n",ptyName);
					fclose(fp);
					return 0;
				}
			}
		}
	}
	fclose(fp);
	fp = NULL;
	return 0;
}

int xgetpty(char *line, char *nowClientIp) {
	int p;
	struct stat stb;
	int num = 1;
	int rv = 0;
	char ptyName[16];

	strcpy(line, "/dev/ptyXX");

	//根据IP 地址从配置文件中选择要用的pty号
	memset(ptyName, 0x00, 16);
	sprintf(ptyName, "/dev/");

	//查找8 个屏号循环8次
	for (num = 1; num <= 8; num++) {
		rv = ReadALine("/etc/hy_tty.cfg", nowClientIp, num, ptyName + 5);
		if (rv != 0) {
			continue;
		} else {
			strcpy(line, ptyName);
			if (stat(line, &stb) < 0) //判断状态，
					{
				return -1;
			}
			p = open(line, O_RDWR | O_NOCTTY);
			if (p >= 0) {
				line[5] = 't';
				return p;
			} else {
			}

		}
	}
	return -1;
}

int xopen(const char *pathname, int flags) {
	return xopen3(pathname, flags, 0666);
}

void xdup2(int from, int to) {
	if (dup2(from, to) != to) {
	}
	//printf("can't duplicate file descriptor\n");
}
int xopen3(const char *pathname, int flags, int mode) {
	int ret;

	ret = open(pathname, flags, mode);
	if (ret < 0) {
		return 0;
	}
	return ret;
}

void print_login_issue(const char *issue_file, const char *tty) {
	FILE *fp;
	int c;
	char buf[256 + 1];
	const char *outbuf;
	time_t t;
	struct utsname uts;

	time(&t);
	uname(&uts);
	//向前端显示信息
	puts("\r"); /* start a new line */
	printf("欢迎使用山东汇金终端仿真软件V3.0!本终端tty名称为:%s\n", tty);

	fp = fopen(issue_file, "r");
	if (!fp)
		return;
	while ((c = fgetc(fp)) != EOF) {
		outbuf = buf;
		buf[0] = c;
		buf[1] = '\0';
		if (c == '\n') {
			buf[1] = '\r';
			buf[2] = '\0';
		}
		if (c == '\\' || c == '%') {
			c = fgetc(fp);
			switch (c) {
			case 's':
				outbuf = uts.sysname;
				break;
			case 'n':
			case 'h':
				outbuf = uts.nodename;
				break;
			case 'r':
				outbuf = uts.release;
				break;
			case 'v':
				outbuf = uts.version;
				break;
			case 'm':
				outbuf = uts.machine;
				break;
				/* The field domainname of struct utsname is Linux specific. */
#if defined(__linux__)
			case 'D':
			case 'o':
				outbuf = uts.domainname;
				break;
#endif
			case 'd':
				strftime(buf, sizeof(buf), fmtstr_d, localtime(&t));
				break;
			case 't':
				strftime(buf, sizeof(buf), fmtstr_t, localtime(&t));
				break;
			case 'l':
				outbuf = tty;
				break;
			default:
				buf[0] = c;
			}
		}
		//可以加入当前TTY号的显示
		fputs(outbuf, stdout);
	}
	fclose(fp);
	fflush(NULL);
}

int bb_execvp(const char *file, char * const argv[]) {
	return execvp(file, argv);
}
/* Turn on nonblocking I/O on a fd */
int ndelay_on(int fd) {
	return fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
}
int close_on_exec_on(int fd) {
	return fcntl(fd, F_SETFD, FD_CLOEXEC);
}
void bb_signals(int sigs, void (*f)(int)) {
	int sig_no = 0;
	int bit = 1;

	while (sigs) {
		if (sigs & bit) {
			sigs &= ~bit;
			signal(sig_no, f);
		}
		sig_no++;
		bit <<= 1;
	}
}

ssize_t safe_read_ptyfd(int fd, void *buf, size_t count, pid_t sonPid, int *retry) {
	ssize_t n;
	do {
		n = read(fd, buf, count);
		if (n < 0) {
			if (errno == EIO) {
				*retry = 1;
				break;
//				kill(sonPid, 0);
//				if (errno == ESRCH) {
//					break;
//				}
			}
			*retry = 0;
			if (errno == EINTR) {
				continue;
			}
			if (errno == EAGAIN) {
				continue;
			}
		}
		break;
	} while (true);
	return n;
}

ssize_t safe_read_socket(int fd, void *buf, size_t count) {
	ssize_t n;
	do {
		n = read(fd, buf, count);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			if (errno == EAGAIN) {
				continue;
			}
			break;
		} else {
			return n;
		}
	} while (true);

	return n;
}

unsigned char *remove_iacs(unsigned char *ts, int tsLen, int ttyFd,
		int *pnum_totty) {
	unsigned char *ptr0 = ts;
	unsigned char *ptr = ptr0;
	unsigned char *totty = ptr;
	unsigned char *end = ptr + tsLen;
	int num_totty;

	while (ptr < end) {
		if (*ptr != IAC) {
			char c = *ptr;

			*totty++ = c;
			ptr++;
			/* We map \r\n ==> \r for pragmatic reasons.
			 * Many client implementations send \r\n when
			 * the user hits the CarriageReturn key.
			 */
			if (c == '\r' && ptr < end && (*ptr == '\n' || *ptr == '\0'))
				ptr++;
			continue;
		}

		if ((ptr + 1) >= end)
			break;
		if (ptr[1] == NOP) { /* Ignore? (putty keepalive, etc.) */
			ptr += 2;
			continue;
		}
		if (ptr[1] == IAC) { /* Literal IAC? (emacs M-DEL) */
			*totty++ = ptr[1];
			ptr += 2;
			continue;
		}

		/*
		 * TELOPT_NAWS support!
		 */
		if ((ptr + 2) >= end) {
			/* Only the beginning of the IAC is in the
			 buffer we were asked to process, we can't
			 process this char */
			break;
		}
		/*
		 * IAC -> SB -> TELOPT_NAWS -> 4-byte -> IAC -> SE
		 */
		if (ptr[1] == SB && ptr[2] == TELOPT_NAWS) {
			struct winsize ws;
			if ((ptr + 8) >= end)
				break; /* incomplete, can't process */
			ws.ws_col = (ptr[3] << 8) | ptr[4];
			ws.ws_row = (ptr[5] << 8) | ptr[6];
			ioctl(ttyFd, TIOCSWINSZ, (char *) &ws);
			ptr += 9;
			continue;
		}
		/* skip 3-byte IAC non-SB cmd */
		ptr += 3;
	}

	num_totty = totty - ptr0;
	*pnum_totty = num_totty;
	/* The difference between ptr and totty is number of iacs
	 we removed from the stream. Adjust buf1 accordingly */
	if ((ptr - totty) == 0) /* 99.999% of cases */
		return ptr0;
	ts += ptr - totty;
	tsLen -= ptr - totty;
	/* Move chars meant for the terminal towards the end of the buffer */
	return (unsigned char *) memmove(ptr - num_totty, ptr0, num_totty);
}
ssize_t safe_write(int fd, const void *buf, size_t count) {
	ssize_t n;

	do {
		n = write(fd, buf, count);
	} while (n < 0 && errno == EINTR);

	return n;
}
size_t iac_safe_write(int fd, const char *buf, size_t count) {
	const char *IACptr;
	size_t wr, rc, total;

	total = 0;
	while (1) {
		if (count == 0)
			return total;
		if (*buf == (char) IAC) {
			const char IACIAC[] = { IAC, IAC };
			rc = safe_write(fd, IACIAC, 2);
			if (rc != 2)
				break;
			buf++;
			total++;
			count--;
			continue;
		}
		/* count != 0, *buf != IAC */
		IACptr = (const char *) memchr(buf, IAC, count);
		wr = count;
		if (IACptr)
			wr = IACptr - buf;
		rc = safe_write(fd, buf, wr);
		if (rc != wr)
			break;
		buf += rc;
		total += rc;
		count -= rc;
	}
	/* here: rc - result of last short write */
	if ((ssize_t) rc < 0) { /* error? */
		if (total == 0)
			return rc;
		rc = 0;
	}
	return total + rc;
}

//读配置文件
int readValue(char *redName, char *value) {
	FILE *fp;
	char strChar[128];
	int strCharLen = 0;
	if ((fp = fopen("/opt/hy_setup.cfg", "r")) == NULL) {
		return -1;
	} else {
		char one_line[128];
		memset(one_line, 0x00, 128);
		while (fgets(one_line, 128, fp) != NULL) {
			if (strncmp("#", one_line, 1) == 0) {
				continue;
			}
			if (strncmp(redName, one_line, strlen(redName)) == 0) {
				int i = strlen(redName) + 1;
				int j = 0;
				while (one_line[i] != '\0') {
					strChar[j++] = one_line[i++];
					strCharLen++;
				}
				break;
			}
		}
		if (strlen(strChar) == 0) {
			return -2;
		}
		memcpy(value, strChar, strCharLen);
		//printf("value is:\n",value);
		fclose(fp);

	}
	return 0;
}

