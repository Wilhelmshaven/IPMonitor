#include "stdafx.h"
#include "Packet.h"

Device::Device()
{
	// 初始化变量
	ip_addr = new char[16];
	ip_netmask = new char[16];
	gateway_ip = new char[16];
	mac = new char[6];
	macStr = new char[17];
	errbuf = new char[PCAP_ERRBUF_SIZE];
	select = 0;
	adhandle = NULL;

	/* 获取本机设备列表*/
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)exit(1);
}

Device::~Device()
{
	if (adhandle != NULL) pcap_close(adhandle); // 关闭打开的网卡
	pcap_freealldevs(alldevs);                  // 释放设备列表
}

void Device::findCurrentDevice(int option)
{
	// 确定哪块网卡被选中，并打开它
	pcap_if_t *d;

	d = alldevs;
	for (int i = 0; i < option; i++)d = d->next;// 跳转到指定网卡

	OpenDevice(d);                              // 打开网卡
	GetInfo(d, ip_addr, ip_netmask);            // 获得自己的IP与掩码

	/*=================================WindowsAPI部分，蛋疼……================================*/
	// PIP_ADAPTER_INFO结构体指针存储本机网卡信息
	PIP_ADAPTER_INFO pIpAdapterInfo = new IP_ADAPTER_INFO();
	// 得到结构体大小,用于GetAdaptersInfo参数
	DWORD stSize = sizeof(IP_ADAPTER_INFO);
	// 调用GetAdaptersInfo函数,填充pIpAdapterInfo指针变量;其中stSize参数既是一个输入量也是一个输出量
	int nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);
	if (ERROR_BUFFER_OVERFLOW == nRel)
	{
		// 如果函数返回的是ERROR_BUFFER_OVERFLOW
		// 则说明GetAdaptersInfo参数传递的内存空间不够,同时其传出stSize,表示需要的空间大小
		// 这也是说明为什么stSize既是一个输入量也是一个输出量
		// 释放原来的内存空间
		delete pIpAdapterInfo;
		// 重新申请内存空间用来存储所有网卡信息
		pIpAdapterInfo = (PIP_ADAPTER_INFO)new BYTE[stSize];
		// 再次调用GetAdaptersInfo函数,填充pIpAdapterInfo指针变量
		nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);
	}
	if (ERROR_SUCCESS == nRel)
	{
		while (pIpAdapterInfo)
		{
			IP_ADDR_STRING *pIpAddrString = &(pIpAdapterInfo->IpAddressList);

			do{
				if (strcmp(ip_addr ,pIpAddrString->IpAddress.String) == 0)// WinPcap取到的本机IP和WindowsAPI取到的本机IP相同：同一张网卡
				{
					// 获取网关IP
					gateway_ip = pIpAdapterInfo->GatewayList.IpAddress.String;
					// 获取自己的MAC地址
					sprintf(macStr, "%02X-%02X-%02X-%02X-%02X-%02X", 
						pIpAdapterInfo->Address[0], 
						pIpAdapterInfo->Address[1],
						pIpAdapterInfo->Address[2], 
						pIpAdapterInfo->Address[3], 
						pIpAdapterInfo->Address[4],
						pIpAdapterInfo->Address[5]);
					for (int i = 0; i < 6; i++)mac[i] = pIpAdapterInfo->Address[i];

					goto endWindowsAPI;// 乖，不和你玩了哦！
				}
				pIpAddrString = pIpAddrString->Next;
			} while (pIpAddrString);

			pIpAdapterInfo = pIpAdapterInfo->Next;
		}
	}
	
endWindowsAPI:
	;// 大家一起和WindowsAPI说拜拜~

}

// 获得自己的IP与掩码
void Device::GetInfo(pcap_if_t *d, char *ip_addr, char *ip_netmask)
{
	pcap_addr_t *a;
	for (a = d->addresses; a; a = a->next)
	{
		if (a->addr->sa_family == AF_INET)     // internetwork: UDP, TCP, etc. 即取IP包
		{
			if (a->addr)
			{
				char *ipstr;
				ipstr = iptos(((sockaddr_in *)a->addr)->sin_addr.s_addr);
				memcpy(ip_addr, ipstr, 16);
			}
			if (a->netmask)
			{
				char *netmaskstr;
				netmaskstr = iptos(((sockaddr_in *)a->netmask)->sin_addr.s_addr);
				memcpy(ip_netmask, netmaskstr, 16);
			}
		}
	}
}

//打开设备
int Device::OpenDevice(pcap_if_t *d)
{
	if ((adhandle = pcap_open(d->name,          // 设备名
		65536,            // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
		PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式，以保证抓到ARP包
		1,             /*读取超时时间，单位为毫秒，捕捉数据包的时候，延迟一定的时间，然后再调用内核中的程序，
					   这样效率较高。0表示没有延迟，没有包到达的时候永不返回。-1表示立即返回。*/
					   NULL,             // 远程机器验证
					   errbuf            // 错误缓冲池
					   )) == NULL)
	{
		pcap_freealldevs(alldevs);// 释放设备列表
		return -1;
	}
	else return 0;
}

// 初始化ARP报结构
arp_head :: arp_head()
{
	memset(dest_mac_add, 0xff, 6);  // 初始化为广播地址
	hardware_add_len = 6;
	protocol_add_len = 4;
}

// 初始化以太网帧头
ethernet_head :: ethernet_head()
{
	memset(dest_mac_add, 0xff, 6);
	memset(source_mac_add, 0xff, 6);
}