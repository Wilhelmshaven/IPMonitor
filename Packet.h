#pragma once

// 28字节ARP帧结构
class arp_head
{
public:
	WORD hardware_type;      // 硬件类型,2字节
	WORD protocol_type;      // 协议类型，2字节
	BYTE hardware_add_len;   // 硬件地址长度，1字节
	BYTE protocol_add_len;   // 协议地址长度，1字节
	WORD operation_field;    // 操作字段，2字节
	BYTE source_mac_add[6];  // 源mac地址，6字节
	DWORD source_ip_add;     // 源ip地址，4字节
	BYTE dest_mac_add[6];    // 目的mac地址，6字节
	DWORD dest_ip_add;       // 目的ip地址，4字节

public:
	arp_head();
	~arp_head(){};
};

// 32字节IP数据报结构
class IP_head
{
public:
	BYTE versionAndIHL;         // 版本与首部长度，1字节，前4位后4位分开
	BYTE service;               // 区分服务，1字节
	WORD length;                // 总长度，2字节
	WORD id;                    // 标识，2字节
	WORD flagAndOffset;         // 标志和片偏移，2字节，前3位后13位分开
	BYTE TTL;                   // 生存时间，1字节
	BYTE protocol;              // 协议，1字节
	WORD checksum;              // 首部校验和，2字节
	DWORD source_add;           // 源地址，4字节
	DWORD dest_add;             // 目的地址，4字节
	BYTE padding[12];

public:
	IP_head(){};
	~IP_head(){};
};

// 14字节以太网帧结构
class ethernet_head
{
public:
	BYTE dest_mac_add[6];    // 目的mac地址，6字节
	BYTE source_mac_add[6];  // 源mac地址，6字节
	WORD type;               // 帧类型，2字节

public:
	ethernet_head();
	~ethernet_head(){};
};

// IP数据帧
class ip_frame
{
public:
	ethernet_head eh;
	IP_head ih;

public:
	ip_frame(){};
	~ip_frame(){};
};

// arp数据帧
class arp_frame
{
public:
	ethernet_head eh;
	arp_head ah;
	BYTE padding[18];
	//BYTE fcs[4];       // 不能有这一段，否则会出错（只能被自动加上）

public:
	arp_frame(){};
	~arp_frame(){};

};

// 设备类
class Device
{
public:

	pcap_t *adhandle;     // 当前设备
	pcap_if_t *alldevs;   // 设备列表
	char *ip_addr;        // 自己的IP
	char *ip_netmask;     // 自己的子网掩码
	char *mac;            // 自己的MAC地址（十六进制）
	char *macStr;         // 自己的MAC地址（字符串）
	char *gateway_ip;     // 网关IP地址
	int select;           // 选中的网卡编号

private:
	
	char *errbuf;         // 错误缓存

private:
	
	// 将数字类型的IP地址转换成字符串类型的
	char *iptos(u_long in)
	{
		char *ipstr = new char[16];
		u_char *p;
		p = (u_char *)&in;// 这部分通过指针类型的改变实现了转换过程
		sprintf(ipstr, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
		return ipstr;
	}

	void GetInfo(pcap_if_t *d, char *ip_addr, char *ip_netmask);// 获得自己的IP和子网掩码
	int OpenDevice(pcap_if_t *d);// 打开设备

public:

	Device();  // 构造函数，并获取本机设备列表
	~Device(); // 析构函数，并释放本机设备列表及关闭打开的网卡
	void findCurrentDevice(int option);// 根据获得的被选中的设备名字去获取该网卡信息（IP、掩码、MAC、网关IP）
};

// 线程共享参数域
class sparam
{
public:
	pcap_t *adhandle;
	char *gateway_ip;
	char *myIP;
	char *netmask;
	HWND myDlg;

public:
	sparam(){};
	~sparam(){};
};