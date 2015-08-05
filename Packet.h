#pragma once

// 28�ֽ�ARP֡�ṹ
class arp_head
{
public:
	WORD hardware_type;      // Ӳ������,2�ֽ�
	WORD protocol_type;      // Э�����ͣ�2�ֽ�
	BYTE hardware_add_len;   // Ӳ����ַ���ȣ�1�ֽ�
	BYTE protocol_add_len;   // Э���ַ���ȣ�1�ֽ�
	WORD operation_field;    // �����ֶΣ�2�ֽ�
	BYTE source_mac_add[6];  // Դmac��ַ��6�ֽ�
	DWORD source_ip_add;     // Դip��ַ��4�ֽ�
	BYTE dest_mac_add[6];    // Ŀ��mac��ַ��6�ֽ�
	DWORD dest_ip_add;       // Ŀ��ip��ַ��4�ֽ�

public:
	arp_head();
	~arp_head(){};
};

// 32�ֽ�IP���ݱ��ṹ
class IP_head
{
public:
	BYTE versionAndIHL;         // �汾���ײ����ȣ�1�ֽڣ�ǰ4λ��4λ�ֿ�
	BYTE service;               // ���ַ���1�ֽ�
	WORD length;                // �ܳ��ȣ�2�ֽ�
	WORD id;                    // ��ʶ��2�ֽ�
	WORD flagAndOffset;         // ��־��Ƭƫ�ƣ�2�ֽڣ�ǰ3λ��13λ�ֿ�
	BYTE TTL;                   // ����ʱ�䣬1�ֽ�
	BYTE protocol;              // Э�飬1�ֽ�
	WORD checksum;              // �ײ�У��ͣ�2�ֽ�
	DWORD source_add;           // Դ��ַ��4�ֽ�
	DWORD dest_add;             // Ŀ�ĵ�ַ��4�ֽ�
	BYTE padding[12];

public:
	IP_head(){};
	~IP_head(){};
};

// 14�ֽ���̫��֡�ṹ
class ethernet_head
{
public:
	BYTE dest_mac_add[6];    // Ŀ��mac��ַ��6�ֽ�
	BYTE source_mac_add[6];  // Դmac��ַ��6�ֽ�
	WORD type;               // ֡���ͣ�2�ֽ�

public:
	ethernet_head();
	~ethernet_head(){};
};

// IP����֡
class ip_frame
{
public:
	ethernet_head eh;
	IP_head ih;

public:
	ip_frame(){};
	~ip_frame(){};
};

// arp����֡
class arp_frame
{
public:
	ethernet_head eh;
	arp_head ah;
	BYTE padding[18];
	//BYTE fcs[4];       // ��������һ�Σ���������ֻ�ܱ��Զ����ϣ�

public:
	arp_frame(){};
	~arp_frame(){};

};

// �豸��
class Device
{
public:

	pcap_t *adhandle;     // ��ǰ�豸
	pcap_if_t *alldevs;   // �豸�б�
	char *ip_addr;        // �Լ���IP
	char *ip_netmask;     // �Լ�����������
	char *mac;            // �Լ���MAC��ַ��ʮ�����ƣ�
	char *macStr;         // �Լ���MAC��ַ���ַ�����
	char *gateway_ip;     // ����IP��ַ
	int select;           // ѡ�е��������

private:
	
	char *errbuf;         // ���󻺴�

private:
	
	// ���������͵�IP��ַת�����ַ������͵�
	char *iptos(u_long in)
	{
		char *ipstr = new char[16];
		u_char *p;
		p = (u_char *)&in;// �ⲿ��ͨ��ָ�����͵ĸı�ʵ����ת������
		sprintf(ipstr, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
		return ipstr;
	}

	void GetInfo(pcap_if_t *d, char *ip_addr, char *ip_netmask);// ����Լ���IP����������
	int OpenDevice(pcap_if_t *d);// ���豸

public:

	Device();  // ���캯��������ȡ�����豸�б�
	~Device(); // �������������ͷű����豸�б��رմ򿪵�����
	void findCurrentDevice(int option);// ���ݻ�õı�ѡ�е��豸����ȥ��ȡ��������Ϣ��IP�����롢MAC������IP��
};

// �̹߳��������
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