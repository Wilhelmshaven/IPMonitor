#include "stdafx.h"
#include "Packet.h"

Device::Device()
{
	// ��ʼ������
	ip_addr = new char[16];
	ip_netmask = new char[16];
	gateway_ip = new char[16];
	mac = new char[6];
	macStr = new char[17];
	errbuf = new char[PCAP_ERRBUF_SIZE];
	select = 0;
	adhandle = NULL;

	/* ��ȡ�����豸�б�*/
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)exit(1);
}

Device::~Device()
{
	if (adhandle != NULL) pcap_close(adhandle); // �رմ򿪵�����
	pcap_freealldevs(alldevs);                  // �ͷ��豸�б�
}

void Device::findCurrentDevice(int option)
{
	// ȷ���Ŀ�������ѡ�У�������
	pcap_if_t *d;

	d = alldevs;
	for (int i = 0; i < option; i++)d = d->next;// ��ת��ָ������

	OpenDevice(d);                              // ������
	GetInfo(d, ip_addr, ip_netmask);            // ����Լ���IP������

	/*=================================WindowsAPI���֣����ۡ���================================*/
	// PIP_ADAPTER_INFO�ṹ��ָ��洢����������Ϣ
	PIP_ADAPTER_INFO pIpAdapterInfo = new IP_ADAPTER_INFO();
	// �õ��ṹ���С,����GetAdaptersInfo����
	DWORD stSize = sizeof(IP_ADAPTER_INFO);
	// ����GetAdaptersInfo����,���pIpAdapterInfoָ�����;����stSize��������һ��������Ҳ��һ�������
	int nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);
	if (ERROR_BUFFER_OVERFLOW == nRel)
	{
		// ����������ص���ERROR_BUFFER_OVERFLOW
		// ��˵��GetAdaptersInfo�������ݵ��ڴ�ռ䲻��,ͬʱ�䴫��stSize,��ʾ��Ҫ�Ŀռ��С
		// ��Ҳ��˵��ΪʲôstSize����һ��������Ҳ��һ�������
		// �ͷ�ԭ�����ڴ�ռ�
		delete pIpAdapterInfo;
		// ���������ڴ�ռ������洢����������Ϣ
		pIpAdapterInfo = (PIP_ADAPTER_INFO)new BYTE[stSize];
		// �ٴε���GetAdaptersInfo����,���pIpAdapterInfoָ�����
		nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);
	}
	if (ERROR_SUCCESS == nRel)
	{
		while (pIpAdapterInfo)
		{
			IP_ADDR_STRING *pIpAddrString = &(pIpAdapterInfo->IpAddressList);

			do{
				if (strcmp(ip_addr ,pIpAddrString->IpAddress.String) == 0)// WinPcapȡ���ı���IP��WindowsAPIȡ���ı���IP��ͬ��ͬһ������
				{
					// ��ȡ����IP
					gateway_ip = pIpAdapterInfo->GatewayList.IpAddress.String;
					// ��ȡ�Լ���MAC��ַ
					sprintf(macStr, "%02X-%02X-%02X-%02X-%02X-%02X", 
						pIpAdapterInfo->Address[0], 
						pIpAdapterInfo->Address[1],
						pIpAdapterInfo->Address[2], 
						pIpAdapterInfo->Address[3], 
						pIpAdapterInfo->Address[4],
						pIpAdapterInfo->Address[5]);
					for (int i = 0; i < 6; i++)mac[i] = pIpAdapterInfo->Address[i];

					goto endWindowsAPI;// �ԣ�����������Ŷ��
				}
				pIpAddrString = pIpAddrString->Next;
			} while (pIpAddrString);

			pIpAdapterInfo = pIpAdapterInfo->Next;
		}
	}
	
endWindowsAPI:
	;// ���һ���WindowsAPI˵�ݰ�~

}

// ����Լ���IP������
void Device::GetInfo(pcap_if_t *d, char *ip_addr, char *ip_netmask)
{
	pcap_addr_t *a;
	for (a = d->addresses; a; a = a->next)
	{
		if (a->addr->sa_family == AF_INET)     // internetwork: UDP, TCP, etc. ��ȡIP��
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

//���豸
int Device::OpenDevice(pcap_if_t *d)
{
	if ((adhandle = pcap_open(d->name,          // �豸��
		65536,            // 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
		PCAP_OPENFLAG_PROMISCUOUS,    // ����ģʽ���Ա�֤ץ��ARP��
		1,             /*��ȡ��ʱʱ�䣬��λΪ���룬��׽���ݰ���ʱ���ӳ�һ����ʱ�䣬Ȼ���ٵ����ں��еĳ���
					   ����Ч�ʽϸߡ�0��ʾû���ӳ٣�û�а������ʱ���������ء�-1��ʾ�������ء�*/
					   NULL,             // Զ�̻�����֤
					   errbuf            // ���󻺳��
					   )) == NULL)
	{
		pcap_freealldevs(alldevs);// �ͷ��豸�б�
		return -1;
	}
	else return 0;
}

// ��ʼ��ARP���ṹ
arp_head :: arp_head()
{
	memset(dest_mac_add, 0xff, 6);  // ��ʼ��Ϊ�㲥��ַ
	hardware_add_len = 6;
	protocol_add_len = 4;
}

// ��ʼ����̫��֡ͷ
ethernet_head :: ethernet_head()
{
	memset(dest_mac_add, 0xff, 6);
	memset(source_mac_add, 0xff, 6);
}