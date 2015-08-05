/*************************************************************
*   I declare that the assignment here submitted is original *
* except for source material explicitly acknowledged. I also *
* acknowledge that I am aware of University policy and       *
* regulations on honesty in academic work, and of the        *
* disciplinary guidelines and procedures applicable to       *
* breaches of such policy and regulations.                   *
*                                                            *
* Hongjie Li                    2014.11.03                   *
* Signature						Date                         *
*************************************************************/
// IPMonitor.cpp : ����Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
#include "IPMonitor.h"
#include "Packet.h"

//���任
#pragma comment(linker, "\"/manifestdependency:type='Win32'\
 name='Microsoft.Windows.Common-Controls' version='6.0.0.0'\
 processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// ȫ�ֱ���: 
enum CustomDefine
{
	MAX_LOADSTRING = 100,
	ETH_ARP = 0x0806,      // ��̫��֡���ͱ�ʾ�������ݵ����ͣ�����ARP�����Ӧ����˵�����ֶε�ֵΪx0806
	ARP_HARDWARE = 1,      // Ӳ�������ֶ�ֵΪ��ʾ��̫����ַ
	ETH_IP = 0x0800,       // Э�������ֶα�ʾҪӳ���Э���ַ����ֵΪx0800��ʾIP��ַ
	ARP_REQUEST = 1,
	ARP_REPLY = 2,
	TCP = 0x06,            // IP���ݱ���TCPЭ��
	UDP = 0x11             // IP���ݱ���UDPЭ��
};

HINSTANCE hInst;								// ��ǰʵ��
TCHAR szTitle[MAX_LOADSTRING];					// �������ı�
TCHAR szWindowClass[MAX_LOADSTRING];			// ����������
Device myDevice;                                // �豸��

HANDLE hArpEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
HANDLE hCapture = CreateEvent(NULL, TRUE, FALSE, NULL);
HANDLE hFinish = CreateEvent(NULL, TRUE, FALSE, NULL);

sparam sp;                                      // �̹߳������

// �����ж�״̬��ȫ�ֱ�����δ�������¼��������
int Selected = -1;
BOOL sCheck = FALSE;
BOOL dCheck = FALSE;

// �˴���ģ���а����ĺ�����ǰ������: 
ATOM				MyRegisterClass(HINSTANCE hInstance);
BOOL				InitInstance(HINSTANCE, int);
LRESULT CALLBACK	WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK	About(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    DlgProc(HWND hdlg, UINT msg, WPARAM wParam, LPARAM lParam);         // �Ӵ���

// �ѽ�������ListView��
BOOL                AddListViewItems(HWND hwndListView, char *ip_add, char *dest_add, char *protocol); 

// �շ�������
UINT SendArpPacket(LPVOID lpParameter);
UINT AnalyzePacket(LPVOID lpParameter);
HANDLE sendThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)SendArpPacket, NULL, 0, NULL);
HANDLE recvThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)AnalyzePacket, NULL, 0, NULL);

/*============================== WinMain ==============================*/
int APIENTRY _tWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPTSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // TODO:  �ڴ˷��ô��롣
    MSG msg;
    HACCEL hAccelTable;

    // ��ʼ��ȫ���ַ���
    LoadString(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadString(hInstance, IDC_IPMONITOR, szWindowClass, MAX_LOADSTRING);
    MyRegisterClass(hInstance);

    // ִ��Ӧ�ó����ʼ��: 
    if (!InitInstance (hInstance, nCmdShow))
    {
        return FALSE;
    }

    hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_IPMONITOR));

    // ����Ϣѭ��: 
    while (GetMessage(&msg, NULL, 0, 0))
    {
        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    return (int) msg.wParam;
}

// ע�ᴰ����
ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEX wcex;

    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style			= CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc	= WndProc;
    wcex.cbClsExtra		= 0;
    wcex.cbWndExtra		= 0;
    wcex.hInstance		= hInstance;
    wcex.hIcon			= LoadIcon(hInstance, MAKEINTRESOURCE(IDI_IPMONITOR));
    wcex.hCursor		= LoadCursor(NULL, IDC_ARROW);
    wcex.hbrBackground	= (HBRUSH)(COLOR_WINDOW+1);
    wcex.lpszMenuName	= MAKEINTRESOURCE(IDC_IPMONITOR);
    wcex.lpszClassName	= szWindowClass;
    wcex.hIconSm		= LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

    return RegisterClassEx(&wcex);
}

// ����ʵ�����������������
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   HWND hWnd;

   hInst = hInstance; // ��ʵ������洢��ȫ�ֱ�����

   // �����ڲ��ɱ��С��ͬʱ�������
   hWnd = CreateWindow(szWindowClass, szTitle, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
       CW_USEDEFAULT, 0, 540, 580, NULL, NULL, hInstance, NULL);

   if (!hWnd)
   {
      return FALSE;
   }

   ShowWindow(hWnd, nCmdShow);
   UpdateWindow(hWnd);

   return TRUE;
}

// ���������ڵ���Ϣ
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    int wmId, wmEvent;
    HWND myhdlg = NULL;

    switch (message)
    {
    case WM_CREATE:
    {
        // �����ӶԻ��򲢽�����Ϊ������
        myhdlg = CreateDialog(hInst, MAKEINTRESOURCE(IDD_FORMVIEW), hWnd, (DLGPROC)DlgProc);
        ShowWindow(myhdlg, SW_SHOW);

        // ���ñ���������ʽ
        LOGFONT TitleFont;
        ZeroMemory(&TitleFont,sizeof(TitleFont));                     // �����������������߰���ĳ�ֵ
        lstrcpy(TitleFont.lfFaceName, "Segoe Script");                // ��������
        TitleFont.lfWeight = FW_BOLD;                                 // ��ϸ��BOLD=700��д��CSS��֪��
        TitleFont.lfHeight = -24;                                     // �����С��������н�������
        TitleFont.lfCharSet = DEFAULT_CHARSET;                        // Ĭ���ַ���
        TitleFont.lfOutPrecision = OUT_DEVICE_PRECIS;                 // �������

        HFONT hFont = CreateFontIndirect(&TitleFont);                 
        HWND hWndStatic = GetDlgItem(myhdlg, IDC_STATIC_TITLE);       
        SendMessage(hWndStatic, WM_SETFONT, (WPARAM)hFont, 0);        

		// ������Ŀ������ʽ
        LOGFONT TextFont;
        ZeroMemory(&TextFont, sizeof(TextFont)); 
        lstrcpy(TextFont.lfFaceName, "Gabriola");
        TextFont.lfHeight = -16; 
        hFont = CreateFontIndirect(&TextFont);
		 
		// ���ÿؼ�����
        hWndStatic = GetDlgItem(myhdlg, IDC_TEXT_1);
        SendMessage(hWndStatic, WM_SETFONT, (WPARAM)hFont, 0);
        hWndStatic = GetDlgItem(myhdlg, IDC_TEXT_2);
        SendMessage(hWndStatic, WM_SETFONT, (WPARAM)hFont, 0);
        hWndStatic = GetDlgItem(myhdlg, IDC_TEXT_3);
        SendMessage(hWndStatic, WM_SETFONT, (WPARAM)hFont, 0);
        hWndStatic = GetDlgItem(myhdlg, IDC_TEXT_4);
        SendMessage(hWndStatic, WM_SETFONT, (WPARAM)hFont, 0);
        hWndStatic = GetDlgItem(myhdlg, IDC_TEXT_5);
        SendMessage(hWndStatic, WM_SETFONT, (WPARAM)hFont, 0);
        hWndStatic = GetDlgItem(myhdlg, IDC_TEXT_6);
        SendMessage(hWndStatic, WM_SETFONT, (WPARAM)hFont, 0);
    }// WM_CREATE

    case WM_COMMAND:
        wmId    = LOWORD(wParam);
        wmEvent = HIWORD(wParam);
        // �����˵�ѡ��: 
        switch (wmId)
        {
        case IDM_ABOUT:
            DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
            break;
        case IDM_EXIT:
            DestroyWindow(hWnd);
            break;
        default:
            return DefWindowProc(hWnd, message, wParam, lParam);
        }
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

// �����ڡ������Ϣ�������
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}

// ����Ի�����Ϣ  
INT_PTR CALLBACK DlgProc(HWND hdlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    int wmId, wmEvent;
    HWND hListview = GetDlgItem(hdlg, IDC_LIST1);       // ListView
    HWND hWndComboBox = GetDlgItem(hdlg, IDC_COMBO1);   // ComboBox
	HWND hButton = NULL;                                // Button
	HWND hEditBox = NULL;                               // Editbox
	HWND hCheckBox = NULL;                              // CheckBox

    switch (msg)
    {
    case WM_INITDIALOG:
    {
        // ���Listview����������������

        // ����ListView����  
        LVCOLUMN lvc;
		lvc.mask = LVCF_FMT | LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
		ListView_SetTextColor(hListview, RGB(0, 0, 255));                // ����������ɫ
		ListView_SetTextBkColor(hListview, RGB(199, 237, 204));          // �������ֱ�����ɫ
		ListView_SetExtendedListViewStyle(hListview, LVS_EX_GRIDLINES);  // ��ӵ�����

        lvc.pszText = "Source";          // �б���  
        lvc.cx = 0;                      // �п�  
        lvc.iSubItem = 0;                // ������������һ�������� (0) 
        lvc.fmt = LVCFMT_CENTER;
        ListView_InsertColumn(hListview, 0, &lvc);
		lvc.cx = 150;
		ListView_InsertColumn(hListview, 1, &lvc);

        lvc.pszText = "Destination";
        lvc.cx = 150;
        lvc.iSubItem = 1;               // ��������  
        lvc.fmt = LVCFMT_CENTER;
        ListView_InsertColumn(hListview, 2, &lvc);

        lvc.pszText = "Protocol";
        lvc.cx = 80;
        lvc.iSubItem = 2;
        lvc.fmt = LVCFMT_CENTER;
        ListView_InsertColumn(hListview, 3, &lvc);

        lvc.pszText = "Packets";
        lvc.cx = 80;
        lvc.iSubItem = 3;
        lvc.fmt = LVCFMT_CENTER;
        ListView_InsertColumn(hListview, 4, &lvc);

        // �������б������Ŀ
        pcap_if_t *d;
        for (d = myDevice.alldevs; d; d = d->next)
        {
            SendMessage(hWndComboBox, CB_ADDSTRING, 0, (LPARAM)d->description);
        }

		// Ĭ��CheckBoxȫ����
		CheckDlgButton(hdlg, IDC_CHECK_S, BST_CHECKED);
		CheckDlgButton(hdlg, IDC_CHECK_D, BST_CHECKED);

        break;
    }// WM_INITIALIZE

    case WM_CREATE:
    {
        // ������ť
        hButton = CreateWindow(
            "BUTTON",                                               // Predefined class; Unicode assumed 
            "OK",                                                   // Button text 
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,  // Styles 
            100,                                                    // x position 
            100,                                                    // y position 
            100,                                                    // Button width
            100,                                                    // Button height
            hdlg,                                                   // Parent window
            (HMENU)IDC_BTN_BEGIN,                                   // No menu.
            (HINSTANCE)GetWindowLong(hdlg, GWL_HINSTANCE),
            NULL);                                                  // Pointer not needed.

		hButton = CreateWindow(
			"BUTTON", "OK",
			WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
			100, 100, 100, 100, hdlg, (HMENU)IDC_BTN_STOP,
			(HINSTANCE)GetWindowLong(hdlg, GWL_HINSTANCE), NULL);

		hButton = CreateWindow(
			"BUTTON", "OK",
			WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
			100, 100, 100, 100, hdlg, (HMENU)IDC_BTN_ABOUT,
			(HINSTANCE)GetWindowLong(hdlg, GWL_HINSTANCE), NULL);

		hButton = CreateWindow(
			"BUTTON", "OK",
			WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
			100, 100, 100, 100, hdlg, (HMENU)IDC_BTN_EXIT,
			(HINSTANCE)GetWindowLong(hdlg, GWL_HINSTANCE), NULL);

		// ����CheckBox
		hButton = CreateWindow(
			"CHECKBOX", "OK",
			WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_CHECKBOX,
			100, 100, 100, 100, hdlg, (HMENU)IDC_CHECK_S,
			(HINSTANCE)GetWindowLong(hdlg, GWL_HINSTANCE), NULL);

		hButton = CreateWindow(
			"CHECKBOX", "OK",
			WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_CHECKBOX,
			100, 100, 100, 100, hdlg, (HMENU)IDC_CHECK_D,
			(HINSTANCE)GetWindowLong(hdlg, GWL_HINSTANCE), NULL);
		Button_Enable(hButton, TRUE);
		
        break;
    }// WM_CREATE

    case WM_COMMAND:
    {
        wmId = LOWORD(wParam);
        wmEvent = HIWORD(wParam);

        switch (wmId)
        {
            // ��ť���ܵ�ʵ��
		case IDC_BTN_BEGIN:
		{
			// �����Ҫ��յ���Ϣ������һ�ε�ɨ������
			SendMessage(hListview, LVM_DELETEALLITEMS, 0, 0);

			//���CheckBox״̬�����ѹ���������ΪTrue
			hCheckBox = GetDlgItem(hdlg, IDC_CHECK_S);
			if (Button_GetCheck(hCheckBox) == BST_CHECKED)sCheck = TRUE;
			hCheckBox = GetDlgItem(hdlg, IDC_CHECK_D);
			if (Button_GetCheck(hCheckBox) == BST_CHECKED)dCheck = TRUE;

			if (Selected != -1)
			{
				// ������CheckBox��û�б����ϵĻ������Զ�����ȫ�����ϣ�Ĭ��ģʽ�ɾ����ǣ�
				if ((sCheck == FALSE) && (dCheck == FALSE))
				{
					CheckDlgButton(hdlg, IDC_CHECK_S, BST_CHECKED);
					CheckDlgButton(hdlg, IDC_CHECK_D, BST_CHECKED);
					sCheck = TRUE;
					dCheck = TRUE;
				}
				
				// ��ʼ�շ����������¼�
				SetEvent(hArpEvent);
				SetEvent(hCapture);

				// ��һЩȨ�޹���
				ComboBox_Enable(hWndComboBox, FALSE);
				hButton = GetDlgItem(hdlg, IDC_BTN_BEGIN);
				Button_Enable(hButton, FALSE);
				hButton = GetDlgItem(hdlg, IDC_BTN_STOP);
				Button_Enable(hButton, TRUE);
				hCheckBox = GetDlgItem(hdlg, IDC_CHECK_S);
				Button_Enable(hCheckBox, FALSE);
				hCheckBox = GetDlgItem(hdlg, IDC_CHECK_D);
				Button_Enable(hCheckBox, FALSE);
			}
			else     
			{
				Beep(880, 100);
				PostMessage(hdlg, WM_COMMAND, (WPARAM)IDC_BTN_STOP, NULL);
			}
			break;
		}// IDC_BTN_BEGIN
		case IDC_BTN_STOP:
		{
			// ֻ��Ҫֹͣ�հ��̣߳����𼴿�
			ResetEvent(hCapture);

			sCheck = FALSE;
			dCheck = FALSE;

			// ��һЩȨ�޹���
			ComboBox_Enable(hWndComboBox, TRUE);
			hButton = GetDlgItem(hdlg, IDC_BTN_BEGIN);
			Button_Enable(hButton, TRUE);
			hButton = GetDlgItem(hdlg, IDC_BTN_STOP);
			Button_Enable(hButton, FALSE);
			hCheckBox = GetDlgItem(hdlg, IDC_CHECK_S);
			Button_Enable(hCheckBox, TRUE);
			hCheckBox = GetDlgItem(hdlg, IDC_CHECK_D);
			Button_Enable(hCheckBox, TRUE);
			MessageBox(NULL, "ɨ����ֹ", "", MB_OK);

			break;
		}// IDC_BTN_STOP
        case IDC_BTN_ABOUT:
            DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hdlg, About);
            break;
        case IDC_BTN_EXIT:
			SetEvent(hFinish);
			SetEvent(hArpEvent);
			SetEvent(hCapture);

            PostQuitMessage(0);
            break;
        default:
            break;
        }// wmID

        //����ؼ���Ϣ
        switch (wmEvent)
        {
			// �����б�ѡ�����仯
        case CBN_SELCHANGE:
        {
            Selected = -1;

            Selected = (int)SendMessage(hWndComboBox, CB_GETCURSEL, 0, 0); // ���ѡ�е�ѡ����

			// ��û��ѡ����Ŀ����ֹͣ���У�������Ϣ
			if (Selected == -1)
			{
				Beep(880, 100);
				PostMessage(hdlg, WM_COMMAND, (WPARAM)IDC_BTN_STOP, NULL);
				break;
			}

			// ���ݻ�õı�ѡ�е��豸����ȥ��ȡ��������Ϣ��IP�����룩
            myDevice.findCurrentDevice(Selected);
            SendMessage(hWndComboBox, CB_SETCURSEL, (WPARAM)Selected, 0); // ��ʾѡ�е�����

            // ��ʾ����IP
            hEditBox = GetDlgItem(hdlg, IDC_EDIT_IP);
            SendMessage(hEditBox, EM_SETREADONLY, 0, 0);
            SendMessage(hEditBox, WM_SETTEXT, 0, (LPARAM)myDevice.ip_addr);

            // ��ʾ��������
            hEditBox = GetDlgItem(hdlg, IDC_EDIT_MASK);
            SendMessage(hEditBox, EM_SETREADONLY, 0, 0);
            SendMessage(hEditBox, WM_SETTEXT, 0, (LPARAM)myDevice.ip_netmask);

            // ��ʾ����MAC
            hEditBox = GetDlgItem(hdlg, IDC_EDIT_MAC);
            SendMessage(hEditBox, EM_SETREADONLY, 0, 0);
            SendMessage(hEditBox, WM_SETTEXT, 0, (LPARAM)myDevice.macStr);

            // ��ʾ����IP
            hEditBox = GetDlgItem(hdlg, IDC_EDIT_GATEIP);
            SendMessage(hEditBox, EM_SETREADONLY, 0, 0);
            SendMessage(hEditBox, WM_SETTEXT, 0, (LPARAM)myDevice.gateway_ip);

			// ��ʼ�����������MAC��ַ�Ի�������
			hEditBox = GetDlgItem(hdlg, IDC_EDIT_GATEMAC);
			SendMessage(hEditBox, EM_SETREADONLY, 0, 0);
			SendMessage(hEditBox, WM_SETTEXT, 0, NULL);

            // �������ݰ������������ݣ�����Ҫ����ȡ�����ص�ַ
            sp.adhandle = myDevice.adhandle;
            sp.gateway_ip = myDevice.gateway_ip;
            sp.myIP = myDevice.ip_addr;
            sp.netmask = myDevice.ip_netmask;
            sp.myDlg = hdlg;                       // ���ھ��

            break;
        }// WM_SELCHANGE
        default:
            break;
        }// wmEvent

        break;
    }// WM_COMMAND
    }// msg

    return (INT_PTR)FALSE;
}

/* Ϊ�˻�ȡ����MAC��ַ����������Ҫ�Σ��ͷ�һ��ARP�� */
UINT SendArpPacket(LPVOID lpParameter)//(pcap_t *adhandle,char *ip,BYTE *mac,char *netmask)
{
	sparam *spara = &sp;
	BYTE *sendbuf = new BYTE[60];                      // arp���ṹ��С��ֻ����60������fcs
	arp_frame arpFrame;
	
	while (1)
	{
		// �ȴ���ʼָ�ȷ���Ƿ����˳�ָ��
		WaitForSingleObject(hArpEvent, INFINITE);
		if (WaitForSingleObject(hFinish, 0) == WAIT_OBJECT_0)break;

		Beep(440, 200);
		pcap_t *adhandle = spara->adhandle;
		char *gateway_ip = spara->gateway_ip;              // ����IP
		char *ip = spara->myIP;                            // �Լ���IP
		char *netmask = spara->netmask;                    // �Լ���NETMASK	

		// �������
		arpFrame.eh.type = htons(ETH_ARP);                        // ��̫��֡ͷЭ������
		memset(arpFrame.eh.dest_mac_add, 0xff, 6);                // MAC�Ĺ㲥��ַΪFF-FF-FF-FF-FF-FF
		for (int i = 0; i < 6; i++)arpFrame.eh.source_mac_add[i] = myDevice.mac[i];
		arpFrame.ah.hardware_type = htons(ARP_HARDWARE);          // Ӳ����ַ
		arpFrame.ah.protocol_type = htons(ETH_IP);                // ARP��Э������
		inet_pton(AF_INET, ip, &arpFrame.ah.source_ip_add);       // ���󷽵�IP��ַΪ�����IP��ַ         	
		arpFrame.ah.operation_field = htons(ARP_REQUEST);         // ARP�����
		inet_pton(AF_INET, gateway_ip, &arpFrame.ah.dest_ip_add); // Ŀ��IP��дΪ����IP

		// �����õ����ݰ�װ�뻺��
		memset(sendbuf, 0, sizeof(sendbuf));
		memcpy(sendbuf, &arpFrame, sizeof(arpFrame));

		pcap_sendpacket(adhandle, sendbuf, 60);                   // ����

		// ARP�¼���λ
		ResetEvent(hArpEvent);
	}

	delete[]sendbuf;

    return 0;
}

/* �������������ݰ���ȡ�������IP��ַ */
UINT AnalyzePacket(LPVOID lpParameter)//(pcap_t *adhandle)
{
	sparam *spara = &sp;
	HWND hwndListView;
	HWND EditBox;
	char *source_ip = new char[16];           // ԴIP
	char *dest_ip = new char[16];             // Ŀ��IP
	char *mac_add = new char[18];             // MAC��ַ

	while (1)
	{
		// �ȴ���ʼָ�ȷ���Ƿ����˳�ָ��
		WaitForSingleObject(hCapture, INFINITE);
		if (WaitForSingleObject(hFinish, 0) == WAIT_OBJECT_0)break;

		Beep(880, 200);
		hwndListView = GetDlgItem(spara->myDlg, IDC_LIST1);

		pcap_t *adhandle = spara->adhandle;
		int res;                                // ������
		
		char *myIP = spara->myIP;               // �ҵ�IP
		pcap_pkthdr * pkt_header;
		const u_char * pkt_data;
		int arp = 0;                            // ARP�����Ʊ�����ֻ��һ���������滻
		arp_frame *recvARP;
		ip_frame *recvIP;

		while (WaitForSingleObject(hCapture, 0) == WAIT_OBJECT_0)
		{
			if (WaitForSingleObject(hFinish, 0) == WAIT_OBJECT_0)break;

			if ((res = pcap_next_ex(adhandle, &pkt_header, &pkt_data)) > 0)// ʹ�÷ǻص������������ݰ�
			{
				if (arp == 0)
				{
					// �ж�ARP���ĵ�13,14λ��Type���Ƿ����0x0806��Ŀ�����˳�ARP��	
					if (*(WORD *)(pkt_data + 12) == htons(ETH_ARP))		
					{
						// ��������װ��ARP֡�ṹ
						recvARP = (arp_frame *)pkt_data;

						// ��ʽ��IP�Խ��бȽ�
						sprintf_s(source_ip, 16, "%d.%d.%d.%d", recvARP->ah.source_ip_add & 255, recvARP->ah.source_ip_add >> 8 & 255,
							recvARP->ah.source_ip_add >> 16 & 255, recvARP->ah.source_ip_add >> 24 & 255);

						// �жϲ�����λ�Ƿ���ARP_REPLY�����˳�ARPӦ�����ȷ�������ش𸴵�ARP��
						if (recvARP->ah.operation_field == htons(ARP_REPLY) && (strcmp(source_ip, spara->gateway_ip) == 0))
						{
							// ��ʽ��MAC�������
							sprintf_s(mac_add, 18, "%02X-%02X-%02X-%02X-%02X-%02X", recvARP->ah.source_mac_add[0],
								recvARP->ah.source_mac_add[1], recvARP->ah.source_mac_add[2], recvARP->ah.source_mac_add[3],
								recvARP->ah.source_mac_add[4], recvARP->ah.source_mac_add[5]);

							// ������ص�MAC��ַ
							EditBox = GetDlgItem(spara->myDlg, IDC_EDIT_GATEMAC);
							SendMessage(EditBox, EM_SETREADONLY, 0, 0);
							SendMessage(EditBox, WM_SETTEXT, 0, (LPARAM)mac_add);

							// �ҵ�����MAC��ַ��
							if (WaitForSingleObject(hArpEvent, 0) == WAIT_OBJECT_0)
							{
								++arp; // ������ȡARP��
							}
						}
					}
				}// ARP

				// �������IP��
				if (*(WORD *)(pkt_data + 12) == htons(ETH_IP))
				{
					// ��������װ��IP֡�ṹ
					recvIP = (ip_frame *)pkt_data;

					// ��ʽ��IP�Խ��бȽ�
					sprintf_s(source_ip, 16, "%d.%d.%d.%d", recvIP->ih.source_add & 255, recvIP->ih.source_add >> 8 & 255,
						recvIP->ih.source_add >> 16 & 255, recvIP->ih.source_add >> 24 & 255);
					sprintf_s(dest_ip, 16, "%d.%d.%d.%d", recvIP->ih.dest_add & 255, recvIP->ih.dest_add >> 8 & 255,
						recvIP->ih.dest_add >> 16 & 255, recvIP->ih.dest_add >> 24 & 255);

					// �ж��Ƿ����ҵİ������ҵ�IP���бȽϣ��Լ�CheckBox��״̬��
					if (((strcmp(source_ip, spara->myIP) == 0) && sCheck) || ((strcmp(dest_ip, spara->myIP) == 0) && dCheck))
					{
						// �ж�Э����ɶ��ʮ������UDP��17(0x11)��TCP��6(0x06)
						if (recvIP->ih.protocol == TCP)
						{
							AddListViewItems(hwndListView, source_ip, dest_ip, "TCP");
						}
						if (recvIP->ih.protocol == UDP)
						{
							AddListViewItems(hwndListView, source_ip, dest_ip, "UDP");
						}
					}
				}// IP
			}			
		}

		// �յ��˳�ָ��
		if (WaitForSingleObject(hFinish, 0) == WAIT_OBJECT_0)break;
	}

	delete []source_ip;
	delete []dest_ip;
	delete []mac_add;

    return 0;
}

// ��ListView����������
BOOL AddListViewItems(HWND hwndListView, char *ip_add, char *dest_add, char *protocol)
{
	// �Ƚ��м�������Ŀ�ǲ����Ѿ�����
	int ListItemCount = ListView_GetItemCount(hwndListView);
	char *sIP = new char[16];
	char *dIP = new char[16];
	char *pro = new char[6];
	char *count = new char[6];
	int packets = 0;
	int flag = 0;

	// ���бȶԣ��������ÿؼ�
	for (int i = 0; i < ListItemCount; i++)
	{
		// �������ǵ���ƣ���ȡǰ���е�����
		ListView_GetItemText(hwndListView, i, 1, sIP, 16);
		ListView_GetItemText(hwndListView, i, 2, dIP, 16);
		ListView_GetItemText(hwndListView, i, 3, pro, 6);

		// �ȶ�ǰ�����Ƿ�������Ҫ�ģ��ǵĻ���������Ҫ�ҵģ��������ظ��ģ���Ϊ����һֱ�������飩
		if ((strcmp(sIP, ip_add)==0) && (strcmp(dIP, dest_add)==0) && (strcmp(pro, protocol)==0))
		{
			// ˢ��ͳ�����ݣ��Ȼ�ȡ�����е����֣��ַ�������ת�����ͼ�һ����ת���ַ������ȥ���˲Ű���
			ListView_GetItemText(hwndListView, i, 4, count, 8);
			packets = atoi(count);
			sprintf_s(count, 6, "%d", packets + 1);
			ListView_SetItemText(hwndListView, i, 4, count);
			flag = 1;
			break;
		}
	}

	// ���û�в��ҵ����Ǿ���������
	if (flag == 0)
	{
		LVITEM lvi;
		ZeroMemory(&lvi, sizeof(lvi));// �����������������߰���ĳ�ֵ
		// ��Ч����
		lvi.mask = LVIF_TEXT | LVIF_PARAM | LVIF_STATE;
		// ����ı��ͳ���
		lvi.pszText = ip_add;
		lvi.cchTextMax = lstrlen(lvi.pszText) + 1;
		// �����У����һ��ȷʵ��1
		ListView_InsertItem(hwndListView, &lvi);
		ListView_SetItemText(hwndListView, 0, 1, ip_add);
		ListView_SetItemText(hwndListView, 0, 2, dest_add);
		ListView_SetItemText(hwndListView, 0, 3, protocol);
		ListView_SetItemText(hwndListView, 0, 4, "1");
	}

	delete []sIP;
	delete []dIP;
	delete []pro;
	delete []count;

    return TRUE;
}