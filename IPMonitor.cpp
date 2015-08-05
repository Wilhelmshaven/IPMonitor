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
// IPMonitor.cpp : 定义应用程序的入口点。
//

#include "stdafx.h"
#include "IPMonitor.h"
#include "Packet.h"

//风格变换
#pragma comment(linker, "\"/manifestdependency:type='Win32'\
 name='Microsoft.Windows.Common-Controls' version='6.0.0.0'\
 processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// 全局变量: 
enum CustomDefine
{
	MAX_LOADSTRING = 100,
	ETH_ARP = 0x0806,      // 以太网帧类型表示后面数据的类型，对于ARP请求或应答来说，该字段的值为x0806
	ARP_HARDWARE = 1,      // 硬件类型字段值为表示以太网地址
	ETH_IP = 0x0800,       // 协议类型字段表示要映射的协议地址类型值为x0800表示IP地址
	ARP_REQUEST = 1,
	ARP_REPLY = 2,
	TCP = 0x06,            // IP数据报的TCP协议
	UDP = 0x11             // IP数据报的UDP协议
};

HINSTANCE hInst;								// 当前实例
TCHAR szTitle[MAX_LOADSTRING];					// 标题栏文本
TCHAR szWindowClass[MAX_LOADSTRING];			// 主窗口类名
Device myDevice;                                // 设备类

HANDLE hArpEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
HANDLE hCapture = CreateEvent(NULL, TRUE, FALSE, NULL);
HANDLE hFinish = CreateEvent(NULL, TRUE, FALSE, NULL);

sparam sp;                                      // 线程共享参数

// 用来判断状态的全局变量，未来会用事件进行替代
int Selected = -1;
BOOL sCheck = FALSE;
BOOL dCheck = FALSE;

// 此代码模块中包含的函数的前向声明: 
ATOM				MyRegisterClass(HINSTANCE hInstance);
BOOL				InitInstance(HINSTANCE, int);
LRESULT CALLBACK	WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK	About(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    DlgProc(HWND hdlg, UINT msg, WPARAM wParam, LPARAM lParam);         // 子窗口

// 把结果输出到ListView中
BOOL                AddListViewItems(HWND hwndListView, char *ip_add, char *dest_add, char *protocol); 

// 收发包方法
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

    // TODO:  在此放置代码。
    MSG msg;
    HACCEL hAccelTable;

    // 初始化全局字符串
    LoadString(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadString(hInstance, IDC_IPMONITOR, szWindowClass, MAX_LOADSTRING);
    MyRegisterClass(hInstance);

    // 执行应用程序初始化: 
    if (!InitInstance (hInstance, nCmdShow))
    {
        return FALSE;
    }

    hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_IPMONITOR));

    // 主消息循环: 
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

// 注册窗口类
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

// 保存实例句柄并创建主窗口
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   HWND hWnd;

   hInst = hInstance; // 将实例句柄存储在全局变量中

   // 主窗口不可变大小，同时禁用最大化
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

// 处理主窗口的消息
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    int wmId, wmEvent;
    HWND myhdlg = NULL;

    switch (message)
    {
    case WM_CREATE:
    {
        // 创建子对话框并将其作为主窗口
        myhdlg = CreateDialog(hInst, MAKEINTRESOURCE(IDD_FORMVIEW), hWnd, (DLGPROC)DlgProc);
        ShowWindow(myhdlg, SW_SHOW);

        // 设置标题字体样式
        LOGFONT TitleFont;
        ZeroMemory(&TitleFont,sizeof(TitleFont));                     // 这个必须做，清除乱七八糟的初值
        lstrcpy(TitleFont.lfFaceName, "Segoe Script");                // 设置字体
        TitleFont.lfWeight = FW_BOLD;                                 // 粗细，BOLD=700，写过CSS都知道
        TitleFont.lfHeight = -24;                                     // 字体大小，这个很有讲究……
        TitleFont.lfCharSet = DEFAULT_CHARSET;                        // 默认字符集
        TitleFont.lfOutPrecision = OUT_DEVICE_PRECIS;                 // 输出精度

        HFONT hFont = CreateFontIndirect(&TitleFont);                 
        HWND hWndStatic = GetDlgItem(myhdlg, IDC_STATIC_TITLE);       
        SendMessage(hWndStatic, WM_SETFONT, (WPARAM)hFont, 0);        

		// 设置类目字体样式
        LOGFONT TextFont;
        ZeroMemory(&TextFont, sizeof(TextFont)); 
        lstrcpy(TextFont.lfFaceName, "Gabriola");
        TextFont.lfHeight = -16; 
        hFont = CreateFontIndirect(&TextFont);
		 
		// 设置控件字体
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
        // 分析菜单选择: 
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

// “关于”框的消息处理程序。
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

// 处理对话框消息  
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
        // 添加Listview的列与下拉框数据

        // 设置ListView的列  
        LVCOLUMN lvc;
		lvc.mask = LVCF_FMT | LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
		ListView_SetTextColor(hListview, RGB(0, 0, 255));                // 设置文字颜色
		ListView_SetTextBkColor(hListview, RGB(199, 237, 204));          // 设置文字背景颜色
		ListView_SetExtendedListViewStyle(hListview, LVS_EX_GRIDLINES);  // 添加导航线

        lvc.pszText = "Source";          // 列标题  
        lvc.cx = 0;                      // 列宽  
        lvc.iSubItem = 0;                // 子项索引，第一列无子项 (0) 
        lvc.fmt = LVCFMT_CENTER;
        ListView_InsertColumn(hListview, 0, &lvc);
		lvc.cx = 150;
		ListView_InsertColumn(hListview, 1, &lvc);

        lvc.pszText = "Destination";
        lvc.cx = 150;
        lvc.iSubItem = 1;               // 子项索引  
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

        // 给下拉列表填充项目
        pcap_if_t *d;
        for (d = myDevice.alldevs; d; d = d->next)
        {
            SendMessage(hWndComboBox, CB_ADDSTRING, 0, (LPARAM)d->description);
        }

		// 默认CheckBox全勾上
		CheckDlgButton(hdlg, IDC_CHECK_S, BST_CHECKED);
		CheckDlgButton(hdlg, IDC_CHECK_D, BST_CHECKED);

        break;
    }// WM_INITIALIZE

    case WM_CREATE:
    {
        // 创建按钮
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

		// 创建CheckBox
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
            // 按钮功能的实现
		case IDC_BTN_BEGIN:
		{
			// 清空需要清空的信息（如上一次的扫描结果）
			SendMessage(hListview, LVM_DELETEALLITEMS, 0, 0);

			//检查CheckBox状态，若已勾上则设置为True
			hCheckBox = GetDlgItem(hdlg, IDC_CHECK_S);
			if (Button_GetCheck(hCheckBox) == BST_CHECKED)sCheck = TRUE;
			hCheckBox = GetDlgItem(hdlg, IDC_CHECK_D);
			if (Button_GetCheck(hCheckBox) == BST_CHECKED)dCheck = TRUE;

			if (Selected != -1)
			{
				// 若两个CheckBox都没有被勾上的话，则自动帮其全部勾上（默认模式吧就算是）
				if ((sCheck == FALSE) && (dCheck == FALSE))
				{
					CheckDlgButton(hdlg, IDC_CHECK_S, BST_CHECKED);
					CheckDlgButton(hdlg, IDC_CHECK_D, BST_CHECKED);
					sCheck = TRUE;
					dCheck = TRUE;
				}
				
				// 开始收发包，设置事件
				SetEvent(hArpEvent);
				SetEvent(hCapture);

				// 做一些权限管理
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
			// 只需要停止收包线程，挂起即可
			ResetEvent(hCapture);

			sCheck = FALSE;
			dCheck = FALSE;

			// 做一些权限管理
			ComboBox_Enable(hWndComboBox, TRUE);
			hButton = GetDlgItem(hdlg, IDC_BTN_BEGIN);
			Button_Enable(hButton, TRUE);
			hButton = GetDlgItem(hdlg, IDC_BTN_STOP);
			Button_Enable(hButton, FALSE);
			hCheckBox = GetDlgItem(hdlg, IDC_CHECK_S);
			Button_Enable(hCheckBox, TRUE);
			hCheckBox = GetDlgItem(hdlg, IDC_CHECK_D);
			Button_Enable(hCheckBox, TRUE);
			MessageBox(NULL, "扫描终止", "", MB_OK);

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

        //处理控件消息
        switch (wmEvent)
        {
			// 下拉列表选择发生变化
        case CBN_SELCHANGE:
        {
            Selected = -1;

            Selected = (int)SendMessage(hWndComboBox, CB_GETCURSEL, 0, 0); // 获得选中的选项编号

			// 若没有选择项目，则停止运行，弹出消息
			if (Selected == -1)
			{
				Beep(880, 100);
				PostMessage(hdlg, WM_COMMAND, (WPARAM)IDC_BTN_STOP, NULL);
				break;
			}

			// 根据获得的被选中的设备名字去获取该网卡信息（IP、掩码）
            myDevice.findCurrentDevice(Selected);
            SendMessage(hWndComboBox, CB_SETCURSEL, (WPARAM)Selected, 0); // 显示选中的网卡

            // 显示本机IP
            hEditBox = GetDlgItem(hdlg, IDC_EDIT_IP);
            SendMessage(hEditBox, EM_SETREADONLY, 0, 0);
            SendMessage(hEditBox, WM_SETTEXT, 0, (LPARAM)myDevice.ip_addr);

            // 显示子网掩码
            hEditBox = GetDlgItem(hdlg, IDC_EDIT_MASK);
            SendMessage(hEditBox, EM_SETREADONLY, 0, 0);
            SendMessage(hEditBox, WM_SETTEXT, 0, (LPARAM)myDevice.ip_netmask);

            // 显示本机MAC
            hEditBox = GetDlgItem(hdlg, IDC_EDIT_MAC);
            SendMessage(hEditBox, EM_SETREADONLY, 0, 0);
            SendMessage(hEditBox, WM_SETTEXT, 0, (LPARAM)myDevice.macStr);

            // 显示网关IP
            hEditBox = GetDlgItem(hdlg, IDC_EDIT_GATEIP);
            SendMessage(hEditBox, EM_SETREADONLY, 0, 0);
            SendMessage(hEditBox, WM_SETTEXT, 0, (LPARAM)myDevice.gateway_ip);

			// 初始化：清除网关MAC地址对话框内容
			hEditBox = GetDlgItem(hdlg, IDC_EDIT_GATEMAC);
			SendMessage(hEditBox, EM_SETREADONLY, 0, 0);
			SendMessage(hEditBox, WM_SETTEXT, 0, NULL);

            // 自制数据包：填充相关数据，还需要发包取得网关地址
            sp.adhandle = myDevice.adhandle;
            sp.gateway_ip = myDevice.gateway_ip;
            sp.myIP = myDevice.ip_addr;
            sp.netmask = myDevice.ip_netmask;
            sp.myDlg = hdlg;                       // 窗口句柄

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

/* 为了获取网关MAC地址，发包还是要滴，就发一个ARP包 */
UINT SendArpPacket(LPVOID lpParameter)//(pcap_t *adhandle,char *ip,BYTE *mac,char *netmask)
{
	sparam *spara = &sp;
	BYTE *sendbuf = new BYTE[60];                      // arp包结构大小，只能是60，不计fcs
	arp_frame arpFrame;
	
	while (1)
	{
		// 等待开始指令并确认是否有退出指令
		WaitForSingleObject(hArpEvent, INFINITE);
		if (WaitForSingleObject(hFinish, 0) == WAIT_OBJECT_0)break;

		Beep(440, 200);
		pcap_t *adhandle = spara->adhandle;
		char *gateway_ip = spara->gateway_ip;              // 网关IP
		char *ip = spara->myIP;                            // 自己的IP
		char *netmask = spara->netmask;                    // 自己的NETMASK	

		// 填充内容
		arpFrame.eh.type = htons(ETH_ARP);                        // 以太网帧头协议类型
		memset(arpFrame.eh.dest_mac_add, 0xff, 6);                // MAC的广播地址为FF-FF-FF-FF-FF-FF
		for (int i = 0; i < 6; i++)arpFrame.eh.source_mac_add[i] = myDevice.mac[i];
		arpFrame.ah.hardware_type = htons(ARP_HARDWARE);          // 硬件地址
		arpFrame.ah.protocol_type = htons(ETH_IP);                // ARP包协议类型
		inet_pton(AF_INET, ip, &arpFrame.ah.source_ip_add);       // 请求方的IP地址为自身的IP地址         	
		arpFrame.ah.operation_field = htons(ARP_REQUEST);         // ARP请求包
		inet_pton(AF_INET, gateway_ip, &arpFrame.ah.dest_ip_add); // 目的IP填写为网关IP

		// 把做好的数据包装入缓存
		memset(sendbuf, 0, sizeof(sendbuf));
		memcpy(sendbuf, &arpFrame, sizeof(arpFrame));

		pcap_sendpacket(adhandle, sendbuf, 60);                   // 发包

		// ARP事件复位
		ResetEvent(hArpEvent);
	}

	delete[]sendbuf;

    return 0;
}

/* 分析截留的数据包获取活动的主机IP地址 */
UINT AnalyzePacket(LPVOID lpParameter)//(pcap_t *adhandle)
{
	sparam *spara = &sp;
	HWND hwndListView;
	HWND EditBox;
	char *source_ip = new char[16];           // 源IP
	char *dest_ip = new char[16];             // 目的IP
	char *mac_add = new char[18];             // MAC地址

	while (1)
	{
		// 等待开始指令并确认是否有退出指令
		WaitForSingleObject(hCapture, INFINITE);
		if (WaitForSingleObject(hFinish, 0) == WAIT_OBJECT_0)break;

		Beep(880, 200);
		hwndListView = GetDlgItem(spara->myDlg, IDC_LIST1);

		pcap_t *adhandle = spara->adhandle;
		int res;                                // 数据流
		
		char *myIP = spara->myIP;               // 我的IP
		pcap_pkthdr * pkt_header;
		const u_char * pkt_data;
		int arp = 0;                            // ARP包控制变量（只收一个），待替换
		arp_frame *recvARP;
		ip_frame *recvIP;

		while (WaitForSingleObject(hCapture, 0) == WAIT_OBJECT_0)
		{
			if (WaitForSingleObject(hFinish, 0) == WAIT_OBJECT_0)break;

			if ((res = pcap_next_ex(adhandle, &pkt_header, &pkt_data)) > 0)// 使用非回调方法捕获数据包
			{
				if (arp == 0)
				{
					// 判断ARP包的第13,14位（Type）是否等于0x0806，目的是滤出ARP包	
					if (*(WORD *)(pkt_data + 12) == htons(ETH_ARP))		
					{
						// 把流数据装进ARP帧结构
						recvARP = (arp_frame *)pkt_data;

						// 格式化IP以进行比较
						sprintf_s(source_ip, 16, "%d.%d.%d.%d", recvARP->ah.source_ip_add & 255, recvARP->ah.source_ip_add >> 8 & 255,
							recvARP->ah.source_ip_add >> 16 & 255, recvARP->ah.source_ip_add >> 24 & 255);

						// 判断操作符位是否是ARP_REPLY，即滤出ARP应答包并确认是网关答复的ARP包
						if (recvARP->ah.operation_field == htons(ARP_REPLY) && (strcmp(source_ip, spara->gateway_ip) == 0))
						{
							// 格式化MAC便于输出
							sprintf_s(mac_add, 18, "%02X-%02X-%02X-%02X-%02X-%02X", recvARP->ah.source_mac_add[0],
								recvARP->ah.source_mac_add[1], recvARP->ah.source_mac_add[2], recvARP->ah.source_mac_add[3],
								recvARP->ah.source_mac_add[4], recvARP->ah.source_mac_add[5]);

							// 输出网关的MAC地址
							EditBox = GetDlgItem(spara->myDlg, IDC_EDIT_GATEMAC);
							SendMessage(EditBox, EM_SETREADONLY, 0, 0);
							SendMessage(EditBox, WM_SETTEXT, 0, (LPARAM)mac_add);

							// 找到网关MAC地址了
							if (WaitForSingleObject(hArpEvent, 0) == WAIT_OBJECT_0)
							{
								++arp; // 不再收取ARP包
							}
						}
					}
				}// ARP

				// 这里过滤IP包
				if (*(WORD *)(pkt_data + 12) == htons(ETH_IP))
				{
					// 把流数据装进IP帧结构
					recvIP = (ip_frame *)pkt_data;

					// 格式化IP以进行比较
					sprintf_s(source_ip, 16, "%d.%d.%d.%d", recvIP->ih.source_add & 255, recvIP->ih.source_add >> 8 & 255,
						recvIP->ih.source_add >> 16 & 255, recvIP->ih.source_add >> 24 & 255);
					sprintf_s(dest_ip, 16, "%d.%d.%d.%d", recvIP->ih.dest_add & 255, recvIP->ih.dest_add >> 8 & 255,
						recvIP->ih.dest_add >> 16 & 255, recvIP->ih.dest_add >> 24 & 255);

					// 判断是否是我的包（和我的IP进行比较，以及CheckBox的状态）
					if (((strcmp(source_ip, spara->myIP) == 0) && sCheck) || ((strcmp(dest_ip, spara->myIP) == 0) && dCheck))
					{
						// 判断协议是啥，十进制中UDP是17(0x11)，TCP是6(0x06)
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

		// 收到退出指令
		if (WaitForSingleObject(hFinish, 0) == WAIT_OBJECT_0)break;
	}

	delete []source_ip;
	delete []dest_ip;
	delete []mac_add;

    return 0;
}

// 在ListView里面增加项
BOOL AddListViewItems(HWND hwndListView, char *ip_add, char *dest_add, char *protocol)
{
	// 先进行检索看条目是不是已经有了
	int ListItemCount = ListView_GetItemCount(hwndListView);
	char *sIP = new char[16];
	char *dIP = new char[16];
	char *pro = new char[6];
	char *count = new char[6];
	int packets = 0;
	int flag = 0;

	// 逐行比对，即遍历该控件
	for (int i = 0; i < ListItemCount; i++)
	{
		// 根据我们的设计，获取前三列的内容
		ListView_GetItemText(hwndListView, i, 1, sIP, 16);
		ListView_GetItemText(hwndListView, i, 2, dIP, 16);
		ListView_GetItemText(hwndListView, i, 3, pro, 6);

		// 比对前三列是否都是我们要的，是的话就是我们要找的（不会有重复的，因为我们一直做这个检查）
		if ((strcmp(sIP, ip_add)==0) && (strcmp(dIP, dest_add)==0) && (strcmp(pro, protocol)==0))
		{
			// 刷新统计数据，先获取第四列的数字（字符串），转成整型加一，再转回字符串填回去，人才啊！
			ListView_GetItemText(hwndListView, i, 4, count, 8);
			packets = atoi(count);
			sprintf_s(count, 6, "%d", packets + 1);
			ListView_SetItemText(hwndListView, i, 4, count);
			flag = 1;
			break;
		}
	}

	// 如果没有查找到，那就是新项了
	if (flag == 0)
	{
		LVITEM lvi;
		ZeroMemory(&lvi, sizeof(lvi));// 这个必须做，清除乱七八糟的初值
		// 有效的项
		lvi.mask = LVIF_TEXT | LVIF_PARAM | LVIF_STATE;
		// 项的文本和长度
		lvi.pszText = ip_add;
		lvi.cchTextMax = lstrlen(lvi.pszText) + 1;
		// 插入列，最后一个确实是1
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