#include <imgui_internal.h>
#include <random>
#include <imgui.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <paths.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <linux/input.h>
#include <linux/uinput.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <linux/types.h>
#include <termios.h>
#include <time.h>
#include <pthread.h>
#include <thread>
#include <unistd.h>
#include <linux/input.h>
#include <linux/uinput.h>
#include <signal.h>
#include <touch.h>
#include <draw.h>
#include <timer.h>
#include <dirent.h>
#include <set>

using namespace std;
using std::string;

struct eventinfo {
	int ID;
	bool io = false;
	struct input_absinfo data;
};

//触控设备数据结构
struct events {
	int ID;
	bool io = false;
	bool infoio = false;
	eventinfo eventmsg[KEY_MAX + 1];
};

float x_proportion, y_proportion;
int ScreenType = 0; // 竖屏 横屏
TouchFinger Fingers[10]; 
events eventdata[EV_MAX + 1];

int thread_us = 20;
bool grabImGuiEvent = false;

int GetEventCount()
{
	DIR *dir = opendir("/dev/input/");
	dirent *ptr = NULL;
	int count = 0;
	while ((ptr = readdir(dir)) != NULL)
	{
		if (strstr(ptr->d_name, "event"))
			count++;
	}
	return count;
}

int GetEventId()
{
	int EventCount = GetEventCount();
	int *fdArray = (int *)malloc(EventCount * 4 + 4);
	int result;

	for (int i = 0; i < EventCount; i++)
	{
		char temp[128];
		sprintf(temp, "/dev/input/event%d", i);
		fdArray[i] = open(temp, O_RDWR | O_NONBLOCK);
	}

	int k = 0;
	input_event ev;
	
	while (1)
	{
		for (int i = 0; i < EventCount; i++)
		{
			memset(&ev, 0, sizeof(ev));
			read(fdArray[i], &ev, sizeof(ev));
			if (ev.type == EV_ABS)
			{
				// printf("id:%d\n", i);
				free(fdArray);
				return i;
			}
		}
		usleep(100);
	}
}

int fb,dev_fd;
int last_slot = -1;
bool touch_status = false;

static int device_writeEvent(int fd, uint16_t type, uint16_t keycode, int32_t value) {
    struct input_event ev;  
  
    memset(&ev, 0, sizeof(struct input_event));  
  
    ev.type = type;  
    ev.code = keycode;  
    ev.value = value;
    if (write(fd, &ev, sizeof(struct input_event)) < 0) {
		//char * mesg = strerror(errno);
        return 0;
    }  
	return 1;
}
 
bool TouchLock = false;

int global_tracking_id = 0;

void (*callback)(TouchFinger*);

void setTouchCallback(void (*_callback)(TouchFinger*)){
    callback = _callback;
}

bool bLock = false;
bool windowHasFoused = false;

void Upload(int slot) {
    if (dev_fd <= 0) {
		bLock = false;
		return; // 都没抢夺触摸屏上传你妈逼
	}
    
    auto& Finger = Fingers[slot];
    if (Fingers[slot].status == FINGER_NO) {
		bLock = false;
        return;
	}
    
	int TimeBlock = 0;
	while (true) {
		if (!bLock || TimeBlock >= 200) {
			break;
		}
		TimeBlock ++;
	}
    
	bLock = true;
	
    struct input_event event[16];
    // 开始上传数据
	
    int32_t tmpCnt = 0;
    // 重置事件
    
    if (Finger.status != FINGER_UP) {
    	if (!touch_status)
		{
			touch_status = true;
			event[tmpCnt].type = EV_KEY;
			event[tmpCnt].code = BTN_TOUCH;
			event[tmpCnt].value = 1;
			tmpCnt++;
		}
		
        if (last_slot != slot)
		{
			event[tmpCnt].type = EV_ABS;
		    event[tmpCnt].code = ABS_MT_SLOT;
	        event[tmpCnt].value = slot;
		    tmpCnt++;
			last_slot = slot;
		}
		
	    event[tmpCnt].type = EV_ABS;
		event[tmpCnt].code = ABS_MT_TRACKING_ID;
	    event[tmpCnt].value = Finger.tracking_id;
		tmpCnt++;
		
		bool x_update = Finger.status == FINGER_X_UPDATE || Finger.status == FINGER_XY_UPDATE;
		bool y_update = Finger.status == FINGER_Y_UPDATE || Finger.status == FINGER_XY_UPDATE;
		
		if (x_update) {
		    event[tmpCnt].type = EV_ABS;
		    event[tmpCnt].code = ABS_MT_POSITION_X;
	        event[tmpCnt].value = Finger.x;
		    tmpCnt++;
	    }
		if (y_update) {
			event[tmpCnt].type = EV_ABS;
		    event[tmpCnt].code = ABS_MT_POSITION_Y;
	        event[tmpCnt].value = Finger.y;
		    tmpCnt++;
		}
		
    	event[tmpCnt].type = EV_SYN;
        event[tmpCnt].code = SYN_REPORT;
        event[tmpCnt].value = 0;
        tmpCnt++;
    } else {
        if (last_slot != slot)
		{
			event[tmpCnt].type = EV_ABS;
		    event[tmpCnt].code = ABS_MT_SLOT;
	        event[tmpCnt].value = slot;
		    tmpCnt++;
			last_slot = slot;
		}
		
		event[tmpCnt].type = EV_ABS;
	    event[tmpCnt].code = ABS_MT_TRACKING_ID;
        event[tmpCnt].value = -1;
	    tmpCnt++;
		
		event[tmpCnt].type = EV_SYN;
        event[tmpCnt].code = SYN_REPORT;
        event[tmpCnt].value = 0;
        tmpCnt++;
	
		touch_status = false;
    }
    
    for (int i = 0; i < tmpCnt; i ++) {
        event[i].time = Finger.time;
    }
   
    Finger.status = FINGER_NO;
       
	bLock = false;
	
	write(dev_fd, event, sizeof(struct input_event) * tmpCnt);
}

char *randstr(char *str, const int len)
{
    srand(time(NULL));
    int i;
    for (i = 0; i < len; ++i)
    {
        switch ((rand() % 13))
        {
        case 1:
            str[i] = 'A' + rand() % 26;
            break;
        case 2:
            str[i] = 'a' + rand() % 26;
            break;
        default:
            str[i] = '0' + rand() % 10;
            break;
        }
    }
    str[++i] = '\0';
    return str;
}

void Touch_Down(int slot, int x,int y){
    auto& Finger = Fingers[slot];
	
    if (Finger.x != x && Finger.y != y)
		Finger.status = FINGER_XY_UPDATE;
	else if (Finger.x != x)
		Finger.status = FINGER_X_UPDATE;
	else if (Finger.y != y)
		Finger.status = FINGER_Y_UPDATE;
		
    Finger.x = x * x_proportion;
    Finger.y = y * y_proportion;
	
    Finger.tracking_id = slot;
    
    gettimeofday(&Finger.time, 0);
	
    Upload(slot);
}

void Touch_Move(int slot, int x,int y){
    Touch_Down(slot, x,y);
}

void Touch_Up(int slot){
    auto& Finger = Fingers[slot];
	Finger.status = FINGER_UP;
    gettimeofday(&Finger.time, 0);
	Upload(slot);
}

timer loopAutoSleep;
ImGuiIO* io;

bool IsHandleTouchEvent = false;

void HandleTouchEvent() {
    int input_id = GetEventId();  // GetTouchEventNum();
	char devicepath[64];
	
	sprintf(devicepath, "/dev/input/event%d", input_id);
	//printf("Eventpath: %s \n", devicepath);
	
    fb = open(devicepath, O_RDONLY | O_NONBLOCK);
	struct input_absinfo absX;
	struct input_absinfo absY;
	ioctl(fb, EVIOCGABS(ABS_MT_POSITION_X), &absX);
	ioctl(fb, EVIOCGABS(ABS_MT_POSITION_Y), &absY);
	float Width = absX.maximum + 1;
	float Height = absY.maximum + 1;
	
	int scr_x = abs_ScreenX;
	int scr_y = abs_ScreenY;
	
	if(scr_x > scr_y){
	    int t = scr_y;
	    scr_y = scr_x;
	    scr_x = t;
	}
    
    x_proportion = Width / scr_x;
    y_proportion = Height / scr_y;
    
    struct input_event in_ev, last_in_ev;

	int slot = 0, tracking_id = 0;
	int type, code, value;
	
	IsHandleTouchEvent = true;
	std::set<int> UpdatePointers;
	loopAutoSleep.SetFps(700);
    loopAutoSleep.AotuFPS_init();
	
	// GrabTouchScreen();  // 注释掉独占触摸屏，允许多应用共存
	
	while (true) {	
		UpdatePointers.clear();	   
		
		while (true) {	
    	    io = &ImGui::GetIO();    
    	    read(fb, &in_ev, sizeof(in_ev));
    	    
    	    if (in_ev.code != SYN_REPORT) {
    			type = in_ev.type;
    			code = in_ev.code;
    			value = in_ev.value;
    			
    			auto& Finger = Fingers[slot];
    			Finger.time = in_ev.time;
    		
    			if (code == ABS_MT_POSITION_Y) {
    			    if (slot == 0) {
    			        if (displayInfo.orientation == 0)
        			        io->MousePos.y = value / y_proportion;
        			    else if(displayInfo.orientation == 1)
        			    	io->MousePos.x = value / y_proportion;
        				else
        			     	io->MousePos.x = scr_y - value / y_proportion;
        			}		    
    			    Finger.y = value;
    		        Finger.status |= FINGER_Y_UPDATE;
    			    UpdatePointers.insert(slot);		    
    		    } else if(code == ABS_MT_POSITION_X) {
    		        if (slot == 0) {
    			        if (displayInfo.orientation == 0)
        			        io->MousePos.x = value / x_proportion;
        			    else if(displayInfo.orientation == 1)
        			    	io->MousePos.y = scr_x - value / x_proportion;
        				else
    				        io->MousePos.y = value / x_proportion;
    			    }		  		    
    		        Finger.x = value;
    		        Finger.status |= FINGER_X_UPDATE;		
    		        UpdatePointers.insert(slot);		   
    			} else if(code == ABS_MT_TRACKING_ID) {
    			    if (value == -1){
    			        if(slot == 0)
    			            io->MouseDown[0] = false;
    			        			
    			        Finger.status = FINGER_UP;
    			        UpdatePointers.insert(slot);		     
    			    } else {
    			        if(slot == 0)
    			            io->MouseDown[0] = true;
    			        
    			        Finger.tracking_id = global_tracking_id;
    					global_tracking_id ++;				
    			    }		  			    
    			} else if(code == ABS_MT_SLOT) {
    			    slot = value;
    			}			
    		} else {
                for (std::set<int>::iterator i=UpdatePointers.begin();i!=UpdatePointers.end();i++) {
                     Upload(*i); //注意指针运算符
                }
    		    break;	
    		}
		}
	    loopAutoSleep.AotuFPS();
	}
}




    



bool GrabTouchScreen() {
	char temp[128];

	if (ioctl(fb, 0x40044590uLL, 1))
	{
		char *v1 = strerror(*__errno());
		//printf("创建触摸屏失败 %s.\n", v1);
		return false;
	} else {		
		// 创建驱动	
		static int uinp_fd;
		struct uinput_user_dev uinp;
		struct input_event event;
		
		uinp_fd = open("/dev/uinput", O_WRONLY|O_NONBLOCK);
		
		if (uinp_fd == 0) { // 打开uinput
			//printf("无法打开 /dev/uinput 请检查是否有root权限\n");
			return false;
		}
		
		dev_fd = uinp_fd; 
				
		// configure touch device event properties
		memset(&uinp, 0, sizeof(uinp));

    	struct input_absinfo absX;
    	struct input_absinfo absY;
    	ioctl(fb, EVIOCGABS(ABS_MT_POSITION_X), &absX);
    	ioctl(fb, EVIOCGABS(ABS_MT_POSITION_Y), &absY);

		    uinp.id.bustype = ID_BUS;
    		uinp.id.version = 0x13;
    		uinp.id.vendor  = 0x14;
    		uinp.id.product = 0x15;
    		char name[29];
			
		strncpy(uinp.name, randstr(name, 28.65735), UINPUT_MAX_NAME_SIZE);
		ioctl(uinp_fd, UI_SET_PHYS, name);    	





		int fd = fb;
		if (fd) {
			struct input_id id;
			if (!ioctl(fd, EVIOCGID, &id)) {
				uinp.id.bustype = id.bustype;
				uinp.id.vendor = id.vendor;
				uinp.id.product = id.product;
				uinp.id.version = id.version;
			}
			uint8_t *bits = NULL;
			ssize_t bits_size = 0;
			int res, j, k;
			while (1) {
				res = ioctl(fd, EVIOCGBIT(EV_KEY, bits_size), bits);
				if (res < bits_size)
					break;
				bits_size = res + 16;
				bits = (uint8_t *) realloc(bits, bits_size * 2);
			}
			for (j = 0; j < res; j++) {
				for (k = 0; k < 8; k++) {
					if (bits[j] & 1 << k) {
						if (j * 8 + k == BTN_TOUCH || j * 8 + k == BTN_TOOL_FINGER)
							continue;
						ioctl(uinp_fd, UI_SET_KEYBIT, j * 8 + k);
					}
				}
			}
			free(bits);
		}

        uinp.absmin[ABS_MT_SLOT] = 0;
        uinp.absmax[ABS_MT_SLOT] = 8;
        uinp.absmin[ABS_MT_TRACKING_ID] = 0;
        uinp.absmax[ABS_MT_TRACKING_ID] = 65535;// 按键码ID累计叠加最大值

        uinp.absmin[ABS_MT_POSITION_X] = 0;
        uinp.absmax[ABS_MT_POSITION_X] = absX.maximum;

        uinp.absmin[ABS_MT_POSITION_Y] = 0;
        uinp.absmax[ABS_MT_POSITION_Y] = absY.maximum;

        ioctl(uinp_fd, UI_SET_PROPBIT, INPUT_PROP_DIRECT);

        ioctl(uinp_fd, UI_SET_EVBIT, EV_ABS);
        ioctl(uinp_fd, UI_SET_ABSBIT, ABS_MT_SLOT);
        ioctl(uinp_fd, UI_SET_ABSBIT, ABS_MT_POSITION_X);
        ioctl(uinp_fd, UI_SET_ABSBIT, ABS_MT_POSITION_Y);
        ioctl(uinp_fd, UI_SET_ABSBIT, ABS_MT_TRACKING_ID);

        ioctl(uinp_fd, UI_SET_EVBIT, EV_SYN);

		/* Create input device into input sub-system */
		write(uinp_fd, &uinp, sizeof(uinp));
		if (ioctl(uinp_fd, UI_DEV_CREATE)) {
			return false;
		}
	}

	//printf("创建触摸屏成功!\n");
	return true;
}

TouchFinger* getTouchFinger(int slot){
    return &Fingers[slot];
}

void TouchScreenHandle()
{
    thread touch_thread(HandleTouchEvent);
    touch_thread.detach();
    usleep(450);
}
