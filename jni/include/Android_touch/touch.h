#ifndef TOUCH_H
#define TOUCH_H
#define BITS_PER_LONG (sizeof(long) * 8)
#define NBITS(x) ((((x)-1)/BITS_PER_LONG)+1)
#define test_bit(array, bit) ((array[bit / BITS_PER_LONG] >> bit % BITS_PER_LONG) & 1)

void HandleTouchEvent();

bool GrabTouchScreen();

enum FingerStatus {
    FINGER_NO, // 无状态
    FINGER_X_UPDATE, // X更新
    FINGER_Y_UPDATE, // Y更新
    FINGER_XY_UPDATE, // XY同时更新
    FINGER_UP // 抬起
};
extern bool 创建触摸;
struct TouchFinger {
    int x = -1, y = -1; // 触摸点XY数据
    int tracking_id = -1; // 触摸点追踪ID数据
    int status = FINGER_NO;
    timeval time;
};// 10根手指

void Touch_Down(int slot,float x,float y);
void Touch_Up(int slot);
void Touch_Move(int slot, float x, float y);
void TouchScreenHandle();
	
#endif
