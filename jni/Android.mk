LOCAL_PATH := $(call my-dir)

# ====================================================
# 静态库 — 仅含 main.cpp 和 draw_Gui.cpp，启用 OLLVM 混淆
# ====================================================
include $(CLEAR_VARS)
LOCAL_MODULE := obfuscated

# 加固: 启用栈保护 + FORTIFY + 警告（去掉 -w）
LOCAL_CPPFLAGS := -std=c++17 -fexceptions -Wall -Wextra -Os -fstack-protector-strong -D_FORTIFY_SOURCE=2
LOCAL_CFLAGS   := -std=c11 -Wall -Wextra -Os -fstack-protector-strong -D_FORTIFY_SOURCE=2

LOCAL_C_INCLUDES += $(LOCAL_PATH)/include
LOCAL_C_INCLUDES += $(LOCAL_PATH)/include/Android_draw
LOCAL_C_INCLUDES += $(LOCAL_PATH)/src/Android_draw
LOCAL_C_INCLUDES += $(LOCAL_PATH)/include/Android_Graphics
LOCAL_C_INCLUDES += $(LOCAL_PATH)/include/Android_my_imgui
LOCAL_C_INCLUDES += $(LOCAL_PATH)/include/Android_touch
LOCAL_C_INCLUDES += $(LOCAL_PATH)/include/ImGui
LOCAL_C_INCLUDES += $(LOCAL_PATH)/include/ImGui/backends
LOCAL_C_INCLUDES += $(LOCAL_PATH)/include/ImGui/misc
LOCAL_C_INCLUDES += $(LOCAL_PATH)/include/My_Utils
LOCAL_C_INCLUDES += $(LOCAL_PATH)/include/native_surface
LOCAL_C_INCLUDES += $(LOCAL_PATH)/src/weiyan
LOCAL_C_INCLUDES += $(LOCAL_PATH)/Protect

LOCAL_CFLAGS   += -DVK_USE_PLATFORM_ANDROID_KHR -DIMGUI_IMPL_VULKAN_NO_PROTOTYPES
LOCAL_CPPFLAGS += -DVK_USE_PLATFORM_ANDROID_KHR -DIMGUI_IMPL_VULKAN_NO_PROTOTYPES

# OLLVM 混淆标志（仅此模块生效）
LOCAL_CPPFLAGS += -mllvm -irobf -mllvm -irobf-indbr
LOCAL_CPPFLAGS += -mllvm -irobf-icall=1 -mllvm -level-icall=50000
LOCAL_CPPFLAGS += -mllvm -irobf-indgv=1  -mllvm -level-indgv=30000
LOCAL_CPPFLAGS += -mllvm -irobf-cff -mllvm -irobf-cse

LOCAL_SRC_FILES := src/main.cpp src/Android_draw/draw_Gui.cpp

include $(BUILD_STATIC_LIBRARY)

# ====================================================
# 主可执行文件 — 其余源码，链接 obfuscated 静态库
# ====================================================
include $(CLEAR_VARS)
LOCAL_MODULE := safe_bypass

# 加固: 启用栈保护 + FORTIFY + 警告
LOCAL_CPPFLAGS := -std=c++17 -fexceptions -Wall -Wextra -Os -fstack-protector-strong -D_FORTIFY_SOURCE=2
LOCAL_CFLAGS   := -std=c11 -Wall -Wextra -Os -fstack-protector-strong -D_FORTIFY_SOURCE=2

LOCAL_C_INCLUDES += $(LOCAL_PATH)/include
LOCAL_C_INCLUDES += $(LOCAL_PATH)/include/Android_draw
LOCAL_C_INCLUDES += $(LOCAL_PATH)/src/Android_draw
LOCAL_C_INCLUDES += $(LOCAL_PATH)/include/Android_Graphics
LOCAL_C_INCLUDES += $(LOCAL_PATH)/include/Android_my_imgui
LOCAL_C_INCLUDES += $(LOCAL_PATH)/include/Android_touch
LOCAL_C_INCLUDES += $(LOCAL_PATH)/include/ImGui
LOCAL_C_INCLUDES += $(LOCAL_PATH)/include/ImGui/backends
LOCAL_C_INCLUDES += $(LOCAL_PATH)/include/ImGui/misc
LOCAL_C_INCLUDES += $(LOCAL_PATH)/include/My_Utils
LOCAL_C_INCLUDES += $(LOCAL_PATH)/include/native_surface
LOCAL_C_INCLUDES += $(LOCAL_PATH)/src/weiyan
LOCAL_C_INCLUDES += $(LOCAL_PATH)/Protect

LOCAL_CFLAGS   += -DVK_USE_PLATFORM_ANDROID_KHR -DIMGUI_IMPL_VULKAN_NO_PROTOTYPES
LOCAL_CPPFLAGS += -DVK_USE_PLATFORM_ANDROID_KHR -DIMGUI_IMPL_VULKAN_NO_PROTOTYPES

# 排除 main.cpp 和 draw_Gui.cpp（已在 obfuscated 库中）
FILE_LIST := $(wildcard $(LOCAL_PATH)/src/Android_draw/*.c)
FILE_LIST += $(wildcard $(LOCAL_PATH)/src/Android_touch/*.cpp)
FILE_LIST += $(wildcard $(LOCAL_PATH)/src/Android_Graphics/*.cpp)
FILE_LIST += $(wildcard $(LOCAL_PATH)/src/Android_my_imgui/*.cpp)
FILE_LIST += $(wildcard $(LOCAL_PATH)/src/ImGui/*.cpp)
FILE_LIST += $(wildcard $(LOCAL_PATH)/src/ImGui/backends/*.cpp)
FILE_LIST += $(LOCAL_PATH)/src/utils/integrity_sha256.cpp
LOCAL_SRC_FILES := $(FILE_LIST:$(LOCAL_PATH)/%=%)

LOCAL_LDLIBS := -llog -landroid -lEGL -lGLESv3 -lz -lvulkan
# 链接加固: full RELRO + strip
LOCAL_LDFLAGS := -Wl,-z,relro,-z,now -Wl,--strip-all

LOCAL_STATIC_LIBRARIES := obfuscated

include $(BUILD_EXECUTABLE)
