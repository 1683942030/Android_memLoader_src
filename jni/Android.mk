LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := core_substrate
LOCAL_SRC_FILES :=  Substrate/hde64.c \
				    Substrate/SubstrateDebug.cpp \
				    Substrate/SubstrateHook.cpp \
				    Substrate/SubstratePosixMemory.cpp
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/Substrate
LOCAL_EXPORT_LDLIBS := -llog
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE :=  ndk_load
LOCAL_SRC_FILES := LL.cpp \
				   loader/loader.cpp\
				   loader/utils.cpp
LOCAL_STATIC_LIBRARIES :=  core_substrate 
LOCAL_LDLIBS := -llog
LOCAL_LDLIBS += -ldl
LOCAL_CFLAGS := -Wall -fno-unwind-tables -fvisibility=hidden -fpermissive 
#include $(BUILD_SHARED_LIBRARY)
include $(BUILD_EXECUTABLE)
