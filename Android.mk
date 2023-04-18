LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := start
LOCAL_SRC_FILES := 	start.cpp \
					ArpCheat.cpp \
					ArpSniffer.cpp \
					ClientAddress.cpp \
					ethtool.cpp \
					FileOper.cpp \
					init.cpp \
					NetcardInfo.cpp \
					NetParam.cpp \
					PacketProcess.cpp \
					PublicUtils.cpp\
					Log.cpp\
					Public.cpp\
					config.cpp
					
					

LOCAL_LDLIBS +=  -llog

LOCAL_CFLAGS += -pie -fPIE -fPIC

LOCAL_CPPFLAGS += -fexceptions

include $(BUILD_EXECUTABLE)

#include $(BUILD_SHARED_LIBRARY)
