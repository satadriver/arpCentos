APP_PLATFORM:=android-14
APP_ABI:=armeabi-v7a armeabi
APP_STL:=stlport_static
APP_OPTIM:=debug
NDK_DEBUG=1
LOCAL_CFLAGS += -UNDEBUG -D_DEBUG

ifdef APP_DEBUG
   ifeq ($(APP_DEBUG),true)
      CFLAGS+=  -O0 -g
      LOCAL_CFLAGS+=    -D_DEBUG
      APP_OPTIM := debug
   else
      CFLAGS+=  -O2 -g
      LOCAL_CFLAGS+=    -DNDEBUG
      APP_OPTIM := release
  endif
endif

