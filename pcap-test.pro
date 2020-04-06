TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
HEADERS += ./libnet/libnet_headers.h
SOURCES += \
        main.cpp
