CC = gcc
CFLAGS = -Wall

#執行檔名稱
TARGET = prog
#檔案
SRCS = prog.c

#編譯 TARGET
all: $(TARGET)
$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS)

#清除
clean:
	rm -f $(TARGET)
