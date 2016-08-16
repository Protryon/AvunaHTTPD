################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../src/accept.c \
../src/cache.c \
../src/collection.c \
../src/config.c \
../src/fcgi.c \
../src/http.c \
../src/http2.c \
../src/log.c \
../src/main.c \
../src/mime.c \
../src/oqueue.c \
../src/streams.c \
../src/tls.c \
../src/util.c \
../src/vhost.c \
../src/work.c \
../src/xstring.c 

OBJS += \
./src/accept.o \
./src/cache.o \
./src/collection.o \
./src/config.o \
./src/fcgi.o \
./src/http.o \
./src/http2.o \
./src/log.o \
./src/main.o \
./src/mime.o \
./src/oqueue.o \
./src/streams.o \
./src/tls.o \
./src/util.o \
./src/vhost.o \
./src/work.o \
./src/xstring.o 

C_DEPS += \
./src/accept.d \
./src/cache.d \
./src/collection.d \
./src/config.d \
./src/fcgi.d \
./src/http.d \
./src/http2.d \
./src/log.d \
./src/main.d \
./src/mime.d \
./src/oqueue.d \
./src/streams.d \
./src/tls.d \
./src/util.d \
./src/vhost.d \
./src/work.d \
./src/xstring.d 


# Each subdirectory must supply rules for building sources it contributes
src/%.o: ../src/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -std=gnu11 -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


