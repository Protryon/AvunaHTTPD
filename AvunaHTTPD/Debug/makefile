-include ../makefile.init

RM := rm -rf
CP := cp -r
CHMOD := chmod
MKDIR := mkdir

# All of the sources participating in the build are defined here
-include sources.mk
-include src/subdir.mk
-include subdir.mk
-include objects.mk

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(strip $(C_DEPS)),)
-include $(C_DEPS)
endif
endif

-include ../makefile.defs

# Add inputs and outputs from these tool invocations to the build variables 

# All Target
all: AvunaHTTPD

debug: CFLAGS += -DDEBUG
debug: AvunaHTTPD

# Tool invocations
AvunaHTTPD: $(OBJS) $(USER_OBJS)
	@echo 'Building target: $@'
	@echo 'Invoking: GCC C Linker'
	$(CC) $(CFLAGS) -o "AvunaHTTPD" $(OBJS) $(USER_OBJS) $(LDFLAGS) $(LIBS)
	@echo 'Finished building target: $@'
	@echo ' '

# Other Targets
clean:
	-$(RM) $(EXECUTABLES)$(OBJS)$(C_DEPS) AvunaHTTPD
	-@echo ' '

install:
	-$(CP) AvunaHTTPD /usr/bin/AvunaHTTPD
	-$(CHMOD) 755 /usr/bin/AvunaHTTPD
	-$(MKDIR) -p /etc/avuna/httpd/
        -$(CP) ../main.cfg /etc/avuna/httpd/main.cfg
	-$(CP) ../mime.txt /etc/avuna/httpd/mime.txt

.PHONY: all clean dependents
.SECONDARY:

-include ../makefile.targets
