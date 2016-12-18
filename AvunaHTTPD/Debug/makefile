-include ../makefile.init

RM := rm -rf
CP := cp -r
CHMOD := chmod
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

debug:
	CFLAGS="$(CFLAGS)-DDEBUG" ;\
	make all

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

.PHONY: all clean dependents
.SECONDARY:

-include ../makefile.targets
