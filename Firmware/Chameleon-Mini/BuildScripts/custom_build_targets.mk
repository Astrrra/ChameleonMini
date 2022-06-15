.PHONY:     mifare mifare-classic desfire desfire-dev iso-modes ntag215 vicinity sl2s2002 tagatit em4233
.SECONDARY: custom-build

ECHOFLAGS=-e
ECHO = $(shell which echo) $(ECHOFLAGS)
ifeq ("$(shell uname -s)", "Darwin")
	ECHOFLAGS=
endif

DEFAULT_TAG_SUPPORT_BASE     = -DCONFIG_ISO14443A_SNIFF_SUPPORT \
                               -DCONFIG_ISO14443A_READER_SUPPORT
SUPPORTED_TAGS_BUILD         =
EXTRA_CONFIG_SETTINGS        =

custom-build: local-clean $(TARGET).elf $(TARGET).hex $(TARGET).eep $(TARGET).bin check_size
	@cp $(TARGET).hex $(TARGET)-CustomBuild_$(TARGET_CUSTOM_BUILD_NAME).hex
	@cp $(TARGET).eep $(TARGET)-CustomBuild_$(TARGET_CUSTOM_BUILD_NAME).eep
	@cp $(TARGET).elf $(TARGET)-CustomBuild_$(TARGET_CUSTOM_BUILD_NAME).elf
	@cp $(TARGET).bin $(TARGET)-CustomBuild_$(TARGET_CUSTOM_BUILD_NAME).bin
	@$(ECHO) $(MSG_TIDY_ENDSEP)$(MSG_TIDY_ENDSEP)$(MSG_TIDY_ENDSEP)
	@avr-size -C -x $(TARGET).elf
	@$(ECHO) $(MSG_TIDY_ENDSEP)
	@avr-size -B -x $(TARGET).elf
	@$(ECHO) "\n"$(MSG_TIDY_ENDSEP)$(MSG_TIDY_ENDSEP)$(MSG_TIDY_ENDSEP)"\n"
	@$(ECHO) $(FMT_ANSIC_BOLD)$(FMT_ANSIC_EXCLAIM)"[!!!]"$(FMT_ANSIC_END) \
		" 💬  "$(FMT_ANSIC_BOLD)$(FMT_ANSIC_UNDERLINE)"SUCCESS BUILDING CUSTOM FIRMWARE:"$(FMT_ANSIC_END)
	@$(ECHO) $(FMT_ANSIC_BOLD)$(FMT_ANSIC_EXCLAIM)"[!!!]"$(FMT_ANSIC_END) \
		" 💯  "$(FMT_ANSIC_BOLD)"$(TARGET)-CustomBuild_$(TARGET_CUSTOM_BUILD_NAME).(HEX|EEP|ELF|BIN)"$(FMT_ANSIC_END)
	@$(ECHO) "\n"

mifare: SUPPORTED_TAGS_BUILD:=\
                -DCONFIG_MF_CLASSIC_MINI_4B_SUPPORT \
                -DCONFIG_MF_CLASSIC_1K_SUPPORT \
                -DCONFIG_MF_CLASSIC_1K_7B_SUPPORT \
                -DCONFIG_MF_CLASSIC_4K_SUPPORT \
                -DCONFIG_MF_CLASSIC_4K_7B_SUPPORT \
                -DCONFIG_MF_ULTRALIGHT_SUPPORT
mifare: TARGET_CUSTOM_BUILD_NAME:=MifareDefaultSupport
mifare: CONFIG_SETTINGS:=$(SUPPORTED_TAGS_BUILD) -DDEFAULT_CONFIGURATION=CONFIG_NONE $(EXTRA_CONFIG_SETTINGS)
mifare: custom-build

mifare-classic: SUPPORTED_TAGS_BUILD:=\
                -DCONFIG_MF_CLASSIC_MINI_4B_SUPPORT \
                -DCONFIG_MF_CLASSIC_1K_SUPPORT \
                -DCONFIG_MF_CLASSIC_1K_7B_SUPPORT \
                -DCONFIG_MF_CLASSIC_4K_SUPPORT \
                -DCONFIG_MF_CLASSIC_4K_7B_SUPPORT
mifare-classic: TARGET_CUSTOM_BUILD_NAME:=MifareClassicSupport
mifare-classic: CONFIG_SETTINGS:=$(SUPPORTED_TAGS_BUILD) -DDEFAULT_CONFIGURATION=CONFIG_NONE $(EXTRA_CONFIG_SETTINGS)
mifare-classic: custom-build

desfire: FLASH_DATA_SIZE:=0x0E000
desfire: SUPPORTED_TAGS_BUILD:=-DCONFIG_MF_DESFIRE_SUPPORT
desfire: EXTRA_CONFIG_SETTINGS:=-DMEMORY_LIMITED_TESTING \
                                -DDESFIRE_CRYPTO1_SAVE_SPACE \
				-finline-small-functions
desfire: TARGET_CUSTOM_BUILD_NAME:=DESFire
desfire: CONFIG_SETTINGS:=$(SUPPORTED_TAGS_BUILD) -DDEFAULT_CONFIGURATION=CONFIG_NONE $(EXTRA_CONFIG_SETTINGS)
desfire: custom-build

desfire-dev: FLASH_DATA_SIZE:=0x0E000
desfire-dev: SUPPORTED_TAGS_BUILD:=-DCONFIG_MF_DESFIRE_SUPPORT
desfire-dev: EXTRA_CONFIG_SETTINGS:=-DMEMORY_LIMITED_TESTING \
                                -DDESFIRE_CRYPTO1_SAVE_SPACE \
				-finline-small-functions \
                		-DDESFIRE_MIN_OUTGOING_LOGSIZE=0 \
                		-DDESFIRE_MIN_INCOMING_LOGSIZE=0 \
                		-DDESFIRE_DEFAULT_LOGGING_MODE=DEBUGGING \
                		-DDESFIRE_DEFAULT_TESTING_MODE=1
desfire-dev: TARGET_CUSTOM_BUILD_NAME:=DESFire_DEV
desfire-dev: CONFIG_SETTINGS:=$(SUPPORTED_TAGS_BUILD) -DDEFAULT_CONFIGURATION=CONFIG_NONE $(EXTRA_CONFIG_SETTINGS)
desfire-dev: custom-build

iso-modes: SUPPORTED_TAGS_BUILD:=\
                -DCONFIG_ISO14443A_SNIFF_SUPPORT \
                -DCONFIG_ISO14443A_READER_SUPPORT \
                -DCONFIG_ISO15693_SNIFF_SUPPORT
iso-modes: TARGET_CUSTOM_BUILD_NAME:=ISOSniffReaderModeSupport
iso-modes: CONFIG_SETTINGS:=$(SUPPORTED_TAGS_BUILD) -DDEFAULT_CONFIGURATION=CONFIG_NONE $(EXTRA_CONFIG_SETTINGS)
iso-modes: custom-build

ntag215: SUPPORTED_TAGS_BUILD:=$(DEFAULT_TAG_SUPPORT_BASE) -DCONFIG_NTAG215_SUPPORT
ntag215: TARGET_CUSTOM_BUILD_NAME:=NTAG215Support
ntag215: CONFIG_SETTINGS:=$(SUPPORTED_TAGS_BUILD) -DDEFAULT_CONFIGURATION=CONFIG_NONE $(EXTRA_CONFIG_SETTINGS)
ntag215: custom-build

vicinity: SUPPORTED_TAGS_BUILD:=$(DEFAULT_TAG_SUPPORT_BASE) -DCONFIG_VICINITY_SUPPORT
vicinity: TARGET_CUSTOM_BUILD_NAME:=VicinitySupport
vicinity: CONFIG_SETTINGS:=$(SUPPORTED_TAGS_BUILD) -DDEFAULT_CONFIGURATION=CONFIG_NONE $(EXTRA_CONFIG_SETTINGS)
vicinity: custom-build

sl2s2002: SUPPORTED_TAGS_BUILD:=$(DEFAULT_TAG_SUPPORT_BASE) -DCONFIG_SL2S2002_SUPPORT
sl2s2002: TARGET_CUSTOM_BUILD_NAME:=SL2S2002Support
sl2s2002: CONFIG_SETTINGS:=$(SUPPORTED_TAGS_BUILD) -DDEFAULT_CONFIGURATION=CONFIG_NONE $(EXTRA_CONFIG_SETTINGS)
sl2s2002: custom-build

tagatit: SUPPORTED_TAGS_BUILD:=$(DEFAULT_TAG_SUPPORT_BASE) \
                -DCONFIG_TITAGITSTANDARD_SUPPORT \
                -DCONFIG_TITAGITPLUS_SUPPORT
tagatit: TARGET_CUSTOM_BUILD_NAME:=TagatitSupport
tagatit: CONFIG_SETTINGS:=$(SUPPORTED_TAGS_BUILD) -DDEFAULT_CONFIGURATION=CONFIG_NONE $(EXTRA_CONFIG_SETTINGS)
tagatit: custom-build

em4233: SUPPORTED_TAGS_BUILD:=$(DEFAULT_TAG_SUPPORT_BASE) -DCONFIG_EM4233_SUPPORT
em4233: TARGET_CUSTOM_BUILD_NAME:=EM4233Support
em4233: CONFIG_SETTINGS:=$(SUPPORTED_TAGS_BUILD) -DDEFAULT_CONFIGURATION=CONFIG_NONE $(EXTRA_CONFIG_SETTINGS)
em4233: custom-build
