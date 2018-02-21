#------------------------------- Relative utility path ---------------------------------#
#
# Specify the relative path ... where Makefile utilities are located
#
#---------------------------------------------------------------------------------------#
BUILD = ../../../../software/build

#---------------------------------- Application type -----------------------------------#
#
# Specify the application type: Exe, archive (.a) or dynamic lib (.so)
#
# APP_TYPE= exe, lib or dll
# APP_EXT=	# Allow to specify application extension (not use for librarie)
#
#---------------------------------------------------------------------------------------#
#APP_EXT=
APP_TYPE = exe

#------------------------------ Application or lib name --------------------------------#
#
# Specify the target file base name
#
#---------------------------------------------------------------------------------------#
APP_NAME = generator 

#----------------------------------- Makefile name -------------------------------------#
#
# Predefined in Makefile.pre 
# Default is $(APP_NAME).mak
# May be overrided
#
#---------------------------------------------------------------------------------------#
MAKEFILENAME = Makefile

#------------------------------------ Config name --------------------------------------#
#
# To use when same application may have various configurations
# Affect object path directory name: (see OBJPath )
# 	
#---------------------------------------------------------------------------------------#
#CONFIGNAME = 

#------------------------------- Object path definition --------------------------------#
#
# Predefined in Makefile.pre
# May be overrided
# Default is OBJPATH = $(CONFIGNAME_)$(BUILD_DIR)$(OBJ_PATH_SUFFIX)
#
#---------------------------------------------------------------------------------------#
#OBJPATH = 

#---------------------------- Application or lib full name -----------------------------#
#
# Predefined in Makefile.pre
# May be overrided
#
# where $(APP_FULL_NAME) = $(FILE_PREFIX)$(APP_NAME)$(CONFIGNAME)$(TGT_SUFFIX)$(FILE_EXT)
#---------------------------------------------------------------------------------------#
#APP_FULL_NAME = 

#-------------------------- App compiler specific directive ----------------------------#
#
# Added to CCFLAGS
#
#---------------------------------------------------------------------------------------#
APP_CC_FLAGS =

#-----------------------------------  Make utility -------------------------------------#
#
# Utility for target system and cross platform related utilities
#
#---------------------------------------------------------------------------------------#
include $(BUILD)/Makefile.pre

#----------------------------  Source file sub directory -------------------------------#
# 
# Directory where source file are located. (Related to this make file path )
#
#---------------------------------------------------------------------------------------#
SRC_DIR = source ../../common/source ../../../common/source

#-----------------------------------  Source files -------------------------------------#
# 
# List of source files.
#
#---------------------------------------------------------------------------------------#
SRC_FILES = \
	generator.c \
        octvocsamples_vspmp_voc_api_stats.c \
	octvocsamples_main_api_stats.c \
	octvocsamples_pkt_api_session.c \
	octvocsamples_string_utils.c  \
        oct_common_conio.c
                                  
#-------------------------------- Library Dependencies ---------------------------------#
# 
# List of depended libraries ... automatically rebuild by make 'all' rules
#		(related $(BUILD) path )
#
#---------------------------------------------------------------------------------------#
OCTLIB_DEP = \
	../octvc1pktapi/octvc1pktapi.mak \
	../common/octosal/octosal.mak \
	../common/octtransapi/octtransapi/octtransapi.mak \
	../common/octtransapi/octtransapi_eth/octtransapi_eth.mak

#------------------------------------- Other libs --------------------------------------#
# 
# Other libs to link with
#
#---------------------------------------------------------------------------------------#
OCTLIBS += 

#--------------------------------  Post build command ----------------------------------#
# 
# Normally use to copy and remove libs to default path $(BUILD)../lib
#
#---------------------------------------------------------------------------------------#
POSTBUILD =
POSTBUILD_CLEAN =

#----------------------  List of application specific includes -------------------------#
# 
#---------------------------------------------------------------------------------------#
INC += -I../../common/include -I../../../common/include

#------------------------- List of application specific flags --------------------------#
# 
#---------------------------------------------------------------------------------------#
CCFLAGS +=

#-------------------------------- Defaults make rules ----------------------------------#
# 
#---------------------------------------------------------------------------------------#
include $(BUILD)/Makefile.rules

