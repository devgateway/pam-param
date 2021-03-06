# Copyright 2016 Development Gateway, Inc
# This file is part of pam_param, see COPYING
cmake_minimum_required(VERSION 2.8.11)
include(GNUInstallDirs)
project(pam_param C)

find_path(PAM_INCLUDE NAMES "pam_modules.h" PATH_SUFFIXES "security" "pam")

add_subdirectory(ldapescape)

add_library(pam_param MODULE pam_param.c)
target_compile_definitions(pam_param PRIVATE CONFIG_FILE="${CMAKE_INSTALL_SYSCONFDIR}/security/pam_param.ini")
set_target_properties(pam_param PROPERTIES PREFIX "")
target_include_directories(pam_param PRIVATE ${PAM_INCLUDE} inih)
target_link_libraries(pam_param inih ldap pam ldapescape)

add_library(inih STATIC inih/ini.c)
target_compile_definitions(inih PRIVATE INI_MAX_LINE=512)
set_target_properties(inih PROPERTIES POSITION_INDEPENDENT_CODE true)

add_executable(pam_param_test authtest.c)
target_include_directories(pam_param_test PRIVATE ${PAM_INCLUDE})
target_link_libraries(pam_param_test pam)

install(TARGETS pam_param pam_param_test
	RUNTIME DESTINATION "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_SBINDIR}"
	LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}/security"
	NAMELINK_SKIP)

add_subdirectory(man)
