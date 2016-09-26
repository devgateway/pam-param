cmake_minimum_required(VERSION 2.8.11)
project(pam_param C)

find_path(PAM_INCLUDE NAMES "pam_modules.h" PATH_SUFFIXES "security" "pam")

add_library(pam_param MODULE pam_param.c)
set_target_properties(pam_param PROPERTIES PREFIX "")
target_include_directories(pam_param PRIVATE ${PAM_INCLUDE} inih)
target_link_libraries(pam_param inih ldap pam)

add_library(inih STATIC inih/ini.c)
target_compile_definitions(inih PRIVATE INI_MAX_LINE=512)
set_target_properties(inih PROPERTIES POSITION_INDEPENDENT_CODE true)

add_executable(pam_param_test authtest.c)
target_include_directories(pam_param_test PRIVATE ${PAM_INCLUDE})
target_link_libraries(pam_param_test pam)

set(MODULEDIR  /usr/lib/security  CACHE PATH "PAM module path")
set(SBINDIR    /usr/sbin          CACHE PATH "Privileged user binary path")
set(SECCONFDIR /etc/security      CACHE PATH "Security config path")
set(PAMCONFDIR /etc/pam.d         CACHE PATH "PAM config path")

install(TARGETS pam_param LIBRARY
	DESTINATION "${MODULEDIR}"
	NAMELINK_ONLY)
install(TARGETS pam_param_test RUNTIME
	DESTINATION "${SBINDIR}")
install(FILES "samples/pam_param.ini"
	DESTINATION "${SECCONFDIR}"
	PERMISSIONS OWNER_WRITE OWNER_READ)
install(FILES "samples/pam_param_test.pamd"
	DESTINATION "${PAMCONFDIR}"
	RENAME "pam_param_test")
