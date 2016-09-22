cmake_minimum_required(VERSION 2.8.11)
project (PAMPARAM)

find_path(PAM_INCLUDE NAMES "pam_modules.h" PATH_SUFFIXES "security" "pam")

add_library(pam_param MODULE pam-param.c)
set_target_properties(pam_param PROPERTIES PREFIX "")
target_include_directories(pam_param PRIVATE ${PAM_INCLUDE} inih)
target_link_libraries(pam_param inih ldap pam)

add_library(inih STATIC inih/ini.c)
target_compile_definitions(inih PRIVATE INI_MAX_LINE=512)
set_target_properties(inih PROPERTIES POSITION_INDEPENDENT_CODE true)

add_executable(authtest authtest.c)
target_include_directories(authtest PRIVATE ${PAM_INCLUDE})
target_link_libraries(authtest pam)

set(MODULEDIR /usr/lib/security CACHE PATH "PAM module path")
set(LIBEXECDIR /usr/libexec CACHE PATH "Supplemental binary path")
set(SECCONFDIR /etc/security CACHE PATH "Security config path")
set(PAMCONFDIR /etc/pam.d CACHE PATH "PAM config path")

install(TARGETS pam_param LIBRARY
	DESTINATION "${MODULEDIR}"
	NAMELINK_ONLY)
install(TARGETS authtest RUNTIME
	DESTINATION "${LIBEXECDIR}/${CMAKE_PROJECT_NAME}")
install(FILES "samples/pam-param.ini"
	DESTINATION "${SECCONFDIR}"
	PERMISSIONS OWNER_WRITE OWNER_READ)
install(FILES "samples/pam-param-test.pamd"
	DESTINATION "${PAMCONFDIR}"
	RENAME "pam-param-test")
