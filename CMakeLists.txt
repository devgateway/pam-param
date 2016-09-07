cmake_minimum_required(VERSION 2.8.11)
project (PAMPARAM)

find_path(PAM_INCLUDE NAMES "pam_modules.h" PATH_SUFFIXES "security" "pam")

add_library(pam_param MODULE pam-param.c)
set_target_properties(pam_param PROPERTIES PREFIX "")
target_include_directories(pam_param PRIVATE ${PAM_INCLUDE} inih)
target_link_libraries(pam_param inih)

add_library(inih STATIC inih/ini.c)
target_compile_definitions(inih PRIVATE INI_MAX_LINE=512)
set_target_properties(inih PROPERTIES POSITION_INDEPENDENT_CODE true)

add_executable(smoketest EXCLUDE_FROM_ALL test.c)
target_include_directories(smoketest PRIVATE ${PAM_INCLUDE} inih)
target_link_libraries(smoketest inih)

add_test(NAME smoke_test COMMAND $<TARGET_FILE:smoketest>)
