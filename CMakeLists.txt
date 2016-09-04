cmake_minimum_required(VERSION 2.6)
project (PAMPARAM)

find_path(PAM_INCLUDE NAMES "pam_modules.h" PATH_SUFFIXES "security" "pam")

add_library(pam_param MODULE pam-param.c)
set_target_properties(pam_param PROPERTIES PREFIX "")
target_include_directories(pam_param PRIVATE ${PAM_INCLUDE} inih)
target_link_libraries(pam_param PRIVATE inih)

add_library(inih STATIC inih/ini.c)
target_compile_definitions(inih PRIVATE INI_MAX_LINE=512)
