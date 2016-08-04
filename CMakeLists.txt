cmake_minimum_required(VERSION 2.6)
project (PAMPARAM)

add_library(pam_param MODULE pam-param.c)
set_target_properties(pam_param PROPERTIES PREFIX "")
