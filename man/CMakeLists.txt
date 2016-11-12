cmake_minimum_required(VERSION 2.8.11)
project(manpages NONE)

set(MANDIR /usr/share/man CACHE PATH "Manual pages directory")

file(GLOB MANSRC *.[0-9])

foreach(SRC IN LISTS MANSRC)
	string(REGEX MATCH "[^.]+$" SECTION "${SRC}")
	install(FILES ${SRC}
		DESTINATION ${MANDIR}/man${SECTION}
		PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)
endforeach()
