cmake_minimum_required(VERSION 3.13)

project(flowperf
	VERSION 0.0.0
	LANGUAGES C)

add_executable(flowperf
	src/main.c src/server.c src/client.c src/prob.c src/print.c src/util.c)
target_include_directories(flowperf
	PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(flowperf uring)
target_compile_options(flowperf PRIVATE "-Wall")

# copy scripts to build directory
configure_file(${CMAKE_SOURCE_DIR}/scripts/flowperf-summary
	${CMAKE_BINARY_DIR}/ COPYONLY)

install(TARGETS flowperf
	DESTINATION bin)
install(FILES ${CMAKE_BINARY_DIR}/flowperf-summary
	DESTINATION bin)
