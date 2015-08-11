cmake_minimum_required(VERSION 2.6)
project(inotify_recursive)

add_executable(inotify_recursive inotify.c chk_kernel.c socket_client.c curr_time.c enum_ip_inter.c )

install(TARGETS inotify_recursive RUNTIME DESTINATION bin)
