cmake_minimum_required(VERSION 2.6)
project(inotify_recursive)

add_executable(inotify_recursive inotify.c)

install(TARGETS inotify_recursive RUNTIME DESTINATION bin)
