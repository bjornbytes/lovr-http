cmake_minimum_required(VERSION 3.5.0)
project(lovr-http)

add_library(http MODULE http.c)
set_target_properties(http PROPERTIES PREFIX "")

if(WIN32)
  target_link_libraries(http wininet)
elseif(APPLE)
  target_link_libraries(http objc)
endif()
