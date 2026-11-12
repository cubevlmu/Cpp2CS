cmake_minimum_required(VERSION 3.20)
project(cpp2cs_sleigh_bridge LANGUAGES CXX)

# 使用匹配版本的 standalone SLEIGH 安装包。
find_package(sleigh CONFIG REQUIRED)

add_library(cpp2cs_sleigh_bridge SHARED sleigh_bridge.cpp)
target_compile_features(cpp2cs_sleigh_bridge PRIVATE cxx_std_17)
target_link_libraries(cpp2cs_sleigh_bridge PRIVATE sleigh::sla sleigh::decomp)
target_compile_definitions(cpp2cs_sleigh_bridge PRIVATE CPP2CS_SLEIGH_BRIDGE_BUILD=1)
if(MSVC)
  target_compile_options(cpp2cs_sleigh_bridge PRIVATE /W4 /EHsc /utf-8)
else()
  target_compile_options(cpp2cs_sleigh_bridge PRIVATE -Wall -Wextra)
endif()
