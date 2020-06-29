cmake_minimum_required (VERSION 2.8)
project (MorulaExtractor)
set (MorulaExtractor_VERSION_MAJOR 0)
set (MorulaExtractor_VERSION_MINOR 0)

find_package(Z3)
find_package(LLVM REQUIRED CONFIG)

include_directories(${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})
llvm_map_components_to_libnames(llvm_libs support core irreader)

include_directories("${PROJECT_BINARY_DIR}")
include_directories("${PROJECT_SOURCE_DIR}/include")
set(LIB_SRC_DIR "${PROJECT_SOURCE_DIR}/src")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -g")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3")

file(GLOB LIB_SRC
  "${PROJECT_SOURCE_DIR}/src/*.cpp"
  )

add_library(extractor STATIC ${LIB_SRC})

target_link_libraries(extractor z3)
target_link_libraries(extractor ${llvm_libs})

file(GLOB EXEC_SRC
  "${PROJECT_SOURCE_DIR}/exec/*.cpp"
  )

foreach(src_file ${EXEC_SRC})
  get_filename_component(prog_name ${src_file} NAME_WE)
  add_executable(${prog_name} ${src_file})
  target_link_libraries(${prog_name} extractor)
  target_link_libraries(${prog_name} ${llvm_libs})
  target_link_libraries(${prog_name} z3)
endforeach(src_file ${EXEC_SRC})
