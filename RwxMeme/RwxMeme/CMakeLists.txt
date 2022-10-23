cmake_minimum_required (VERSION 3.8)

set(CMAKE_MFC_FLAG 1)

file(GLOB_RECURSE sourcefiles
    "src/*.h"
    "src/*.cpp"
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
add_compile_definitions(WIN32_LEAN_AND_MEAN)
add_compile_definitions(NOMINMAX)

find_package(MFC)
if (NOT MFC_FOUND)
  MESSAGE(FATAL_ERROR "MFC could not be found!")
endif()

macro(replace_flags var these those)
  if("${${var}}" MATCHES "${these}")
    string(REGEX REPLACE "${these}" "${those}" ${var} "${${var}}")
  endif()
  message(STATUS "info: ${var}='${${var}}'")
endmacro()

set(has_correct_flag 0)
foreach(lang C CXX)
foreach(suffix "" _DEBUG _MINSIZEREL _RELEASE _RELWITHDEBINFO)
    replace_flags("CMAKE_${lang}_FLAGS${suffix}" "/MD" "/MT")
    if(CMAKE_${lang}_FLAGS${suffix} MATCHES "/MT")
    set(has_correct_flag 1)
    endif()
endforeach()
endforeach()
if(NOT has_correct_flag)
    message(FATAL_ERROR "no CMAKE_*_FLAGS var contains /MT")
endif()

if(CMAKE_CXX_FLAGS MATCHES "/W[0-4]")
    string(REGEX REPLACE "/W[0-4]" "/W0" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W0")
endif()

if(CMAKE_CXX_FLAGS MATCHES "/Ob[0-4]")
    string(REGEX REPLACE "/Ob[0-4]" "/Ob1" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /Ob1")
endif()

if(CMAKE_CXX_FLAGS_RELEASE MATCHES "/Ob[0-4]")
    string(REGEX REPLACE "/Ob[0-4]" "/Ob1" CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS}")
else()
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} /Ob1")
endif()

link_directories(${CMAKE_SOURCE_DIR}/RwxMeme/lib)

add_executable(RwxMeme ${sourcefiles})
target_link_libraries(RwxMeme VMProtectSDK64)
