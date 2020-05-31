set(CMAKE_C_STANDARD 99)
if(NOT DISABLE_DYNAMIC)
  add_executable(sq sq.c)
  add_executable(sq_fuzz sq_fuzz.cpp)
  add_executable(exploit exploit.cpp)
  add_executable(squirrel::interpreter ALIAS sq)
  set_target_properties(sq PROPERTIES LINKER_LANGUAGE C EXPORT_NAME interpreter)
  target_link_libraries(sq squirrel sqstdlib)
  target_link_libraries(sq_fuzz
    squirrel sqstdlib
    $<$<C_COMPILER_ID:Clang>:-fsanitize=fuzzer,address>
  )
  target_link_libraries(exploit squirrel_static sqstdlib_static)
  target_compile_options(sq_fuzz
            PRIVATE $<$<C_COMPILER_ID:Clang>:-g -O1 -fsanitize=fuzzer,address>
            )
  if(NOT SQ_DISABLE_INSTALLER)
    install(TARGETS sq EXPORT squirrel RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT Runtime)
  endif()
  target_include_directories(sq PUBLIC
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
    )
  target_include_directories(sq_fuzz PUBLIC
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>"
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
    )
  target_include_directories(exploit PUBLIC
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>"
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
    )
endif()

if(NOT DISABLE_STATIC)
  add_executable(sq_static sq.c)
  add_executable(squirrel::interpreter_static ALIAS sq)
  set_target_properties(sq_static PROPERTIES LINKER_LANGUAGE C EXPORT_NAME interpreter_static)
  target_link_libraries(sq_static squirrel_static sqstdlib_static)
  if(NOT SQ_DISABLE_INSTALLER)
    install(TARGETS sq_static EXPORT squirrel RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT Runtime)
  endif()
  target_include_directories(sq_static PUBLIC
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
    )
endif()

if(LONG_OUTPUT_NAMES)
  if(NOT DISABLE_DYNAMIC)
    set_target_properties(sq PROPERTIES OUTPUT_NAME squirrel3)
  endif()

  if(NOT DISABLE_STATIC)
    set_target_properties(sq_static PROPERTIES OUTPUT_NAME squirrel3_static)
  endif()
endif()
